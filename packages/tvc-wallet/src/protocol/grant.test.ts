import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";
import { compactLowS } from "../platform/authorizer.js";
import { descriptorDigest } from "./digest.js";
import {
  MAX_WALLET_GRANT_RENEWAL_SKEW_MS,
  signWalletGrantRenewal,
  verifyWalletGrantRenewal,
  WALLET_GRANT_RENEWAL_DOMAIN,
  walletGrantRenewalMessage,
} from "./grant.js";
import { encodeLowerHex } from "./hex.js";
import { signWalletDescriptor } from "./provisioning.js";
import type { WalletDescriptor } from "./types.js";

const provisioningSecret = new Uint8Array(32).fill(7);
const clientSecret = new Uint8Array(32).fill(9);
const now = 1_790_000_000_000n;

function descriptorFor(clientPublicKey: string): WalletDescriptor {
  return signWalletDescriptor(
    {
      releasePolicy: {
        securityDomainId: "2e".repeat(32),
        environment: "development",
        allowedOperations: ["Bootstrap", "Decrypt", "Derive", "TransactionKeys", "Prove"],
      },
      turnkeyOrganizationId: "69febc39-7ac1-42c1-9786-f20f9cc52c5b",
      turnkeyWalletId: "wallet-1",
      address: "7oS2B9oQ6QwcyC6EmmxAoBYBoKnVCkpR5pqL3xC9wVYq",
      clientPublicKey,
    },
    provisioningSecret,
  );
}

const descriptor = descriptorFor(encodeLowerHex(p256.getPublicKey(clientSecret, false)));

describe("walletGrantRenewalMessage", () => {
  it("is the domain, a zero byte, the descriptor digest and the big-endian time", () => {
    const message = walletGrantRenewalMessage(descriptor, 0x0102030405060708n);
    const domain = new TextEncoder().encode(WALLET_GRANT_RENEWAL_DOMAIN);
    expect(message.subarray(0, domain.length)).toEqual(domain);
    expect(message[domain.length]).toBe(0);
    expect(message.subarray(domain.length + 1, domain.length + 33)).toEqual(descriptorDigest(descriptor));
    expect([...message.subarray(domain.length + 33)]).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });
});

describe("verifyWalletGrantRenewal", () => {
  it("accepts a renewal by the descriptor's client key at either edge of the skew", () => {
    for (const issuedAtMs of [now - MAX_WALLET_GRANT_RENEWAL_SKEW_MS, now, now + MAX_WALLET_GRANT_RENEWAL_SKEW_MS]) {
      expect(() => verifyWalletGrantRenewal(signWalletGrantRenewal(descriptor, issuedAtMs, clientSecret), now)).not.toThrow();
    }
  });

  it("accepts the WebCrypto ECDSA-SHA256 signature a browser key makes", async () => {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const browserDescriptor = descriptorFor(encodeLowerHex(publicKey));
    const message = walletGrantRenewalMessage(browserDescriptor, now);
    const signature = compactLowS(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new Uint8Array(message)),
    );
    expect(() =>
      verifyWalletGrantRenewal(
        { descriptor: browserDescriptor, issuedAtMs: Number(now), signature: encodeLowerHex(signature) },
        now,
      ),
    ).not.toThrow();
  });

  it("refuses a renewal outside the skew", () => {
    for (const issuedAtMs of [now - MAX_WALLET_GRANT_RENEWAL_SKEW_MS - 1n, now + MAX_WALLET_GRANT_RENEWAL_SKEW_MS + 1n]) {
      expect(() => verifyWalletGrantRenewal(signWalletGrantRenewal(descriptor, issuedAtMs, clientSecret), now)).toThrow(
        /StaleRenewal/,
      );
    }
  });

  it("refuses another key, another time or another descriptor", () => {
    const signed = signWalletGrantRenewal(descriptor, now, clientSecret);
    const foreign = signWalletGrantRenewal(descriptor, now, new Uint8Array(32).fill(3));
    expect(() => verifyWalletGrantRenewal(foreign, now)).toThrow(/InvalidSignature/);
    expect(() => verifyWalletGrantRenewal({ ...signed, issuedAtMs: signed.issuedAtMs + 1 }, now)).toThrow(
      /InvalidSignature/,
    );
    const other = descriptorFor(descriptor.allowed_clients[0]!.client_public_key);
    const retargeted = { ...other, turnkey_wallet_id: "wallet-2" };
    expect(() => verifyWalletGrantRenewal({ ...signed, descriptor: retargeted }, now)).toThrow(/InvalidSignature/);
  });

  it("refuses a descriptor without exactly one client and a malformed time", () => {
    const signed = signWalletGrantRenewal(descriptor, now, clientSecret);
    const client = descriptor.allowed_clients[0]!;
    for (const allowed_clients of [[], [client, client]]) {
      expect(() => verifyWalletGrantRenewal({ ...signed, descriptor: { ...descriptor, allowed_clients } }, now)).toThrow(
        /InvalidDescriptor/,
      );
    }
    for (const issuedAtMs of [-1, 1.5, Number.MAX_SAFE_INTEGER + 2]) {
      expect(() => verifyWalletGrantRenewal({ ...signed, issuedAtMs }, now)).toThrow(/InvalidDecimal/);
    }
  });

  it("signs the SHA-256 of the message", () => {
    const signed = signWalletGrantRenewal(descriptor, now, clientSecret);
    const digest = sha256(walletGrantRenewalMessage(descriptor, now));
    expect(p256.verify(signed.signature, digest, p256.getPublicKey(clientSecret, false), { prehash: false })).toBe(true);
  });
});
