import { signP256Message, signP256Prehash, verifyP256Message } from "../crypto/p256.js";
import { encodeDecimalU64 } from "./decimal.js";
import { descriptorDigest, walletGrantDigest } from "./digest.js";
import { TvcError } from "./error.js";
import { decodeLowerHex, encodeLowerHex } from "./hex.js";
import { p256SecretFromKeyFile } from "./key-file.js";
import type { WalletDescriptor, WalletGrant } from "./types.js";

/** The enclave refuses a grant that lives longer (`MAX_WALLET_GRANT_LIFETIME_MS`). */
export const MAX_WALLET_GRANT_LIFETIME_MS = 3_600_000n;

/**
 * The development wallet-grant key the enclave is built with (`GRANT_PUBLIC` in
 * `apps/privacy-wallet/src/operations/mod.rs`). A grant signed by any other key
 * is refused there, so `walletGrantSecret` refuses it here first.
 */
export const DEVELOPMENT_WALLET_GRANT_PUBLIC_KEY =
  "0416e341bbb4c796cc62c7d81fcc067754f5bd000693423f9e1cf1ec024b04288fafd17806b67de5b0fcd89c4039e7181230b3bb133fcea7e3ff67bbb91ba5df66";

/** tvc-gateway's domain for a client key's grant renewal signature. */
export const WALLET_GRANT_RENEWAL_DOMAIN = "HELIUS_TVC_GATEWAY_WALLET_GRANT_RENEWAL_V1";

/** An issuer refuses a renewal whose `issuedAtMs` is further than this from its clock. */
export const MAX_WALLET_GRANT_RENEWAL_SKEW_MS = 60_000n;

/** `POST /wallet-grant`: `signature` is lower hex of the raw 64-byte low-S P-256 signature. */
export type WalletGrantRenewal = {
  readonly descriptor: WalletDescriptor;
  readonly issuedAtMs: number;
  readonly signature: string;
};

export type WalletGrantInput = {
  readonly descriptor: WalletDescriptor;
  readonly clientKeyId: string;
  /** The account the issuer attributes the wallet to; the enclave does not read it. */
  readonly projectId: string;
  readonly issuedAtMs: bigint;
  readonly lifetimeMs: bigint;
};

/**
 * The wallet-grant secret from a key file (`{"private_key": hex}`), checked to
 * be the key the enclave expects. The caller wipes it after use.
 */
export function walletGrantSecret(
  keyJson: string,
  expectedPublicKey: string = DEVELOPMENT_WALLET_GRANT_PUBLIC_KEY,
): Uint8Array {
  return p256SecretFromKeyFile(keyJson, expectedPublicKey, {
    invalid: "InvalidWalletGrantKey",
    wrong: "WrongWalletGrantKey",
  });
}

/**
 * A grant for one descriptor and client key, signed with the grant key's
 * secret as the 64-byte raw low-S P-256 signature over `walletGrantDigest`.
 */
export function signWalletGrant(input: WalletGrantInput, secret: Uint8Array): WalletGrant {
  if (input.lifetimeMs <= 0n || input.lifetimeMs > MAX_WALLET_GRANT_LIFETIME_MS) {
    throw new TvcError("InvalidDescriptor", "grant lifetime must be positive and at most one hour");
  }
  const unsigned: WalletGrant = {
    version: 1,
    descriptor_digest: encodeLowerHex(descriptorDigest(input.descriptor)),
    client_key_id: input.clientKeyId,
    project_id: input.projectId,
    issued_at_ms: encodeDecimalU64(input.issuedAtMs),
    expires_at_ms: encodeDecimalU64(input.issuedAtMs + input.lifetimeMs),
    signature: "",
  };
  return Object.freeze({
    ...unsigned,
    signature: encodeLowerHex(signP256Prehash(secret, walletGrantDigest(unsigned))),
  });
}

/**
 * The message the descriptor's client key signs with ECDSA over SHA-256 to
 * renew a grant:
 * `WALLET_GRANT_RENEWAL_DOMAIN || 0x00 || descriptorDigest || be_u64(issuedAtMs)`.
 */
export function walletGrantRenewalMessage(descriptor: WalletDescriptor, issuedAtMs: bigint): Uint8Array {
  if (issuedAtMs < 0n || issuedAtMs > 0xffff_ffff_ffff_ffffn) {
    throw new TvcError("InvalidDecimal", "renewal time must be an unsigned 64-bit integer");
  }
  const domain = new TextEncoder().encode(WALLET_GRANT_RENEWAL_DOMAIN);
  const message = new Uint8Array(domain.length + 1 + 32 + 8);
  message.set(domain, 0);
  message.set(descriptorDigest(descriptor), domain.length + 1);
  new DataView(message.buffer).setBigUint64(domain.length + 1 + 32, issuedAtMs, false);
  return message;
}

/** A renewal signed with the client key's P-256 secret, for tests and non-browser clients. */
export function signWalletGrantRenewal(
  descriptor: WalletDescriptor,
  issuedAtMs: bigint,
  clientSecret: Uint8Array,
): WalletGrantRenewal {
  return Object.freeze({
    descriptor,
    issuedAtMs: Number(issuedAtMs),
    signature: encodeLowerHex(signP256Message(clientSecret, walletGrantRenewalMessage(descriptor, issuedAtMs))),
  });
}

/**
 * Checks that a renewal is signed by the descriptor's only client key within
 * `MAX_WALLET_GRANT_RENEWAL_SKEW_MS` of `nowMs`. The caller verifies the
 * descriptor's provisioning signature.
 */
export function verifyWalletGrantRenewal(renewal: WalletGrantRenewal, nowMs: bigint): void {
  if (!Number.isSafeInteger(renewal.issuedAtMs) || renewal.issuedAtMs < 0) {
    throw new TvcError("InvalidDecimal", "renewal time must be a non-negative integer");
  }
  const issuedAtMs = BigInt(renewal.issuedAtMs);
  const skew = issuedAtMs > nowMs ? issuedAtMs - nowMs : nowMs - issuedAtMs;
  if (skew > MAX_WALLET_GRANT_RENEWAL_SKEW_MS) throw new TvcError("StaleRenewal");
  const [client, ...others] = renewal.descriptor.allowed_clients;
  if (!client || others.length > 0) throw new TvcError("InvalidDescriptor", "a renewal needs exactly one client");
  verifyP256Message(
    decodeLowerHex(client.client_public_key),
    walletGrantRenewalMessage(renewal.descriptor, issuedAtMs),
    decodeLowerHex(renewal.signature),
  );
}
