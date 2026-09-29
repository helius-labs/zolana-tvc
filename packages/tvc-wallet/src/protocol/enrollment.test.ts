import { sha256 } from "@noble/hashes/sha256";
import { describe, expect, it } from "vitest";
import { WALLET_ENROLLMENT_DOMAIN, walletEnrollmentMessage, type WalletEnrollment } from "./enrollment.js";
import { encodeLowerHex } from "./hex.js";

const enrollment: WalletEnrollment = {
  parentOrganizationId: "9b98a0d8-04a4-47a3-9dc3-afa84c686de4",
  organizationId: "1f0e6b1e-2a4c-4f7e-8d2b-3c4d5e6f7a8b",
  walletName: "Solana Wallet",
  turnkeyWalletId: "2a1b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d",
  solanaAddress: "7oS2B9oQ6QwcyC6EmmxAoBYBoKnVCkpR5pqL3xC9wVYq",
  clientPublicKey: `04${"ab".repeat(64)}`,
  issuedAtMs: 1_800_000_000_000,
};

describe("walletEnrollmentMessage", () => {
  it("is the domain and the digest of the fields, one per line", () => {
    const fields = [
      enrollment.parentOrganizationId,
      enrollment.organizationId,
      enrollment.walletName,
      enrollment.turnkeyWalletId,
      enrollment.solanaAddress,
      enrollment.clientPublicKey,
      "1800000000000",
    ].join("\n");
    expect(walletEnrollmentMessage(enrollment)).toBe(
      `${WALLET_ENROLLMENT_DOMAIN}\n${encodeLowerHex(sha256(new TextEncoder().encode(fields)))}`,
    );
  });

  it("changes with every field", () => {
    const message = walletEnrollmentMessage(enrollment);
    for (const changed of [
      { ...enrollment, organizationId: "3b2c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e" },
      { ...enrollment, clientPublicKey: `04${"cd".repeat(64)}` },
      { ...enrollment, issuedAtMs: enrollment.issuedAtMs + 1 },
    ]) {
      expect(walletEnrollmentMessage(changed)).not.toBe(message);
    }
  });

  it("refuses a malformed time or a field that would shift the lines", () => {
    for (const issuedAtMs of [-1, 1.5, Number.MAX_SAFE_INTEGER + 2]) {
      expect(() => walletEnrollmentMessage({ ...enrollment, issuedAtMs })).toThrow(/InvalidDecimal/);
    }
    expect(() => walletEnrollmentMessage({ ...enrollment, walletName: "Solana\nWallet" })).toThrow(
      /InvalidDescriptor/,
    );
  });
});
