import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { describe, expect, it } from "vitest";
import { encodeLowerHex } from "../protocol/hex.js";
import {
  authorizeDefaultRingTransferOperation,
  defaultRingSolWithdrawalIntentDigest,
  defaultRingTransferIntentDigest,
  verifyDefaultRingAuthorizationResult,
} from "./operations.js";

function encodeBase58(bytes: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let leadingZeroes = 0;
  while (leadingZeroes < bytes.length && bytes[leadingZeroes] === 0) leadingZeroes += 1;
  if (leadingZeroes === bytes.length) return "1".repeat(leadingZeroes);
  const digits = [0];
  for (let index = leadingZeroes; index < bytes.length; index += 1) {
    let carry = bytes[index] ?? 0;
    for (let digit = 0; digit < digits.length; digit += 1) {
      carry += (digits[digit] ?? 0) * 256;
      digits[digit] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  return (
    "1".repeat(leadingZeroes) +
    digits
      .reverse()
      .map((digit) => alphabet[digit])
      .join("")
  );
}

function authorizationFixture() {
  const secretKey = sha256(new TextEncoder().encode("default-ring-solana-signer"));
  const publicKey = ed25519.getPublicKey(secretKey);
  const message = new Uint8Array([1, 0, 0, 1, ...new Uint8Array(32).fill(9)]);
  const signature = ed25519.sign(message, secretKey);
  const unsignedTransaction = Uint8Array.from([1, ...new Uint8Array(64), ...message]);
  const signedTransaction = Uint8Array.from([1, ...signature, ...message]);
  const result = {
    type: "AuthorizeDefaultRingTransfer" as const,
    signed_transaction: encodeLowerHex(signedTransaction),
    transaction_signature: encodeBase58(signature),
    intent_digest: "77".repeat(32),
    turnkey_activity_id: "activity-transfer",
    turnkey_app_proofs: [],
    evidence_classification: "CryptographicallyValidButUnbound" as const,
  };
  return { publicKey, result, signedTransaction, unsignedTransaction };
}

describe("default-ring authorization", () => {
  it("derives the intent digest from the exact bytes it authorizes", () => {
    const intent = {
      walletId: "wallet-1",
      solanaAddress: "payer",
      recipient: "recipient",
      asset: { type: "Sol" as const },
      amount: 10n,
      unsignedTransaction: new Uint8Array([1, 2, 3]),
    };
    const operation = authorizeDefaultRingTransferOperation({ kind: "transfer", intent });
    expect(operation.intent_digest).toBe(encodeLowerHex(defaultRingTransferIntentDigest(intent)));
    expect(
      authorizeDefaultRingTransferOperation({
        kind: "transfer",
        intent: { ...intent, unsignedTransaction: new Uint8Array([1, 2, 4]) },
      }).intent_digest,
    ).not.toBe(operation.intent_digest);
  });

  it("domain-separates withdrawals from private transfers", () => {
    const common = {
      walletId: "wallet-1",
      solanaAddress: "payer",
      recipient: "recipient",
      amount: 10n,
      unsignedTransaction: new Uint8Array([1, 2, 3]),
    };
    expect(encodeLowerHex(defaultRingSolWithdrawalIntentDigest(common))).not.toBe(
      encodeLowerHex(defaultRingTransferIntentDigest({ ...common, asset: { type: "Sol" } })),
    );
  });

  it("rejects empty, oversized, or zero-amount transfers", () => {
    const intent = {
      walletId: "wallet-1",
      solanaAddress: "payer",
      recipient: "recipient",
      asset: { type: "Sol" as const },
      amount: 10n,
      unsignedTransaction: new Uint8Array(1_233),
    };
    expect(() => authorizeDefaultRingTransferOperation({ kind: "transfer", intent })).toThrow(
      "InvalidTransferIntent",
    );
    expect(() =>
      authorizeDefaultRingTransferOperation({
        kind: "transfer",
        intent: { ...intent, unsignedTransaction: new Uint8Array() },
      }),
    ).toThrow("InvalidTransferIntent");
    expect(() =>
      authorizeDefaultRingTransferOperation({
        kind: "transfer",
        intent: { ...intent, amount: 0n, unsignedTransaction: new Uint8Array([1]) },
      }),
    ).toThrow("InvalidTransferIntent");
  });

  it("verifies the exact signed legacy transaction", () => {
    const fixture = authorizationFixture();
    expect(() => verifyDefaultRingAuthorizationResult({
      unsignedTransaction: fixture.unsignedTransaction,
      result: fixture.result,
      expectedEd25519PublicKey: fixture.publicKey,
    })).not.toThrow();
  });

  it("rejects changed signed bytes or a changed reported signature", () => {
    const fixture = authorizationFixture();
    const changed = fixture.signedTransaction.slice();
    changed[changed.length - 1] = (changed.at(-1) ?? 0) ^ 1;
    expect(() => verifyDefaultRingAuthorizationResult({
      unsignedTransaction: fixture.unsignedTransaction,
      result: { ...fixture.result, signed_transaction: encodeLowerHex(changed) },
      expectedEd25519PublicKey: fixture.publicKey,
    })).toThrow("ReleaseBindingMismatch");
    expect(() => verifyDefaultRingAuthorizationResult({
      unsignedTransaction: fixture.unsignedTransaction,
      result: { ...fixture.result, transaction_signature: "wrong" },
      expectedEd25519PublicKey: fixture.publicKey,
    })).toThrow("ReleaseBindingMismatch");
  });
});
