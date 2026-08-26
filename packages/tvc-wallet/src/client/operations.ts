import { ed25519 } from "@noble/curves/ed25519";
import { TvcError } from "../protocol/error.js";
import { bytesEqual, encodeLowerHex } from "../protocol/hex.js";
import { MAX_SOLANA_TRANSACTION_BYTES } from "../protocol/constants.js";
import type {
  AuthorizeDefaultRingTransferOperationV1,
  AuthorizeDefaultRingTransferResult,
} from "../protocol/types.js";
import { encodeBase58 } from "./base58.js";
import { requireHex } from "./operation-executor.js";
import {
  defaultRingSolWithdrawalIntentDigest,
  defaultRingTransferIntentDigest,
  type DefaultRingSolWithdrawalIntentInput,
  type DefaultRingTransferIntentInput,
} from "./transfer-intent.js";

/**
 * Carries semantic intent rather than a caller-supplied digest. The package
 * therefore derives the authorization digest from the exact transaction bytes
 * that TVC is asked to sign.
 */
export type AuthorizeDefaultRingTransferInput =
  | { readonly kind: "transfer"; readonly intent: DefaultRingTransferIntentInput }
  | { readonly kind: "solWithdrawal"; readonly intent: DefaultRingSolWithdrawalIntentInput };

export function verifyDefaultRingAuthorizationResult(input: {
  readonly unsignedTransaction: Uint8Array;
  readonly result: AuthorizeDefaultRingTransferResult;
  readonly expectedEd25519PublicKey: Uint8Array;
}): void {
  const signed = requireHex(input.result.signed_transaction);
  const unsigned = input.unsignedTransaction;
  const signatureOffset = 1;
  const messageOffset = signatureOffset + 64;
  const signature = signed.slice(signatureOffset, messageOffset);
  if (
    input.expectedEd25519PublicKey.length !== 32 ||
    unsigned.length <= messageOffset ||
    signed.length !== unsigned.length ||
    unsigned[0] !== 1 ||
    signed[0] !== 1 ||
    unsigned.slice(signatureOffset, messageOffset).some((byte) => byte !== 0) ||
    signature.every((byte) => byte === 0) ||
    (signed[messageOffset]! & 0x80) !== 0 ||
    !bytesEqual(unsigned.slice(messageOffset), signed.slice(messageOffset)) ||
    !ed25519.verify(signature, signed.slice(messageOffset), input.expectedEd25519PublicKey, {
      zip215: false,
    }) ||
    encodeBase58(signature) !== input.result.transaction_signature
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }
}

export function authorizeDefaultRingTransferOperation(
  input: AuthorizeDefaultRingTransferInput,
): AuthorizeDefaultRingTransferOperationV1 {
  const unsignedTransaction = input.intent.unsignedTransaction;
  if (
    unsignedTransaction.length === 0 ||
    unsignedTransaction.length > MAX_SOLANA_TRANSACTION_BYTES
  ) {
    throw new TvcError("InvalidTransferIntent");
  }
  const intentDigest =
    input.kind === "transfer"
      ? defaultRingTransferIntentDigest(input.intent)
      : defaultRingSolWithdrawalIntentDigest(input.intent);
  return {
    type: "AuthorizeDefaultRingTransfer",
    intent_digest: encodeLowerHex(intentDigest),
    unsigned_transaction: encodeLowerHex(unsignedTransaction),
  };
}

export {
  defaultRingSolWithdrawalIntentDigest,
  defaultRingTransferIntentDigest,
  type DefaultRingSolWithdrawalIntentInput,
  type DefaultRingTransferIntentInput,
};
