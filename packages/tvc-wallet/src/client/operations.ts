import { ed25519 } from "@noble/curves/ed25519";
import { TvcError } from "../protocol/error.js";
import { bytesEqual, encodeLowerHex } from "../protocol/hex.js";
import { parseStrictJson } from "../protocol/json.js";
import {
  CLIENT_ED25519_DERIVATION_SUITE,
  MAX_SOLANA_TRANSACTION_BYTES,
} from "../protocol/constants.js";
import type {
  AuthorizeDefaultRingTransferOperationV1,
  AuthorizeDefaultRingTransferResult,
  BootstrapClientEd25519Result,
  WalletOperationResult,
  WalletOperationV1,
} from "../protocol/types.js";
import { encodeBase58 } from "./base58.js";
import { assertExactObjectKeys } from "./http.js";
import {
  defaultRingSolWithdrawalIntentDigest,
  defaultRingTransferIntentDigest,
  type DefaultRingSolWithdrawalIntentInput,
  type DefaultRingTransferIntentInput,
} from "./transfer-intent.js";
import {
  executeOperationEnvelope,
  requireHex,
  verifyTurnkeyProofs,
  type AuthorizeTvcRequestInput,
  type OperationExecutionContext,
  type TvcOperationAuthorizer,
  type TvcWalletOperationsConfig,
} from "./operation-executor.js";

const NO_SERVER_STATE_DIGEST = "00".repeat(32);
// A Record so the compiler still requires an entry per result variant; the
// lookup below uses Object.hasOwn because `result.type` is server-controlled
// and a bare index would resolve inherited names such as "toString".
const RESULT_KEYS: Record<WalletOperationResult["type"], readonly string[]> = {
  BootstrapClientEd25519: [
    "type",
    "solana_address",
    "shielded_owner_hash",
    "shielded_nullifier_public_key",
    "shielded_viewing_public_key",
    "derivation_seed",
    "derivation_suite",
    "turnkey_activity_id",
    "turnkey_app_proofs",
    "evidence_classification",
  ],
  AuthorizeDefaultRingTransfer: [
    "type",
    "signed_transaction",
    "transaction_signature",
    "intent_digest",
    "turnkey_activity_id",
    "turnkey_app_proofs",
    "evidence_classification",
  ],
};

export type WalletOperationResultFor<
  TOperation extends WalletOperationV1,
> = Extract<WalletOperationResult, { type: TOperation["type"] }>;

/**
 * Carries the semantic intent rather than a precomputed digest, so the digest
 * this client authorizes is always derived from the very transaction bytes it
 * sends. Accepting the two separately let a caller pair a digest with unrelated
 * bytes, which is exactly the binding this rail exists to guarantee.
 */
export type AuthorizeDefaultRingTransferInput =
  | { readonly kind: "transfer"; readonly intent: DefaultRingTransferIntentInput }
  | { readonly kind: "solWithdrawal"; readonly intent: DefaultRingSolWithdrawalIntentInput };

function validateResult<TOperation extends WalletOperationV1>(
  result: WalletOperationResult,
  operation: TOperation,
  proofStateDigest: string,
): asserts result is WalletOperationResultFor<TOperation> {
  const allowedKeys = Object.hasOwn(RESULT_KEYS, result.type)
    ? RESULT_KEYS[result.type]
    : undefined;
  if (!allowedKeys) throw new TvcError("UnsupportedVersion");
  assertExactObjectKeys(result, allowedKeys, "InvalidCanonicalJson");
  if (
    result.type !== operation.type ||
    result.evidence_classification !== "CryptographicallyValidButUnbound" ||
    proofStateDigest !== NO_SERVER_STATE_DIGEST
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  verifyTurnkeyProofs(result.turnkey_app_proofs);
  if (result.type === "BootstrapClientEd25519") {
    requireHex(result.shielded_owner_hash, 32);
    requireHex(result.shielded_nullifier_public_key, 32);
    requireHex(result.shielded_viewing_public_key, 33);
    requireHex(result.derivation_seed, 64);
    if (result.derivation_suite !== CLIENT_ED25519_DERIVATION_SUITE) {
      throw new TvcError("ReleaseBindingMismatch");
    }
  } else {
    requireHex(result.signed_transaction);
    requireHex(result.intent_digest, 32);
    if (
      operation.type !== "AuthorizeDefaultRingTransfer" ||
      result.intent_digest !== operation.intent_digest ||
      result.transaction_signature.length === 0
    ) {
      throw new TvcError("ReleaseBindingMismatch");
    }
  }
}

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

export async function executeWalletOperation<TOperation extends WalletOperationV1>(
  context: OperationExecutionContext,
  operation: TOperation,
): Promise<WalletOperationResultFor<TOperation>> {
  const envelope = await executeOperationEnvelope(context, operation);
  const result = parseStrictJson<WalletOperationResult>(envelope.plaintext);
  const target = context.operations.walletDescriptor.turnkey_signing_target;
  if (
    result.type === "BootstrapClientEd25519" &&
    (target.type !== "HdWalletAccount" || result.solana_address !== target.address)
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  if (
    result.type === "AuthorizeDefaultRingTransfer" &&
    operation.type === "AuthorizeDefaultRingTransfer"
  ) {
    verifyDefaultRingAuthorizationResult({
      unsignedTransaction: requireHex(operation.unsigned_transaction),
      result,
      expectedEd25519PublicKey: requireHex(
        context.operations.walletDescriptor.expected_ed25519_public_key,
        32,
      ),
    });
  }
  validateResult(result, operation, envelope.stateDigest);
  return result;
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

export type { AuthorizeDefaultRingTransferResult, BootstrapClientEd25519Result };
export type {
  AuthorizeTvcRequestInput,
  OperationExecutionContext,
  TvcOperationAuthorizer,
  TvcWalletOperationsConfig,
};

export {
  defaultRingSolWithdrawalIntentDigest,
  defaultRingTransferIntentDigest,
  type DefaultRingSolWithdrawalIntentInput,
  type DefaultRingTransferIntentInput,
};
