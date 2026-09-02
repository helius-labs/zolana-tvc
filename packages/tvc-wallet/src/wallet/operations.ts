import { decodeDecimalU64 } from "../protocol/decimal.js";
import { stateDigest } from "../protocol/digest.js";
import { TvcError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex, requireHex } from "../protocol/hex.js";
import { parseStrictJson } from "../protocol/json.js";
import type {
  Checkpoint,
  DecryptOperation,
  DecryptedPayload,
  Operation,
  OperationResult,
  SpendOperation,
} from "../protocol/types.js";
import { assertExactObjectKeys } from "../client/http.js";
import {
  executeOperationEnvelope,
  type OperationExecutionContext,
} from "../client/operation-executor.js";

/** Mirrors `crates/protocol/src/constants.rs`; rejecting here saves a round trip. */
export const MAX_DECRYPT_PAYLOADS_PER_BATCH = 256;
export const MAX_SPEND_INPUTS = 5;

const U32_MAX = 0xffff_ffffn;
const VIEW_TAG_BYTES = 32;
const SALT_BYTES = 16;
const P256_PUBLIC_KEY_BYTES = 33;

// A Record so the compiler still requires an entry per result variant; the
// lookup uses Object.hasOwn because `result.type` is server-controlled and a
// bare index would resolve inherited names such as "toString".
const RESULT_KEYS: Record<OperationResult["type"], readonly string[]> = {
  Bootstrap: [
    "type",
    "solana_address",
    "shielded_owner_hash",
    "shielded_nullifier_public_key",
    "shielded_viewing_public_key",
    "sealed_wallet_state",
    "turnkey_activity_id",
    "turnkey_app_proofs",
  ],
  ViewTags: ["type", "view_tags"],
  Decrypt: ["type", "payloads"],
  Spend: ["type", "signed_transaction", "signature", "turnkey_activity_id", "turnkey_app_proofs"],
  Failure: ["type", "operation", "stage"],
};

const PAYLOAD_KEYS: Record<DecryptedPayload["type"], readonly string[]> = {
  Utxo: ["type", "index", "asset", "amount", "blinding", "ring_program_id", "commitment", "nullifier"],
  Unreadable: ["type", "index"],
};

export type ResultFor<TOperation extends Operation> = Extract<
  OperationResult,
  { type: TOperation["type"] }
>;

/** Checks a `Decrypt` request's bounds and encodings before it is signed. */
export function checkDecrypt(operation: DecryptOperation): DecryptOperation {
  if (operation.payloads.length === 0) throw new TvcError("EmptyDecryptBatch");
  if (operation.payloads.length > MAX_DECRYPT_PAYLOADS_PER_BATCH) {
    throw new TvcError("DecryptBatchTooLarge");
  }
  for (const payload of operation.payloads) {
    if (payload.type === "Encrypted") {
      requireHex(payload.ciphertext);
      requireHex(payload.transaction_viewing_public_key, P256_PUBLIC_KEY_BYTES);
      requireHex(payload.salt, SALT_BYTES);
      const slot = decodeDecimalU64(payload.slot_index);
      if (slot > U32_MAX) throw new TvcError("InvalidSlotIndex");
    } else {
      requireHex(payload.blinding, 32);
      decodeDecimalU64(payload.amount);
    }
  }
  for (const asset of operation.assets) decodeDecimalU64(asset.asset_id);
  return operation;
}

/** Checks a `Spend` request's bounds and encodings before it is signed. */
export function checkSpend(operation: SpendOperation): SpendOperation {
  if (operation.inputs.length === 0) throw new TvcError("NoSpendInputs");
  if (operation.inputs.length > MAX_SPEND_INPUTS) throw new TvcError("TooManySpendInputs");
  for (const input of operation.inputs) {
    requireHex(input.blinding, 32);
    if (decodeDecimalU64(input.amount) === 0n) throw new TvcError("InvalidSpendInput");
  }
  if (decodeDecimalU64(operation.action.amount) === 0n) throw new TvcError("InvalidSpendAmount");
  if (!operation.action.recipient || !operation.tree) throw new TvcError("InvalidSpendAction");
  for (const asset of operation.assets) decodeDecimalU64(asset.asset_id);
  return operation;
}

function checkResult<TOperation extends Operation>(
  result: OperationResult,
  operation: TOperation,
  proofStateDigest: string,
  context: OperationExecutionContext,
): asserts result is ResultFor<TOperation> {
  const keys = Object.hasOwn(RESULT_KEYS, result.type) ? RESULT_KEYS[result.type] : undefined;
  if (!keys) throw new TvcError("UnsupportedVersion");
  assertExactObjectKeys(result, keys, "InvalidCanonicalJson");
  if (result.type === "Failure") {
    if (result.operation !== operation.type) {
      throw new TvcError(
        "ReleaseBindingMismatch",
        `failure names ${result.operation}, asked for ${operation.type}`,
      );
    }
    throw new TvcError("OperationFailed", String(result.stage).slice(0, 200));
  }
  if (result.type !== operation.type) {
    throw new TvcError("ReleaseBindingMismatch", `result is ${result.type}, asked for ${operation.type}`);
  }

  switch (result.type) {
    case "Bootstrap": {
      context.trustVerifier.verifyCustodyProofs(result.turnkey_app_proofs);
      requireHex(result.shielded_owner_hash, 32);
      requireHex(result.shielded_nullifier_public_key, 32);
      requireHex(result.shielded_viewing_public_key, P256_PUBLIC_KEY_BYTES);
      if (!result.solana_address) throw new TvcError("ReleaseBindingMismatch");
      // The sealed blob must be the one the App Proof committed to; otherwise a
      // response could carry a different key state than the one that was signed.
      const digest = encodeLowerHex(stateDigest(requireHex(result.sealed_wallet_state)));
      if (digest !== proofStateDigest) throw new TvcError("ReleaseBindingMismatch");
      return;
    }
    case "ViewTags": {
      if (!Array.isArray(result.view_tags) || result.view_tags.length === 0) {
        throw new TvcError("InvalidCanonicalJson");
      }
      for (const tag of result.view_tags) requireHex(tag, VIEW_TAG_BYTES);
      return;
    }
    case "Decrypt": {
      if (operation.type !== "Decrypt") throw new TvcError("ReleaseBindingMismatch");
      if (!Array.isArray(result.payloads) || result.payloads.length !== operation.payloads.length) {
        throw new TvcError("ReleaseBindingMismatch");
      }
      result.payloads.forEach((payload: DecryptedPayload, position) => {
        const payloadKeys = Object.hasOwn(PAYLOAD_KEYS, payload.type)
          ? PAYLOAD_KEYS[payload.type]
          : undefined;
        if (!payloadKeys) throw new TvcError("UnsupportedVersion");
        assertExactObjectKeys(payload, payloadKeys, "InvalidCanonicalJson");
        // Results carry their own index so callers need not trust ordering;
        // check that it matches the position it arrived in anyway.
        if (decodeDecimalU64(payload.index) !== BigInt(position)) {
          throw new TvcError("ReleaseBindingMismatch");
        }
        if (payload.type === "Utxo") {
          requireHex(payload.blinding, 32);
          requireHex(payload.commitment, 32);
          requireHex(payload.nullifier, 32);
          decodeDecimalU64(payload.amount);
          if (!payload.asset || (payload.ring_program_id !== null && !payload.ring_program_id)) {
            throw new TvcError("InvalidCanonicalJson");
          }
        }
      });
      return;
    }
    case "Spend": {
      context.trustVerifier.verifyCustodyProofs(result.turnkey_app_proofs);
      requireHex(result.signed_transaction);
      if (!result.signature) throw new TvcError("ReleaseBindingMismatch", "no transaction signature");
      return;
    }
  }
}

/**
 * Runs one operation through the encrypted envelope and returns its checked
 * result. When a checkpoint is presented, the App Proof must name exactly that
 * key state, or the answer could have come from different keys than the ones
 * asked about.
 */
export async function executeOperation<TOperation extends Operation>(
  context: OperationExecutionContext,
  operation: TOperation,
  checkpoint?: Checkpoint,
): Promise<ResultFor<TOperation>> {
  const envelope = await executeOperationEnvelope(context, operation, checkpoint);
  if (
    checkpoint &&
    envelope.stateDigest !== encodeLowerHex(stateDigest(decodeLowerHex(checkpoint.sealedWalletState)))
  ) {
    throw new TvcError("ReleaseBindingMismatch", "proof names another key state");
  }
  const result = parseStrictJson<OperationResult>(envelope.plaintext);
  checkResult(result, operation, envelope.stateDigest, context);
  return result;
}
