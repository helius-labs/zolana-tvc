import { decodeDecimalU64 } from "../protocol/decimal.js";
import { stateDigest } from "../protocol/digest.js";
import { TvcError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex, requireHex } from "../protocol/hex.js";
import { parseStrictJson } from "../protocol/json.js";
import type {
  Checkpoint,
  DecryptOperation,
  DeriveOperation,
  Operation,
  OperationResult,
  ProveOperation,
  TransactionKeysOperation,
} from "../protocol/types.js";
import { assertExactObjectKeys } from "../client/http.js";
import {
  executeOperationEnvelope,
  type OperationExecutionContext,
} from "../client/operation-executor.js";

/** Mirrors `crates/protocol/src/constants.rs`; rejecting here saves a round trip. */
export const MAX_ITEMS_PER_BATCH = 256;
export const MAX_PROVE_INPUTS = 8;

const U32_MAX = 0xffff_ffffn;
const U8_MAX = 0xffn;
const SALT_BYTES = 16;
const P256_PUBLIC_KEY_BYTES = 33;
const PROVE_CIRCUITS = new Set(["transfer-confidential", "transfer-ring", "merge"]);

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
  Decrypt: ["type", "plaintexts"],
  Derive: ["type", "values"],
  TransactionKeys: ["type", "secrets"],
  Prove: ["type", "proof"],
  Failure: ["type", "operation", "stage"],
};

export type ResultFor<TOperation extends Operation> = Extract<
  OperationResult,
  { type: TOperation["type"] }
>;

function checkBatch(items: readonly unknown[]): void {
  if (items.length === 0) throw new TvcError("EmptyBatch");
  if (items.length > MAX_ITEMS_PER_BATCH) throw new TvcError("BatchTooLarge");
}

/** Checks a `Decrypt` request's bounds and encodings before it is signed. */
export function checkDecrypt(operation: DecryptOperation): DecryptOperation {
  checkBatch(operation.items);
  for (const item of operation.items) {
    requireHex(item.ciphertext);
    requireHex(item.viewing_public_key, P256_PUBLIC_KEY_BYTES);
    requireHex(item.transaction_viewing_public_key, P256_PUBLIC_KEY_BYTES);
    requireHex(item.salt, SALT_BYTES);
    const slot = decodeDecimalU64(item.slot_index);
    if (slot > U32_MAX || (item.label === "RingDeposit" && slot !== 0n)) {
      throw new TvcError("InvalidSlotIndex");
    }
    if (item.label !== "Transfer" && item.label !== "RingDeposit") {
      throw new TvcError("InvalidCanonicalJson");
    }
  }
  return operation;
}

/** Checks a `Derive` request's bounds and encodings before it is signed. */
export function checkDerive(operation: DeriveOperation): DeriveOperation {
  checkBatch(operation.items);
  for (const item of operation.items) {
    switch (item.kind) {
      case "Nullifier":
        requireHex(item.utxo_hash, 32);
        requireHex(item.blinding, 32);
        break;
      case "MergeDummyNullifier":
        requireHex(item.first_nullifier, 32);
        if (decodeDecimalU64(item.slot_index) > U8_MAX) throw new TvcError("InvalidSlotIndex");
        break;
      case "MergeOutputBlinding":
        requireHex(item.first_nullifier, 32);
        break;
    }
  }
  return operation;
}

/** Checks a `TransactionKeys` request's bounds and encodings before it is signed. */
export function checkTransactionKeys(
  operation: TransactionKeysOperation,
): TransactionKeysOperation {
  checkBatch(operation.items);
  for (const item of operation.items) {
    requireHex(item.viewing_public_key, P256_PUBLIC_KEY_BYTES);
    requireHex(item.first_nullifier, 32);
  }
  return operation;
}

/**
 * Checks a `Prove` request names a circuit the enclave completes and leaves at
 * least one slot for it to fill; the body's shape is otherwise the prover's.
 */
export function checkProve(operation: ProveOperation): ProveOperation {
  const body = operation.request;
  const circuit = body["circuitType"];
  if (typeof circuit !== "string" || !PROVE_CIRCUITS.has(circuit)) {
    throw new TvcError("InvalidProverRequest");
  }
  const inputs = body["inputs"];
  if (!Array.isArray(inputs) || inputs.length === 0 || inputs.length > MAX_PROVE_INPUTS) {
    throw new TvcError("InvalidProverRequest");
  }
  const open =
    circuit === "merge"
      ? body["userNullifierSecret"] === null
      : inputs.some(
          (input: unknown) =>
            typeof input === "object" &&
            input !== null &&
            (input as Record<string, unknown>)["nullifierSecret"] === null,
        );
  if (!open) throw new TvcError("InvalidProverRequest");
  return operation;
}

function checkHexList(values: unknown, count: number, bytes?: number): asserts values is string[] {
  if (!Array.isArray(values) || values.length !== count) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  for (const value of values) requireHex(value, bytes);
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
    case "Decrypt": {
      if (operation.type !== "Decrypt") throw new TvcError("ReleaseBindingMismatch");
      checkHexList(result.plaintexts, operation.items.length);
      return;
    }
    case "Derive": {
      if (operation.type !== "Derive") throw new TvcError("ReleaseBindingMismatch");
      checkHexList(result.values, operation.items.length, 32);
      return;
    }
    case "TransactionKeys": {
      if (operation.type !== "TransactionKeys") throw new TvcError("ReleaseBindingMismatch");
      checkHexList(result.secrets, operation.items.length, 32);
      return;
    }
    case "Prove": {
      if (result.proof === null || typeof result.proof !== "object") {
        throw new TvcError("ReleaseBindingMismatch", "no proof");
      }
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
