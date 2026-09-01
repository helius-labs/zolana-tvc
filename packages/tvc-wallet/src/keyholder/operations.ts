import { decodeDecimalU64, encodeDecimalU64 } from "../protocol/decimal.js";
import { stateDigest } from "../protocol/digest.js";
import { decodeLowerHex, encodeLowerHex, requireHex } from "../protocol/hex.js";
import { TvcError } from "../protocol/error.js";
import { parseStrictJson } from "../protocol/json.js";
import type {
  BootstrapKeyholderResult,
  AssetV1,
  PrivateDomainV1,
  DecryptedPayloadV1,
  DecryptUtxosOperationV1,
  DecryptUtxosResult,
  SpendIntentV1,
  AuthorizeSpendResult,
  FinalizeSpendOperationV1,
  FinalizedSpendResult,
  PrepareSpendOperationV1,
  PreparedExactSpendResult,
  PreparedSppSpendResult,
  PreparedSpendResult,
  SppPlanV1,
  DeriveViewTagsOperationV1,
  DeriveViewTagsResult,
  EncryptedPayloadV1,
  WalletOperationResult,
  WalletOperationV1,
  TvcWalletCheckpoint,
} from "../protocol/types.js";
import { assertExactObjectKeys } from "../client/http.js";
import {
  executeOperationEnvelope,
  verifyCustodyProofs,
  type AuthorizeTvcRequestInput,
  type OperationExecutionContext,
  type TvcOperationAuthorizer,
  type TvcWalletOperationsConfig,
} from "../client/operation-executor.js";

/**
 * Mirrors the enclave-side caps in `crates/protocol/src/constants.rs`. The
 * envelope limit bounds request bytes, but these operations are the first where
 * a small request can ask for a large amount of work, so the bound on work is
 * separate. Rejecting here saves a round trip the enclave would refuse anyway.
 */
export const MAX_DECRYPT_PAYLOADS_PER_BATCH = 256;
export const MAX_SPENDABLE_OUTPUTS = 512;

const U32_MAX = 0xffff_ffffn;
const VIEW_TAG_BYTES = 32;
const SALT_BYTES = 16;
const TRANSACTION_VIEWING_KEY_BYTES = 33;

// A Record so the compiler still requires an entry per result variant; the
// lookup below uses Object.hasOwn because `result.type` is server-controlled
// and a bare index would resolve inherited names such as "toString".
const RESULT_KEYS: Record<WalletOperationResult["type"], readonly string[]> = {
  BootstrapKeyholder: [
    "type",
    "solana_address",
    "shielded_owner_hash",
    "shielded_nullifier_public_key",
    "shielded_viewing_public_key",
    "sealed_wallet_state",
    "derivation_suite",
    "turnkey_activity_id",
    "turnkey_app_proofs",
    "evidence_classification",
  ],
  DeriveViewTags: ["type", "view_tags"],
  DecryptUtxos: ["type", "payloads", "spendable_outputs"],
  AuthorizeSpend: [
    "type",
    "signed_transaction",
    "transaction_signature",
    "shielded_balance_before",
    "turnkey_activity_id",
    "turnkey_app_proofs",
    "evidence_classification",
  ],
  Failure: ["type", "operation", "stage"],
};

const PREPARED_SPEND_RESULT_KEYS = [
  "type",
  "phase",
  "prepared",
  "sealed_authorization_capsule",
  "shielded_balance_before",
] as const;

const PREPARED_EXACT_KEYS = ["type", "unsigned_transaction", "transaction_digest"] as const;
const PREPARED_SPP_KEYS = [
  "type",
  "program_id",
  "input_tree",
  "plan_digest",
  "transact",
  "transact_digest",
  "private_tx_hash",
  "external_data_hash",
] as const;

const FINALIZED_SPEND_RESULT_KEYS = [
  "type",
  "phase",
  "signed_transaction",
  "transaction_signature",
  "shielded_balance_before",
  "turnkey_activity_id",
  "turnkey_app_proofs",
  "evidence_classification",
] as const;

const PAYLOAD_KEYS: Record<DecryptUtxosResult["payloads"][number]["type"], readonly string[]> = {
  Plaintext: ["type", "index", "plaintext"],
  Malformed: ["type", "index"],
};
const SPENDABLE_OUTPUT_KEYS = ["commitment", "asset", "amount", "ring_program_id"] as const;

export type WalletResultFor<TOperation extends WalletOperationV1> =
  TOperation extends PrepareSpendOperationV1
    ? PreparedSpendResult
    : TOperation extends FinalizeSpendOperationV1
      ? FinalizedSpendResult
      : Extract<
          Exclude<WalletOperationResult, { type: "Failure" }>,
          { type: TOperation["type"] }
        >;

export type DeriveViewTagsInput = {
  readonly checkpoint: TvcWalletCheckpoint;
};

export type DecryptUtxosInput = {
  readonly checkpoint: TvcWalletCheckpoint;
  readonly payloads: readonly EncryptedPayloadV1[];
  readonly includeSpendableOutputs: boolean;
};

export type AssetInput =
  | { readonly type: "Sol" }
  | { readonly type: "Spl"; readonly mint: string; readonly assetId: bigint };

/** The policy domain of a private UTXO. */
export type PrivateDomainInput =
  | { readonly kind: "default" }
  | {
      readonly kind: "ring";
      readonly programId: string;
      /** Must be at least one slot old before the transact referencing it lands. */
      readonly lookupTable: string;
    };

/** Private transfer, explicit public withdrawal, or balance-neutral consolidation. */
export type SpendSettlementInput =
  | {
      readonly kind: "transfer";
      readonly asset: AssetInput;
      /** Registered shielded recipient. */
      readonly recipient: string;
      readonly amount: bigint;
      readonly destination: PrivateDomainInput;
    }
  | {
      readonly kind: "withdrawal";
      readonly asset: AssetInput;
      /** Public wallet owner; SPL settles to its associated token account. */
      readonly recipient: string;
      readonly amount: bigint;
    }
  | {
      readonly kind: "consolidate";
      readonly asset: AssetInput;
    };

export type AuthorizeSpendInput = {
  readonly checkpoint: TvcWalletCheckpoint;
  readonly source: PrivateDomainInput;
  readonly settlement: SpendSettlementInput;
  /** Exact default-ring inputs for a transition into a ring. */
  readonly inputCommitments?: readonly string[];
};

export type FinalizeSpendInput = {
  readonly checkpoint: TvcWalletCheckpoint;
  readonly sealedAuthorizationCapsule: string;
  readonly unsignedTransaction: string;
};

export type PrepareSppSpendInput = {
  readonly checkpoint: TvcWalletCheckpoint;
  readonly plan: SppPlanV1;
};

function domain(input: PrivateDomainInput): PrivateDomainV1 {
  if (input.kind === "default") return { type: "Default" };
  if (!input.programId || !input.lookupTable) {
    throw new TvcError("InvalidRingSpend");
  }
  return {
    type: "Ring",
    program_id: input.programId,
    lookup_table: input.lookupTable,
  };
}

function asset(input: AssetInput): AssetV1 {
  if (input.type === "Sol") return { type: "Sol" };
  if (!input.mint || input.assetId <= 1n) throw new TvcError("InvalidTransferAsset");
  return {
    type: "Spl",
    mint: input.mint,
    asset_id: encodeDecimalU64(input.assetId),
  };
}

function settlement(input: SpendSettlementInput): SpendIntentV1["settlement"] {
  if (input.kind === "consolidate") {
    return { type: "Consolidate", asset: asset(input.asset) };
  }
  if (!input.recipient || input.amount <= 0n) {
    throw new TvcError("InvalidTransferIntent");
  }
  if (input.kind === "transfer") {
    return {
      type: "Transfer",
      asset: asset(input.asset),
      recipient: input.recipient,
      amount: encodeDecimalU64(input.amount),
      destination: domain(input.destination),
    };
  }
  return {
    type: "Withdrawal",
    asset: asset(input.asset),
    recipient: input.recipient,
    amount: encodeDecimalU64(input.amount),
  };
}

function spendIntent(input: AuthorizeSpendInput): SpendIntentV1 {
  const inputCommitments = [...(input.inputCommitments ?? [])];
  for (const commitment of inputCommitments) requireHex(commitment, 32);
  const destination =
    input.settlement.kind === "transfer" ? input.settlement.destination : null;
  const consolidates = input.settlement.kind === "consolidate";
  const entersRing = input.source.kind === "default" && destination?.kind === "ring";
  const crossesRings =
    input.source.kind === "ring" &&
    destination?.kind === "ring" &&
    (input.source.programId !== destination.programId ||
      input.source.lookupTable !== destination.lookupTable);
  if (
    inputCommitments.length > 5 ||
    new Set(inputCommitments).size !== inputCommitments.length ||
    (entersRing && inputCommitments.length === 0) ||
    (!entersRing && inputCommitments.length !== 0) ||
    crossesRings ||
    (consolidates && input.source.kind !== "default")
  ) {
    throw new TvcError("InvalidRingSpend");
  }
  return {
    source: domain(input.source),
    settlement: settlement(input.settlement),
    input_commitments: inputCommitments,
  };
}

export function prepareSpendOperation(input: AuthorizeSpendInput): PrepareSpendOperationV1 {
  return {
    type: "AuthorizeSpend",
    spend: {
      phase: "Prepare",
      plan: { type: "Direct", transition: spendIntent(input) },
    },
  };
}

export function finalizeSpendOperation(input: FinalizeSpendInput): FinalizeSpendOperationV1 {
  requireHex(input.sealedAuthorizationCapsule);
  requireHex(input.unsignedTransaction);
  return {
    type: "AuthorizeSpend",
    spend: {
      phase: "Finalize",
      sealed_authorization_capsule: input.sealedAuthorizationCapsule,
      unsigned_transaction: input.unsignedTransaction,
    },
  };
}

export function prepareSppSpendOperation(
  input: PrepareSppSpendInput,
): PrepareSpendOperationV1 {
  validateSppPlan(input.plan);
  return {
    type: "AuthorizeSpend",
    spend: { phase: "Prepare", plan: { type: "Program", transition: input.plan } },
  };
}

function validateSppPlan(plan: SppPlanV1): void {
  if (
    !plan.program_id ||
    !plan.input_tree ||
    plan.inputs.length === 0 ||
    plan.outputs.length === 0 ||
    !Number.isInteger(plan.shape.inputs) ||
    !Number.isInteger(plan.shape.outputs) ||
    plan.shape.inputs < 1 ||
    plan.shape.inputs > 255 ||
    plan.shape.outputs < 1 ||
    plan.shape.outputs > 255 ||
    plan.shape.inputs < plan.inputs.length ||
    plan.shape.outputs !== plan.outputs.length ||
    plan.program_authorities.length > 8
  ) {
    throw new TvcError("InvalidTransferIntent");
  }
  decodeDecimalU64(plan.expires_at_ms);
  for (const authority of plan.program_authorities) {
    if (authority.seeds.length === 0 || authority.seeds.length > 16) {
      throw new TvcError("InvalidTransferIntent");
    }
    for (const seed of authority.seeds) {
      requireHex(seed);
      if (seed.length > 64) throw new TvcError("InvalidTransferIntent");
    }
  }
  for (const input of plan.inputs) {
    requireHex(input.commitment, 32);
    if (input.type === "Program") {
      validateSppAsset(input.asset);
      decodeDecimalU64(input.amount);
      requireHex(input.blinding, 32);
      if (input.data_hash !== null) requireHex(input.data_hash, 32);
      requireHex(input.nullifier_secret, 31);
      for (const seed of input.authority_seeds) requireHex(seed);
    }
  }
  for (const output of plan.outputs) {
    if (!output.recipient) throw new TvcError("InvalidTransferIntent");
    validateSppAsset(output.asset);
    decodeDecimalU64(output.amount);
    requireHex(output.blinding, 32);
    requireHex(output.data);
    requireHex(output.memo);
    if (output.data_hash !== null) requireHex(output.data_hash, 32);
  }
  for (const message of plan.messages) {
    requireHex(message.view_tag, 32);
    requireHex(message.data);
  }
}

function validateSppAsset(value: AssetV1): void {
  if (value.type === "Sol") return;
  if (!value.mint || decodeDecimalU64(value.asset_id) <= 1n) {
    throw new TvcError("InvalidTransferAsset");
  }
}

export function deriveViewTagsOperation(): DeriveViewTagsOperationV1 {
  return { type: "DeriveViewTags" };
}

export function decryptUtxosOperation(input: DecryptUtxosInput): DecryptUtxosOperationV1 {
  if (typeof input.includeSpendableOutputs !== "boolean") {
    throw new TvcError("InvalidDecryptRequest");
  }
  if (input.payloads.length === 0 && !input.includeSpendableOutputs) {
    throw new TvcError("EmptyDecryptBatch");
  }
  if (input.payloads.length > MAX_DECRYPT_PAYLOADS_PER_BATCH) {
    throw new TvcError("DecryptBatchTooLarge");
  }
  return {
    type: "DecryptUtxos",
    include_spendable_outputs: input.includeSpendableOutputs,
    payloads: input.payloads.map((payload) => {
      requireHex(payload.ciphertext);
      requireHex(payload.transaction_viewing_public_key, TRANSACTION_VIEWING_KEY_BYTES);
      requireHex(payload.salt, SALT_BYTES);
      if (payload.type === "RingDeposit") {
        return {
          type: "RingDeposit",
          ciphertext: payload.ciphertext,
          transaction_viewing_public_key: payload.transaction_viewing_public_key,
          salt: payload.salt,
        };
      }
      const slotIndex = BigInt(payload.slot_index);
      if (slotIndex < 0n || slotIndex > U32_MAX) throw new TvcError("InvalidSlotIndex");
      return {
        type: "Utxo",
        ciphertext: payload.ciphertext,
        transaction_viewing_public_key: payload.transaction_viewing_public_key,
        salt: payload.salt,
        slot_index: encodeDecimalU64(slotIndex),
      };
    }),
  };
}

function validateResult<TOperation extends WalletOperationV1>(
  result: WalletOperationResult,
  operation: TOperation,
  proofStateDigest: string,
  context: OperationExecutionContext,
): asserts result is WalletResultFor<TOperation> {
  const allowedKeys =
    result.type === "AuthorizeSpend" && "phase" in result
      ? result.phase === "Prepare"
        ? PREPARED_SPEND_RESULT_KEYS
        : result.phase === "Finalize"
          ? FINALIZED_SPEND_RESULT_KEYS
          : undefined
      : Object.hasOwn(RESULT_KEYS, result.type)
        ? RESULT_KEYS[result.type]
        : undefined;
  if (!allowedKeys) throw new TvcError("UnsupportedVersion");
  assertExactObjectKeys(result, allowedKeys, "InvalidCanonicalJson");
  if (result.type === "Failure") {
    if (result.operation !== operation.type) {
      throw new TvcError(
        "ReleaseBindingMismatch",
        `failure names ${result.operation}, asked for ${operation.type}`,
      );
    }
    throw new TvcError(
      "OperationFailed",
      typeof result.stage === "string" ? result.stage.slice(0, 200) : "unknown",
    );
  }
  if (result.type !== operation.type) {
    throw new TvcError(
      "ReleaseBindingMismatch",
      `result is ${result.type}, asked for ${operation.type}`,
    );
  }

  if (result.type === "AuthorizeSpend" && operation.type === "AuthorizeSpend") {
    if (operation.spend.phase !== result.phase) {
      throw new TvcError("ReleaseBindingMismatch", "spend phase does not match request");
    }
    if (
      operation.spend.phase === "Prepare" &&
      result.phase === "Prepare" &&
      ((operation.spend.plan.type === "Direct" &&
        result.prepared.type !== "ExactTransaction") ||
        (operation.spend.plan.type === "Program" && result.prepared.type !== "Spp"))
    ) {
      throw new TvcError("ReleaseBindingMismatch", "prepared artifact does not match plan");
    }
  }

  if (result.type === "BootstrapKeyholder") {
    if (result.evidence_classification !== "CryptographicallyValidButUnbound") {
      throw new TvcError("ReleaseBindingMismatch");
    }
    verifyCustodyProofs(context, result.turnkey_app_proofs);
    requireHex(result.shielded_owner_hash, 32);
    requireHex(result.shielded_nullifier_public_key, 32);
    requireHex(result.shielded_viewing_public_key, TRANSACTION_VIEWING_KEY_BYTES);
    requireHex(result.sealed_wallet_state);
    if (!result.derivation_suite || !result.solana_address) {
      throw new TvcError("ReleaseBindingMismatch");
    }
    // The sealed blob must be the one the App Proof committed to; otherwise a
    // response could carry a different key state than the one that was signed.
    const blobDigest = encodeLowerHex(
      stateDigest(decodeLowerHex(result.sealed_wallet_state)),
    );
    if (blobDigest !== proofStateDigest) {
      throw new TvcError("ReleaseBindingMismatch");
    }
    return;
  }

  if (result.type === "AuthorizeSpend") {
    if ("phase" in result && result.phase === "Prepare") {
      const preparedKeys =
        result.prepared.type === "ExactTransaction"
          ? PREPARED_EXACT_KEYS
          : result.prepared.type === "Spp"
            ? PREPARED_SPP_KEYS
            : undefined;
      if (!preparedKeys) throw new TvcError("UnsupportedVersion");
      assertExactObjectKeys(result.prepared, preparedKeys, "InvalidCanonicalJson");
      if (result.prepared.type === "ExactTransaction") {
        requireHex(result.prepared.unsigned_transaction);
        requireHex(result.prepared.transaction_digest, 32);
      } else {
        if (!result.prepared.program_id || !result.prepared.input_tree) {
          throw new TvcError("ReleaseBindingMismatch");
        }
        if (
          operation.type !== "AuthorizeSpend" ||
          operation.spend.phase !== "Prepare" ||
          operation.spend.plan.type !== "Program" ||
          result.prepared.program_id !== operation.spend.plan.transition.program_id ||
          result.prepared.input_tree !== operation.spend.plan.transition.input_tree
        ) {
          throw new TvcError("ReleaseBindingMismatch", "prepared SPP authority changed");
        }
        requireHex(result.prepared.plan_digest, 32);
        requireHex(result.prepared.transact);
        requireHex(result.prepared.transact_digest, 32);
        requireHex(result.prepared.private_tx_hash, 32);
        requireHex(result.prepared.external_data_hash, 32);
      }
      requireHex(result.sealed_authorization_capsule);
      decodeDecimalU64(result.shielded_balance_before);
      return;
    }
    if (result.evidence_classification !== "CryptographicallyValidButUnbound") {
      throw new TvcError("ReleaseBindingMismatch", "unexpected evidence class");
    }
    verifyCustodyProofs(context, result.turnkey_app_proofs);
    requireHex(result.signed_transaction);
    decodeDecimalU64(result.shielded_balance_before);
    if (!result.transaction_signature) {
      throw new TvcError("ReleaseBindingMismatch", "no transaction signature");
    }
    return;
  }

  // The two oracle operations answer against a key state the caller presented,
  // so the proof must name that state and not some other one.
  if (operation.type !== "DeriveViewTags" && operation.type !== "DecryptUtxos") {
    throw new TvcError("ReleaseBindingMismatch", `unhandled result ${result.type}`);
  }

  if (result.type === "DeriveViewTags") {
    if (!Array.isArray(result.view_tags) || result.view_tags.length === 0) {
      throw new TvcError("InvalidCanonicalJson");
    }
    for (const tag of result.view_tags) requireHex(tag, VIEW_TAG_BYTES);
    return;
  }

  if (operation.type !== "DecryptUtxos") throw new TvcError("ReleaseBindingMismatch");
  if (!Array.isArray(result.payloads)) throw new TvcError("InvalidCanonicalJson");
  if (result.payloads.length !== operation.payloads.length) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  result.payloads.forEach((payload: DecryptedPayloadV1, position: number) => {
    const payloadKeys = Object.hasOwn(PAYLOAD_KEYS, payload.type)
      ? PAYLOAD_KEYS[payload.type]
      : undefined;
    if (!payloadKeys) throw new TvcError("UnsupportedVersion");
    assertExactObjectKeys(payload, payloadKeys, "InvalidCanonicalJson");
    // Results carry their own index so callers need not trust ordering; check
    // that the index actually matches the position it arrived in.
    if (BigInt(payload.index) !== BigInt(position)) {
      throw new TvcError("ReleaseBindingMismatch");
    }
    if (payload.type === "Plaintext") requireHex(payload.plaintext);
  });
  if (operation.include_spendable_outputs) {
    if (!Array.isArray(result.spendable_outputs)) {
      throw new TvcError("ReleaseBindingMismatch", "missing spendable-output snapshot");
    }
    if (result.spendable_outputs.length > MAX_SPENDABLE_OUTPUTS) {
      throw new TvcError("ReleaseBindingMismatch", "spendable-output snapshot is too large");
    }
    const commitments = new Set<string>();
    for (const output of result.spendable_outputs) {
      assertExactObjectKeys(output, SPENDABLE_OUTPUT_KEYS, "InvalidCanonicalJson");
      requireHex(output.commitment, 32);
      validateSppAsset(output.asset);
      decodeDecimalU64(output.amount);
      if (output.ring_program_id !== null && !output.ring_program_id) {
        throw new TvcError("InvalidCanonicalJson");
      }
      if (commitments.has(output.commitment)) throw new TvcError("ReleaseBindingMismatch");
      commitments.add(output.commitment);
    }
  } else if (result.spendable_outputs !== null) {
    throw new TvcError("ReleaseBindingMismatch", "unexpected spendable-output snapshot");
  }
}

export async function executeKeyholderOperation<TOperation extends WalletOperationV1>(
  context: OperationExecutionContext,
  operation: TOperation,
  checkpoint?: TvcWalletCheckpoint,
): Promise<WalletResultFor<TOperation>> {
  const envelope = await executeOperationEnvelope(context, operation, checkpoint);
  // The enclave binds the digest of the key state it answered against into the
  // App Proof. When we presented one, the proof must name that state and not
  // another, or the answer could have been computed from different keys than
  // the ones we asked about.
  if (
    checkpoint &&
    envelope.stateDigest !==
      encodeLowerHex(stateDigest(decodeLowerHex(checkpoint.sealedWalletState)))
  ) {
    throw new TvcError("ReleaseBindingMismatch", "proof names another key state");
  }
  const result = parseStrictJson<WalletOperationResult>(envelope.plaintext);
  validateResult(result, operation, envelope.stateDigest, context);
  return result;
}

export function checkpointFromBootstrapResult(
  result: BootstrapKeyholderResult,
): TvcWalletCheckpoint {
  requireHex(result.sealed_wallet_state);
  return Object.freeze({
    sealedWalletState: result.sealed_wallet_state,
  });
}

export type {
  AuthorizeTvcRequestInput,
  AuthorizeSpendResult,
  FinalizedSpendResult,
  PreparedExactSpendResult,
  PreparedSppSpendResult,
  PreparedSpendResult,
  DecryptUtxosResult,
  DeriveViewTagsResult,
  OperationExecutionContext,
  TvcOperationAuthorizer,
  TvcWalletOperationsConfig,
};
