import { encodeDecimalU64 } from "../protocol/decimal.js";
import { TvcError } from "../protocol/error.js";
import { parseStrictJson } from "../protocol/json.js";
import type {
  BootstrapKeyholderResult,
  AssetV1,
  CustomRingV1,
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
  SolanaInstructionV1,
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
  requireHex,
  verifyTurnkeyProofs,
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

const U64_MAX = 0xffff_ffff_ffff_ffffn;
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
    "state_version",
    "state_digest",
    "derivation_suite",
    "turnkey_activity_id",
    "turnkey_app_proofs",
    "evidence_classification",
  ],
  DeriveViewTags: ["type", "view_tags"],
  DecryptUtxos: ["type", "payloads"],
  AuthorizeSpend: [
    "type",
    "signed_transaction",
    "transaction_signature",
    "sealed_wallet_state",
    "state_version",
    "state_digest",
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
  "sealed_wallet_state",
  "state_version",
  "state_digest",
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
  "sealed_wallet_state",
  "state_version",
  "state_digest",
  "shielded_balance_before",
  "turnkey_activity_id",
  "turnkey_app_proofs",
  "evidence_classification",
] as const;

const PAYLOAD_KEYS: Record<DecryptUtxosResult["payloads"][number]["type"], readonly string[]> = {
  Plaintext: ["type", "index", "plaintext"],
  Malformed: ["type", "index"],
};

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
};

export type AssetInput =
  | { readonly type: "Sol" }
  | { readonly type: "Spl"; readonly mint: string; readonly assetId: bigint };

/** Where a spend draws from. Absent is the default ring. */
export type CustomRingInput = {
  readonly direction: "enter" | "exit";
  readonly programId: string;
  /** Must be at least one slot old before the transact referencing it lands. */
  readonly lookupTable: string;
};

/** Where a ring spend settles. The ring itself is always required. */
export type SpendSettlementInput =
  | {
      readonly kind: "transfer";
      readonly asset: AssetInput;
      /** Registered shielded recipient. */
      readonly recipient: string;
      readonly amount: bigint;
    }
  | {
      readonly kind: "solWithdrawal";
      /** Public recipient, never resolved as a shielded address. */
      readonly recipient: string;
      readonly amount: bigint;
    };

export type AuthorizeSpendInput = {
  readonly checkpoint: TvcWalletCheckpoint;
  /** `null` selects the protocol's default ring. */
  readonly ring: CustomRingInput | null;
  readonly settlement: SpendSettlementInput;
  readonly proverProfileId: string;
  /** Exact default-ring inputs for an `enter` transition. */
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

export type FinalizeSppSpendInput = {
  readonly checkpoint: TvcWalletCheckpoint;
  readonly sealedAuthorizationCapsule: string;
  readonly instruction: SolanaInstructionV1;
  readonly addressLookupTables: readonly string[];
};

function ring(input: CustomRingInput): CustomRingV1 {
  if (
    !input.programId ||
    !input.lookupTable ||
    !["enter", "exit"].includes(input.direction)
  ) {
    throw new TvcError("InvalidRingSpend");
  }
  return {
    direction: input.direction === "enter" ? "Enter" : "Exit",
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

function requireU64(value: bigint): string {
  if (value < 0n || value > U64_MAX) throw new TvcError("InvalidDecimal");
  return encodeDecimalU64(value);
}

function settlement(input: SpendSettlementInput): SpendIntentV1["settlement"] {
  if (!input.recipient || input.amount <= 0n) {
    throw new TvcError("InvalidTransferIntent");
  }
  if (input.kind === "transfer") {
    return {
      type: "Transfer",
      asset: asset(input.asset),
      recipient: input.recipient,
      amount: encodeDecimalU64(input.amount),
    };
  }
  return {
    type: "SolWithdrawal",
    recipient: input.recipient,
    amount: encodeDecimalU64(input.amount),
  };
}

function spendIntent(input: AuthorizeSpendInput): SpendIntentV1 {
  if (!input.proverProfileId) throw new TvcError("InvalidTransferIntent");
  const inputCommitments = [...(input.inputCommitments ?? [])];
  for (const commitment of inputCommitments) requireHex(commitment, 32);
  if (
    inputCommitments.length > 5 ||
    new Set(inputCommitments).size !== inputCommitments.length ||
    (input.ring?.direction === "enter" && inputCommitments.length === 0) ||
    (input.ring?.direction !== "enter" && inputCommitments.length !== 0)
  ) {
    throw new TvcError("InvalidRingSpend");
  }
  return {
    ring: input.ring === null ? null : ring(input.ring),
    settlement: settlement(input.settlement),
    prover_profile_id: input.proverProfileId,
    input_commitments: inputCommitments,
  };
}

export function prepareSpendOperation(input: AuthorizeSpendInput): PrepareSpendOperationV1 {
  return {
    type: "AuthorizeSpend",
    spend: {
      phase: "Prepare",
      plan: { type: "Builtin", intent: spendIntent(input) },
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
      finalization: {
        type: "ExactTransaction",
        unsigned_transaction: input.unsignedTransaction,
      },
    },
  };
}

export function prepareSppSpendOperation(
  input: PrepareSppSpendInput,
): PrepareSpendOperationV1 {
  validateSppPlan(input.plan);
  return {
    type: "AuthorizeSpend",
    spend: { phase: "Prepare", plan: { type: "Spp", plan: input.plan } },
  };
}

export function finalizeSppSpendOperation(
  input: FinalizeSppSpendInput,
): FinalizeSpendOperationV1 {
  requireHex(input.sealedAuthorizationCapsule);
  if (!input.instruction.program_id || input.instruction.accounts.length === 0) {
    throw new TvcError("InvalidTransferIntent");
  }
  requireHex(input.instruction.data);
  return {
    type: "AuthorizeSpend",
    spend: {
      phase: "Finalize",
      sealed_authorization_capsule: input.sealedAuthorizationCapsule,
      finalization: {
        type: "SppProgram",
        instruction: input.instruction,
        address_lookup_tables: [...input.addressLookupTables],
      },
    },
  };
}

function validateSppPlan(plan: SppPlanV1): void {
  if (
    !plan.program_id ||
    !plan.input_tree ||
    !plan.prover_profile_id ||
    plan.public_effects.type !== "PrivateOnly" ||
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
  requireU64(BigInt(plan.expires_at_ms));
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
      const amount = BigInt(input.amount);
      requireU64(amount);
      requireHex(input.blinding, 32);
      if (input.data_hash !== null) requireHex(input.data_hash, 32);
      requireHex(input.nullifier_secret, 31);
      for (const seed of input.authority_seeds) requireHex(seed);
    }
  }
  for (const output of plan.outputs) {
    if (!output.recipient) throw new TvcError("InvalidTransferIntent");
    validateSppAsset(output.asset);
    const amount = BigInt(output.amount);
    requireU64(amount);
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
  const assetId = BigInt(value.asset_id);
  if (
    !value.mint ||
    assetId <= 1n ||
    requireU64(assetId) !== value.asset_id
  ) {
    throw new TvcError("InvalidTransferAsset");
  }
}

export function deriveViewTagsOperation(): DeriveViewTagsOperationV1 {
  return { type: "DeriveViewTags" };
}

export function decryptUtxosOperation(input: DecryptUtxosInput): DecryptUtxosOperationV1 {
  if (input.payloads.length === 0) throw new TvcError("EmptyDecryptBatch");
  if (input.payloads.length > MAX_DECRYPT_PAYLOADS_PER_BATCH) {
    throw new TvcError("DecryptBatchTooLarge");
  }
  return {
    type: "DecryptUtxos",
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
      ((operation.spend.plan.type === "Builtin" &&
        result.prepared.type !== "ExactTransaction") ||
        (operation.spend.plan.type === "Spp" && result.prepared.type !== "Spp"))
    ) {
      throw new TvcError("ReleaseBindingMismatch", "prepared artifact does not match plan");
    }
  }

  if (result.type === "BootstrapKeyholder") {
    if (result.evidence_classification !== "CryptographicallyValidButUnbound") {
      throw new TvcError("ReleaseBindingMismatch");
    }
    verifyTurnkeyProofs(result.turnkey_app_proofs);
    requireHex(result.shielded_owner_hash, 32);
    requireHex(result.shielded_nullifier_public_key, 32);
    requireHex(result.shielded_viewing_public_key, TRANSACTION_VIEWING_KEY_BYTES);
    requireHex(result.sealed_wallet_state);
    requireU64(BigInt(result.state_version));
    requireHex(result.state_digest, 32);
    if (!result.derivation_suite || !result.solana_address) {
      throw new TvcError("ReleaseBindingMismatch");
    }
    // The sealed blob must be the one the App Proof committed to; otherwise a
    // response could carry a different key state than the one that was signed.
    if (result.state_digest !== proofStateDigest) {
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
          operation.spend.plan.type !== "Spp" ||
          result.prepared.program_id !== operation.spend.plan.plan.program_id ||
          result.prepared.input_tree !== operation.spend.plan.plan.input_tree
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
      requireHex(result.sealed_wallet_state);
      requireU64(BigInt(result.state_version));
      requireHex(result.state_digest, 32);
      requireU64(BigInt(result.shielded_balance_before));
      if (result.state_digest !== proofStateDigest) {
        throw new TvcError("ReleaseBindingMismatch", "state digest is not the proven one");
      }
      return;
    }
    if (result.evidence_classification !== "CryptographicallyValidButUnbound") {
      throw new TvcError("ReleaseBindingMismatch", "unexpected evidence class");
    }
    verifyTurnkeyProofs(result.turnkey_app_proofs);
    requireHex(result.signed_transaction);
    requireU64(BigInt(result.state_version));
    requireHex(result.state_digest, 32);
    requireU64(BigInt(result.shielded_balance_before));
    if (!result.transaction_signature) {
      throw new TvcError("ReleaseBindingMismatch", "no transaction signature");
    }
    if (result.state_digest !== proofStateDigest) {
      throw new TvcError("ReleaseBindingMismatch", "state digest is not the proven one");
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
  if (checkpoint && envelope.stateDigest !== checkpoint.stateDigest) {
    throw new TvcError("ReleaseBindingMismatch", "proof names another key state");
  }
  const result = parseStrictJson<WalletOperationResult>(envelope.plaintext);
  validateResult(result, operation, envelope.stateDigest);
  return result;
}

export function checkpointFromBootstrapResult(
  result: BootstrapKeyholderResult,
): TvcWalletCheckpoint {
  requireHex(result.sealed_wallet_state);
  requireU64(BigInt(result.state_version));
  requireHex(result.state_digest, 32);
  return Object.freeze({
    sealedWalletState: result.sealed_wallet_state,
    stateVersion: result.state_version,
    stateDigest: result.state_digest,
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
