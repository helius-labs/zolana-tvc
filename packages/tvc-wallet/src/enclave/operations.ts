import { encodeDecimalU64 } from "../protocol/decimal.js";
import { TvcError } from "../protocol/error.js";
import { parseStrictJson } from "../protocol/json.js";
import type {
  BuildTransferOperationV1,
  ShieldSplOperationV1,
  BuildTransferResult,
  BootstrapEd25519Result,
  AssetV1,
  EnclaveWalletOperationResult,
  EnclaveWalletOperationV1,
  PrepareWalletResult,
  ShieldSolOperationV1,
  ShieldSolResult,
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

// A Record so the compiler still requires an entry per result variant; the
// lookup below uses Object.hasOwn because `result.type` is server-controlled
// and a bare index would resolve inherited names such as "toString".
const RESULT_KEYS: Record<EnclaveWalletOperationResult["type"], readonly string[]> = {
  CreateWallet: [
    "type",
    "wallet_name",
    "turnkey_wallet_id",
    "turnkey_wallet_account_id",
    "solana_address",
    "derivation_path",
    "turnkey_activity_id",
    "turnkey_app_proofs",
    "evidence_classification",
  ],
  BootstrapEd25519: [
    "type",
    "solana_address",
    "shielded_owner_hash",
    "shielded_nullifier_public_key",
    "shielded_viewing_public_key",
    "sealed_wallet_state",
    "state_version",
    "state_digest",
    "turnkey_activity_id",
    "turnkey_app_proofs",
    "evidence_classification",
  ],
  PrepareWallet: [
    "type",
    "signed_registration_transaction",
    "registration_signature",
    "registration_activity_id",
    "registration_app_proofs",
    "sealed_wallet_state",
    "state_version",
    "state_digest",
    "evidence_classification",
  ],
  ShieldSpl: [
    "type",
    "signed_transaction",
    "transaction_signature",
    "sealed_wallet_state",
    "state_version",
    "state_digest",
    "mint",
    "asset_id",
    "public_balance_before",
    "shielded_balance_before",
    "turnkey_activity_id",
    "turnkey_app_proofs",
    "evidence_classification",
  ],
  ShieldSol: [
    "type",
    "signed_transaction",
    "transaction_signature",
    "sealed_wallet_state",
    "state_version",
    "state_digest",
    "public_balance_before",
    "shielded_balance_before",
    "turnkey_activity_id",
    "turnkey_app_proofs",
    "evidence_classification",
  ],
  BuildTransfer: [
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

export type TvcEnclaveOperationsConfig = TvcWalletOperationsConfig;

export type EnclaveWalletResultFor<
  TOperation extends EnclaveWalletOperationV1,
> = Extract<EnclaveWalletOperationResult, { type: TOperation["type"] }>;

export type PrepareWalletInput = {
  readonly checkpoint: TvcWalletCheckpoint;
  readonly recentBlockhash: Uint8Array;
};

export type ShieldSolInput = {
  readonly checkpoint: TvcWalletCheckpoint;
  readonly amount: bigint;
};

export type ShieldSplInput = {
  readonly checkpoint: TvcWalletCheckpoint;
  readonly mint: string;
  readonly assetId: bigint;
  readonly amount: bigint;
};

export type EnclaveAssetInput =
  | { readonly type: "Sol" }
  | { readonly type: "Spl"; readonly mint: string; readonly assetId: bigint };

export type BuildEnclaveTransferInput = {
  readonly checkpoint: TvcWalletCheckpoint;
  readonly asset: EnclaveAssetInput;
  readonly recipient: string;
  readonly amount: bigint;
  readonly proverProfileId: string;
};

function validateResult<TOperation extends EnclaveWalletOperationV1>(
  result: EnclaveWalletOperationResult,
  operation: TOperation,
  proofStateDigest: string,
): asserts result is EnclaveWalletResultFor<TOperation> {
  const allowedKeys = Object.hasOwn(RESULT_KEYS, result.type)
    ? RESULT_KEYS[result.type]
    : undefined;
  if (!allowedKeys) throw new TvcError("UnsupportedVersion");
  assertExactObjectKeys(result, allowedKeys, "InvalidCanonicalJson");
  if (result.type === "Failure") {
    if (result.operation !== operation.type) throw new TvcError("ReleaseBindingMismatch");
    // `stage` is server-supplied text, so it travels as detail only and never
    // reaches the code that callers compare against fixed strings.
    throw new TvcError(
      "OperationFailed",
      typeof result.stage === "string" ? result.stage.slice(0, 200) : "unknown",
    );
  }
  if (
    result.type !== operation.type ||
    result.evidence_classification !== "CryptographicallyValidButUnbound"
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  verifyTurnkeyProofs(
    result.type === "PrepareWallet" ? result.registration_app_proofs : result.turnkey_app_proofs,
  );
  if (result.type !== "CreateWallet") {
    requireHex(result.sealed_wallet_state);
    encodeDecimalU64(BigInt(result.state_version));
    requireHex(result.state_digest, 32);
  }
  if (result.type === "BootstrapEd25519") {
    requireHex(result.shielded_owner_hash, 32);
    requireHex(result.shielded_nullifier_public_key, 32);
    requireHex(result.shielded_viewing_public_key, 33);
  }
  if (result.type === "PrepareWallet") {
    requireHex(result.signed_registration_transaction);
    if (!result.registration_signature) throw new TvcError("ReleaseBindingMismatch");
  }
  if (result.type === "ShieldSpl") {
    requireHex(result.signed_transaction);
    encodeDecimalU64(BigInt(result.public_balance_before));
    encodeDecimalU64(BigInt(result.shielded_balance_before));
    encodeDecimalU64(BigInt(result.asset_id));
    if (!result.transaction_signature || !result.mint) {
      throw new TvcError("ReleaseBindingMismatch");
    }
    // The enclave echoes the mint and asset id it resolved; a mismatch means it
    // deposited a different asset than the caller asked for.
    if (
      operation.type !== "ShieldSpl" ||
      result.mint !== operation.mint ||
      result.asset_id !== operation.asset_id
    ) {
      throw new TvcError("ReleaseBindingMismatch");
    }
  }
  if (result.type === "ShieldSol" || result.type === "BuildTransfer") {
    requireHex(result.signed_transaction);
    encodeDecimalU64(BigInt(result.shielded_balance_before));
    if (!result.transaction_signature) throw new TvcError("ReleaseBindingMismatch");
  }
  if (result.type === "ShieldSol") encodeDecimalU64(BigInt(result.public_balance_before));
  const stateDigest = result.type === "CreateWallet" ? "00".repeat(32) : result.state_digest;
  if (stateDigest !== proofStateDigest) throw new TvcError("ReleaseBindingMismatch");
}

export async function executeEnclaveWalletOperation<
  TOperation extends EnclaveWalletOperationV1,
>(
  context: OperationExecutionContext,
  operation: TOperation,
  checkpoint?: TvcWalletCheckpoint,
): Promise<EnclaveWalletResultFor<TOperation>> {
  const envelope = await executeOperationEnvelope(context, operation, checkpoint);
  const result = parseStrictJson<EnclaveWalletOperationResult>(envelope.plaintext);
  validateResult(result, operation, envelope.stateDigest);
  return result;
}

export function checkpointFromResult(
  result: BootstrapEd25519Result | PrepareWalletResult | ShieldSolResult | BuildTransferResult,
): TvcWalletCheckpoint {
  requireHex(result.sealed_wallet_state);
  encodeDecimalU64(BigInt(result.state_version));
  requireHex(result.state_digest, 32);
  return Object.freeze({
    sealedWalletState: result.sealed_wallet_state,
    stateVersion: result.state_version,
    stateDigest: result.state_digest,
  });
}

export function buildTransferOperation(
  input: BuildEnclaveTransferInput,
): BuildTransferOperationV1 {
  if (!input.recipient || !input.proverProfileId || input.amount <= 0n) {
    throw new TvcError("InvalidTransferIntent");
  }
  return {
    type: "BuildTransfer",
    intent: {
      asset: enclaveAsset(input.asset),
      recipient: input.recipient,
      amount: encodeDecimalU64(input.amount),
      prover_profile_id: input.proverProfileId,
    },
  };
}

export function shieldSolOperation(input: ShieldSolInput): ShieldSolOperationV1 {
  if (input.amount <= 0n) throw new TvcError("InvalidShieldAmount");
  return { type: "ShieldSol", amount: encodeDecimalU64(input.amount) };
}

export function shieldSplOperation(input: ShieldSplInput): ShieldSplOperationV1 {
  if (input.amount <= 0n) throw new TvcError("InvalidShieldAmount");
  // asset_id 0 and 1 are reserved; the enclave rejects them against the
  // shielded-pool registry, so reject them here rather than round-tripping.
  if (!input.mint || input.assetId <= 1n) throw new TvcError("InvalidTransferAsset");
  return {
    type: "ShieldSpl",
    mint: input.mint,
    asset_id: encodeDecimalU64(input.assetId),
    amount: encodeDecimalU64(input.amount),
  };
}

function enclaveAsset(input: EnclaveAssetInput): AssetV1 {
  if (input.type === "Sol") return { type: "Sol" };
  if (!input.mint || input.assetId <= 1n) throw new TvcError("InvalidTransferAsset");
  return {
    type: "Spl",
    mint: input.mint,
    asset_id: encodeDecimalU64(input.assetId),
  };
}

export type {
  AuthorizeTvcRequestInput,
  OperationExecutionContext,
  TvcOperationAuthorizer,
};
