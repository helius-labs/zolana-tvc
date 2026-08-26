import { TvcError } from "../protocol/error.js";
import type { TvcWalletCheckpoint, WalletDescriptorV1 } from "../protocol/types.js";
import {
  clearRecord,
  isCanonicalU64 as isU64,
  isLowerHex,
  isRecordWithKeys,
  isSolanaBase58 as isBase58,
  hasOnlyKeys,
  loadRecord,
  saveRecord,
} from "../platform/persisted-state.js";

const DATABASE_NAME = "zolana-tvc-enclave-wallet-v1";
const STATE_RECORD = "wallet-state";
const MAX_TRANSACTIONS = 100;
const STATE_KEYS = [
  "version",
  "clientKeyId",
  "turnkeyServicePublicKey",
  "walletDescriptor",
  "bootstrap",
  "checkpoint",
  "registered",
  "shieldedBalanceRaw",
  "pendingSubmission",
  "transactions",
] as const;
const CHECKPOINT_KEYS = ["sealedWalletState", "stateVersion", "stateDigest"] as const;
const BOOTSTRAP_KEYS = [
  "solanaAddress",
  "shieldedOwnerHash",
  "shieldedNullifierPublicKey",
  "shieldedViewingPublicKey",
] as const;
const PENDING_KEYS = [
  "type",
  "signedTransaction",
  "transactionSignature",
  "nextCheckpoint",
  "amountRaw",
  "recipient",
  "shieldedBalanceBeforeRaw",
] as const;
const TRANSACTION_KEYS = [
  "type",
  "signature",
  "amountRaw",
  "recipient",
  "balanceAfterRaw",
  "finalizedAtMs",
] as const;

export type EnclaveBrowserBootstrap = {
  readonly solanaAddress: string;
  readonly shieldedOwnerHash: string;
  readonly shieldedNullifierPublicKey: string;
  readonly shieldedViewingPublicKey: string;
};

export type EnclaveBrowserPendingSubmission = {
  readonly type: "PrepareWallet" | "ShieldSol" | "BuildTransfer";
  readonly signedTransaction: string;
  readonly transactionSignature: string;
  readonly nextCheckpoint: TvcWalletCheckpoint;
  readonly amountRaw: string | null;
  readonly recipient: string | null;
  readonly shieldedBalanceBeforeRaw: string | null;
};

export type EnclaveBrowserTransaction = {
  readonly type: "ShieldSol" | "BuildTransfer";
  readonly signature: string;
  readonly amountRaw: string;
  readonly recipient: string | null;
  readonly balanceAfterRaw: string;
  readonly finalizedAtMs: string;
};

export type EnclaveBrowserWalletState = {
  readonly version: 1;
  readonly clientKeyId: string;
  readonly turnkeyServicePublicKey: string;
  readonly walletDescriptor: WalletDescriptorV1;
  readonly bootstrap: EnclaveBrowserBootstrap | null;
  readonly checkpoint: TvcWalletCheckpoint | null;
  readonly registered: boolean;
  readonly shieldedBalanceRaw: string;
  readonly pendingSubmission: EnclaveBrowserPendingSubmission | null;
  readonly transactions: readonly EnclaveBrowserTransaction[];
};

function isCheckpoint(value: unknown): value is TvcWalletCheckpoint {
  if (!isRecordWithKeys(value, CHECKPOINT_KEYS)) return false;
  const checkpoint = value as Partial<TvcWalletCheckpoint>;
  return (
    isLowerHex(checkpoint.sealedWalletState) &&
    isU64(checkpoint.stateVersion) &&
    isLowerHex(checkpoint.stateDigest, 32)
  );
}

function isBootstrap(value: unknown): value is EnclaveBrowserBootstrap {
  if (!isRecordWithKeys(value, BOOTSTRAP_KEYS)) return false;
  const bootstrap = value as Partial<EnclaveBrowserBootstrap>;
  return (
    isBase58(bootstrap.solanaAddress) &&
    isLowerHex(bootstrap.shieldedOwnerHash, 32) &&
    isLowerHex(bootstrap.shieldedNullifierPublicKey, 32) &&
    isLowerHex(bootstrap.shieldedViewingPublicKey, 33)
  );
}

function isPending(value: unknown): value is EnclaveBrowserPendingSubmission {
  if (!isRecordWithKeys(value, PENDING_KEYS)) return false;
  const pending = value as Partial<EnclaveBrowserPendingSubmission>;
  if (
    !["PrepareWallet", "ShieldSol", "BuildTransfer"].includes(pending.type ?? "") ||
    !isLowerHex(pending.signedTransaction) ||
    !isBase58(pending.transactionSignature) ||
    !isCheckpoint(pending.nextCheckpoint)
  ) {
    return false;
  }
  if (pending.type === "PrepareWallet") {
    return (
      pending.amountRaw === null &&
      pending.recipient === null &&
      pending.shieldedBalanceBeforeRaw === null
    );
  }
  return (
    isU64(pending.amountRaw) &&
    BigInt(pending.amountRaw) > 0n &&
    isU64(pending.shieldedBalanceBeforeRaw) &&
    (pending.type === "ShieldSol"
      ? pending.recipient === null
      : isBase58(pending.recipient) &&
        BigInt(pending.amountRaw) <= BigInt(pending.shieldedBalanceBeforeRaw))
  );
}

function isTransaction(value: unknown): value is EnclaveBrowserTransaction {
  if (!isRecordWithKeys(value, TRANSACTION_KEYS)) return false;
  const transaction = value as Partial<EnclaveBrowserTransaction>;
  return (
    (transaction.type === "ShieldSol" || transaction.type === "BuildTransfer") &&
    isBase58(transaction.signature) &&
    isU64(transaction.amountRaw) &&
    BigInt(transaction.amountRaw) > 0n &&
    (transaction.type === "ShieldSol"
      ? transaction.recipient === null
      : isBase58(transaction.recipient)) &&
    isU64(transaction.balanceAfterRaw) &&
    isU64(transaction.finalizedAtMs)
  );
}

export function parseEnclaveBrowserWalletState(value: unknown): EnclaveBrowserWalletState | null {
  if (value === undefined) return null;
  if (!value || typeof value !== "object") throw new TvcError("StorageCorrupted");
  const state = value as Partial<EnclaveBrowserWalletState>;
  const descriptor = state.walletDescriptor as Partial<WalletDescriptorV1> | undefined;
  if (
    !hasOnlyKeys(value, STATE_KEYS) ||
    state.version !== 1 ||
    !/^tvc-browser-p256-[0-9a-f]{32}$/.test(state.clientKeyId ?? "") ||
    !/^(02|03)[0-9a-f]{64}$/.test(state.turnkeyServicePublicKey ?? "") ||
    descriptor?.version !== 1 ||
    typeof descriptor.wallet_id !== "string" ||
    !isLowerHex(descriptor.provisioning_signature) ||
    (state.bootstrap !== null && !isBootstrap(state.bootstrap)) ||
    (state.checkpoint !== null && !isCheckpoint(state.checkpoint)) ||
    typeof state.registered !== "boolean" ||
    !isU64(state.shieldedBalanceRaw) ||
    (state.pendingSubmission !== null && !isPending(state.pendingSubmission)) ||
    !Array.isArray(state.transactions) ||
    state.transactions.length > MAX_TRANSACTIONS ||
    !state.transactions.every(isTransaction) ||
    (state.bootstrap === null) !== (state.checkpoint === null) ||
    (state.registered && state.bootstrap === null) ||
    (state.pendingSubmission?.type === "PrepareWallet" && state.registered) ||
    (state.pendingSubmission !== null &&
      state.pendingSubmission.type !== "PrepareWallet" &&
      !state.registered) ||
    (!state.registered && state.transactions.length > 0) ||
    (state.bootstrap !== null &&
      descriptor.turnkey_signing_target?.type === "HdWalletAccount" &&
      state.bootstrap.solanaAddress !== descriptor.turnkey_signing_target.address)
  ) {
    throw new TvcError("StorageCorrupted");
  }
  return state as EnclaveBrowserWalletState;
}

export function loadEnclaveBrowserWalletState(): Promise<EnclaveBrowserWalletState | null> {
  return loadRecord(DATABASE_NAME, STATE_RECORD, parseEnclaveBrowserWalletState);
}

export function saveEnclaveBrowserWalletState(
  state: EnclaveBrowserWalletState,
): Promise<void> {
  parseEnclaveBrowserWalletState(state);
  return saveRecord(DATABASE_NAME, STATE_RECORD, state);
}

export function clearEnclaveBrowserWalletState(): Promise<void> {
  return clearRecord(DATABASE_NAME, STATE_RECORD);
}
