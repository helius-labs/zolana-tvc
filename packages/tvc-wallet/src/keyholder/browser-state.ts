import { TvcError } from "../protocol/error.js";
import type { TvcWalletCheckpoint, WalletDescriptorV1 } from "../protocol/types.js";
import {
  clearRecord,
  hasOnlyKeys,
  isCanonicalU64,
  isLowerHex,
  isSolanaBase58,
  loadRecord,
  saveRecord,
} from "../platform/persisted-state.js";

const DATABASE_NAME = "zolana-tvc-privacy-wallet-v1";
const STATE_RECORD = "wallet-state";
const MAX_TRANSACTIONS = 100;
const STATE_KEYS = [
  "version",
  "clientKeyId",
  "turnkeyServicePublicKey",
  "walletDescriptor",
  "identity",
  "checkpoint",
  "registered",
  "shieldedBalanceRaw",
  "pendingSubmission",
  "transactions",
] as const;
const PENDING_KEYS = [
  "type",
  "signedTransaction",
  "transactionSignature",
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

export type TvcWalletIdentity = {
  readonly solanaAddress: string;
  readonly shieldedOwnerHash: string;
  readonly shieldedNullifierPublicKey: string;
  readonly shieldedViewingPublicKey: string;
  /** Compressed P-256 signing key of the ring identity. */
  readonly ringSigningPublicKey: string | null;
  readonly ringOwnerHash: string | null;
};

export type TvcWalletPendingSubmission = {
  readonly type: "Register" | "ShieldSol" | "SignRingSpend";
  readonly signedTransaction: string;
  readonly transactionSignature: string;
  readonly amountRaw: string | null;
  readonly recipient: string | null;
  readonly shieldedBalanceBeforeRaw: string | null;
};

export type TvcWalletTransaction = {
  readonly type: "ShieldSol" | "SignRingSpend";
  readonly signature: string;
  readonly amountRaw: string;
  readonly recipient: string | null;
  readonly balanceAfterRaw: string;
  readonly finalizedAtMs: string;
};

export type PersistentBrowserTvcWalletState = {
  readonly version: 1;
  readonly clientKeyId: string;
  readonly turnkeyServicePublicKey: string;
  readonly walletDescriptor: WalletDescriptorV1;
  readonly identity: TvcWalletIdentity | null;
  readonly checkpoint: TvcWalletCheckpoint | null;
  readonly registered: boolean;
  readonly shieldedBalanceRaw: string;
  readonly pendingSubmission: TvcWalletPendingSubmission | null;
  readonly transactions: readonly TvcWalletTransaction[];
};

function validIdentity(value: unknown): value is TvcWalletIdentity {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const identity = value as Partial<TvcWalletIdentity>;
  return (
    hasOnlyKeys(value, [
      "solanaAddress",
      "shieldedOwnerHash",
      "shieldedNullifierPublicKey",
      "shieldedViewingPublicKey",
      "ringSigningPublicKey",
      "ringOwnerHash",
    ]) &&
    isSolanaBase58(identity.solanaAddress) &&
    isLowerHex(identity.shieldedOwnerHash, 32) &&
    isLowerHex(identity.shieldedNullifierPublicKey, 32) &&
    isLowerHex(identity.shieldedViewingPublicKey, 33) &&
    // The two ring fields are one identity, so they are present together.
    (identity.ringSigningPublicKey === null) === (identity.ringOwnerHash === null) &&
    (identity.ringSigningPublicKey === null ||
      isLowerHex(identity.ringSigningPublicKey, 33)) &&
    (identity.ringOwnerHash === null || isLowerHex(identity.ringOwnerHash, 32))
  );
}

function validCheckpoint(value: unknown): value is TvcWalletCheckpoint {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const checkpoint = value as Partial<TvcWalletCheckpoint>;
  return (
    hasOnlyKeys(value, ["sealedWalletState", "stateVersion", "stateDigest"]) &&
    isLowerHex(checkpoint.sealedWalletState) &&
    isCanonicalU64(checkpoint.stateVersion) &&
    BigInt(checkpoint.stateVersion) > 0n &&
    isLowerHex(checkpoint.stateDigest, 32)
  );
}

function validPending(value: unknown): value is TvcWalletPendingSubmission {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const pending = value as Partial<TvcWalletPendingSubmission>;
  if (
    !hasOnlyKeys(value, PENDING_KEYS) ||
    !["Register", "ShieldSol", "SignRingSpend"].includes(
      pending.type ?? "",
    ) ||
    !isLowerHex(pending.signedTransaction) ||
    !isSolanaBase58(pending.transactionSignature)
  ) {
    return false;
  }
  if (pending.type === "Register") {
    return (
      pending.amountRaw === null &&
      pending.recipient === null &&
      pending.shieldedBalanceBeforeRaw === null
    );
  }
  return (
    isCanonicalU64(pending.amountRaw) &&
    BigInt(pending.amountRaw) > 0n &&
    isCanonicalU64(pending.shieldedBalanceBeforeRaw) &&
    (pending.type === "ShieldSol"
      ? pending.recipient === null
      : isSolanaBase58(pending.recipient) &&
        BigInt(pending.amountRaw) <= BigInt(pending.shieldedBalanceBeforeRaw))
  );
}

function validTransaction(value: unknown): value is TvcWalletTransaction {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const transaction = value as Partial<TvcWalletTransaction>;
  return (
    hasOnlyKeys(value, TRANSACTION_KEYS) &&
    (transaction.type === "ShieldSol" || transaction.type === "SignRingSpend") &&
    isSolanaBase58(transaction.signature) &&
    isCanonicalU64(transaction.amountRaw) &&
    BigInt(transaction.amountRaw) > 0n &&
    (transaction.type === "ShieldSol"
      ? transaction.recipient === null
      : isSolanaBase58(transaction.recipient)) &&
    isCanonicalU64(transaction.balanceAfterRaw) &&
    isCanonicalU64(transaction.finalizedAtMs)
  );
}

export function parsePersistentBrowserTvcWalletState(
  value: unknown,
): PersistentBrowserTvcWalletState | null {
  if (value === undefined) return null;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TvcError("StorageCorrupted");
  }
  const state = value as Partial<PersistentBrowserTvcWalletState>;
  const descriptor = state.walletDescriptor as Partial<WalletDescriptorV1> | undefined;
  const target = descriptor?.turnkey_signing_target;
  if (
    !hasOnlyKeys(value, STATE_KEYS) ||
    state.version !== 1 ||
    !/^tvc-browser-p256-[0-9a-f]{32}$/.test(state.clientKeyId ?? "") ||
    !/^(02|03)[0-9a-f]{64}$/.test(state.turnkeyServicePublicKey ?? "") ||
    !descriptor ||
    descriptor.version !== 1 ||
    typeof descriptor.wallet_id !== "string" ||
    !isLowerHex(descriptor.provisioning_signature) ||
    target?.type !== "HdWalletAccount" ||
    !isSolanaBase58(target.address) ||
    (state.identity !== null && !validIdentity(state.identity)) ||
    (state.checkpoint !== null && !validCheckpoint(state.checkpoint)) ||
    (state.identity === null) !== (state.checkpoint === null) ||
    typeof state.registered !== "boolean" ||
    (state.identity === null && state.registered) ||
    !isCanonicalU64(state.shieldedBalanceRaw) ||
    (state.pendingSubmission !== null && !validPending(state.pendingSubmission)) ||
    !Array.isArray(state.transactions) ||
    state.transactions.length > MAX_TRANSACTIONS ||
    !state.transactions.every(validTransaction) ||
    (state.pendingSubmission?.type === "Register" && state.registered) ||
    (state.pendingSubmission !== null &&
      state.pendingSubmission.type !== "Register" &&
      !state.registered) ||
    (!state.registered && state.transactions.length > 0) ||
    (state.identity !== null && state.identity.solanaAddress !== target.address)
  ) {
    throw new TvcError("StorageCorrupted");
  }
  return state as PersistentBrowserTvcWalletState;
}

export function loadPersistentBrowserTvcWalletState(): Promise<PersistentBrowserTvcWalletState | null> {
  return loadRecord(DATABASE_NAME, STATE_RECORD, parsePersistentBrowserTvcWalletState);
}

export function savePersistentBrowserTvcWalletState(
  state: PersistentBrowserTvcWalletState,
): Promise<void> {
  parsePersistentBrowserTvcWalletState(state);
  return saveRecord(DATABASE_NAME, STATE_RECORD, state);
}

export function clearPersistentBrowserTvcWalletState(): Promise<void> {
  return clearRecord(DATABASE_NAME, STATE_RECORD);
}
