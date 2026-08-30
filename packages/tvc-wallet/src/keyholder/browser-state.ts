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
  "pendingRingMove",
  "transactions",
] as const;
const PENDING_KEYS = [
  "type",
  "signedTransaction",
  "transactionSignature",
  "amountRaw",
  "recipient",
  "ringBalanceBeforeRaw",
  "walletBalanceBeforeRaw",
  "ringProgramId",
  "programId",
  "action",
  "balanceDeltaRaw",
  "programState",
  "destinationRingProgramId",
  "destinationRingBalanceBeforeRaw",
] as const;
const TRANSACTION_KEYS = [
  "type",
  "signature",
  "amountRaw",
  "recipient",
  "walletBalanceAfterRaw",
  "ringBalanceAfterRaw",
  "ringProgramId",
  "programId",
  "action",
  "balanceDeltaRaw",
  "programState",
  "destinationRingProgramId",
  "destinationRingBalanceAfterRaw",
  "finalizedAtMs",
] as const;
const PENDING_RING_MOVE_KEYS = [
  "phase",
  "sourceRingProgramId",
  "destinationRingProgramId",
  "amountRaw",
  "walletBalanceBeforeRaw",
  "destinationRingBalanceBeforeRaw",
  "bridgeTransactionSignature",
  "bridgeCommitment",
] as const;

export type TvcWalletIdentity = {
  readonly solanaAddress: string;
  readonly shieldedOwnerHash: string;
  readonly shieldedNullifierPublicKey: string;
  readonly shieldedViewingPublicKey: string;
};

export type TvcWalletPendingSubmission = {
  readonly type:
    | "Register"
    | "ShieldSol"
    | "PrivateTransfer"
    | "UnshieldSol"
    | "ProgramSpend"
    | "RingMoveBridge"
    | "RingMoveDestination";
  readonly signedTransaction: string;
  readonly transactionSignature: string;
  readonly amountRaw: string | null;
  readonly recipient: string | null;
  /** Balance in the selected ring before this operation. */
  readonly ringBalanceBeforeRaw: string | null;
  /** Whole-wallet balance before this operation; null only for registration. */
  readonly walletBalanceBeforeRaw: string | null;
  /** `null` is the default ring or an operation without a private source. */
  readonly ringProgramId: string | null;
  /** Ecosystem program authorized by a generic SPP plan. */
  readonly programId?: string;
  /** Short display label chosen by the integrating SDK. */
  readonly action?: string;
  /** Signed whole-wallet/default-ring delta for a program action. */
  readonly balanceDeltaRaw?: string;
  /** Opaque, untrusted recovery context owned by the integrating program. */
  readonly programState?: string;
  /** Destination for a private ring move. */
  readonly destinationRingProgramId?: string | null;
  /** Destination balance before a private ring move. */
  readonly destinationRingBalanceBeforeRaw?: string;
};

export type TvcWalletTransaction = {
  readonly type:
    | "ShieldSol"
    | "PrivateTransfer"
    | "UnshieldSol"
    | "ProgramSpend"
    | "RingMove";
  readonly signature: string;
  readonly amountRaw: string;
  readonly recipient: string | null;
  /** Whole-wallet balance after this operation. */
  readonly walletBalanceAfterRaw: string;
  /** Selected-ring balance after this operation. */
  readonly ringBalanceAfterRaw: string;
  /** `null` is the default ring. */
  readonly ringProgramId: string | null;
  readonly programId?: string;
  readonly action?: string;
  readonly balanceDeltaRaw?: string;
  readonly programState?: string;
  /** Ring receiving a `RingMove`. */
  readonly destinationRingProgramId?: string | null;
  /** Destination balance after a `RingMove`. */
  readonly destinationRingBalanceAfterRaw?: string;
  readonly finalizedAtMs: string;
};

export type TvcWalletPendingRingMove = {
  readonly phase: "BridgePending" | "AwaitingBridgeNote" | "DestinationPending";
  readonly sourceRingProgramId: string | null;
  readonly destinationRingProgramId: string | null;
  readonly amountRaw: string;
  readonly walletBalanceBeforeRaw: string;
  readonly destinationRingBalanceBeforeRaw: string;
  readonly bridgeTransactionSignature: string | null;
  readonly bridgeCommitment: string | null;
};

export type PersistentBrowserTvcWalletState = {
  readonly version: 2;
  readonly clientKeyId: string;
  readonly turnkeyServicePublicKey: string;
  readonly walletDescriptor: WalletDescriptorV1;
  readonly identity: TvcWalletIdentity | null;
  readonly checkpoint: TvcWalletCheckpoint | null;
  readonly registered: boolean;
  readonly shieldedBalanceRaw: string;
  readonly pendingSubmission: TvcWalletPendingSubmission | null;
  readonly pendingRingMove: TvcWalletPendingRingMove | null;
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
    ]) &&
    isSolanaBase58(identity.solanaAddress) &&
    isLowerHex(identity.shieldedOwnerHash, 32) &&
    isLowerHex(identity.shieldedNullifierPublicKey, 32) &&
    isLowerHex(identity.shieldedViewingPublicKey, 33)
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

function isCanonicalSignedU64Delta(value: unknown): value is string {
  if (typeof value !== "string" || !/^-?(0|[1-9][0-9]*)$/.test(value) || value === "-0") {
    return false;
  }
  const parsed = BigInt(value);
  const max = (1n << 64n) - 1n;
  return parsed >= -max && parsed <= max;
}

function validProgramState(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 32_768;
}

function validPending(value: unknown): value is TvcWalletPendingSubmission {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const pending = value as Partial<TvcWalletPendingSubmission>;
  if (
    !hasOnlyKeys(value, PENDING_KEYS) ||
    ![
      "Register",
      "ShieldSol",
      "PrivateTransfer",
      "UnshieldSol",
      "ProgramSpend",
      "RingMoveBridge",
      "RingMoveDestination",
    ].includes(pending.type ?? "") ||
    !isLowerHex(pending.signedTransaction) ||
    !isSolanaBase58(pending.transactionSignature) ||
    !("walletBalanceBeforeRaw" in value) ||
    !("ringProgramId" in value)
  ) {
    return false;
  }
  if (
    (pending.walletBalanceBeforeRaw !== null &&
      !isCanonicalU64(pending.walletBalanceBeforeRaw)) ||
    (pending.ringProgramId !== null &&
      !isSolanaBase58(pending.ringProgramId)) ||
    (pending.programId !== undefined && !isSolanaBase58(pending.programId)) ||
    (pending.action !== undefined &&
      !/^[a-zA-Z0-9:_-]{1,64}$/.test(pending.action)) ||
    (pending.balanceDeltaRaw !== undefined &&
      !isCanonicalSignedU64Delta(pending.balanceDeltaRaw)) ||
    (pending.programState !== undefined && !validProgramState(pending.programState)) ||
    (pending.destinationRingProgramId !== undefined &&
      pending.destinationRingProgramId !== null &&
      !isSolanaBase58(pending.destinationRingProgramId)) ||
    (pending.destinationRingBalanceBeforeRaw !== undefined &&
      !isCanonicalU64(pending.destinationRingBalanceBeforeRaw))
  ) {
    return false;
  }
  if (pending.type === "Register") {
    return (
      pending.amountRaw === null &&
      pending.recipient === null &&
      pending.ringBalanceBeforeRaw === null &&
      pending.walletBalanceBeforeRaw === null &&
      pending.ringProgramId === null &&
      pending.programId === undefined &&
      pending.action === undefined &&
      pending.balanceDeltaRaw === undefined &&
      pending.programState === undefined &&
      pending.destinationRingProgramId === undefined &&
      pending.destinationRingBalanceBeforeRaw === undefined
    );
  }
  const isRingMove =
    pending.type === "RingMoveBridge" || pending.type === "RingMoveDestination";
  const isProgramSpend = pending.type === "ProgramSpend";
  const programBalanceAfter =
    isProgramSpend &&
    pending.balanceDeltaRaw !== undefined &&
    isCanonicalU64(pending.ringBalanceBeforeRaw)
      ? BigInt(pending.ringBalanceBeforeRaw) +
        BigInt(pending.balanceDeltaRaw)
      : null;
  return (
    isCanonicalU64(pending.amountRaw) &&
    BigInt(pending.amountRaw) > 0n &&
    isCanonicalU64(pending.ringBalanceBeforeRaw) &&
    isCanonicalU64(pending.walletBalanceBeforeRaw) &&
    (pending.type === "ShieldSol" || isProgramSpend
      ? pending.recipient === null
      : isSolanaBase58(pending.recipient) &&
        BigInt(pending.amountRaw) <= BigInt(pending.ringBalanceBeforeRaw)) &&
    (!isProgramSpend ||
      (programBalanceAfter === null
        ? BigInt(pending.amountRaw) <= BigInt(pending.ringBalanceBeforeRaw)
        : programBalanceAfter >= 0n && programBalanceAfter < (1n << 64n))) &&
    (isProgramSpend
      ? pending.programId !== undefined &&
        pending.action !== undefined &&
        pending.ringProgramId === null
      : pending.programId === undefined &&
        pending.action === undefined &&
        pending.balanceDeltaRaw === undefined &&
        pending.programState === undefined) &&
    (isRingMove
      ? pending.destinationRingProgramId !== undefined &&
        (pending.ringProgramId !== pending.destinationRingProgramId ||
          (pending.type === "RingMoveBridge" &&
            pending.ringProgramId === null)) &&
        pending.destinationRingBalanceBeforeRaw !== undefined
      : pending.destinationRingProgramId === undefined &&
        pending.destinationRingBalanceBeforeRaw === undefined)
  );
}

function validPendingRingMove(value: unknown): value is TvcWalletPendingRingMove {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const move = value as Partial<TvcWalletPendingRingMove>;
  const validRing = (ring: unknown) => ring === null || isSolanaBase58(ring);
  if (
    !hasOnlyKeys(value, PENDING_RING_MOVE_KEYS) ||
    !["BridgePending", "AwaitingBridgeNote", "DestinationPending"].includes(
      move.phase ?? "",
    ) ||
    !validRing(move.sourceRingProgramId) ||
    !validRing(move.destinationRingProgramId) ||
    move.sourceRingProgramId === move.destinationRingProgramId ||
    !isCanonicalU64(move.amountRaw) ||
    BigInt(move.amountRaw) <= 0n ||
    !isCanonicalU64(move.walletBalanceBeforeRaw) ||
    !isCanonicalU64(move.destinationRingBalanceBeforeRaw)
  ) {
    return false;
  }
  if (move.phase === "BridgePending") {
    return move.bridgeTransactionSignature === null && move.bridgeCommitment === null;
  }
  return (
    isSolanaBase58(move.bridgeTransactionSignature) &&
    (move.phase === "AwaitingBridgeNote"
      ? move.bridgeCommitment === null || isLowerHex(move.bridgeCommitment, 32)
      : isLowerHex(move.bridgeCommitment, 32))
  );
}

function validTransaction(value: unknown): value is TvcWalletTransaction {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const transaction = value as Partial<TvcWalletTransaction>;
  return (
    hasOnlyKeys(value, TRANSACTION_KEYS) &&
    [
      "ShieldSol",
      "PrivateTransfer",
      "UnshieldSol",
      "ProgramSpend",
      "RingMove",
    ].includes(transaction.type ?? "") &&
    isSolanaBase58(transaction.signature) &&
    isCanonicalU64(transaction.amountRaw) &&
    BigInt(transaction.amountRaw) > 0n &&
    (transaction.type === "ShieldSol" || transaction.type === "ProgramSpend"
      ? transaction.recipient === null
      : isSolanaBase58(transaction.recipient)) &&
    isCanonicalU64(transaction.walletBalanceAfterRaw) &&
    isCanonicalU64(transaction.ringBalanceAfterRaw) &&
    (transaction.ringProgramId === null || isSolanaBase58(transaction.ringProgramId)) &&
    (transaction.type === "ProgramSpend"
      ? isSolanaBase58(transaction.programId) &&
        typeof transaction.action === "string" &&
        /^[a-zA-Z0-9:_-]{1,64}$/.test(transaction.action) &&
        (transaction.balanceDeltaRaw === undefined ||
          isCanonicalSignedU64Delta(transaction.balanceDeltaRaw)) &&
        (transaction.programState === undefined ||
          validProgramState(transaction.programState)) &&
        transaction.ringProgramId === null
      : transaction.programId === undefined &&
        transaction.action === undefined &&
        transaction.balanceDeltaRaw === undefined &&
        transaction.programState === undefined) &&
    (transaction.type === "RingMove"
      ? transaction.destinationRingProgramId !== undefined &&
        (transaction.destinationRingProgramId === null ||
          isSolanaBase58(transaction.destinationRingProgramId)) &&
        transaction.destinationRingProgramId !== transaction.ringProgramId &&
        isCanonicalU64(transaction.destinationRingBalanceAfterRaw)
      : transaction.destinationRingProgramId === undefined &&
        transaction.destinationRingBalanceAfterRaw === undefined) &&
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
  const pendingRingMove = state.pendingRingMove;
  if (
    !hasOnlyKeys(value, STATE_KEYS) ||
    state.version !== 2 ||
    !/^tvc-browser-p256-[0-9a-f]{32}$/.test(state.clientKeyId ?? "") ||
    !/^(02|03)[0-9a-f]{64}$/.test(state.turnkeyServicePublicKey ?? "") ||
    !descriptor ||
    "turnkey_ring_signing_key_id" in descriptor ||
    "ring_grant" in descriptor ||
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
    (pendingRingMove !== null && !validPendingRingMove(pendingRingMove)) ||
    !Array.isArray(state.transactions) ||
    state.transactions.length > MAX_TRANSACTIONS ||
    !state.transactions.every(validTransaction) ||
    (state.pendingSubmission?.type === "Register" && state.registered) ||
    (state.pendingSubmission !== null &&
      state.pendingSubmission.type !== "Register" &&
      !state.registered) ||
    (!state.registered && state.transactions.length > 0) ||
    (state.identity !== null && state.identity.solanaAddress !== target.address) ||
    (pendingRingMove === null &&
      (state.pendingSubmission?.type === "RingMoveBridge" ||
        state.pendingSubmission?.type === "RingMoveDestination")) ||
    (pendingRingMove?.phase === "BridgePending" &&
      state.pendingSubmission?.type !== "RingMoveBridge") ||
    (pendingRingMove?.phase === "AwaitingBridgeNote" &&
      state.pendingSubmission !== null) ||
    (pendingRingMove?.phase === "DestinationPending" &&
      state.pendingSubmission?.type !== "RingMoveDestination")
  ) {
    throw new TvcError("StorageCorrupted");
  }
  return {
    ...(state as PersistentBrowserTvcWalletState),
    pendingRingMove,
  };
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
