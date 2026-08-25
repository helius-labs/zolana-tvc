import { TvcError } from "../protocol/error.js";
import type { TvcWalletCheckpoint, WalletDescriptorV1 } from "../protocol/types.js";

const DATABASE_NAME = "zolana-tvc-enclave-wallet-v1";
const STORE_NAME = "records";
const STATE_RECORD = "wallet-state";
const MAX_TRANSACTIONS = 100;

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

function isLowerHex(value: unknown, bytes?: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length % 2 === 0 &&
    /^[0-9a-f]+$/.test(value) &&
    (bytes === undefined || value.length === bytes * 2)
  );
}

function isU64(value: unknown): value is string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) return false;
  try {
    return BigInt(value) <= 18_446_744_073_709_551_615n;
  } catch {
    return false;
  }
}

function isBase58(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 32 &&
    value.length <= 90 &&
    /^[1-9A-HJ-NP-Za-km-z]+$/.test(value)
  );
}

function isCheckpoint(value: unknown): value is TvcWalletCheckpoint {
  if (!value || typeof value !== "object") return false;
  const checkpoint = value as Partial<TvcWalletCheckpoint>;
  return (
    isLowerHex(checkpoint.sealedWalletState) &&
    isU64(checkpoint.stateVersion) &&
    isLowerHex(checkpoint.stateDigest, 32)
  );
}

function isBootstrap(value: unknown): value is EnclaveBrowserBootstrap {
  if (!value || typeof value !== "object") return false;
  const bootstrap = value as Partial<EnclaveBrowserBootstrap>;
  return (
    isBase58(bootstrap.solanaAddress) &&
    isLowerHex(bootstrap.shieldedOwnerHash, 32) &&
    isLowerHex(bootstrap.shieldedNullifierPublicKey, 32) &&
    isLowerHex(bootstrap.shieldedViewingPublicKey, 33)
  );
}

function isPending(value: unknown): value is EnclaveBrowserPendingSubmission {
  if (!value || typeof value !== "object") return false;
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
  if (!value || typeof value !== "object") return false;
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

function openDatabase(): Promise<IDBDatabase> {
  if (!globalThis.indexedDB) throw new TvcError("UnsupportedPlatform");
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onerror = () => reject(request.error ?? new TvcError("StorageUnavailable"));
    request.onsuccess = () => resolve(request.result);
  });
}

export function parseEnclaveBrowserWalletState(value: unknown): EnclaveBrowserWalletState | null {
  if (value === undefined) return null;
  if (!value || typeof value !== "object") throw new TvcError("StorageCorrupted");
  const state = value as Partial<EnclaveBrowserWalletState>;
  const descriptor = state.walletDescriptor as Partial<WalletDescriptorV1> | undefined;
  if (
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

export async function loadEnclaveBrowserWalletState(): Promise<EnclaveBrowserWalletState | null> {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const request = database.transaction(STORE_NAME, "readonly")
        .objectStore(STORE_NAME)
        .get(STATE_RECORD);
      request.onerror = () => reject(request.error ?? new TvcError("StorageUnavailable"));
      request.onsuccess = () => {
        try {
          resolve(parseEnclaveBrowserWalletState(request.result));
        } catch (error) {
          reject(error);
        }
      };
    });
  } finally {
    database.close();
  }
}

export async function saveEnclaveBrowserWalletState(
  state: EnclaveBrowserWalletState,
): Promise<void> {
  parseEnclaveBrowserWalletState(state);
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).put(state, STATE_RECORD);
      transaction.onerror = () => reject(transaction.error ?? new TvcError("StorageUnavailable"));
      transaction.onabort = () => reject(transaction.error ?? new TvcError("StorageUnavailable"));
      transaction.oncomplete = () => resolve();
    });
  } finally {
    database.close();
  }
}

export async function clearEnclaveBrowserWalletState(): Promise<void> {
  const database = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readwrite");
      transaction.objectStore(STORE_NAME).delete(STATE_RECORD);
      transaction.onerror = () => reject(transaction.error ?? new TvcError("StorageUnavailable"));
      transaction.onabort = () => reject(transaction.error ?? new TvcError("StorageUnavailable"));
      transaction.oncomplete = () => resolve();
    });
  } finally {
    database.close();
  }
}
