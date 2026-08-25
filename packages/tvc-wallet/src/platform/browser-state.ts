import { TvcError } from "../protocol/error.js";
import type { WalletDescriptorV1 } from "../protocol/types.js";
import { CLIENT_ED25519_DERIVATION_SUITE } from "../protocol/constants.js";
import type { PersistentBrowserTvcSealedValue } from "./browser-authorizer.js";

const DATABASE_NAME = "zolana-tvc-lightweight-wallet-v1";
const STORE_NAME = "records";
const STATE_RECORD = "wallet-state";
const STATE_KEYS = [
  "version",
  "clientKeyId",
  "turnkeyServicePublicKey",
  "walletDescriptor",
  "bootstrap",
  "sealedWalletState",
  "registered",
  "pendingSubmission",
] as const;

export type PersistentBrowserTvcBootstrap = {
  readonly solanaAddress: string;
  readonly shieldedOwnerHash: string;
  readonly shieldedNullifierPublicKey: string;
  readonly shieldedViewingPublicKey: string;
  readonly derivationSuite: typeof CLIENT_ED25519_DERIVATION_SUITE;
  readonly sealedDerivationSeed: PersistentBrowserTvcSealedValue;
};

export type PersistentBrowserTvcPendingSubmission = {
  readonly type: "DefaultRingTransfer" | "DefaultRingSolWithdrawal";
  readonly intentDigest: string;
  readonly signedTransaction: string;
  readonly transactionSignature: string;
  readonly createdAtMs: string;
};

/**
 * The lightweight profile persists only encrypted privacy state. Balances and
 * activity are reconstructed from the encrypted Zolana wallet snapshot after
 * a client-side indexer sync; TVC checkpoints do not exist in this profile.
 */
export type PersistentBrowserTvcWalletState = {
  readonly version: 1;
  readonly clientKeyId: string;
  readonly turnkeyServicePublicKey: string;
  readonly walletDescriptor: WalletDescriptorV1;
  readonly bootstrap: PersistentBrowserTvcBootstrap | null;
  readonly sealedWalletState: PersistentBrowserTvcSealedValue | null;
  readonly registered: boolean;
  readonly pendingSubmission: PersistentBrowserTvcPendingSubmission | null;
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

function hasOnlyKeys(value: object, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

function isCanonicalU64(value: unknown): value is string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) return false;
  try {
    return BigInt(value) <= 18_446_744_073_709_551_615n;
  } catch {
    return false;
  }
}

function isSolanaBase58(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 32 &&
    value.length <= 90 &&
    /^[1-9A-HJ-NP-Za-km-z]+$/.test(value)
  );
}

function isSealedValue(value: unknown): value is PersistentBrowserTvcSealedValue {
  if (!value || typeof value !== "object") return false;
  const sealed = value as Partial<PersistentBrowserTvcSealedValue>;
  return (
    hasOnlyKeys(value, ["version", "nonce", "ciphertext"]) &&
    sealed.version === 1 &&
    isLowerHex(sealed.nonce, 12) &&
    isLowerHex(sealed.ciphertext) &&
    sealed.ciphertext.length >= 32
  );
}

function isBootstrap(value: unknown): value is PersistentBrowserTvcBootstrap {
  if (!value || typeof value !== "object") return false;
  const bootstrap = value as Partial<PersistentBrowserTvcBootstrap>;
  return (
    hasOnlyKeys(value, [
      "solanaAddress",
      "shieldedOwnerHash",
      "shieldedNullifierPublicKey",
      "shieldedViewingPublicKey",
      "derivationSuite",
      "sealedDerivationSeed",
    ]) &&
    isSolanaBase58(bootstrap.solanaAddress) &&
    isLowerHex(bootstrap.shieldedOwnerHash, 32) &&
    isLowerHex(bootstrap.shieldedNullifierPublicKey, 32) &&
    isLowerHex(bootstrap.shieldedViewingPublicKey, 33) &&
    bootstrap.derivationSuite === CLIENT_ED25519_DERIVATION_SUITE &&
    isSealedValue(bootstrap.sealedDerivationSeed)
  );
}

function isPendingSubmission(value: unknown): value is PersistentBrowserTvcPendingSubmission {
  if (!value || typeof value !== "object") return false;
  const pending = value as Partial<PersistentBrowserTvcPendingSubmission>;
  return (
    hasOnlyKeys(value, [
      "type",
      "intentDigest",
      "signedTransaction",
      "transactionSignature",
      "createdAtMs",
    ]) &&
    (pending.type === "DefaultRingTransfer" || pending.type === "DefaultRingSolWithdrawal") &&
    isLowerHex(pending.intentDigest, 32) &&
    isLowerHex(pending.signedTransaction) &&
    isSolanaBase58(pending.transactionSignature) &&
    isCanonicalU64(pending.createdAtMs) &&
    BigInt(pending.createdAtMs) > 0n
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

export function parsePersistentBrowserTvcWalletState(
  value: unknown,
): PersistentBrowserTvcWalletState | null {
  if (value === undefined) return null;
  if (!value || typeof value !== "object") throw new TvcError("StorageCorrupted");
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
    (state.bootstrap !== null && !isBootstrap(state.bootstrap)) ||
    (state.sealedWalletState !== null && !isSealedValue(state.sealedWalletState)) ||
    typeof state.registered !== "boolean" ||
    (state.pendingSubmission !== null && !isPendingSubmission(state.pendingSubmission)) ||
    (state.bootstrap === null) !== (state.sealedWalletState === null) ||
    (!state.registered && state.pendingSubmission !== null) ||
    (state.bootstrap !== null && state.bootstrap.solanaAddress !== target.address) ||
    (state.bootstrap === null && (state.registered || state.pendingSubmission !== null))
  ) {
    throw new TvcError("StorageCorrupted");
  }
  return state as PersistentBrowserTvcWalletState;
}

export async function loadPersistentBrowserTvcWalletState(): Promise<PersistentBrowserTvcWalletState | null> {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, "readonly");
      const request = transaction.objectStore(STORE_NAME).get(STATE_RECORD);
      request.onerror = () => reject(request.error ?? new TvcError("StorageUnavailable"));
      request.onsuccess = () => {
        try {
          resolve(parsePersistentBrowserTvcWalletState(request.result));
        } catch (error) {
          reject(error);
        }
      };
    });
  } finally {
    database.close();
  }
}

export async function savePersistentBrowserTvcWalletState(
  state: PersistentBrowserTvcWalletState,
): Promise<void> {
  parsePersistentBrowserTvcWalletState(state);
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

export async function clearPersistentBrowserTvcWalletState(): Promise<void> {
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
