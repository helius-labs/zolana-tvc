// Shared validation and IndexedDB plumbing for persistent privacy-wallet state.

import { TvcError } from "../protocol/error.js";

const STORE_NAME = "records";

export function isLowerHex(value: unknown, bytes?: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length % 2 === 0 &&
    /^[0-9a-f]+$/.test(value) &&
    (bytes === undefined || value.length === bytes * 2)
  );
}

export function isCanonicalU64(value: unknown): value is string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) return false;
  try {
    return BigInt(value) <= 18_446_744_073_709_551_615n;
  } catch {
    return false;
  }
}

export function isSolanaBase58(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 32 &&
    value.length <= 90 &&
    /^[1-9A-HJ-NP-Za-km-z]+$/.test(value)
  );
}

/** Rejects records carrying keys this schema version does not define. */
export function hasOnlyKeys(value: object, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

export function isRecordWithKeys(
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && hasOnlyKeys(value as object, keys);
}

function openWalletDatabase(name: string): Promise<IDBDatabase> {
  if (!globalThis.indexedDB) throw new TvcError("UnsupportedPlatform");
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onblocked = () => reject(new TvcError("StorageUnavailable"));
    request.onerror = () => reject(request.error ?? new TvcError("StorageUnavailable"));
    request.onsuccess = () => resolve(request.result);
  });
}

async function withDatabase<T>(
  name: string,
  run: (database: IDBDatabase) => Promise<T>,
): Promise<T> {
  const database = await openWalletDatabase(name);
  try {
    return await run(database);
  } finally {
    database.close();
  }
}

export function loadRecord<T>(
  databaseName: string,
  recordKey: string,
  parse: (value: unknown) => T,
): Promise<T> {
  return withDatabase(
    databaseName,
    (database) =>
      new Promise<T>((resolve, reject) => {
        const request = database
          .transaction(STORE_NAME, "readonly")
          .objectStore(STORE_NAME)
          .get(recordKey);
        request.onerror = () => reject(request.error ?? new TvcError("StorageUnavailable"));
        request.onsuccess = () => {
          try {
            resolve(parse(request.result));
          } catch (error) {
            reject(error);
          }
        };
      }),
  );
}

function mutate(
  databaseName: string,
  apply: (store: IDBObjectStore) => void,
): Promise<void> {
  return withDatabase(
    databaseName,
    (database) =>
      new Promise<void>((resolve, reject) => {
        const transaction = database.transaction(STORE_NAME, "readwrite");
        apply(transaction.objectStore(STORE_NAME));
        transaction.onerror = () => reject(transaction.error ?? new TvcError("StorageUnavailable"));
        transaction.onabort = () => reject(transaction.error ?? new TvcError("StorageUnavailable"));
        transaction.oncomplete = () => resolve();
      }),
  );
}

export function saveRecord(
  databaseName: string,
  recordKey: string,
  value: unknown,
): Promise<void> {
  return mutate(databaseName, (store) => store.put(value, recordKey));
}

export function clearRecord(databaseName: string, recordKey: string): Promise<void> {
  return mutate(databaseName, (store) => store.delete(recordKey));
}
