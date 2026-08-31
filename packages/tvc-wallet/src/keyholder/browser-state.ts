import { TvcError } from "../protocol/error.js";
import type { TvcWalletCheckpoint, WalletDescriptorV1 } from "../protocol/types.js";
import type { ShieldedIdentity } from "./index.js";
import {
  clearRecord,
  hasOnlyKeys,
  isLowerHex,
  isSolanaBase58,
  loadRecord,
  saveRecord,
} from "../platform/persisted-state.js";

const DATABASE_NAME = "zolana-tvc-privacy-wallet-v2";
const STATE_RECORD = "wallet-state";
const DESCRIPTOR_KEYS = [
  "version",
  "security_domain_id",
  "environment",
  "turnkey_organization_id",
  "turnkey_wallet_id",
  "address",
  "allowed_clients",
  "provisioning_signature",
];
const STATE_KEYS = [
  "version",
  "clientKeyId",
  "turnkeyServicePublicKey",
  "walletDescriptor",
  "identity",
  "checkpoint",
  "registered",
] as const;

/**
 * The material a browser wallet must persist between sessions to call
 * keyholder operations. Application state such as pending submissions or a
 * transaction journal belongs to the application, not this record.
 */
export type PersistentBrowserTvcWalletState = {
  readonly version: 4;
  readonly clientKeyId: string;
  readonly turnkeyServicePublicKey: string;
  readonly walletDescriptor: WalletDescriptorV1;
  readonly identity: ShieldedIdentity | null;
  readonly checkpoint: TvcWalletCheckpoint | null;
  readonly registered: boolean;
};

function validIdentity(value: unknown): value is ShieldedIdentity {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const identity = value as Partial<ShieldedIdentity>;
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
    hasOnlyKeys(value, ["sealedWalletState"]) &&
    isLowerHex(checkpoint.sealedWalletState)
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
  if (
    !hasOnlyKeys(value, STATE_KEYS) ||
    state.version !== 4 ||
    !/^tvc-browser-p256-[0-9a-f]{32}$/.test(state.clientKeyId ?? "") ||
    !/^(02|03)[0-9a-f]{64}$/.test(state.turnkeyServicePublicKey ?? "") ||
    !descriptor ||
    !hasOnlyKeys(descriptor, DESCRIPTOR_KEYS) ||
    descriptor.version !== 1 ||
    typeof descriptor.turnkey_wallet_id !== "string" ||
    !isLowerHex(descriptor.provisioning_signature) ||
    !isSolanaBase58(descriptor.address ?? "") ||
    (state.identity !== null && !validIdentity(state.identity)) ||
    (state.checkpoint !== null && !validCheckpoint(state.checkpoint)) ||
    (state.identity === null) !== (state.checkpoint === null) ||
    typeof state.registered !== "boolean" ||
    (state.identity === null && state.registered) ||
    (state.identity !== null && state.identity.solanaAddress !== descriptor.address)
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
