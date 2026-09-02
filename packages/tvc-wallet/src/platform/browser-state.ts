import { TvcError } from "../protocol/error.js";
import type { Checkpoint, WalletDescriptor } from "../protocol/types.js";
import type { ShieldedIdentity } from "../wallet/client.js";
import {
  clearRecord,
  hasOnlyKeys,
  isLowerHex,
  isSolanaAddress,
  loadRecord,
  saveRecord,
} from "./persisted-state.js";

const DATABASE_NAME = "zolana-tvc-privacy-wallet-v3";
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
  "walletDescriptor",
  "identity",
  "checkpoint",
  "registered",
] as const;

/** Enclave material only; pending submissions and journals belong to the application. */
export type PersistentBrowserTvcWalletState = {
  readonly version: 5;
  readonly clientKeyId: string;
  readonly walletDescriptor: WalletDescriptor;
  readonly identity: ShieldedIdentity | null;
  readonly checkpoint: Checkpoint | null;
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
    isSolanaAddress(identity.solanaAddress) &&
    isLowerHex(identity.shieldedOwnerHash, 32) &&
    isLowerHex(identity.shieldedNullifierPublicKey, 32) &&
    isLowerHex(identity.shieldedViewingPublicKey, 33)
  );
}

function validCheckpoint(value: unknown): value is Checkpoint {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const checkpoint = value as Partial<Checkpoint>;
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
  const descriptor = state.walletDescriptor as Partial<WalletDescriptor> | undefined;
  const clientKeyId = state.clientKeyId ?? "";
  if (
    !hasOnlyKeys(value, STATE_KEYS) ||
    state.version !== 5 ||
    !clientKeyId.startsWith("tvc-browser-p256-") ||
    !isLowerHex(clientKeyId.slice("tvc-browser-p256-".length), 16) ||
    !descriptor ||
    !hasOnlyKeys(descriptor, DESCRIPTOR_KEYS) ||
    descriptor.version !== 1 ||
    typeof descriptor.turnkey_wallet_id !== "string" ||
    !isLowerHex(descriptor.provisioning_signature) ||
    !isSolanaAddress(descriptor.address ?? "") ||
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
