import { TvcError } from "../protocol/error.js";
import type { WalletDescriptorV1 } from "../protocol/types.js";
import { CLIENT_ED25519_DERIVATION_SUITE } from "../protocol/constants.js";
import type { PersistentBrowserTvcSealedValue } from "./browser-authorizer.js";
import {
  clearRecord,
  isCanonicalU64,
  isLowerHex,
  isRecordWithKeys,
  isSolanaBase58,
  hasOnlyKeys,
  loadRecord,
  saveRecord,
} from "./persisted-state.js";

const DATABASE_NAME = "zolana-tvc-lightweight-wallet-v1";
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

function isSealedValue(value: unknown): value is PersistentBrowserTvcSealedValue {
  if (!isRecordWithKeys(value, ["version", "nonce", "ciphertext"])) return false;
  const sealed = value as Partial<PersistentBrowserTvcSealedValue>;
  return (
    sealed.version === 1 &&
    isLowerHex(sealed.nonce, 12) &&
    isLowerHex(sealed.ciphertext) &&
    sealed.ciphertext.length >= 32
  );
}

function isBootstrap(value: unknown): value is PersistentBrowserTvcBootstrap {
  if (
    !isRecordWithKeys(value, [
      "solanaAddress",
      "shieldedOwnerHash",
      "shieldedNullifierPublicKey",
      "shieldedViewingPublicKey",
      "derivationSuite",
      "sealedDerivationSeed",
    ])
  ) {
    return false;
  }
  const bootstrap = value as Partial<PersistentBrowserTvcBootstrap>;
  return (
    isSolanaBase58(bootstrap.solanaAddress) &&
    isLowerHex(bootstrap.shieldedOwnerHash, 32) &&
    isLowerHex(bootstrap.shieldedNullifierPublicKey, 32) &&
    isLowerHex(bootstrap.shieldedViewingPublicKey, 33) &&
    bootstrap.derivationSuite === CLIENT_ED25519_DERIVATION_SUITE &&
    isSealedValue(bootstrap.sealedDerivationSeed)
  );
}

function isPendingSubmission(value: unknown): value is PersistentBrowserTvcPendingSubmission {
  if (
    !isRecordWithKeys(value, [
      "type",
      "intentDigest",
      "signedTransaction",
      "transactionSignature",
      "createdAtMs",
    ])
  ) {
    return false;
  }
  const pending = value as Partial<PersistentBrowserTvcPendingSubmission>;
  return (
    (pending.type === "DefaultRingTransfer" || pending.type === "DefaultRingSolWithdrawal") &&
    isLowerHex(pending.intentDigest, 32) &&
    isLowerHex(pending.signedTransaction) &&
    isSolanaBase58(pending.transactionSignature) &&
    isCanonicalU64(pending.createdAtMs) &&
    BigInt(pending.createdAtMs) > 0n
  );
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
