import { describe, expect, it } from "vitest";
import { parsePersistentBrowserTvcWalletState } from "./browser-state.js";

const address = "4".repeat(44);
const descriptor = {
  version: 1,
  wallet_id: "wallet-1",
  provisioning_signature: "00",
  turnkey_signing_target: {
    type: "HdWalletAccount",
    turnkey_wallet_id: "wallet-id",
    wallet_account_id: "account-id",
    address,
    derivation_path: "m/44'/501'/0'/0'",
  },
};
const sealed = {
  version: 1,
  nonce: "11".repeat(12),
  ciphertext: "22".repeat(32),
} as const;

function baseState() {
  return {
    version: 1,
    clientKeyId: `tvc-browser-p256-${"ab".repeat(16)}`,
    turnkeyServicePublicKey: `02${"66".repeat(32)}`,
    walletDescriptor: descriptor,
    bootstrap: null,
    sealedWalletState: null,
    registered: false,
    pendingSubmission: null,
  };
}

function bootstrappedState() {
  return {
    ...baseState(),
    bootstrap: {
      solanaAddress: address,
      shieldedOwnerHash: "33".repeat(32),
      shieldedNullifierPublicKey: "44".repeat(32),
      shieldedViewingPublicKey: `03${"55".repeat(32)}`,
      derivationSuite: "zolana-ed25519-role-expansion-v1",
      sealedDerivationSeed: sealed,
    },
    sealedWalletState: sealed,
  };
}

describe("lightweight browser TVC wallet state", () => {
  it("accepts an unbootstrapped descriptor without enclave checkpoints", () => {
    expect(parsePersistentBrowserTvcWalletState(baseState())).toMatchObject({
      version: 1,
      bootstrap: null,
      sealedWalletState: null,
    });
  });

  it("accepts encrypted derivation and wallet state", () => {
    expect(parsePersistentBrowserTvcWalletState(bootstrappedState())).toMatchObject({
      bootstrap: { solanaAddress: address },
      sealedWalletState: sealed,
    });
  });

  it("rejects a plaintext or malformed seed", () => {
    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...bootstrappedState(),
        bootstrap: {
          ...bootstrappedState().bootstrap,
          sealedDerivationSeed: "11".repeat(64),
        },
      }),
    ).toThrowError("StorageCorrupted");
  });

  it("rejects half-written bootstrap state", () => {
    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...bootstrappedState(),
        sealedWalletState: null,
      }),
    ).toThrowError("StorageCorrupted");
  });

  it("preserves an exact pending default-ring submission", () => {
    const pendingSubmission = {
      type: "DefaultRingTransfer",
      intentDigest: "66".repeat(32),
      signedTransaction: "77".repeat(100),
      transactionSignature: "8".repeat(80),
      createdAtMs: "1787520000000",
    } as const;
    expect(
      parsePersistentBrowserTvcWalletState({
        ...bootstrappedState(),
        registered: true,
        pendingSubmission,
      })?.pendingSubmission,
    ).toEqual(pendingSubmission);
  });

  it("preserves an exact pending SOL withdrawal", () => {
    const pendingSubmission = {
      type: "DefaultRingSolWithdrawal",
      intentDigest: "66".repeat(32),
      signedTransaction: "77".repeat(100),
      transactionSignature: "8".repeat(80),
      createdAtMs: "1787520000000",
    } as const;
    expect(
      parsePersistentBrowserTvcWalletState({
        ...bootstrappedState(),
        registered: true,
        pendingSubmission,
      })?.pendingSubmission,
    ).toEqual(pendingSubmission);
  });

  it("rejects a pending transfer before registration", () => {
    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...bootstrappedState(),
        pendingSubmission: {
          type: "DefaultRingTransfer",
          intentDigest: "66".repeat(32),
          signedTransaction: "77".repeat(100),
          transactionSignature: "8".repeat(80),
          createdAtMs: "1787520000000",
        },
      }),
    ).toThrowError("StorageCorrupted");
  });

  it("rejects version-four full-enclave state instead of migrating it", () => {
    expect(() => parsePersistentBrowserTvcWalletState({ ...baseState(), version: 4 })).toThrowError(
      "StorageCorrupted",
    );
  });

  it("rejects fields from the superseded checkpoint format", () => {
    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...baseState(),
        checkpoint: { version: 1 },
      }),
    ).toThrowError("StorageCorrupted");
  });

  it("rejects state without its Turnkey service-key binding", () => {
    const { turnkeyServicePublicKey: _, ...unbound } = baseState();
    expect(() => parsePersistentBrowserTvcWalletState(unbound)).toThrowError(
      "StorageCorrupted",
    );
  });
});
