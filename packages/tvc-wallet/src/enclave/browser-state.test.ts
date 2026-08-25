import { describe, expect, it } from "vitest";
import { parseEnclaveBrowserWalletState } from "./browser-state.js";

const address = "4".repeat(44);
const checkpoint = {
  sealedWalletState: "11".repeat(64),
  stateVersion: "1",
  stateDigest: "22".repeat(32),
};
const descriptor = {
  version: 1,
  wallet_id: "wallet-1",
  provisioning_signature: "33".repeat(64),
  turnkey_signing_target: {
    type: "HdWalletAccount",
    address,
  },
};

function baseState() {
  return {
    version: 1,
    clientKeyId: `tvc-browser-p256-${"ab".repeat(16)}`,
    turnkeyServicePublicKey: `02${"44".repeat(32)}`,
    walletDescriptor: descriptor,
    bootstrap: null,
    checkpoint: null,
    registered: false,
    shieldedBalanceRaw: "0",
    pendingSubmission: null,
    transactions: [],
  };
}

function bootstrappedState() {
  return {
    ...baseState(),
    bootstrap: {
      solanaAddress: address,
      shieldedOwnerHash: "55".repeat(32),
      shieldedNullifierPublicKey: "66".repeat(32),
      shieldedViewingPublicKey: `03${"77".repeat(32)}`,
    },
    checkpoint,
  };
}

describe("enclave browser wallet state", () => {
  it("accepts descriptor-only and bootstrapped checkpoints", () => {
    expect(parseEnclaveBrowserWalletState(baseState())?.checkpoint).toBeNull();
    expect(parseEnclaveBrowserWalletState(bootstrappedState())?.checkpoint).toEqual(checkpoint);
  });

  it("rejects half-written checkpoint state", () => {
    expect(() =>
      parseEnclaveBrowserWalletState({ ...bootstrappedState(), checkpoint: null }),
    ).toThrowError("StorageCorrupted");
  });

  it("preserves an exact pending registration submission", () => {
    const pendingSubmission = {
      type: "PrepareWallet",
      signedTransaction: "88".repeat(100),
      transactionSignature: "9".repeat(80),
      nextCheckpoint: { ...checkpoint, stateVersion: "2" },
      amountRaw: null,
      recipient: null,
      shieldedBalanceBeforeRaw: null,
    } as const;
    expect(
      parseEnclaveBrowserWalletState({
        ...bootstrappedState(),
        pendingSubmission,
      })?.pendingSubmission,
    ).toEqual(pendingSubmission);
  });

  it("rejects a transfer whose amount exceeds the proof-bound balance", () => {
    expect(() =>
      parseEnclaveBrowserWalletState({
        ...bootstrappedState(),
        registered: true,
        pendingSubmission: {
          type: "BuildTransfer",
          signedTransaction: "88".repeat(100),
          transactionSignature: "9".repeat(80),
          nextCheckpoint: { ...checkpoint, stateVersion: "2" },
          amountRaw: "2",
          recipient: address,
          shieldedBalanceBeforeRaw: "1",
        },
      }),
    ).toThrowError("StorageCorrupted");
  });
});
