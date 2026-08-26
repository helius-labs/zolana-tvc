import { describe, expect, it } from "vitest";
import { parsePersistentBrowserTvcWalletState } from "./browser-state.js";

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
  turnkey_signing_target: { type: "HdWalletAccount", address },
};

function baseState() {
  return {
    version: 1,
    clientKeyId: `tvc-browser-p256-${"ab".repeat(16)}`,
    turnkeyServicePublicKey: `02${"44".repeat(32)}`,
    walletDescriptor: descriptor,
    identity: null,
    checkpoint: null,
    registered: false,
    shieldedBalanceRaw: "0",
    pendingSubmission: null,
    transactions: [],
  };
}

function readyState() {
  return {
    ...baseState(),
    identity: {
      solanaAddress: address,
      shieldedOwnerHash: "55".repeat(32),
      shieldedNullifierPublicKey: "66".repeat(32),
      shieldedViewingPublicKey: `03${"77".repeat(32)}`,
    },
    checkpoint,
    registered: true,
  };
}

describe("keyholder browser wallet state", () => {
  it("accepts descriptor-only and ready states", () => {
    expect(parsePersistentBrowserTvcWalletState(baseState())?.identity).toBeNull();
    expect(parsePersistentBrowserTvcWalletState(readyState())?.checkpoint).toEqual(
      checkpoint,
    );
  });

  it("rejects a half-written identity checkpoint", () => {
    expect(() =>
      parsePersistentBrowserTvcWalletState({ ...readyState(), checkpoint: null }),
    ).toThrowError("StorageCorrupted");
  });

  it("preserves an exact proof-bound pending transfer", () => {
    const pendingSubmission = {
      type: "BuildTransfer",
      signedTransaction: "88".repeat(100),
      transactionSignature: "9".repeat(80),
      amountRaw: "2",
      recipient: address,
      shieldedBalanceBeforeRaw: "3",
    } as const;
    expect(
      parsePersistentBrowserTvcWalletState({
        ...readyState(),
        pendingSubmission,
      })?.pendingSubmission,
    ).toEqual(pendingSubmission);
  });

  it("rejects an impossible proof-bound balance", () => {
    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...readyState(),
        pendingSubmission: {
          type: "BuildTransfer",
          signedTransaction: "88".repeat(100),
          transactionSignature: "9".repeat(80),
          amountRaw: "4",
          recipient: address,
          shieldedBalanceBeforeRaw: "3",
        },
      }),
    ).toThrowError("StorageCorrupted");
  });

  it("preserves an explicit public SOL withdrawal", () => {
    const transaction = {
      type: "BuildSolWithdrawal",
      signature: "9".repeat(80),
      amountRaw: "2",
      recipient: address,
      balanceAfterRaw: "1",
      finalizedAtMs: "1",
    } as const;
    expect(
      parsePersistentBrowserTvcWalletState({
        ...readyState(),
        transactions: [transaction],
      })?.transactions,
    ).toEqual([transaction]);
  });
});
