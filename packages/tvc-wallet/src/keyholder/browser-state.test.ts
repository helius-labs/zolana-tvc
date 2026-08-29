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

  it("rejects a descriptor from the retired P-256 ring schema", () => {
    const descriptorWithSecondRingKey: Record<string, unknown> = { ...descriptor };
    descriptorWithSecondRingKey.turnkey_ring_signing_key_id = null;
    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...baseState(),
        walletDescriptor: descriptorWithSecondRingKey,
      }),
    ).toThrowError("StorageCorrupted");
  });

  it("preserves an exact pending private transfer", () => {
    const pendingSubmission = {
      type: "PrivateTransfer",
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

  it("preserves optional per-ring balance context without rejecting older records", () => {
    const pendingSubmission = {
      type: "UnshieldSol",
      signedTransaction: "88".repeat(100),
      transactionSignature: "9".repeat(80),
      amountRaw: "2",
      recipient: address,
      shieldedBalanceBeforeRaw: "7",
      walletBalanceBeforeRaw: "11",
      ringProgramId: "5".repeat(44),
    } as const;
    const parsed = parsePersistentBrowserTvcWalletState({
      ...readyState(),
      pendingSubmission,
    });
    expect(parsed?.pendingSubmission).toEqual(pendingSubmission);
  });

  it("rejects an impossible proof-bound balance", () => {
    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...readyState(),
        pendingSubmission: {
          type: "PrivateTransfer",
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
      type: "UnshieldSol",
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

  it("preserves a program-neutral ecosystem spend", () => {
    const pendingSubmission = {
      type: "ProgramSpend",
      signedTransaction: "88".repeat(100),
      transactionSignature: "9".repeat(80),
      amountRaw: "2",
      recipient: null,
      shieldedBalanceBeforeRaw: "3",
      walletBalanceBeforeRaw: "3",
      ringProgramId: null,
      programId: "5".repeat(44),
      action: "swap:make",
    } as const;
    expect(
      parsePersistentBrowserTvcWalletState({
        ...readyState(),
        pendingSubmission,
      })?.pendingSubmission,
    ).toEqual(pendingSubmission);
  });

  it("preserves the authoritative post-operation ring balance", () => {
    const transaction = {
      type: "UnshieldSol",
      signature: "9".repeat(80),
      amountRaw: "2",
      recipient: address,
      balanceAfterRaw: "9",
      ringBalanceAfterRaw: "5",
      ringProgramId: null,
      finalizedAtMs: "1",
    } as const;
    expect(
      parsePersistentBrowserTvcWalletState({
        ...readyState(),
        transactions: [transaction],
      })?.transactions,
    ).toEqual([transaction]);
  });

  it("preserves a recoverable default-ring bridge", () => {
    const pendingSubmission = {
      type: "RingMoveBridge",
      signedTransaction: "88".repeat(100),
      transactionSignature: "9".repeat(80),
      amountRaw: "2",
      recipient: address,
      shieldedBalanceBeforeRaw: "7",
      walletBalanceBeforeRaw: "11",
      ringProgramId: null,
      destinationRingProgramId: null,
      destinationRingBalanceBeforeRaw: "7",
    } as const;
    const pendingRingMove = {
      phase: "BridgePending",
      sourceRingProgramId: null,
      destinationRingProgramId: "5".repeat(44),
      amountRaw: "2",
      walletBalanceBeforeRaw: "11",
      destinationRingBalanceBeforeRaw: "4",
      bridgeTransactionSignature: null,
      bridgeCommitment: null,
    } as const;
    const parsed = parsePersistentBrowserTvcWalletState({
      ...readyState(),
      pendingSubmission,
      pendingRingMove,
    });
    expect(parsed?.pendingRingMove).toEqual(pendingRingMove);
  });

  it("normalizes records written before ring routing", () => {
    expect(parsePersistentBrowserTvcWalletState(readyState())?.pendingRingMove).toBeNull();
  });
});
