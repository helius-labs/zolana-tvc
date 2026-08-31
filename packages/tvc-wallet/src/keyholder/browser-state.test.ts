import { describe, expect, it } from "vitest";
import { parsePersistentBrowserTvcWalletState } from "./browser-state.js";

const address = "4".repeat(44);
const asset = { type: "Sol" } as const;
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
    version: 3,
    clientKeyId: `tvc-browser-p256-${"ab".repeat(16)}`,
    turnkeyServicePublicKey: `02${"44".repeat(32)}`,
    walletDescriptor: descriptor,
    identity: null,
    checkpoint: null,
    registered: false,
    pendingSubmission: null,
    pendingRingMove: null,
    pendingConsolidation: null,
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
      asset,
      signedTransaction: "88".repeat(100),
      transactionSignature: "9".repeat(80),
      amountRaw: "2",
      recipient: address,
      ringBalanceBeforeRaw: "3",
      walletBalanceBeforeRaw: "3",
      ringProgramId: null,
    } as const;
    expect(
      parsePersistentBrowserTvcWalletState({
        ...readyState(),
        pendingSubmission,
      })?.pendingSubmission,
    ).toEqual(pendingSubmission);
  });

  it("preserves a reload-safe UTXO consolidation", () => {
    const pendingSubmission = {
      type: "Consolidate",
      asset,
      signedTransaction: "88".repeat(100),
      transactionSignature: "9".repeat(80),
      amountRaw: "7",
      recipient: null,
      ringBalanceBeforeRaw: "7",
      walletBalanceBeforeRaw: "7",
      ringProgramId: null,
    } as const;
    const pendingConsolidation = {
      phase: "MergePending",
      asset,
      recipient: address,
      amountRaw: "2",
      sourceBalanceBeforeRaw: "7",
      mergeTransactionSignature: null,
      attempts: 0,
    } as const;
    const parsed = parsePersistentBrowserTvcWalletState({
      ...readyState(),
      pendingSubmission,
      pendingConsolidation,
    });
    expect(parsed?.pendingConsolidation).toEqual(pendingConsolidation);
  });

  it("normalizes pre-consolidation version 3 state without losing identity", () => {
    const previous = readyState();
    delete (previous as Partial<typeof previous>).pendingConsolidation;
    expect(
      parsePersistentBrowserTvcWalletState(previous)?.pendingConsolidation,
    ).toBeNull();
  });

  it("preserves per-ring balance context", () => {
    const pendingSubmission = {
      type: "Unshield",
      asset,
      signedTransaction: "88".repeat(100),
      transactionSignature: "9".repeat(80),
      amountRaw: "2",
      recipient: address,
      ringBalanceBeforeRaw: "7",
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
          asset,
          signedTransaction: "88".repeat(100),
          transactionSignature: "9".repeat(80),
          amountRaw: "4",
          recipient: address,
          ringBalanceBeforeRaw: "3",
          walletBalanceBeforeRaw: "3",
          ringProgramId: null,
        },
      }),
    ).toThrowError("StorageCorrupted");
  });

  it("preserves an explicit public withdrawal", () => {
    const transaction = {
      type: "Unshield",
      asset,
      signature: "9".repeat(80),
      amountRaw: "2",
      recipient: address,
      walletBalanceAfterRaw: "1",
      ringBalanceAfterRaw: "1",
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

  it("preserves a program-neutral ecosystem spend", () => {
    const pendingSubmission = {
      type: "ProgramSpend",
      asset,
      signedTransaction: "88".repeat(100),
      transactionSignature: "9".repeat(80),
      amountRaw: "2",
      recipient: null,
      ringBalanceBeforeRaw: "3",
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

  it("preserves a recoverable program credit with a signed balance delta", () => {
    const pendingSubmission = {
      type: "ProgramSpend",
      asset,
      signedTransaction: "88".repeat(100),
      transactionSignature: "9".repeat(80),
      amountRaw: "7",
      recipient: null,
      ringBalanceBeforeRaw: "3",
      walletBalanceBeforeRaw: "3",
      ringProgramId: null,
      programId: "5".repeat(44),
      action: "swap:cancel",
      balanceDeltaRaw: "7",
      programState: JSON.stringify({ version: 1, order: "opaque" }),
    } as const;
    expect(
      parsePersistentBrowserTvcWalletState({
        ...readyState(),
        pendingSubmission,
      })?.pendingSubmission,
    ).toEqual(pendingSubmission);
  });

  it("rejects a program delta that would make the balance negative", () => {
    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...readyState(),
        pendingSubmission: {
          type: "ProgramSpend",
          asset,
          signedTransaction: "88".repeat(100),
          transactionSignature: "9".repeat(80),
          amountRaw: "9",
          recipient: null,
          ringBalanceBeforeRaw: "3",
          walletBalanceBeforeRaw: "3",
          ringProgramId: null,
          programId: "5".repeat(44),
          action: "swap:take",
          balanceDeltaRaw: "-4",
        },
      }),
    ).toThrowError("StorageCorrupted");
  });

  it("preserves the authoritative post-operation ring balance", () => {
    const transaction = {
      type: "Unshield",
      asset,
      signature: "9".repeat(80),
      amountRaw: "2",
      recipient: address,
      walletBalanceAfterRaw: "9",
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
      asset,
      signedTransaction: "88".repeat(100),
      transactionSignature: "9".repeat(80),
      amountRaw: "2",
      recipient: address,
      ringBalanceBeforeRaw: "7",
      walletBalanceBeforeRaw: "11",
      ringProgramId: null,
      destinationRingProgramId: null,
      destinationRingBalanceBeforeRaw: "7",
    } as const;
    const pendingRingMove = {
      phase: "BridgePending",
      asset,
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

  it("rejects recovery state whose bridge and submission name different assets", () => {
    const pendingSubmission = {
      type: "RingMoveBridge",
      asset,
      signedTransaction: "88".repeat(100),
      transactionSignature: "9".repeat(80),
      amountRaw: "2",
      recipient: address,
      ringBalanceBeforeRaw: "7",
      walletBalanceBeforeRaw: "11",
      ringProgramId: null,
      destinationRingProgramId: null,
      destinationRingBalanceBeforeRaw: "7",
    } as const;
    const pendingRingMove = {
      phase: "BridgePending",
      asset: {
        type: "Spl",
        mint: "So11111111111111111111111111111111111111112",
        asset_id: "14",
      },
      sourceRingProgramId: null,
      destinationRingProgramId: "5".repeat(44),
      amountRaw: "2",
      walletBalanceBeforeRaw: "11",
      destinationRingBalanceBeforeRaw: "4",
      bridgeTransactionSignature: null,
      bridgeCommitment: null,
    } as const;

    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...readyState(),
        pendingSubmission,
        pendingRingMove,
      }),
    ).toThrowError("StorageCorrupted");
  });
});
