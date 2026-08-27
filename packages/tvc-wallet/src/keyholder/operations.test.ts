import { describe, expect, expectTypeOf, it } from "vitest";
import type {
  BootstrapKeyholderResult,
  BuildSolWithdrawalOperationV1,
  BuildSolWithdrawalResult,
  BuildTransferOperationV1,
  BuildTransferResult,
  DecryptUtxosOperationV1,
  DecryptUtxosResult,
  DeriveViewTagsOperationV1,
  DeriveViewTagsResult,
  EncryptedPayloadV1,
  TvcWalletCheckpoint,
} from "../protocol/types.js";
import { shieldedIdentityOf } from "./index.js";
import {
  checkpointFromBootstrapResult,
  buildSolWithdrawalOperation,
  buildTransferOperation,
  decryptUtxosOperation,
  deriveViewTagsOperation,
  expectedOperationKind,
  MAX_DECRYPT_PAYLOADS_PER_BATCH,
  type WalletResultFor,
} from "./operations.js";

const CHECKPOINT: TvcWalletCheckpoint = {
  sealedWalletState: "11".repeat(64),
  stateVersion: "1",
  stateDigest: "22".repeat(32),
};

function ringDeposit(): EncryptedPayloadV1 {
  return {
    type: "RingDeposit",
    ciphertext: "ab".repeat(32),
    transaction_viewing_public_key: `02${"cd".repeat(32)}`,
    salt: "ef".repeat(16),
  };
}

describe("keyholder operation builders", () => {
  it("maps each operation discriminant to its exact result type", () => {
    expectTypeOf<WalletResultFor<{ type: "BootstrapKeyholder" }>>()
      .toEqualTypeOf<BootstrapKeyholderResult>();
    expectTypeOf<WalletResultFor<DeriveViewTagsOperationV1>>()
      .toEqualTypeOf<DeriveViewTagsResult>();
    expectTypeOf<WalletResultFor<DecryptUtxosOperationV1>>()
      .toEqualTypeOf<DecryptUtxosResult>();
    expectTypeOf<WalletResultFor<BuildTransferOperationV1>>()
      .toEqualTypeOf<BuildTransferResult>();
    expectTypeOf<WalletResultFor<BuildSolWithdrawalOperationV1>>()
      .toEqualTypeOf<BuildSolWithdrawalResult>();
  });

  it("builds the closed transfer shape", () => {
    expect(
      buildTransferOperation({
        checkpoint: CHECKPOINT,
        asset: { type: "Sol" },
        recipient: "So11111111111111111111111111111111111111112",
        amount: 7n,
        proverProfileId: "zolnet-devnet-external-http-v1",
      }),
    ).toEqual({
      type: "BuildTransfer",
      intent: {
        asset: { type: "Sol" },
        recipient: "So11111111111111111111111111111111111111112",
        amount: "7",
        prover_profile_id: "zolnet-devnet-external-http-v1",
        ring: null,
      },
    });
  });

  it("builds an explicit public SOL withdrawal shape", () => {
    expect(
      buildSolWithdrawalOperation({
        checkpoint: CHECKPOINT,
        recipient: "So11111111111111111111111111111111111111112",
        amount: 7n,
        proverProfileId: "zolnet-devnet-external-http-v1",
      }),
    ).toEqual({
      type: "BuildSolWithdrawal",
      intent: {
        recipient: "So11111111111111111111111111111111111111112",
        amount: "7",
        prover_profile_id: "zolnet-devnet-external-http-v1",
        ring: null,
      },
    });
  });

  it("asks for the wallet's tags without naming a range", () => {
    // The tags a wallet is found by are stable, so the request carries no
    // window. An earlier version sent from_tx_count/count and derived sender
    // tags, which are well-formed and match nothing: no query uses that family.
    expect(deriveViewTagsOperation()).toEqual({ type: "DeriveViewTags" });
  });

  it("names the ring a spend draws from, or the default one", () => {
    const base = {
      checkpoint: CHECKPOINT,
      asset: { type: "Sol" } as const,
      recipient: "So11111111111111111111111111111111111111112",
      amount: 1_000n,
      proverProfileId: "zolnet-devnet-external-http-v1",
    };

    // Absent means the default ring, and has to travel as an explicit null:
    // the enclave parses strictly and rejects a missing field.
    expect(buildTransferOperation(base).intent.ring).toBeNull();

    expect(
      buildTransferOperation({
        ...base,
        ring: { programId: "ringProgram", lookupTable: "table" },
      }).intent.ring,
    ).toEqual({ program_id: "ringProgram", lookup_table: "table" });
  });

  it("expects the kind the application will report, not the request's tag", () => {
    // A `Failure` names the operation kind, and for a spend the kind follows
    // the ring rather than the tag. Getting this wrong does not lose the
    // failure quietly -- it replaces the reported stage with a release
    // binding mismatch, which sends the reader to the wrong problem.
    const base = {
      checkpoint: CHECKPOINT,
      asset: { type: "Sol" } as const,
      recipient: "So11111111111111111111111111111111111111112",
      amount: 1_000n,
      proverProfileId: "zolnet-devnet-external-http-v1",
    };
    const ring = { programId: "ringProgram", lookupTable: "table" };

    expect(expectedOperationKind(buildTransferOperation(base))).toBe(
      "BuildTransfer",
    );
    expect(
      expectedOperationKind(buildTransferOperation({ ...base, ring })),
    ).toBe("BuildCustomRingTransfer");

    const withdrawal = {
      checkpoint: CHECKPOINT,
      recipient: "So11111111111111111111111111111111111111112",
      amount: 1_000n,
      proverProfileId: "zolnet-devnet-external-http-v1",
    };
    expect(expectedOperationKind(buildSolWithdrawalOperation(withdrawal))).toBe(
      "BuildSolWithdrawal",
    );
    expect(
      expectedOperationKind(
        buildSolWithdrawalOperation({ ...withdrawal, ring }),
      ),
    ).toBe("BuildCustomRingSolWithdrawal");
  });

  it("refuses a ring named without the table its transact needs", () => {
    // A custom-ring transact does not fit a legacy packet, so it cannot be
    // built without a lookup table. Sending the ring alone would fail inside
    // the enclave instead of here.
    expect(() =>
      buildSolWithdrawalOperation({
        checkpoint: CHECKPOINT,
        recipient: "So11111111111111111111111111111111111111112",
        amount: 1_000n,
        proverProfileId: "zolnet-devnet-external-http-v1",
        ring: { programId: "ringProgram", lookupTable: "" },
      }),
    ).toThrowError("InvalidRingSpend");
  });

  it("bounds the decrypt batch", () => {
    expect(() =>
      decryptUtxosOperation({ checkpoint: CHECKPOINT, payloads: [] }),
    ).toThrowError("EmptyDecryptBatch");
    expect(() =>
      decryptUtxosOperation({
        checkpoint: CHECKPOINT,
        payloads: Array.from({ length: MAX_DECRYPT_PAYLOADS_PER_BATCH + 1 }, ringDeposit),
      }),
    ).toThrowError("DecryptBatchTooLarge");
  });

  it("rejects public material of the wrong length before sending it", () => {
    const withPayload = (payload: EncryptedPayloadV1) => () =>
      decryptUtxosOperation({ checkpoint: CHECKPOINT, payloads: [payload] });

    expect(withPayload({ ...ringDeposit(), salt: "ef".repeat(8) })).toThrowError();
    expect(
      withPayload({ ...ringDeposit(), transaction_viewing_public_key: "cd".repeat(32) }),
    ).toThrowError();
    expect(
      withPayload({
        type: "Utxo",
        ciphertext: "ab".repeat(32),
        transaction_viewing_public_key: `02${"cd".repeat(32)}`,
        salt: "ef".repeat(16),
        slot_index: "4294967296",
      }),
    ).toThrowError("InvalidSlotIndex");
  });

  it("carries the slot index only for slot-addressed payloads", () => {
    const operation = decryptUtxosOperation({
      checkpoint: CHECKPOINT,
      payloads: [
        ringDeposit(),
        {
          type: "Utxo",
          ciphertext: "ab".repeat(32),
          transaction_viewing_public_key: `02${"cd".repeat(32)}`,
          salt: "ef".repeat(16),
          slot_index: "2",
        },
      ],
    });
    expect(operation.payloads[0]).not.toHaveProperty("slot_index");
    expect(operation.payloads[1]).toMatchObject({ type: "Utxo", slot_index: "2" });
  });

  it("projects the identity a rotation must land back on", () => {
    // The sealed blob is a cache; the identity is what must survive a new
    // release with a new Quorum key, so it is compared field by field.
    const result = {
      type: "BootstrapKeyholder",
      solana_address: "So11111111111111111111111111111111111111112",
      shielded_owner_hash: "33".repeat(32),
      shielded_nullifier_public_key: "44".repeat(32),
      shielded_viewing_public_key: `02${"55".repeat(32)}`,
    } as BootstrapKeyholderResult;

    expect(shieldedIdentityOf(result)).toEqual({
      solanaAddress: "So11111111111111111111111111111111111111112",
      shieldedOwnerHash: "33".repeat(32),
      shieldedNullifierPublicKey: "44".repeat(32),
      shieldedViewingPublicKey: `02${"55".repeat(32)}`,
    });
    // Re-deriving the same seed under a different Quorum key must yield the
    // same identity, so the projection must not depend on the sealed state.
    const resealed = { ...result, sealed_wallet_state: "ff".repeat(64) };
    expect(shieldedIdentityOf(resealed as BootstrapKeyholderResult)).toEqual(
      shieldedIdentityOf(result),
    );
  });

  it("turns a bootstrap result into the checkpoint later calls present", () => {
    const result = {
      type: "BootstrapKeyholder",
      sealed_wallet_state: "11".repeat(64),
      state_version: "1",
      state_digest: "22".repeat(32),
    } as BootstrapKeyholderResult;
    expect(checkpointFromBootstrapResult(result)).toEqual(CHECKPOINT);
    // The seed is never part of a keyholder result, so nothing here can leak it.
    expect(result).not.toHaveProperty("derivation_seed");
  });
});
