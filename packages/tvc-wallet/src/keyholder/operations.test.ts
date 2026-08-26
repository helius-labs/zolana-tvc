import { describe, expect, expectTypeOf, it } from "vitest";
import type {
  BootstrapKeyholderResult,
  DecryptUtxosOperationV1,
  DecryptUtxosResult,
  DeriveViewTagsOperationV1,
  DeriveViewTagsResult,
  EncryptedPayloadV1,
  TvcWalletCheckpoint,
} from "../protocol/types.js";
import { keyholderIdentityOf } from "./index.js";
import {
  checkpointFromKeyholderResult,
  decryptUtxosOperation,
  deriveViewTagsOperation,
  MAX_DECRYPT_PAYLOADS_PER_BATCH,
  MAX_VIEW_TAGS_PER_WINDOW,
  type KeyholderResultFor,
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
    expectTypeOf<KeyholderResultFor<{ type: "BootstrapKeyholder" }>>()
      .toEqualTypeOf<BootstrapKeyholderResult>();
    expectTypeOf<KeyholderResultFor<DeriveViewTagsOperationV1>>()
      .toEqualTypeOf<DeriveViewTagsResult>();
    expectTypeOf<KeyholderResultFor<DecryptUtxosOperationV1>>()
      .toEqualTypeOf<DecryptUtxosResult>();
  });

  it("encodes a tag window as decimal strings", () => {
    expect(
      deriveViewTagsOperation({ checkpoint: CHECKPOINT, fromTxCount: 7n, count: 3 }),
    ).toEqual({ type: "DeriveViewTags", from_tx_count: "7", count: "3" });
  });

  it("bounds the tag window and refuses one that would wrap", () => {
    const window = (fromTxCount: bigint, count: number) => () =>
      deriveViewTagsOperation({ checkpoint: CHECKPOINT, fromTxCount, count });

    expect(window(0n, 0)).toThrowError("InvalidTagWindow");
    expect(window(0n, 1.5)).toThrowError("InvalidTagWindow");
    expect(window(-1n, 1)).toThrowError("InvalidTagWindow");
    expect(window(0n, MAX_VIEW_TAGS_PER_WINDOW + 1)).toThrowError("TagWindowTooLarge");
    // Wrapping would ask for a range the caller did not intend; the enclave
    // rejects it too, so catching it here saves a round trip.
    expect(window(0xffff_ffff_ffff_ffffn, 2)).toThrowError("InvalidTagWindow");
    expect(window(0n, MAX_VIEW_TAGS_PER_WINDOW)()).toMatchObject({ type: "DeriveViewTags" });
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

    expect(keyholderIdentityOf(result)).toEqual({
      solanaAddress: "So11111111111111111111111111111111111111112",
      shieldedOwnerHash: "33".repeat(32),
      shieldedNullifierPublicKey: "44".repeat(32),
      shieldedViewingPublicKey: `02${"55".repeat(32)}`,
    });
    // Re-deriving the same seed under a different Quorum key must yield the
    // same identity, so the projection must not depend on the sealed state.
    const resealed = { ...result, sealed_wallet_state: "ff".repeat(64) };
    expect(keyholderIdentityOf(resealed as BootstrapKeyholderResult)).toEqual(
      keyholderIdentityOf(result),
    );
  });

  it("turns a bootstrap result into the checkpoint later calls present", () => {
    const result = {
      type: "BootstrapKeyholder",
      sealed_wallet_state: "11".repeat(64),
      state_version: "1",
      state_digest: "22".repeat(32),
    } as BootstrapKeyholderResult;
    expect(checkpointFromKeyholderResult(result)).toEqual(CHECKPOINT);
    // The seed is never part of a keyholder result, so nothing here can leak it.
    expect(result).not.toHaveProperty("derivation_seed");
  });
});
