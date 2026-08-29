import { describe, expect, expectTypeOf, it } from "vitest";
import type {
  BootstrapKeyholderResult,
  DecryptUtxosOperationV1,
  DecryptUtxosResult,
  DeriveViewTagsOperationV1,
  DeriveViewTagsResult,
  EncryptedPayloadV1,
  FinalizeSpendOperationV1,
  FinalizedSpendResult,
  PrepareSpendOperationV1,
  PreparedSpendResult,
  SppPlanV1,
  TvcWalletCheckpoint,
} from "../protocol/types.js";
import { shieldedIdentityOf } from "./index.js";
import {
  checkpointFromBootstrapResult,
  decryptUtxosOperation,
  deriveViewTagsOperation,
  finalizeSpendOperation,
  finalizeSppSpendOperation,
  MAX_DECRYPT_PAYLOADS_PER_BATCH,
  prepareSpendOperation,
  prepareSppSpendOperation,
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
    expectTypeOf<WalletResultFor<PrepareSpendOperationV1>>()
      .toEqualTypeOf<PreparedSpendResult>();
    expectTypeOf<WalletResultFor<FinalizeSpendOperationV1>>()
      .toEqualTypeOf<FinalizedSpendResult>();
  });

  it("builds a custom-ring exit", () => {
    expect(
      prepareSpendOperation({
        checkpoint: CHECKPOINT,
        ring: { direction: "exit", programId: "ringProgram", lookupTable: "table" },
        settlement: {
          kind: "transfer",
          asset: { type: "Sol" },
          recipient: "So11111111111111111111111111111111111111112",
          amount: 7n,
        },
        proverProfileId: "zolnet-devnet-external-http-v1",
      }),
    ).toEqual({
      type: "AuthorizeSpend",
      spend: {
        phase: "Prepare",
        plan: {
          type: "Builtin",
          intent: {
            ring: {
              direction: "Exit",
              program_id: "ringProgram",
              lookup_table: "table",
            },
            settlement: {
              type: "Transfer",
              asset: { type: "Sol" },
              recipient: "So11111111111111111111111111111111111111112",
              amount: "7",
            },
            prover_profile_id: "zolnet-devnet-external-http-v1",
            input_commitments: [],
          },
        },
      },
    });
  });

  it("selects the default ring explicitly with null", () => {
    expect(
      prepareSpendOperation({
        checkpoint: CHECKPOINT,
        ring: null,
        settlement: {
          kind: "solWithdrawal",
          recipient: "So11111111111111111111111111111111111111112",
          amount: 7n,
        },
        proverProfileId: "zolnet-devnet-external-http-v1",
      }).spend.plan,
    ).toMatchObject({ type: "Builtin", intent: { ring: null } });
  });

  it("binds a ring entry to the exact default-ring commitment", () => {
    const commitment = "11".repeat(32);
    expect(
      prepareSpendOperation({
        checkpoint: CHECKPOINT,
        ring: {
          direction: "enter",
          programId: "ringProgram",
          lookupTable: "table",
        },
        inputCommitments: [commitment],
        settlement: {
          kind: "transfer",
          asset: { type: "Sol" },
          recipient: "So11111111111111111111111111111111111111112",
          amount: 7n,
        },
        proverProfileId: "zolnet-devnet-external-http-v1",
      }).spend.plan,
    ).toMatchObject({
      type: "Builtin",
      intent: {
        ring: { direction: "Enter", program_id: "ringProgram" },
        input_commitments: [commitment],
      },
    });
  });

  it("rejects an entry without an exact input commitment", () => {
    expect(() =>
      prepareSpendOperation({
        checkpoint: CHECKPOINT,
        ring: {
          direction: "enter",
          programId: "ringProgram",
          lookupTable: "table",
        },
        settlement: {
          kind: "transfer",
          asset: { type: "Sol" },
          recipient: "So11111111111111111111111111111111111111112",
          amount: 7n,
        },
        proverProfileId: "zolnet-devnet-external-http-v1",
      }),
    ).toThrowError("InvalidRingSpend");
  });

  it("keeps prepare and finalize under the AuthorizeSpend grant", () => {
    const prepared = prepareSpendOperation({
      checkpoint: CHECKPOINT,
      ring: null,
      settlement: {
        kind: "solWithdrawal",
        recipient: "So11111111111111111111111111111111111111112",
        amount: 7n,
      },
      proverProfileId: "zolnet-devnet-external-http-v1",
    });
    expect(prepared).toMatchObject({
      type: "AuthorizeSpend",
      spend: { phase: "Prepare" },
    });

    expect(
      finalizeSpendOperation({
        checkpoint: CHECKPOINT,
        sealedAuthorizationCapsule: "aa",
        unsignedTransaction: "bb",
      }),
    ).toEqual({
      type: "AuthorizeSpend",
      spend: {
        phase: "Finalize",
        sealed_authorization_capsule: "aa",
        finalization: {
          type: "ExactTransaction",
          unsigned_transaction: "bb",
        },
      },
    });
  });

  it("builds the generic private-only SPP prepare and finalize pair", () => {
    const plan: SppPlanV1 = {
      program_id: "ecosystemProgram",
      input_tree: "inputTree",
      shape: { inputs: 2, outputs: 1 },
      inputs: [{ type: "Wallet", commitment: "11".repeat(32) }],
      program_authorities: [],
      outputs: [
        {
          recipient: "shieldedRecipient",
          asset: { type: "Sol" },
          amount: "7",
          blinding: "22".repeat(32),
          data: "aabb",
          data_hash: null,
          memo: "",
        },
      ],
      messages: [{ view_tag: "33".repeat(32), data: "cc" }],
      public_effects: { type: "PrivateOnly" },
      prover_profile_id: "zolnet-devnet-external-http-v1",
      expires_at_ms: "1750000000000",
    };

    expect(prepareSppSpendOperation({ checkpoint: CHECKPOINT, plan })).toEqual({
      type: "AuthorizeSpend",
      spend: { phase: "Prepare", plan: { type: "Spp", plan } },
    });

    expect(
      finalizeSppSpendOperation({
        checkpoint: CHECKPOINT,
        sealedAuthorizationCapsule: "aa",
        instruction: {
          program_id: "ecosystemProgram",
          accounts: [
            { address: "payer", is_signer: true, is_writable: true },
            { address: "shieldedPool", is_signer: false, is_writable: false },
          ],
          data: "bb",
        },
        addressLookupTables: ["table"],
      }),
    ).toEqual({
      type: "AuthorizeSpend",
      spend: {
        phase: "Finalize",
        sealed_authorization_capsule: "aa",
        finalization: {
          type: "SppProgram",
          instruction: {
            program_id: "ecosystemProgram",
            accounts: [
              { address: "payer", is_signer: true, is_writable: true },
              { address: "shieldedPool", is_signer: false, is_writable: false },
            ],
            data: "bb",
          },
          address_lookup_tables: ["table"],
        },
      },
    });
  });

  it("keeps a public exit distinguishable from a private transfer", () => {
    // Separate settlement variants rather than a nullable recipient pair, so a
    // public recipient can never be read as a registered shielded one.
    expect(
      prepareSpendOperation({
        checkpoint: CHECKPOINT,
        ring: { direction: "exit", programId: "ringProgram", lookupTable: "table" },
        settlement: {
          kind: "solWithdrawal",
          recipient: "So11111111111111111111111111111111111111112",
          amount: 7n,
        },
        proverProfileId: "zolnet-devnet-external-http-v1",
      }).spend.plan,
    ).toMatchObject({
      type: "Builtin",
      intent: {
        settlement: {
          type: "SolWithdrawal",
          recipient: "So11111111111111111111111111111111111111112",
          amount: "7",
        },
      },
    });
  });

  it("asks for the wallet's tags without naming a range", () => {
    // The tags a wallet is found by are stable, so the request carries no
    // window. An earlier version sent from_tx_count/count and derived sender
    // tags, which are well-formed and match nothing: no query uses that family.
    expect(deriveViewTagsOperation()).toEqual({ type: "DeriveViewTags" });
  });

  it("refuses a ring named without the table its transact needs", () => {
    // A custom-ring transact does not fit a legacy packet, so it cannot be
    // built without a lookup table. Sending the ring alone would fail inside
    // the enclave instead of here.
    expect(() =>
      prepareSpendOperation({
        checkpoint: CHECKPOINT,
        ring: { direction: "exit", programId: "ringProgram", lookupTable: "" },
        settlement: {
          kind: "solWithdrawal",
          recipient: "So11111111111111111111111111111111111111112",
          amount: 1_000n,
        },
        proverProfileId: "zolnet-devnet-external-http-v1",
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
