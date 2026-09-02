import { describe, expect, it, vi } from "vitest";

import type { OperationExecutionContext } from "../client/operation-executor.js";
import { encodeLowerHex } from "../protocol/hex.js";
import { stateDigest } from "../protocol/digest.js";
import type { Checkpoint, DecryptItem, OperationResult } from "../protocol/types.js";
import {
  checkDecrypt,
  checkDerive,
  checkProve,
  checkTransactionKeys,
  executeOperation,
} from "./operations.js";

const envelope = vi.hoisted(() => vi.fn());
vi.mock("../client/operation-executor.js", () => ({ executeOperationEnvelope: envelope }));

const checkpoint: Checkpoint = { sealedWalletState: "11".repeat(64) };
const stateDigestHex = encodeLowerHex(stateDigest(new Uint8Array(64).fill(0x11)));
const context = {
  trustVerifier: { verifyCustodyProofs: vi.fn(), verifyOperationAppProof: vi.fn() },
} as unknown as OperationExecutionContext;
const VIEWING = `02${"cd".repeat(32)}`;
const HASH = "22".repeat(32);

function answer(result: OperationResult, digest = stateDigestHex): void {
  envelope.mockResolvedValueOnce({ plaintext: JSON.stringify(result), stateDigest: digest });
}

const item: DecryptItem = {
  ciphertext: "ab",
  viewing_public_key: VIEWING,
  transaction_viewing_public_key: `03${"ef".repeat(32)}`,
  salt: "ef".repeat(16),
  slot_index: "1",
  label: "Transfer",
};

describe("request checks", () => {
  it("bounds every batch before signing a request", () => {
    expect(() => checkDecrypt({ type: "Decrypt", items: [] })).toThrowError("EmptyBatch");
    expect(() => checkDecrypt({ type: "Decrypt", items: Array(257).fill(item) })).toThrowError(
      "BatchTooLarge",
    );
    expect(() =>
      checkDecrypt({ type: "Decrypt", items: [{ ...item, slot_index: "4294967296" }] }),
    ).toThrowError("InvalidSlotIndex");
    expect(() =>
      checkDecrypt({ type: "Decrypt", items: [{ ...item, label: "RingDeposit" }] }),
    ).toThrowError("InvalidSlotIndex");
    expect(() =>
      checkDecrypt({ type: "Decrypt", items: [{ ...item, viewing_public_key: "02" }] }),
    ).toThrowError();

    expect(() => checkDerive({ type: "Derive", items: [] })).toThrowError("EmptyBatch");
    expect(() =>
      checkDerive({
        type: "Derive",
        items: [{ kind: "MergeDummyNullifier", first_nullifier: HASH, slot_index: "256" }],
      }),
    ).toThrowError("InvalidSlotIndex");
    expect(
      checkDerive({
        type: "Derive",
        items: [{ kind: "Nullifier", utxo_hash: HASH, blinding: HASH }],
      }).items,
    ).toHaveLength(1);

    expect(() => checkTransactionKeys({ type: "TransactionKeys", items: [] })).toThrowError(
      "EmptyBatch",
    );
    expect(() =>
      checkTransactionKeys({
        type: "TransactionKeys",
        items: [{ viewing_public_key: VIEWING, first_nullifier: "22" }],
      }),
    ).toThrowError();
  });

  it("sends the prover only a request the enclave has something to fill in", () => {
    const open = {
      circuitType: "transfer-confidential",
      inputs: [{ isDummy: "0x0", nullifierSecret: null }],
    };
    expect(checkProve({ type: "Prove", request: open }).request).toBe(open);
    for (const request of [
      { ...open, circuitType: "custom-ring" },
      { ...open, inputs: [] },
      { ...open, inputs: Array(9).fill(open.inputs[0]) },
      { ...open, inputs: [{ isDummy: "0x0", nullifierSecret: "0x1" }] },
      { circuitType: "merge", inputs: [{}], userNullifierSecret: "0x1" },
    ]) {
      expect(() => checkProve({ type: "Prove", request })).toThrowError("InvalidProverRequest");
    }
    expect(
      checkProve({
        type: "Prove",
        request: { circuitType: "merge", inputs: [{}], userNullifierSecret: null },
      }).request["circuitType"],
    ).toBe("merge");
  });
});

describe("result checks", () => {
  const derive = {
    type: "Derive" as const,
    items: [{ kind: "MergeOutputBlinding" as const, first_nullifier: HASH }],
  };

  it("returns a result that names the requested operation and key state", async () => {
    answer({ type: "Derive", values: ["ab".repeat(32)] });
    await expect(executeOperation(context, derive, checkpoint)).resolves.toEqual({
      type: "Derive",
      values: ["ab".repeat(32)],
    });
  });

  it("rejects a proof over another key state", async () => {
    answer({ type: "Derive", values: ["ab".repeat(32)] }, "00".repeat(32));
    await expect(executeOperation(context, derive, checkpoint)).rejects.toMatchObject({
      code: "ReleaseBindingMismatch",
    });
  });

  it("surfaces an enclave failure stage and refuses a result for another operation", async () => {
    const prove = {
      type: "Prove" as const,
      request: { circuitType: "merge", inputs: [{}], userNullifierSecret: null },
    };
    answer({ type: "Failure", operation: "Prove", stage: "Prover" });
    await expect(executeOperation(context, prove, checkpoint)).rejects.toMatchObject({
      code: "OperationFailed",
      message: "OperationFailed: Prover",
    });

    answer({ type: "Derive", values: ["ab".repeat(32)] });
    await expect(
      executeOperation(context, { type: "Decrypt", items: [item] }, checkpoint),
    ).rejects.toMatchObject({ code: "ReleaseBindingMismatch" });
  });

  it("requires one answer per item, each of the promised width", async () => {
    const decrypt = { type: "Decrypt" as const, items: [item, { ...item, slot_index: "2" }] };
    answer({ type: "Decrypt", plaintexts: ["0102", "03"] });
    await expect(executeOperation(context, decrypt, checkpoint)).resolves.toMatchObject({
      plaintexts: ["0102", "03"],
    });
    answer({ type: "Decrypt", plaintexts: ["0102"] });
    await expect(executeOperation(context, decrypt, checkpoint)).rejects.toMatchObject({
      code: "ReleaseBindingMismatch",
    });
    answer({ type: "Derive", values: ["ab".repeat(31)] });
    await expect(executeOperation(context, derive, checkpoint)).rejects.toMatchObject({
      code: "InvalidHex",
    });
    answer({ type: "TransactionKeys", secrets: ["ab".repeat(32)] });
    await expect(
      executeOperation(
        context,
        { type: "TransactionKeys", items: [{ viewing_public_key: VIEWING, first_nullifier: HASH }] },
        checkpoint,
      ),
    ).resolves.toMatchObject({ secrets: ["ab".repeat(32)] });
  });

  it("passes the prover's answer through and rejects extra fields", async () => {
    const prove = {
      type: "Prove" as const,
      request: { circuitType: "merge", inputs: [{}], userNullifierSecret: null },
    };
    answer({ type: "Prove", proof: { proof: { ar: ["0x1", "0x2"] } } });
    await expect(executeOperation(context, prove, checkpoint)).resolves.toMatchObject({
      proof: { proof: { ar: ["0x1", "0x2"] } },
    });
    answer({ type: "Prove", proof: null });
    await expect(executeOperation(context, prove, checkpoint)).rejects.toMatchObject({
      code: "ReleaseBindingMismatch",
    });

    envelope.mockResolvedValueOnce({
      plaintext: JSON.stringify({ type: "Prove", proof: {}, signed_transaction: "0102" }),
      stateDigest: stateDigestHex,
    });
    await expect(executeOperation(context, prove, checkpoint)).rejects.toMatchObject({
      code: "UnknownJsonField",
    });
  });
});
