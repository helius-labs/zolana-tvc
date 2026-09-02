import { describe, expect, it, vi } from "vitest";

import type { OperationExecutionContext } from "../client/operation-executor.js";
import { encodeLowerHex } from "../protocol/hex.js";
import { stateDigest } from "../protocol/digest.js";
import type { Checkpoint, OperationResult } from "../protocol/types.js";
import { checkDecrypt, checkSpend, executeOperation } from "./operations.js";

const envelope = vi.hoisted(() => vi.fn());
vi.mock("../client/operation-executor.js", () => ({ executeOperationEnvelope: envelope }));

const SOL = "11111111111111111111111111111111";
const checkpoint: Checkpoint = { sealedWalletState: "11".repeat(64) };
const stateDigestHex = encodeLowerHex(stateDigest(new Uint8Array(64).fill(0x11)));
const context = {
  trustVerifier: { verifyCustodyProofs: vi.fn(), verifyOperationAppProof: vi.fn() },
} as unknown as OperationExecutionContext;

function answer(result: OperationResult, digest = stateDigestHex): void {
  envelope.mockResolvedValueOnce({ plaintext: JSON.stringify(result), stateDigest: digest });
}

describe("request checks", () => {
  it("bounds decrypt batches and spend inputs before signing a request", () => {
    const encrypted = {
      type: "Encrypted" as const,
      ciphertext: "ab",
      transaction_viewing_public_key: `02${"cd".repeat(32)}`,
      salt: "ef".repeat(16),
      slot_index: "1",
    };
    expect(() => checkDecrypt({ type: "Decrypt", payloads: [], assets: [] })).toThrowError(
      "EmptyDecryptBatch",
    );
    expect(() =>
      checkDecrypt({ type: "Decrypt", payloads: Array(257).fill(encrypted), assets: [] }),
    ).toThrowError("DecryptBatchTooLarge");
    expect(() =>
      checkDecrypt({
        type: "Decrypt",
        payloads: [{ ...encrypted, slot_index: "4294967296" }],
        assets: [],
      }),
    ).toThrowError("InvalidSlotIndex");

    const input = { asset: SOL, amount: "5", blinding: "22".repeat(32) };
    const action = { type: "Transfer" as const, recipient: "aa".repeat(99), asset: SOL, amount: "1" };
    expect(() => checkSpend({ type: "Spend", tree: "t", inputs: [], action, assets: [] })).toThrowError(
      "NoSpendInputs",
    );
    expect(() =>
      checkSpend({ type: "Spend", tree: "t", inputs: Array(6).fill(input), action, assets: [] }),
    ).toThrowError("TooManySpendInputs");
    expect(() =>
      checkSpend({
        type: "Spend",
        tree: "t",
        inputs: [input],
        action: { ...action, amount: "0" },
        assets: [],
      }),
    ).toThrowError("InvalidSpendAmount");
  });
});

describe("result checks", () => {
  it("returns a result that names the requested operation and key state", async () => {
    answer({ type: "ViewTags", view_tags: ["ab".repeat(32)] });
    await expect(executeOperation(context, { type: "ViewTags" }, checkpoint)).resolves.toEqual({
      type: "ViewTags",
      view_tags: ["ab".repeat(32)],
    });
  });

  it("rejects a proof over another key state", async () => {
    answer({ type: "ViewTags", view_tags: ["ab".repeat(32)] }, "00".repeat(32));
    await expect(executeOperation(context, { type: "ViewTags" }, checkpoint)).rejects.toMatchObject({
      code: "ReleaseBindingMismatch",
    });
  });

  it("surfaces an enclave failure stage and refuses a result for another operation", async () => {
    answer({ type: "Failure", operation: "Spend", stage: "Prover" });
    await expect(
      executeOperation(
        context,
        {
          type: "Spend",
          tree: "t",
          inputs: [{ asset: SOL, amount: "1", blinding: "22".repeat(32) }],
          action: { type: "Withdrawal", recipient: "r", asset: SOL, amount: "1" },
          assets: [],
        },
        checkpoint,
      ),
    ).rejects.toMatchObject({ code: "OperationFailed", message: "OperationFailed: Prover" });

    answer({ type: "ViewTags", view_tags: ["ab".repeat(32)] });
    await expect(
      executeOperation(context, { type: "Decrypt", payloads: [], assets: [] }, checkpoint),
    ).rejects.toMatchObject({ code: "ReleaseBindingMismatch" });
  });

  it("checks decrypted payloads position by position", async () => {
    const operation = {
      type: "Decrypt" as const,
      payloads: [
        { type: "Plain" as const, asset: SOL, amount: "1", blinding: "22".repeat(32) },
        { type: "Plain" as const, asset: SOL, amount: "2", blinding: "33".repeat(32) },
      ],
      assets: [],
    };
    const utxo = {
      type: "Utxo" as const,
      index: "0",
      asset: SOL,
      amount: "1",
      blinding: "22".repeat(32),
      ring_program_id: null,
      commitment: "44".repeat(32),
      nullifier: "55".repeat(32),
    };
    answer({ type: "Decrypt", payloads: [utxo, { type: "Unreadable", index: "1" }] });
    await expect(executeOperation(context, operation, checkpoint)).resolves.toMatchObject({
      payloads: [utxo, { type: "Unreadable", index: "1" }],
    });

    answer({ type: "Decrypt", payloads: [utxo, { type: "Unreadable", index: "0" }] });
    await expect(executeOperation(context, operation, checkpoint)).rejects.toMatchObject({
      code: "ReleaseBindingMismatch",
    });

    answer({ type: "Decrypt", payloads: [utxo] });
    await expect(executeOperation(context, operation, checkpoint)).rejects.toMatchObject({
      code: "ReleaseBindingMismatch",
    });
  });

  it("verifies custody evidence on signed results and rejects extra fields", async () => {
    const spend = {
      type: "Spend" as const,
      tree: "t",
      inputs: [{ asset: SOL, amount: "1", blinding: "22".repeat(32) }],
      action: { type: "Withdrawal" as const, recipient: "r", asset: SOL, amount: "1" },
      assets: [],
    };
    answer({
      type: "Spend",
      signed_transaction: "0102",
      signature: "sig",
      turnkey_activity_id: "activity",
      turnkey_app_proofs: [],
    });
    await expect(executeOperation(context, spend, checkpoint)).resolves.toMatchObject({
      signed_transaction: "0102",
    });
    expect(context.trustVerifier.verifyCustodyProofs).toHaveBeenCalledWith([]);

    envelope.mockResolvedValueOnce({
      plaintext: JSON.stringify({
        type: "Spend",
        signed_transaction: "0102",
        signature: "sig",
        turnkey_activity_id: "activity",
        turnkey_app_proofs: [],
        shielded_balance_before: "1",
      }),
      stateDigest: stateDigestHex,
    });
    await expect(executeOperation(context, spend, checkpoint)).rejects.toMatchObject({
      code: "UnknownJsonField",
    });
  });
});
