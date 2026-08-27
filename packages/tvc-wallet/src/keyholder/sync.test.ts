import { describe, expect, it, vi } from "vitest";
import type {
  DecryptUtxosResult,
  DeriveViewTagsResult,
  EncryptedPayloadV1,
  TvcWalletCheckpoint,
} from "../protocol/types.js";
import type { VerifiedConnection } from "../client/connection.js";
import {
  MAX_DECRYPT_PAYLOADS_PER_BATCH,
  MAX_VIEW_TAGS_PER_WINDOW,
  type DecryptUtxosInput,
  type DeriveViewTagsInput,
} from "./operations.js";
import { syncTvcWallet } from "./sync.js";
import type { TvcWalletClient } from "./index.js";

const CHECKPOINT: TvcWalletCheckpoint = {
  sealedWalletState: "11".repeat(64),
  stateVersion: "1",
  stateDigest: "22".repeat(32),
};
const CONNECTION = {} as VerifiedConnection;

function fetched(index: number, meta: unknown = null) {
  return { payload: payload(index), meta };
}

function payload(index: number): EncryptedPayloadV1 {
  return {
    type: "RingDeposit",
    ciphertext: index.toString(16).padStart(4, "0").repeat(16),
    transaction_viewing_public_key: `02${"cd".repeat(32)}`,
    salt: "ef".repeat(16),
  };
}

/**
 * A client that answers from a supplied ciphertext pool, recording the windows
 * and batch sizes it was asked for. The point is the paging, not the crypto.
 */
function fakeClient(pool: readonly { payload: EncryptedPayloadV1; meta: unknown }[]) {
  const windows: { from: string; count: number }[] = [];
  const batchSizes: number[] = [];
  const decryptRequests: unknown[][] = [];

  const client = {
    deriveViewTags: vi.fn(async (_connection: VerifiedConnection, input: DeriveViewTagsInput) => {
      windows.push({ from: input.fromTxCount.toString(), count: input.count });
      return {
        type: "DeriveViewTags",
        from_tx_count: input.fromTxCount.toString(),
        view_tags: Array.from({ length: input.count }, (_, i) =>
          (Number(input.fromTxCount) + i).toString(16).padStart(2, "0").repeat(32),
        ),
      } satisfies DeriveViewTagsResult;
    }),
    decryptUtxos: vi.fn(async (_connection: VerifiedConnection, input: DecryptUtxosInput) => {
      batchSizes.push(input.payloads.length);
      decryptRequests.push([...input.payloads]);
      return {
        type: "DecryptUtxos",
        payloads: input.payloads.map((_, index) => ({
          type: "Plaintext" as const,
          index: String(index),
          plaintext: "aa".repeat(8),
        })),
      } satisfies DecryptUtxosResult;
    }),
  } as unknown as TvcWalletClient;

  return { client, windows, batchSizes, decryptRequests, pool };
}

describe("keyholder sync", () => {
  it("derives tags, fetches by them, and pairs each ciphertext with its plaintext", async () => {
    const pool = [fetched(0), fetched(1), fetched(2)];
    const { client } = fakeClient(pool);
    const fetchByViewTags = vi.fn(async () => pool);

    const result = await syncTvcWallet(client, {
      connection: CONNECTION,
      checkpoint: CHECKPOINT,
      fetchByViewTags,
      fromTxCount: 0n,
      tagCount: 4,
    });

    expect(result.viewTags).toHaveLength(4);
    expect(result.payloads).toHaveLength(3);
    // The pairing is what a caller relies on to know which ciphertext a
    // plaintext came from; ordering alone would not establish it.
    expect(result.payloads.map((entry) => entry.encrypted)).toEqual(
      pool.map((entry) => entry.payload),
    );
    // The indexer is the caller's call, made with the tags TVC produced.
    expect(fetchByViewTags).toHaveBeenCalledWith(result.viewTags);
  });

  it("pages tag windows against the enclave's cap", async () => {
    const { client, windows } = fakeClient([]);
    await syncTvcWallet(client, {
      connection: CONNECTION,
      checkpoint: CHECKPOINT,
      fetchByViewTags: async () => [],
      fromTxCount: 100n,
      tagCount: MAX_VIEW_TAGS_PER_WINDOW + 5,
    });

    expect(windows).toEqual([
      { from: "100", count: MAX_VIEW_TAGS_PER_WINDOW },
      // The second window continues from where the first ended, so no tag is
      // scanned twice and none is skipped.
      { from: String(100 + MAX_VIEW_TAGS_PER_WINDOW), count: 5 },
    ]);
  });

  it("pages decryption against the enclave's batch cap", async () => {
    const pool = Array.from({ length: MAX_DECRYPT_PAYLOADS_PER_BATCH + 3 }, (_, i) =>
      fetched(i),
    );
    const { client, batchSizes } = fakeClient(pool);

    const result = await syncTvcWallet(client, {
      connection: CONNECTION,
      checkpoint: CHECKPOINT,
      fetchByViewTags: async () => pool,
      fromTxCount: 0n,
      tagCount: 1,
    });

    expect(batchSizes).toEqual([MAX_DECRYPT_PAYLOADS_PER_BATCH, 3]);
    expect(result.payloads).toHaveLength(pool.length);
    expect(result.payloads.map((entry) => entry.encrypted)).toEqual(
      pool.map((entry) => entry.payload),
    );
  });

  it("presents the same checkpoint on both legs", async () => {
    const pool = [fetched(0)];
    const { client } = fakeClient(pool);
    await syncTvcWallet(client, {
      connection: CONNECTION,
      checkpoint: CHECKPOINT,
      fetchByViewTags: async () => pool,
      fromTxCount: 0n,
      tagCount: 1,
    });

    for (const call of [client.deriveViewTags, client.decryptUtxos]) {
      expect(call).toHaveBeenCalledWith(
        CONNECTION,
        expect.objectContaining({ checkpoint: CHECKPOINT }),
      );
    }
  });

  it("returns the caller's metadata without sending it to the enclave", async () => {
    // The scheme needed to decode the answer lives in the slot's unencrypted
    // frame header, so it has to survive the round trip beside the ciphertext.
    // It must not travel inside the request: the enclave decrypts bytes and has
    // no business learning how the caller intends to read them, nor which ring
    // a payload came from.
    const pool = [
      fetched(0, { scheme: 4, ringProgramId: "ringAlpha" }),
      fetched(1, { scheme: 3 }),
    ];
    const { client, decryptRequests } = fakeClient(pool);

    const result = await syncTvcWallet(client, {
      connection: CONNECTION,
      checkpoint: CHECKPOINT,
      fetchByViewTags: async () => pool,
      fromTxCount: 0n,
      tagCount: 1,
    });

    expect(result.payloads.map((entry) => entry.meta)).toEqual(pool.map((e) => e.meta));
    expect(decryptRequests).toEqual([pool.map((entry) => entry.payload)]);
    for (const sent of decryptRequests.flat()) {
      expect(sent).not.toHaveProperty("meta");
      expect(sent).not.toHaveProperty("ringProgramId");
    }
  });

  it("rejects a nonsensical scan length", async () => {
    const { client } = fakeClient([]);
    const sync = (tagCount: number) =>
      syncTvcWallet(client, {
        connection: CONNECTION,
        checkpoint: CHECKPOINT,
        fetchByViewTags: async () => [],
        fromTxCount: 0n,
        tagCount,
      });

    await expect(sync(0)).rejects.toThrowError("InvalidTagWindow");
    await expect(sync(-1)).rejects.toThrowError("InvalidTagWindow");
    await expect(sync(2.5)).rejects.toThrowError("InvalidTagWindow");
  });
});
