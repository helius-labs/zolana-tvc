import { describe, expect, it, vi } from "vitest";
import type {
  DecryptUtxosResult,
  DeriveViewTagsResult,
  TvcWalletCheckpoint,
} from "../protocol/types.js";
import type { VerifiedConnection } from "../client/connection.js";
import {
  MAX_DECRYPT_PAYLOADS_PER_BATCH,
  type DecryptUtxosInput,
} from "./operations.js";
import { syncTvcWallet, type TvcWalletFetchedPayload } from "./sync.js";
import type { TvcWalletClient } from "./index.js";

const CHECKPOINT: TvcWalletCheckpoint = {
  sealedWalletState: "11".repeat(64),
  stateVersion: "1",
  stateDigest: "22".repeat(32),
};
const CONNECTION = {} as VerifiedConnection;
const ENCLAVE_TAG = "aa".repeat(32);

function fetched(index: number, meta: unknown = null): TvcWalletFetchedPayload<unknown> {
  return {
    kind: "ciphertext",
    payload: {
      type: "RingDeposit",
      ciphertext: index.toString(16).padStart(4, "0").repeat(16),
      transaction_viewing_public_key: `02${"cd".repeat(32)}`,
      salt: "ef".repeat(16),
    },
    meta,
  };
}

/**
 * A client that answers from a supplied ciphertext pool, recording what it was
 * asked. The point is the plumbing, not the crypto.
 */
function fakeClient(pool: readonly TvcWalletFetchedPayload<unknown>[]) {
  const batchSizes: number[] = [];
  const decryptRequests: unknown[][] = [];
  let tagCalls = 0;

  const client = {
    deriveViewTags: vi.fn(async () => {
      tagCalls += 1;
      return {
        type: "DeriveViewTags",
        view_tags: [ENCLAVE_TAG],
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
        spendable_outputs: input.includeSpendableOutputs ? [] : null,
      } satisfies DecryptUtxosResult;
    }),
  } as unknown as TvcWalletClient;

  return { client, batchSizes, decryptRequests, tagCalls: () => tagCalls, pool };
}

describe("keyholder sync", () => {
  it("queries the indexer with the enclave's tags and the caller's together", async () => {
    // A scan needs both families. The enclave holds the recipient bootstrap
    // tag; the identity tag derives from the signing public key, so the caller
    // supplies that one without asking. Querying either alone finds nothing.
    const identityTag = "bb".repeat(32);
    const pool = [fetched(0), fetched(1)];
    const { client } = fakeClient(pool);
    const fetchByViewTags = vi.fn(async () => pool);

    const result = await syncTvcWallet(client, {
      connection: CONNECTION,
      checkpoint: CHECKPOINT,
      fetchByViewTags,
      additionalViewTags: [identityTag],
    });

    expect(result.viewTags).toEqual([ENCLAVE_TAG, identityTag]);
    expect(fetchByViewTags).toHaveBeenCalledWith([ENCLAVE_TAG, identityTag]);
    expect(result.payloads.map((entry) => entry.encrypted)).toEqual(
      pool.map((entry) => (entry.kind === "ciphertext" ? entry.payload : undefined)),
    );
  });

  it("asks the enclave for tags once, since they do not depend on a range", async () => {
    const { client, batchSizes, tagCalls } = fakeClient([]);
    await syncTvcWallet(client, {
      connection: CONNECTION,
      checkpoint: CHECKPOINT,
      fetchByViewTags: async () => [],
    });
    expect(tagCalls()).toBe(1);
    // Even an empty history needs one authoritative spendable snapshot.
    expect(batchSizes).toEqual([0]);
  });

  it("does not repeat a tag the caller also supplied", async () => {
    // A duplicate would make the indexer redo work and say nothing new.
    const { client } = fakeClient([]);
    const fetchByViewTags = vi.fn(async () => []);
    const result = await syncTvcWallet(client, {
      connection: CONNECTION,
      checkpoint: CHECKPOINT,
      fetchByViewTags,
      additionalViewTags: [ENCLAVE_TAG],
    });
    expect(result.viewTags).toEqual([ENCLAVE_TAG]);
    expect(fetchByViewTags).toHaveBeenCalledWith([ENCLAVE_TAG]);
  });

  it("can scan on the caller's tags alone, without asking the enclave", async () => {
    // A deposit is published under the identity tag, which derives from the
    // signing public key. So a wallet funded only by deposits is discoverable
    // with no tag round trip at all -- the enclave is still needed to decrypt.
    const identityTag = "bb".repeat(32);
    const pool = [fetched(0)];
    const { client, tagCalls } = fakeClient(pool);
    const fetchByViewTags = vi.fn(async () => pool);

    const result = await syncTvcWallet(client, {
      connection: CONNECTION,
      checkpoint: CHECKPOINT,
      fetchByViewTags,
      additionalViewTags: [identityTag],
      deriveEnclaveTags: false,
    });

    expect(tagCalls()).toBe(0);
    expect(fetchByViewTags).toHaveBeenCalledWith([identityTag]);
    expect(result.payloads).toHaveLength(1);
    // Decryption still goes to the enclave; only tag derivation was skipped.
    expect(client.decryptUtxos).toHaveBeenCalledTimes(1);
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
    });

    expect(batchSizes).toEqual([MAX_DECRYPT_PAYLOADS_PER_BATCH, 3]);
    expect(result.payloads).toHaveLength(pool.length);
    expect(result.spendableOutputs).toEqual([]);
  });

  it("returns the caller's context without sending it to the enclave", async () => {
    // The scheme needed to decode the answer lives in the slot's unencrypted
    // frame header, so it has to survive the round trip beside the ciphertext.
    // It must not travel inside the request: the enclave decrypts bytes and has
    // no business learning how the caller intends to read them.
    const pool = [fetched(0, { scheme: 4 }), fetched(1, { scheme: 3 })];
    const { client, decryptRequests } = fakeClient(pool);

    const result = await syncTvcWallet(client, {
      connection: CONNECTION,
      checkpoint: CHECKPOINT,
      fetchByViewTags: async () => pool,
    });

    expect(result.payloads.map((entry) => entry.meta)).toEqual(pool.map((e) => e.meta));
    expect(decryptRequests).toEqual([
      pool.map((entry) => (entry.kind === "ciphertext" ? entry.payload : undefined)),
    ]);
    for (const sent of decryptRequests.flat()) {
      expect(sent).not.toHaveProperty("meta");
    }
  });

  it("keeps an already-plaintext output away from the enclave", async () => {
    // A deposit is published proofless and in the clear -- the amount was
    // public when it was deposited. Sending it to be decrypted would return
    // garbage and, worse, tell the enclave about an output it had no part in.
    const plaintext = "aa".repeat(16);
    const pool: TvcWalletFetchedPayload<unknown>[] = [
      { kind: "plaintext", plaintext, meta: { scheme: 0 } },
      fetched(1, { scheme: 3 }),
    ];
    const { client, decryptRequests } = fakeClient(pool);

    const result = await syncTvcWallet(client, {
      connection: CONNECTION,
      checkpoint: CHECKPOINT,
      fetchByViewTags: async () => pool,
      deriveEnclaveTags: false,
      additionalViewTags: ["bb".repeat(32)],
    });

    expect(result.payloads).toHaveLength(2);
    const clear = result.payloads.find((entry) => entry.encrypted === undefined);
    expect(clear?.decrypted).toEqual({ type: "Plaintext", index: "0", plaintext });
    // Exactly one batch, holding only the ciphertext.
    expect(decryptRequests).toHaveLength(1);
    expect(decryptRequests[0]).toHaveLength(1);
  });

  it("presents the same checkpoint on both legs", async () => {
    const pool = [fetched(0)];
    const { client } = fakeClient(pool);
    await syncTvcWallet(client, {
      connection: CONNECTION,
      checkpoint: CHECKPOINT,
      fetchByViewTags: async () => pool,
    });

    for (const call of [client.deriveViewTags, client.decryptUtxos]) {
      expect(call).toHaveBeenCalledWith(
        CONNECTION,
        expect.objectContaining({ checkpoint: CHECKPOINT }),
      );
    }
  });
});
