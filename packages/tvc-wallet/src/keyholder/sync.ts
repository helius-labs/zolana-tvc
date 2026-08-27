import { TvcError } from "../protocol/error.js";
import type {
  DecryptedPayloadV1,
  EncryptedPayloadV1,
  TvcWalletCheckpoint,
} from "../protocol/types.js";
import type { VerifiedConnection } from "../client/connection.js";
import {
  MAX_DECRYPT_PAYLOADS_PER_BATCH,
  MAX_VIEW_TAGS_PER_WINDOW,
} from "./operations.js";
import type { TvcWalletClient } from "./index.js";

/**
 * One ciphertext to decrypt, with whatever the caller needs back beside it.
 *
 * `meta` is opaque here and never reaches TVC. It exists because the ciphertext
 * alone is not enough to read the answer: the output scheme lives in the slot's
 * unencrypted frame header, so the decoder to use is known before the round
 * trip and has to survive it. Callers put the ring binding there too.
 */
export type TvcWalletFetchedPayload<TMeta> = {
  readonly payload: EncryptedPayloadV1;
  readonly meta: TMeta;
};

/**
 * Fetches the ciphertexts published under a set of view tags.
 *
 * This is the caller's indexer call. The keyholder application never makes it:
 * that separation is the whole point of the profile, so the package takes the
 * fetch as a parameter rather than owning a transport.
 */
export type TvcWalletTaggedFetch<TMeta> = (
  viewTags: readonly string[],
) => Promise<readonly TvcWalletFetchedPayload<TMeta>[]>;

export type TvcWalletSyncInput<TMeta> = {
  readonly connection: VerifiedConnection;
  readonly checkpoint: TvcWalletCheckpoint;
  readonly fetchByViewTags: TvcWalletTaggedFetch<TMeta>;
  /** Where in the wallet's transaction counter to start. */
  readonly fromTxCount: bigint;
  /** How many tags to scan. Paged internally against the enclave's window cap. */
  readonly tagCount: number;
};

export type TvcWalletSyncResult<TMeta> = {
  /** Every tag scanned, in order, so a caller can record where it stopped. */
  readonly viewTags: readonly string[];
  /**
   * One entry per ciphertext fetched, paired with the payload it came from.
   *
   * These are decryption outputs, not confirmed wallet UTXOs: the transport
   * cipher is unauthenticated, so a payload belonging to another wallet appears
   * here as `Plaintext` full of garbage. Deserialize each one and compare the
   * recovered owner against your own before spending against it.
   */
  readonly payloads: readonly {
    readonly encrypted: EncryptedPayloadV1;
    readonly decrypted: DecryptedPayloadV1;
    /** Carried through untouched from the fetch. */
    readonly meta: TMeta;
  }[];
};

/**
 * Runs one sync: derive tags, fetch by them, decrypt what came back.
 *
 * Two round trips to TVC per page, and the indexer call in between is the
 * caller's. Both legs are paged against the enclave's caps rather than assumed
 * to fit, because a wallet with real history will not.
 */
export async function syncTvcWallet<TMeta>(
  client: TvcWalletClient,
  input: TvcWalletSyncInput<TMeta>,
): Promise<TvcWalletSyncResult<TMeta>> {
  if (!Number.isInteger(input.tagCount) || input.tagCount <= 0) {
    throw new TvcError("InvalidTagWindow");
  }

  const viewTags: string[] = [];
  const payloads: TvcWalletSyncResult<TMeta>["payloads"][number][] = [];

  for (let scanned = 0; scanned < input.tagCount; scanned += MAX_VIEW_TAGS_PER_WINDOW) {
    const count = Math.min(MAX_VIEW_TAGS_PER_WINDOW, input.tagCount - scanned);
    const window = await client.deriveViewTags(input.connection, {
      checkpoint: input.checkpoint,
      fromTxCount: input.fromTxCount + BigInt(scanned),
      count,
    });
    viewTags.push(...window.view_tags);

    const fetched = await input.fetchByViewTags(window.view_tags);
    for (let start = 0; start < fetched.length; start += MAX_DECRYPT_PAYLOADS_PER_BATCH) {
      const batch = fetched.slice(start, start + MAX_DECRYPT_PAYLOADS_PER_BATCH);
      const decrypted = await client.decryptUtxos(input.connection, {
        checkpoint: input.checkpoint,
        // Ciphertexts only. `meta` is the caller's and stays here.
        payloads: batch.map((entry) => entry.payload),
      });
      // The operation layer already checks that each result's index matches its
      // position, so pairing by position here is sound.
      batch.forEach((entry, position) => {
        const result = decrypted.payloads[position];
        if (!result) throw new TvcError("ReleaseBindingMismatch");
        payloads.push({ encrypted: entry.payload, decrypted: result, meta: entry.meta });
      });
    }
  }

  return Object.freeze({
    viewTags: Object.freeze(viewTags),
    payloads: Object.freeze(payloads),
  });
}
