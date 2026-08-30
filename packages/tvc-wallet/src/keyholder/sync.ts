import { TvcError } from "../protocol/error.js";
import type {
  DecryptedPayloadV1,
  EncryptedPayloadV1,
  SpendableOutputV1,
  TvcWalletCheckpoint,
} from "../protocol/types.js";
import type { VerifiedConnection } from "../client/connection.js";
import { MAX_DECRYPT_PAYLOADS_PER_BATCH } from "./operations.js";
import type { TvcWalletClient } from "./index.js";

/**
 * One ciphertext to decrypt, with whatever the caller needs back beside it.
 *
 * `meta` is opaque here and never reaches TVC. It exists because the ciphertext
 * alone is not enough to read the answer: the output scheme lives in the slot's
 * unencrypted frame header, so the decoder to use is known before the round
 * trip and has to survive it. Callers put the ring binding there too.
 */
export type TvcWalletFetchedPayload<TMeta> =
  | {
      readonly kind: "ciphertext";
      readonly payload: EncryptedPayloadV1;
      readonly meta: TMeta;
    }
  /**
   * An output published in the clear. A shielded transaction carries both:
   * a deposit, for one, is proofless and plaintext, because the amount was
   * public the moment it was deposited. The enclave has nothing to do with
   * these -- they pass straight through to the caller.
   */
  | { readonly kind: "plaintext"; readonly plaintext: string; readonly meta: TMeta };

/**
 * Fetches the ciphertexts published under a set of view tags.
 *
 * This is the caller's ciphertext-discovery call, so the package takes it as a
 * parameter rather than owning a transport. TVC separately reconciles the
 * spendable set against its pinned indexer using the nullifier role; it does
 * not use caller-selected network coordinates.
 */
export type TvcWalletTaggedFetch<TMeta> = (
  viewTags: readonly string[],
) => Promise<readonly TvcWalletFetchedPayload<TMeta>[]>;

export type TvcWalletSyncInput<TMeta> = {
  readonly connection: VerifiedConnection;
  readonly checkpoint: TvcWalletCheckpoint;
  readonly fetchByViewTags: TvcWalletTaggedFetch<TMeta>;
  /**
   * Tags the caller derived itself. The identity tag comes from the signing
   * public key, so no enclave is involved, and a deposit is published under it
   * -- a wallet funded only by deposits is fully discoverable from here.
   */
  readonly additionalViewTags?: readonly string[];
  /**
   * Ask the enclave for its recipient bootstrap tags. Default true.
   *
   * Those cover sites the identity tag does not, so a full scan wants them.
   * Turning it off is for a caller that already holds every tag it needs, or
   * one talking to a release that predates the operation.
   */
  readonly deriveEnclaveTags?: boolean;
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
  readonly payloads: readonly TvcWalletSyncPayload<TMeta>[];
  /** TVC's pinned chain/indexer view of outputs that remain spendable. */
  readonly spendableOutputs: readonly SpendableOutputV1[];
};

/** One readable output, however it became readable. */
export type TvcWalletSyncPayload<TMeta> = {
  /** Absent when the output was already in the clear. */
  readonly encrypted?: EncryptedPayloadV1;
  readonly decrypted: DecryptedPayloadV1;
  /** Carried through untouched from the fetch. */
  readonly meta: TMeta;
};

/**
 * Runs one sync: ask the enclave for the wallet's tags, fetch by them, decrypt
 * what came back.
 *
 * The tags are stable rather than a scanned range, so there is nothing to page
 * there. Decryption still pages because a wallet with real history will not
 * fit one batch; the final page also requests the authoritative spendable set.
 */
export async function syncTvcWallet<TMeta>(
  client: TvcWalletClient,
  input: TvcWalletSyncInput<TMeta>,
): Promise<TvcWalletSyncResult<TMeta>> {
  const derived =
    input.deriveEnclaveTags === false
      ? []
      : (await client.deriveViewTags(input.connection, { checkpoint: input.checkpoint }))
          .view_tags;
  // Duplicates would make the indexer repeat work and say nothing new.
  const viewTags = [...new Set([...derived, ...(input.additionalViewTags ?? [])])];
  if (viewTags.length === 0) throw new TvcError("InvalidCanonicalJson");

  const fetched = await input.fetchByViewTags(viewTags);
  const payloads: TvcWalletSyncPayload<TMeta>[] = [];

  // An output already in the clear needs no enclave, so it never leaves here.
  for (const entry of fetched) {
    if (entry.kind !== "plaintext") continue;
    payloads.push({
      decrypted: { type: "Plaintext", index: "0", plaintext: entry.plaintext },
      meta: entry.meta,
    });
  }

  const ciphertexts = fetched.filter((entry) => entry.kind === "ciphertext");
  let spendableOutputs: readonly SpendableOutputV1[] | undefined;
  for (let start = 0; start < ciphertexts.length; start += MAX_DECRYPT_PAYLOADS_PER_BATCH) {
    const batch = ciphertexts.slice(start, start + MAX_DECRYPT_PAYLOADS_PER_BATCH);
    const includeSpendableOutputs = start + batch.length === ciphertexts.length;
    const decrypted = await client.decryptUtxos(input.connection, {
      checkpoint: input.checkpoint,
      // Ciphertexts only. `meta` is the caller's and stays here.
      payloads: batch.map((entry) => entry.payload),
      includeSpendableOutputs,
    });
    if (includeSpendableOutputs) {
      spendableOutputs = decrypted.spendable_outputs ?? undefined;
    }
    // The operation layer already checks that each result's index matches its
    // position, so pairing by position here is sound.
    batch.forEach((entry, position) => {
      const result = decrypted.payloads[position];
      if (!result) throw new TvcError("ReleaseBindingMismatch");
      payloads.push({ encrypted: entry.payload, decrypted: result, meta: entry.meta });
    });
  }

  if (ciphertexts.length === 0) {
    const snapshot = await client.decryptUtxos(input.connection, {
      checkpoint: input.checkpoint,
      payloads: [],
      includeSpendableOutputs: true,
    });
    spendableOutputs = snapshot.spendable_outputs ?? undefined;
  }
  if (!spendableOutputs) throw new TvcError("ReleaseBindingMismatch");

  return Object.freeze({
    viewTags: Object.freeze(viewTags),
    payloads: Object.freeze(payloads),
    spendableOutputs: Object.freeze([...spendableOutputs]),
  });
}
