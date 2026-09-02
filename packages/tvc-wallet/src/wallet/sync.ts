import type { Address, Bytes32, ShieldedAddress, Wallet } from "@heliuslabs/zolana";
import { deserializeWallet, serializeWallet } from "@heliuslabs/zolana";
import type { IndexerReader, IndexerRpcConfig } from "@heliuslabs/zolana/client";
import {
  EncryptedScheme,
  decodeOutputData,
  decodeProofless,
  type AssetRegistry,
  type IndexedShieldedTransaction,
  type SerializedWalletState,
} from "@heliuslabs/zolana/transaction";

import type { VerifiedConnection } from "../client/connection.js";
import { encodeDecimalU64 } from "../protocol/decimal.js";
import { TvcError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type { Checkpoint, DecryptPayload, SplAsset } from "../protocol/types.js";
import type { TvcClient } from "./client.js";
import { MAX_DECRYPT_PAYLOADS_PER_BATCH } from "./operations.js";

const P256_PUBLIC_KEY_LENGTH = 33;
const PAGE_LIMIT = 100;
const MAX_PAGES = 1_000;

export type SyncInput = {
  readonly client: TvcClient;
  readonly connection: VerifiedConnection;
  readonly checkpoint: Checkpoint;
  /** The identity `bootstrap` returned; see `shieldedAddressOf`. */
  readonly identity: ShieldedAddress;
  /** Reads the indexer, normally the Zolana SDK client. */
  readonly indexer: Pick<
    IndexerReader,
    "getShieldedTransactionsByTags" | "getShieldedTransactionsByNullifiers"
  >;
  /** Every SPL asset the wallet may hold. SOL is implied. */
  readonly registry: AssetRegistry;
  /** The wallet from the previous sync, when there was one. */
  readonly wallet?: Wallet;
  /** Slot the indexer must have reached; omitted takes what it has. */
  readonly requireSlot?: bigint;
  readonly indexerConfig?: IndexerRpcConfig;
};

type Serialized = SerializedWalletState["utxos"][number];

/** The SPL entries a request carries; the enclave resolves compact ids with them. */
export function splAssets(registry: AssetRegistry): readonly SplAsset[] {
  return registry
    .entries()
    .filter(([assetId]) => assetId !== 1n)
    .map(([assetId, mint]) => ({ mint, asset_id: encodeDecimalU64(assetId) }));
}

/**
 * Brings a Zolana `Wallet` up to date through the enclave: fetch the outputs
 * published under the wallet's tags, have the enclave open them, adopt the ones
 * whose commitment matches the indexed output, and mark spent whatever the
 * indexer has seen a nullifier for.
 */
export async function syncWallet(input: SyncInput): Promise<Wallet> {
  const config: IndexerRpcConfig = {
    ...(input.indexerConfig ?? {}),
    poll: input.indexerConfig?.poll ?? { numRetries: 5, delayMs: 500n, maxDelayMs: 2_000n },
    ...(input.requireSlot === undefined ? {} : { requireSlot: input.requireSlot }),
  };
  const tags = [
    ...(await input.client.viewTags(input.connection, input.checkpoint)).map(decodeLowerHex),
    input.identity.confidentialViewTag(),
  ] as Bytes32[];
  const transactions = await byTags(input.indexer, tags, config);

  const previous = input.wallet ? snapshot(input.wallet) : undefined;
  const utxos = new Map<string, Serialized>();
  for (const utxo of previous?.utxos ?? []) utxos.set(utxo.outputContext.hash, utxo);

  const ownerHash = encodeLowerHex(input.identity.ownerHash());
  const candidates = outputs(transactions, ownerHash).filter(
    (candidate) => !utxos.has(toBase64(candidate.commitment)),
  );
  const assets = splAssets(input.registry);
  for (let start = 0; start < candidates.length; start += MAX_DECRYPT_PAYLOADS_PER_BATCH) {
    const batch = candidates.slice(start, start + MAX_DECRYPT_PAYLOADS_PER_BATCH);
    const opened = await input.client.decrypt(input.connection, input.checkpoint, {
      payloads: batch.map((candidate) => candidate.payload),
      assets,
    });
    opened.forEach((result, position) => {
      const candidate = batch[position];
      if (!candidate || result.type !== "Utxo") return;
      // The enclave cannot tell whose ciphertext it opened; the indexed
      // commitment can.
      if (result.commitment !== encodeLowerHex(candidate.commitment)) return;
      utxos.set(toBase64(candidate.commitment), {
        owner: toBase64(input.identity.signingPublicKey.toBytes()),
        asset: result.asset as Address,
        amount: result.amount,
        blinding: toBase64(decodeLowerHex(result.blinding)),
        data: [],
        ...(result.ring_program_id === null ? {} : { ringProgramId: result.ring_program_id as Address }),
        outputContext: {
          hash: toBase64(candidate.commitment),
          tree: candidate.tree,
          leafIndex: candidate.leafIndex.toString(),
        },
        nullifier: toBase64(decodeLowerHex(result.nullifier)),
        spent: false,
      });
    });
  }

  const unspent = [...utxos.values()].filter((utxo) => !utxo.spent);
  const spent = await spentNullifiers(
    input.indexer,
    unspent.map((utxo) => fromBase64(utxo.nullifier) as Bytes32),
    config,
  );
  for (const utxo of unspent) {
    if (spent.has(encodeLowerHex(fromBase64(utxo.nullifier)))) {
      utxos.set(utxo.outputContext.hash, { ...utxo, spent: true });
    }
  }

  const state: SerializedWalletState = {
    version: 3,
    identity: {
      signingPublicKey: toBase64(input.identity.signingPublicKey.toBytes()),
      nullifierPublicKey: toBase64(input.identity.nullifierPublicKey),
      viewingPublicKey: toBase64(input.identity.viewingPublicKey.toBytes()),
    },
    assets: assets.map((asset) => ({ assetId: asset.asset_id, mint: asset.mint as Address })),
    viewingKeyHistory: previous?.viewingKeyHistory ?? [
      { viewingPublicKey: toBase64(input.identity.viewingPublicKey.toBytes()), createdAt: "0" },
    ],
    utxos: [...utxos.values()],
    transactions: previous?.transactions ?? [],
    nullifiers: previous?.nullifiers ?? [],
    lastSynced: Date.now().toString(),
    syncCursors: { transactions: [], proofless: [], nullifiers: [] },
    reservations: [],
  };
  return deserializeWallet(JSON.stringify(state));
}

type Candidate = {
  readonly payload: DecryptPayload;
  readonly commitment: Bytes32;
  readonly tree: Address;
  readonly leafIndex: bigint;
};

/** The outputs the enclave can open on this rail, with what to open them with. */
function outputs(
  transactions: readonly IndexedShieldedTransaction[],
  ownerHash: string,
): readonly Candidate[] {
  const candidates: Candidate[] = [];
  for (const transaction of transactions) {
    transaction.outputSlots.forEach((slot, slotIndex) => {
      let frame: ReturnType<typeof decodeOutputData>;
      try {
        frame = decodeOutputData(slot.payload);
      } catch {
        return;
      }
      const context = {
        commitment: slot.outputContext.hash,
        tree: slot.outputContext.tree,
        leafIndex: slot.outputContext.leafIndex,
      };
      if (frame.scheme === EncryptedScheme.proofless) {
        let output: ReturnType<typeof decodeProofless>;
        try {
          output = decodeProofless(frame.body);
        } catch {
          return;
        }
        if (
          encodeLowerHex(output.owner) !== ownerHash ||
          output.ringProgramId !== undefined ||
          output.dataHash !== undefined ||
          output.ringDataHash !== undefined
        ) {
          return;
        }
        candidates.push({
          ...context,
          payload: {
            type: "Plain",
            asset: output.asset,
            amount: encodeDecimalU64(output.amount),
            blinding: encodeLowerHex(output.blinding),
          },
        });
        return;
      }
      if (
        frame.scheme !== EncryptedScheme.confidential ||
        transaction.txViewingPublicKey === undefined ||
        transaction.salt === undefined ||
        frame.body.length <= P256_PUBLIC_KEY_LENGTH
      ) {
        return;
      }
      candidates.push({
        ...context,
        payload: {
          type: "Encrypted",
          // The body leads with the recipient-facing P-256 key the enclave
          // does not need; the transaction-level key is what decrypts.
          ciphertext: encodeLowerHex(frame.body.subarray(P256_PUBLIC_KEY_LENGTH)),
          transaction_viewing_public_key: encodeLowerHex(transaction.txViewingPublicKey.toBytes()),
          salt: encodeLowerHex(transaction.salt),
          slot_index: String(slotIndex),
        },
      });
    });
  }
  return candidates;
}

async function byTags(
  indexer: SyncInput["indexer"],
  tags: readonly Bytes32[],
  config: IndexerRpcConfig,
): Promise<readonly IndexedShieldedTransaction[]> {
  const transactions = new Map<string, IndexedShieldedTransaction>();
  let cursor: Uint8Array | undefined;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const response = await indexer.getShieldedTransactionsByTags(
      { tags, limit: PAGE_LIMIT, ...(cursor === undefined ? {} : { cursor }) },
      config,
    );
    for (const transaction of response.transactions) {
      transactions.set(transaction.txSignature, transaction);
    }
    if (response.nextCursor === undefined) return [...transactions.values()];
    cursor = response.nextCursor;
  }
  throw new TvcError("IndexerPaginationLimitExceeded");
}

async function spentNullifiers(
  indexer: SyncInput["indexer"],
  nullifiers: readonly Bytes32[],
  config: IndexerRpcConfig,
): Promise<ReadonlySet<string>> {
  const spent = new Set<string>();
  for (let start = 0; start < nullifiers.length; start += PAGE_LIMIT) {
    const chunk = nullifiers.slice(start, start + PAGE_LIMIT);
    let cursor: Uint8Array | undefined;
    for (let page = 0; page < MAX_PAGES; page += 1) {
      const response = await indexer.getShieldedTransactionsByNullifiers(
        { nullifiers: chunk, limit: PAGE_LIMIT, ...(cursor === undefined ? {} : { cursor }) },
        config,
      );
      for (const transaction of response.transactions) {
        for (const nullifier of transaction.nullifiers) spent.add(encodeLowerHex(nullifier));
      }
      if (response.nextCursor === undefined) break;
      cursor = response.nextCursor;
    }
  }
  return spent;
}

function snapshot(wallet: Wallet): SerializedWalletState {
  return JSON.parse(serializeWallet(wallet)) as SerializedWalletState;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}
