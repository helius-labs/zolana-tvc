import {
  ShieldedKeypair,
  initializePoseidon,
  type Address,
  type Bytes32,
  type IndexerPollConfig,
} from "@heliuslabs/zolana";
import { AssetRegistry, type IndexedShieldedTransaction } from "@heliuslabs/zolana/transaction";
import { describe, expect, it, vi } from "vitest";

import type { VerifiedConnection } from "../client/connection.js";
import { encodeLowerHex } from "../protocol/hex.js";
import type { DecryptPayload, DecryptedPayload } from "../protocol/types.js";
import type { TvcClient } from "./client.js";
import { syncWallet } from "./sync.js";

const SOL = "11111111111111111111111111111111" as Address;
const TREE = "trEEbaNobcTESNmtsPBj3FX27q5sDCQePV2kb12FYho" as Address;
await initializePoseidon();
const identity = ShieldedKeypair.generate().shieldedAddress();
const fill = (byte: number, length = 32): Bytes32 => new Uint8Array(length).fill(byte) as Bytes32;

/** `[encoding u8][u32 LE length][scheme u8][body]`, as the indexer publishes an output. */
function frame(encoding: number, scheme: number, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(5 + 1 + body.length);
  out[0] = encoding;
  new DataView(out.buffer).setUint32(1, body.length + 1, true);
  out[5] = scheme;
  out.set(body, 6);
  return out;
}

/** A proofless (deposit) output body: owner hash, blinding, mint, amount, then six absent options. */
function proofless(amount: bigint, blinding: Bytes32): Uint8Array {
  const out = new Uint8Array(32 + 32 + 32 + 8 + 6);
  out.set(identity.ownerHash(), 0);
  out.set(blinding, 32);
  new DataView(out.buffer).setBigUint64(96, amount, true);
  return out;
}

const txViewingKey = ShieldedKeypair.generate().shieldedAddress().viewingPublicKey;
const transactions: IndexedShieldedTransaction[] = [
  {
    slot: 10n,
    txSignature: "deposit" as never,
    outputSlots: [
      {
        viewTag: fill(1),
        outputContext: { hash: fill(0xa1), tree: TREE, leafIndex: 0n },
        payload: frame(0, 0, proofless(5n, fill(0x11))),
      },
    ],
    messages: [],
    nullifiers: [],
    proofless: true,
  },
  {
    slot: 11n,
    txSignature: "transfer" as never,
    txViewingPublicKey: txViewingKey,
    salt: fill(0x22, 16) as never,
    outputSlots: [
      {
        viewTag: fill(1),
        outputContext: { hash: fill(0xa2), tree: TREE, leafIndex: 1n },
        payload: frame(1, 3, new Uint8Array([...txViewingKey.toBytes(), 9, 9, 9, 9])),
      },
      {
        viewTag: fill(2),
        outputContext: { hash: fill(0xa3), tree: TREE, leafIndex: 2n },
        payload: frame(1, 3, new Uint8Array([...txViewingKey.toBytes(), 8, 8, 8, 8])),
      },
    ],
    messages: [],
    nullifiers: [],
    proofless: false,
  },
];

function client(decrypt: (payloads: readonly DecryptPayload[]) => readonly DecryptedPayload[]): TvcClient {
  return {
    viewTags: vi.fn().mockResolvedValue([encodeLowerHex(fill(0x77))]),
    decrypt: vi.fn(async (_connection, _checkpoint, input) => decrypt(input.payloads)),
  } as unknown as TvcClient;
}

const indexer = {
  getShieldedTransactionsByTags: vi.fn(async (request: { tags: readonly Bytes32[] }) => {
    expect(request.tags.map(encodeLowerHex)).toEqual([
      encodeLowerHex(fill(0x77)),
      encodeLowerHex(identity.confidentialViewTag()),
    ]);
    return { context: { slot: 11n, blockTime: 0n }, transactions };
  }),
  getShieldedTransactionsByNullifiers: vi.fn(async (request: { nullifiers: readonly Bytes32[] }) => ({
    context: { slot: 11n, blockTime: 0n },
    transactions: request.nullifiers.some((nullifier) => nullifier[0] === 0xb1)
      ? [{ ...transactions[1]!, nullifiers: [fill(0xb1)] }]
      : [],
  })),
};

describe("syncWallet", () => {
  it("adopts outputs whose enclave commitment matches the index and marks spent ones", async () => {
    const opened: DecryptedPayload[] = [
      // The deposit, opened from its plain opening.
      {
        type: "Utxo",
        index: "0",
        asset: SOL,
        amount: "5",
        blinding: encodeLowerHex(fill(0x11)),
        ring_program_id: null,
        commitment: encodeLowerHex(fill(0xa1)),
        nullifier: encodeLowerHex(fill(0xb1)),
      },
      // Our confidential output.
      {
        type: "Utxo",
        index: "1",
        asset: SOL,
        amount: "3",
        blinding: encodeLowerHex(fill(0x12)),
        ring_program_id: null,
        commitment: encodeLowerHex(fill(0xa2)),
        nullifier: encodeLowerHex(fill(0xb2)),
      },
      // Someone else's output that happened to decode: the commitment disagrees.
      {
        type: "Utxo",
        index: "2",
        asset: SOL,
        amount: "99",
        blinding: encodeLowerHex(fill(0x13)),
        ring_program_id: null,
        commitment: encodeLowerHex(fill(0xee)),
        nullifier: encodeLowerHex(fill(0xb3)),
      },
    ];
    const tvc = client((payloads) => {
      expect(payloads).toEqual([
        { type: "Plain", asset: SOL, amount: "5", blinding: encodeLowerHex(fill(0x11)) },
        {
          type: "Encrypted",
          ciphertext: "09090909",
          transaction_viewing_public_key: encodeLowerHex(txViewingKey.toBytes()),
          salt: encodeLowerHex(fill(0x22, 16)),
          slot_index: "0",
        },
        {
          type: "Encrypted",
          ciphertext: "08080808",
          transaction_viewing_public_key: encodeLowerHex(txViewingKey.toBytes()),
          salt: encodeLowerHex(fill(0x22, 16)),
          slot_index: "1",
        },
      ]);
      return opened;
    });
    const poll: IndexerPollConfig = { numRetries: 0, delayMs: 0n, maxDelayMs: 0n };
    const wallet = await syncWallet({
      client: tvc,
      connection: {} as VerifiedConnection,
      checkpoint: { sealedWalletState: "11" },
      identity,
      indexer,
      registry: new AssetRegistry(),
      indexerConfig: { poll },
    });
    const utxos = wallet.utxos();
    expect(utxos.map((entry) => [entry.utxo.amount, entry.spent])).toEqual([
      [5n, true],
      [3n, false],
    ]);
    expect(wallet.balance(SOL).amount).toBe(3n);

    // A second sync keeps what it adopted and re-offers only what it did not.
    const again = client((payloads) => {
      expect(payloads.map((payload) => payload.type)).toEqual(["Encrypted"]);
      return [{ type: "Unreadable", index: "0" }];
    });
    const resynced = await syncWallet({
      client: again,
      connection: {} as VerifiedConnection,
      checkpoint: { sealedWalletState: "11" },
      identity,
      indexer,
      registry: new AssetRegistry(),
      wallet,
      indexerConfig: { poll },
    });
    expect(resynced.balance(SOL).amount).toBe(3n);
  });
});
