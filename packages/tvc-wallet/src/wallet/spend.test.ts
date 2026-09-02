import {
  ShieldedKeypair,
  deserializeWallet,
  initializePoseidon,
  type Address,
  type Bytes32,
  type Wallet,
} from "@heliuslabs/zolana";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type { VerifiedConnection } from "../client/connection.js";
import { encodeLowerHex } from "../protocol/hex.js";
import type { TvcClient } from "./client.js";
import { selectInputs, spend } from "./spend.js";

const SOL = "11111111111111111111111111111111" as Address;
const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" as Address;
const TREE = "trEEbaNobcTESNmtsPBj3FX27q5sDCQePV2kb12FYho" as Address;

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");
const keypair = ShieldedKeypair.generate();

type Note = { asset: Address; amount: bigint; spent?: boolean; tag: number; tree?: Address };

function wallet(notes: readonly Note[]): Wallet {
  const identity = keypair.shieldedAddress();
  return deserializeWallet(
    JSON.stringify({
      version: 3,
      identity: {
        signingPublicKey: b64(identity.signingPublicKey.toBytes()),
        nullifierPublicKey: b64(identity.nullifierPublicKey),
        viewingPublicKey: b64(identity.viewingPublicKey.toBytes()),
      },
      assets: [{ assetId: "2", mint: USDC }],
      viewingKeyHistory: [{ viewingPublicKey: b64(identity.viewingPublicKey.toBytes()), createdAt: "0" }],
      utxos: notes.map((note) => ({
        owner: b64(identity.signingPublicKey.toBytes()),
        asset: note.asset,
        amount: note.amount.toString(),
        blinding: b64(new Uint8Array(32).fill(note.tag)),
        data: [],
        outputContext: {
          hash: b64(new Uint8Array(32).fill(note.tag + 100)),
          tree: note.tree ?? TREE,
          leafIndex: String(note.tag),
        },
        nullifier: b64(new Uint8Array(32).fill(note.tag + 200)),
        spent: note.spent ?? false,
      })),
      transactions: [],
      nullifiers: [],
      lastSynced: "0",
      syncCursors: { transactions: [], proofless: [], nullifiers: [] },
      reservations: [],
    }),
  );
}

beforeAll(() => initializePoseidon());

describe("input selection", () => {
  it("takes the largest unspent notes of the asset until the amount is covered", () => {
    const selected = selectInputs(
      wallet([
        { asset: SOL, amount: 3n, tag: 1 },
        { asset: SOL, amount: 10n, tag: 2 },
        { asset: SOL, amount: 7n, spent: true, tag: 3 },
        { asset: USDC, amount: 50n, tag: 4 },
        { asset: SOL, amount: 5n, tag: 5 },
      ]),
      SOL,
      12n,
    );
    expect(selected.map((entry) => entry.utxo.amount)).toEqual([10n, 5n]);
  });

  it("distinguishes a balance that needs too many inputs from one that is short", () => {
    const dust = Array.from({ length: 6 }, (_, tag) => ({ asset: SOL, amount: 1n, tag }));
    expect(() => selectInputs(wallet(dust), SOL, 6n)).toThrowError("TooManySpendInputs");
    expect(() => selectInputs(wallet(dust), SOL, 7n)).toThrowError("InsufficientBalance");
    expect(() =>
      selectInputs(wallet([{ asset: SOL, amount: 1n, tag: 1 }, { asset: SOL, amount: 1n, tag: 2, tree: SOL }]), SOL, 1n),
    ).toThrowError("MultipleInputTrees");
  });
});

describe("spend", () => {
  it("sends the selected openings, the action, and the registry to the enclave", async () => {
    const client = {
      spend: vi.fn().mockResolvedValue({
        type: "Spend",
        signed_transaction: "0102",
        signature: "sig",
        turnkey_activity_id: "a",
        turnkey_app_proofs: [],
      }),
    } as unknown as TvcClient;
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const spent = await spend({
      client,
      connection: {} as VerifiedConnection,
      checkpoint: { sealedWalletState: "11" },
      wallet: wallet([
        { asset: USDC, amount: 40n, tag: 1 },
        { asset: USDC, amount: 60n, tag: 2 },
      ]),
      action: { kind: "transfer", recipient, asset: USDC, amount: 70n },
    });
    expect(spent.transaction).toEqual(Uint8Array.of(1, 2));
    expect(spent.inputs.map((entry) => entry.utxo.amount)).toEqual([60n, 40n]);
    expect(client.spend).toHaveBeenCalledWith({}, { sealedWalletState: "11" }, {
      tree: TREE,
      inputs: [
        { asset: USDC, amount: "60", blinding: "02".repeat(32) },
        { asset: USDC, amount: "40", blinding: "01".repeat(32) },
      ],
      action: {
        type: "Transfer",
        recipient: encodeLowerHex(recipient.toBytes()),
        asset: USDC,
        amount: "70",
      },
      assets: [{ mint: USDC, asset_id: "2" }],
    });
  });

  it("spends exactly the named inputs", async () => {
    const client = {
      spend: vi.fn().mockResolvedValue({
        type: "Spend",
        signed_transaction: "",
        signature: "sig",
        turnkey_activity_id: "a",
        turnkey_app_proofs: [],
      }),
    } as unknown as TvcClient;
    const spent = await spend({
      client,
      connection: {} as VerifiedConnection,
      checkpoint: { sealedWalletState: "11" },
      wallet: wallet([
        { asset: SOL, amount: 1n, tag: 1 },
        { asset: SOL, amount: 9n, tag: 2 },
      ]),
      action: { kind: "withdrawal", recipient: TREE, asset: SOL, amount: 1n },
      inputs: [new Uint8Array(32).fill(101) as Bytes32],
    });
    expect(spent.inputs.map((entry) => entry.utxo.amount)).toEqual([1n]);
  });
});
