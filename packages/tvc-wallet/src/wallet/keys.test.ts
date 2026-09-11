import { ShieldedKeypair, initializePoseidon, type Bytes16, type Bytes32 } from "@heliuslabs/zolana";
import type { MergeInputs, ProverInputs } from "@heliuslabs/zolana/client";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type { VerifiedConnection } from "../client/connection.js";
import { TvcError } from "../protocol/error.js";
import { encodeLowerHex } from "../protocol/hex.js";
import type { SealedSeed } from "../protocol/types.js";
import type { ShieldedIdentity, TvcClient } from "./client.js";
import { TvcKeys } from "./keys.js";
import type { OperationOptions } from "./operations.js";

const encoders = vi.hoisted(() => ({
  proverRequestBody: vi.fn(),
  mergeProverRequestBody: vi.fn(),
}));
vi.mock("@heliuslabs/zolana/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@heliuslabs/zolana/client")>()),
  proverRequestBody: encoders.proverRequestBody,
  mergeProverRequestBody: encoders.mergeProverRequestBody,
}));

const connection = { verified: true } as unknown as VerifiedConnection;
const sealedSeed: SealedSeed = { sealedSeed: "11".repeat(64) };
const ZERO_PROOF = {
  proof: {
    ar: ["0x0", "0x0"],
    bs: [
      ["0x0", "0x0"],
      ["0x0", "0x0"],
    ],
    krs: ["0x0", "0x0"],
  },
};

function bytes(value: number, length = 32): Uint8Array {
  return new Uint8Array(length).fill(value);
}

function fixture() {
  const keypair = ShieldedKeypair.generate();
  const address = keypair.shieldedAddress();
  const identity: ShieldedIdentity = {
    solanaAddress: address.solanaAddress(),
    shieldedOwnerHash: encodeLowerHex(address.ownerHash()),
    shieldedNullifierPublicKey: encodeLowerHex(address.nullifierPublicKey),
    shieldedViewingPublicKey: encodeLowerHex(address.viewingPublicKey.toBytes()),
  };
  const client = {
    connectAndVerify: vi.fn(),
    bootstrap: vi.fn(),
    decrypt: vi.fn(async (_c: unknown, _k: unknown, items: readonly unknown[]) =>
      items.map((_, index) => encodeLowerHex(bytes(index + 1, 3))),
    ),
    derive: vi.fn(async (_c: unknown, _k: unknown, items: readonly unknown[]) =>
      items.map((_, index) => encodeLowerHex(bytes(index + 1))),
    ),
    transactionKeys: vi.fn(async (_c: unknown, _k: unknown, items: readonly unknown[]) =>
      items.map((_, index) => encodeLowerHex(bytes(index + 1))),
    ),
    prove: vi.fn(async () => ZERO_PROOF),
  } satisfies TvcClient;
  return {
    address,
    identity,
    client,
    keys: new TvcKeys({ client, connection, sealedSeed, identity }),
  };
}

describe("TvcKeys", () => {
  beforeAll(() => initializePoseidon());

  it("is the bootstrapped identity and holds its one viewing key", () => {
    const { address, keys } = fixture();
    expect(keys.address().toBytes()).toEqual(address.toBytes());
    expect(keys.viewingPublicKeys().map((key) => key.toBytes())).toEqual([
      address.viewingPublicKey.toBytes(),
    ]);
    const { identity, client } = fixture();
    expect(
      () =>
        new TvcKeys({
          client,
          connection,
          sealedSeed,
          identity: { ...identity, shieldedOwnerHash: "00".repeat(32) },
        }),
    ).toThrowError(/ShieldedIdentityChanged/);
  });

  it("puts every SDK request on the wire in the enclave's terms", async () => {
    const { address, keys, client } = fixture();
    const other = ShieldedKeypair.generate().viewingPublicKey();
    const plaintexts = await keys.decrypt([
      {
        ciphertext: bytes(9, 4),
        viewingPublicKey: address.viewingPublicKey,
        txViewingPublicKey: other,
        salt: bytes(5, 16) as Bytes16,
        slotIndex: 3,
        label: "transfer",
      },
      {
        ciphertext: bytes(8, 4),
        viewingPublicKey: address.viewingPublicKey,
        txViewingPublicKey: other,
        salt: bytes(5, 16) as Bytes16,
        slotIndex: 0,
        label: "ringDeposit",
      },
    ]);
    expect(client.decrypt).toHaveBeenCalledWith(connection, sealedSeed, [
      {
        ciphertext: "09090909",
        viewing_public_key: encodeLowerHex(address.viewingPublicKey.toBytes()),
        transaction_viewing_public_key: encodeLowerHex(other.toBytes()),
        salt: "05".repeat(16),
        slot_index: "3",
        label: "Transfer",
      },
      expect.objectContaining({ ciphertext: "08080808", slot_index: "0", label: "RingDeposit" }),
    ], {});
    expect(plaintexts).toEqual([bytes(1, 3), bytes(2, 3)]);

    const values = await keys.derive([
      { kind: "nullifier", utxoHash: bytes(1) as Bytes32, blinding: bytes(2) as Bytes32 },
      { kind: "mergeDummyNullifier", firstNullifier: bytes(3) as Bytes32, slotIndex: 7 },
      { kind: "mergeOutputBlinding", firstNullifier: bytes(3) as Bytes32 },
    ]);
    expect(client.derive).toHaveBeenCalledWith(connection, sealedSeed, [
      { kind: "Nullifier", utxo_hash: "01".repeat(32), blinding: "02".repeat(32) },
      { kind: "MergeDummyNullifier", first_nullifier: "03".repeat(32), slot_index: "7" },
      { kind: "MergeOutputBlinding", first_nullifier: "03".repeat(32) },
    ], {});
    expect(values).toEqual([bytes(1), bytes(2), bytes(3)]);

    const [txKey] = await keys.transactionKeys([
      { viewingPublicKey: address.viewingPublicKey, firstNullifier: bytes(4) as Bytes32 },
    ]);
    expect(client.transactionKeys).toHaveBeenCalledWith(connection, sealedSeed, [
      {
        viewing_public_key: encodeLowerHex(address.viewingPublicKey.toBytes()),
        first_nullifier: "04".repeat(32),
      },
    ], {});
    // The enclave answered with the secret 0x01..01; the key is built from it.
    expect(txKey?.secretBytes()).toEqual(bytes(1));
  });

  it("splits a long batch and keeps the answers in request order", async () => {
    const { keys, client } = fixture();
    const values = await keys.derive(
      Array.from({ length: 300 }, (_, index) => ({
        kind: "mergeOutputBlinding" as const,
        firstNullifier: bytes(index % 256) as Bytes32,
      })),
    );
    expect(client.derive).toHaveBeenCalledTimes(2);
    expect(client.derive.mock.calls[0]?.[2]).toHaveLength(256);
    expect(client.derive.mock.calls[1]?.[2]).toHaveLength(44);
    expect(values).toHaveLength(300);
    expect(values[256]).toEqual(bytes(1));
  });

  it("splits on the byte ceiling, preserves order, and propagates other failures", async () => {
    const { keys, client } = fixture();
    client.derive.mockImplementation(async (_c, _k, items) => {
      if (items.length > 2) throw new TvcError("RequestTooLarge");
      return items.map((item) => (item as { first_nullifier: string }).first_nullifier);
    });
    const requests = Array.from({ length: 7 }, (_, index) => ({
      kind: "mergeOutputBlinding" as const,
      firstNullifier: bytes(index) as Bytes32,
    }));
    expect(await keys.derive(requests)).toEqual(requests.map((item) => item.firstNullifier));
    expect(client.derive.mock.calls.map((call) => call[2].length)).toEqual([7, 3, 1, 2, 4, 2, 2]);

    for (const code of ["RequestTooLarge", "OperationRejected"] as const) {
      client.derive.mockClear();
      client.derive.mockRejectedValue(new TvcError(code));
      await expect(keys.derive(requests.slice(0, 1))).rejects.toMatchObject({ code });
      expect(client.derive).toHaveBeenCalledTimes(1);
    }
    client.derive.mockClear();
    await expect(keys.derive(requests)).rejects.toMatchObject({ code: "OperationRejected" });
    expect(client.derive).toHaveBeenCalledTimes(1);
  });

  it("sends the SDK's open prover body and parses the prover's answer", async () => {
    const { keys, client } = fixture();
    const body = { circuitType: "merge", inputs: [{}], userNullifierSecret: null };
    encoders.mergeProverRequestBody.mockReturnValueOnce(body);
    const inputs = { circuit: "merge" } as unknown as MergeInputs;
    const proof = await keys.proveMerge(inputs);
    expect(encoders.mergeProverRequestBody).toHaveBeenCalledWith(inputs);
    expect(client.prove).toHaveBeenCalledWith(connection, sealedSeed, body, {});
    expect(proof.a).toHaveLength(64);

    const transfer = { circuitType: "transfer-confidential", inputs: [{ nullifierSecret: null }] };
    encoders.proverRequestBody.mockReturnValueOnce(transfer);
    await keys.prove({ circuit: "transfer" } as unknown as ProverInputs);
    expect(client.prove).toHaveBeenLastCalledWith(connection, sealedSeed, transfer, {});
  });

  it("hands the SDK's request context to every batch of a key call", async () => {
    const { address, keys, client } = fixture();
    const controller = new AbortController();
    const context = { signal: controller.signal, timeoutMs: 1_000 };

    await keys.derive(
      Array.from({ length: 300 }, (_, index) => ({
        kind: "mergeOutputBlinding" as const,
        firstNullifier: bytes(index % 256) as Bytes32,
      })),
      context,
    );
    // One combined signal per SDK request: the deadline covers both batches.
    const [first, second] = client.derive.mock.calls.map(
      (call) => (call.at(3) as OperationOptions | undefined)?.signal,
    );
    expect(first).toBeInstanceOf(AbortSignal);
    expect(second).toBe(first);

    await keys.decrypt([], context);
    await keys.transactionKeys(
      [{ viewingPublicKey: address.viewingPublicKey, firstNullifier: bytes(4) as Bytes32 }],
      { signal: controller.signal },
    );
    expect(client.transactionKeys).toHaveBeenLastCalledWith(connection, sealedSeed, expect.anything(), {
      signal: controller.signal,
    });
  });

  it("hands the SDK's cancellation and deadline to the enclave call", async () => {
    const { keys, client } = fixture();
    encoders.proverRequestBody.mockReturnValue({ circuitType: "transfer-confidential", inputs: [] });
    const inputs = { circuit: "transfer" } as unknown as ProverInputs;

    const controller = new AbortController();
    await keys.prove(inputs, { signal: controller.signal });
    expect(client.prove).toHaveBeenLastCalledWith(connection, sealedSeed, expect.anything(), {
      signal: controller.signal,
    });

    await keys.prove(inputs, { signal: controller.signal, timeoutMs: 1_000 });
    const options = client.prove.mock.lastCall?.at(3) as OperationOptions | undefined;
    expect(options?.signal).toBeInstanceOf(AbortSignal);
    expect(options?.signal?.aborted).toBe(false);
    controller.abort();
    expect(options?.signal?.aborted).toBe(true);
  });
});
