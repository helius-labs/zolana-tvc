import { ShieldedKeypair, initializePoseidon, type Bytes16, type Bytes32 } from "@heliuslabs/zolana";
import type { MergeInputs, ProverInputs } from "@heliuslabs/zolana/client";
import { gcm } from "@noble/ciphers/aes";
import { beforeAll, describe, expect, it, vi } from "vitest";

import type { VerifiedConnection } from "../client/connection.js";
import type { TvcTransport } from "../client/transport.js";
import { DEVNET_PROVER_POLICY } from "../protocol/prover-policy.js";
import { TvcError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type { ProverSealing, SealedProverRequest, SealedSeed } from "../protocol/types.js";
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

const PROVER_URL = "https://gatekeeper.test/v1/zolana?api-key=k";
const RESPONSE_KEY = "33".repeat(32);

function sealedFor(target: string): SealedProverRequest {
  return { target, enc: "11".repeat(32), ciphertext: "0102", response_key: RESPONSE_KEY };
}

/** An answer as the attested prover seals it under the response key. */
function sealedAnswer(status: number, body: unknown): Uint8Array<ArrayBuffer> {
  const plaintext = new Uint8Array([status >> 8, status & 0xff, ...new TextEncoder().encode(JSON.stringify(body))]);
  const nonce = bytes(7, 12);
  return new Uint8Array([...nonce, ...gcm(decodeLowerHex(RESPONSE_KEY), nonce).encrypt(plaintext)]);
}

/**
 * The prover side of a proof: attestation answers, then the sealed answers in
 * `answers` order. Records every request it sees.
 */
function proverTransport(answers: readonly Response[] = []) {
  const queue = [...answers];
  const seen: { method: string; url: URL; headers: Headers }[] = [];
  const transport: TvcTransport = {
    fetch: vi.fn(async (url: URL, init?: RequestInit) => {
      seen.push({ method: init?.method ?? "GET", url, headers: new Headers(init?.headers) });
      if (url.pathname.endsWith("/tee/v1/attestation")) {
        return Response.json({ platform: "aws-nitro", hpke_public_key: "44".repeat(32) });
      }
      return (
        queue.shift() ??
        new Response(sealedAnswer(200, ZERO_PROOF), { headers: { "Zolana-Tee": "v1" } })
      );
    }),
  };
  return { transport, seen };
}

function fixture(answers: readonly Response[] = []) {
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
    prove: vi.fn(async (_c: unknown, _k: unknown, _r: unknown, prover: ProverSealing) =>
      sealedFor(prover.target),
    ),
  } satisfies TvcClient;
  const { transport, seen } = proverTransport(answers);
  return {
    address,
    identity,
    client,
    seen,
    keys: new TvcKeys({
      client,
      connection,
      sealedSeed,
      identity,
      prover: { url: PROVER_URL, policy: DEVNET_PROVER_POLICY, transport },
    }),
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
          prover: { url: PROVER_URL, policy: DEVNET_PROVER_POLICY },
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
      { kind: "mergePrivateTxBlinding", firstNullifier: bytes(3) as Bytes32 },
    ]);
    expect(client.derive).toHaveBeenCalledWith(connection, sealedSeed, [
      { kind: "Nullifier", utxo_hash: "01".repeat(32), blinding: "02".repeat(32) },
      { kind: "MergeDummyNullifier", first_nullifier: "03".repeat(32), slot_index: "7" },
      { kind: "MergeOutputBlinding", first_nullifier: "03".repeat(32) },
      { kind: "MergePrivateTxBlinding", first_nullifier: "03".repeat(32) },
    ], {});
    expect(values).toEqual([bytes(1), bytes(2), bytes(3), bytes(4)]);

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

  it("seals the SDK's open prover body to the attested prover and opens its answer", async () => {
    const { keys, client, seen } = fixture();
    const body = { circuitType: "merge", inputs: [{}], userNullifierSecret: null };
    encoders.mergeProverRequestBody.mockReturnValueOnce(body);
    const inputs = { circuit: "merge" } as unknown as MergeInputs;
    const proof = await keys.proveMerge(inputs);
    expect(encoders.mergeProverRequestBody).toHaveBeenCalledWith(inputs);
    expect(client.prove).toHaveBeenCalledWith(
      connection,
      sealedSeed,
      body,
      {
        target: "/v1/zolana/prove/merge_1_1",
        nonce: expect.stringMatching(/^[0-9a-f]{64}$/),
        attestation: { platform: "aws-nitro", hpke_public_key: "44".repeat(32) },
        policy: DEVNET_PROVER_POLICY,
      },
      {},
    );
    expect(proof.a).toHaveLength(64);

    // The attestation carries the nonce the enclave checks; the sealed request
    // goes to its target with the base URL's API key and the TEE headers.
    const [attest, submit] = seen;
    const nonce = client.prove.mock.lastCall?.[3].nonce;
    expect(attest?.url.pathname).toBe("/v1/zolana/tee/v1/attestation");
    expect(attest?.url.searchParams.get("nonce")).toBe(nonce);
    expect(attest?.url.searchParams.get("api-key")).toBe("k");
    expect(submit?.method).toBe("POST");
    expect(`${submit?.url.pathname}${submit?.url.search}`).toBe("/v1/zolana/prove/merge_1_1?api-key=k");
    expect(submit?.headers.get("Zolana-Tee")).toBe("v1");
    expect(submit?.headers.get("Zolana-Tee-Enc")).toBe("11".repeat(32));

    const transfer = {
      circuitType: "transfer-confidential",
      inputs: [{ nullifierSecret: null }],
      outputs: [{}, {}],
    };
    encoders.proverRequestBody.mockReturnValueOnce(transfer);
    await keys.prove({ circuit: "transfer" } as unknown as ProverInputs);
    expect(client.prove).toHaveBeenLastCalledWith(
      connection,
      sealedSeed,
      transfer,
      expect.objectContaining({ target: "/v1/zolana/prove/transfer_confidential_1_2" }),
      {},
    );
  });

  it("attests and seals again once when the prover lost its key", async () => {
    const lost = () => Response.json({ code: "tee_decryption_failed" }, { status: 400 });
    const { keys, client, seen } = fixture([lost()]);
    encoders.mergeProverRequestBody.mockReturnValue({
      circuitType: "merge",
      inputs: [{}],
      userNullifierSecret: null,
    });
    const proof = await keys.proveMerge({ circuit: "merge" } as unknown as MergeInputs);
    expect(proof.a).toHaveLength(64);
    expect(client.prove).toHaveBeenCalledTimes(2);
    expect(seen.filter(({ url }) => url.pathname.endsWith("/attestation"))).toHaveLength(2);

    const twice = fixture([lost(), lost()]);
    await expect(
      twice.keys.proveMerge({ circuit: "merge" } as unknown as MergeInputs),
    ).rejects.toMatchObject({ code: "ProverKeyLost" });
  });

  it("refuses an unencrypted success and surfaces the prover's refusal", async () => {
    encoders.mergeProverRequestBody.mockReturnValue({
      circuitType: "merge",
      inputs: [{}],
      userNullifierSecret: null,
    });
    const inputs = { circuit: "merge" } as unknown as MergeInputs;
    const plain = fixture([Response.json(ZERO_PROOF)]);
    await expect(plain.keys.proveMerge(inputs)).rejects.toMatchObject({
      code: "ProverAnswerUnencrypted",
    });
    const refused = fixture([
      new Response(sealedAnswer(422, { code: "bad_witness" }), { headers: { "Zolana-Tee": "v1" } }),
    ]);
    await expect(refused.keys.proveMerge(inputs)).rejects.toMatchObject({ code: "ProverRefused" });
    const tampered = sealedAnswer(200, ZERO_PROOF);
    tampered[20] = (tampered[20] ?? 0) ^ 1;
    const forged = fixture([new Response(tampered, { headers: { "Zolana-Tee": "v1" } })]);
    await expect(forged.keys.proveMerge(inputs)).rejects.toMatchObject({
      code: "ProverAnswerInvalid",
    });
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
    encoders.proverRequestBody.mockReturnValue({
      circuitType: "transfer-confidential",
      inputs: [{ nullifierSecret: null }],
      outputs: [{}],
    });
    const inputs = { circuit: "transfer" } as unknown as ProverInputs;

    const controller = new AbortController();
    await keys.prove(inputs, { signal: controller.signal });
    expect(client.prove).toHaveBeenLastCalledWith(
      connection,
      sealedSeed,
      expect.anything(),
      expect.anything(),
      { signal: controller.signal },
    );

    await keys.prove(inputs, { signal: controller.signal, timeoutMs: 1_000 });
    const options = client.prove.mock.lastCall?.at(4) as OperationOptions | undefined;
    expect(options?.signal).toBeInstanceOf(AbortSignal);
    expect(options?.signal?.aborted).toBe(false);
    controller.abort();
    expect(options?.signal?.aborted).toBe(true);
  });
});
