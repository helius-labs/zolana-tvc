import { describe, expect, it, vi } from "vitest";

import type { TvcTransport } from "../client/transport.js";
import { DEVNET_PROVER_POLICY } from "../protocol/prover-policy.js";
import { decodeLowerHex } from "../protocol/hex.js";
import {
  attestationReuseMs,
  decryptProverAnswer,
  fetchAttestation,
  isProverTarget,
  provingKeyName,
  sealingFor,
} from "./prover.js";

/** zolana `prover/tee/testdata/vectors.json`: an answer the Go prover sealed. */
const VECTOR = {
  responseKey: "6cdd0d870824d20a0d49e35e4fd5efc7aa1d1d02cde58c455d34d45fa3fcf93e",
  encryptedResponse:
    "458aeb3721728301508e11bda7408dfe9cf0fef050cd35727f3bb94ed23fb45538256f50928b6e8c4018acdf",
  status: 200,
  body: '{"proof":"ok"}',
};

const transfer = (circuit: string, inputs: number, outputs: number) => ({
  circuitType: circuit,
  inputs: Array.from({ length: inputs }, () => ({})),
  outputs: Array.from({ length: outputs }, () => ({})),
});
const merge = (circuit: string, inputs: number) => ({
  circuitType: circuit,
  inputs: Array.from({ length: inputs }, () => ({})),
});

describe("prover answers", () => {
  it("open the wire contract's vector", () => {
    const { status, body } = decryptProverAnswer(
      decodeLowerHex(VECTOR.responseKey),
      decodeLowerHex(VECTOR.encryptedResponse),
    );
    expect(status).toBe(VECTOR.status);
    expect(new TextDecoder().decode(body)).toBe(VECTOR.body);
  });

  it("refuse another key, a tampered byte, or a truncated answer", () => {
    const encrypted = decodeLowerHex(VECTOR.encryptedResponse);
    const tampered = encrypted.slice();
    tampered[14] = (tampered[14] ?? 0) ^ 1;
    for (const [key, bytes] of [
      [decodeLowerHex("00".repeat(32)), encrypted],
      [decodeLowerHex(VECTOR.responseKey), tampered],
      [decodeLowerHex(VECTOR.responseKey), encrypted.subarray(0, 20)],
    ] as const) {
      expect(() => decryptProverAnswer(key, bytes)).toThrowError("ProverAnswerInvalid");
    }
  });
});

describe("proving key routes", () => {
  it("name the key the enclave names", () => {
    for (const [request, key] of [
      [transfer("transfer-confidential", 2, 2), "transfer_confidential_2_2"],
      [transfer("transfer-confidential", 12, 16), "transfer_confidential_12_16"],
      [transfer("transfer-ring", 1, 2), "transfer_ring_1_2"],
      [merge("merge", 8), "merge_8_1"],
      [merge("merge-ring", 54), "merge_ring_54_1"],
    ] as const) {
      expect(provingKeyName(request)).toBe(key);
    }
    for (const request of [
      transfer("transfer-ring-authority", 1, 2),
      { circuitType: "toString", inputs: [{}], outputs: [{}] },
      transfer("transfer-confidential", 0, 2),
      transfer("transfer-confidential", 2, 0),
      merge("merge", 55),
    ]) {
      expect(() => provingKeyName(request)).toThrowError("InvalidProverRequest");
    }
  });

  it("accept only the key's route under plain segments", () => {
    for (const target of ["/prove/merge_8_1", "/v1/zolana/prove/merge_8_1"]) {
      expect(isProverTarget(target, "merge_8_1")).toBe(true);
    }
    for (const target of [
      "/v1/zolana/prove/merge_24_1",
      "/v1/zolana/prove/merge_8_1?jobId=1",
      "/v1/zolana/prove/merge_8_1/",
      "/v1//prove/merge_8_1",
      "/v1/../prove/merge_8_1",
      "v1/prove/merge_8_1",
      "prove/merge_8_1",
      `/${"a".repeat(256)}/prove/merge_8_1`,
    ]) {
      expect(isProverTarget(target, "merge_8_1"), target).toBe(false);
    }
  });
});

describe("attestation", () => {
  const request = merge("merge", 8);
  const config = (response: Response) => {
    const transport: TvcTransport = { fetch: vi.fn(async () => response) };
    return { url: "https://gatekeeper.test/v1/zolana/?api-key=k", policy: DEVNET_PROVER_POLICY, transport };
  };

  it("carries the prover's answer and names the route under the base path", async () => {
    const prover = config(Response.json({ platform: "aws-nitro" }));
    const attested = await fetchAttestation(prover);
    const sealing = sealingFor(prover, attested, request);
    expect(sealing.target).toBe("/v1/zolana/prove/merge_8_1");
    expect(sealing.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(sealing.nonce).toBe(attested.nonce);
    expect(sealing.attestation).toEqual({ platform: "aws-nitro" });
    expect(sealing.policy).toBe(DEVNET_PROVER_POLICY);
  });

  it("is reused for the policy's max age and never past its expiry", () => {
    const policy = (maxAge: unknown, expiresAtMs: number) => ({
      ...DEVNET_PROVER_POLICY,
      policy: {
        ...DEVNET_PROVER_POLICY.policy,
        tee: { ...DEVNET_PROVER_POLICY.policy.tee, max_age_secs: maxAge },
        expiresAtMs: String(expiresAtMs),
      },
    });
    expect(attestationReuseMs(policy(600, 10_000_000), 0)).toBe(600_000);
    expect(attestationReuseMs(policy(600, 1_000), 0)).toBe(1_000);
    expect(attestationReuseMs(policy(600, 1_000), 2_000)).toBe(0);
    for (const maxAge of [0, -1, 1.5, "600", undefined]) {
      expect(attestationReuseMs(policy(maxAge, 10_000_000), 0), String(maxAge)).toBe(0);
    }
  });

  it("refuses an unavailable prover or an answer that is not an object", async () => {
    await expect(
      fetchAttestation(config(Response.json({ code: "attestation_busy" }, { status: 429 }))),
    ).rejects.toMatchObject({ code: "ProverAttestationUnavailable", status: 429 });
    for (const body of ["[]", "null", "not json"]) {
      await expect(fetchAttestation(config(new Response(body)))).rejects.toMatchObject({
        code: "ProverAttestationInvalid",
      });
    }
  });
});
