import { p256 } from "@noble/curves/p256";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { encodeLowerHex } from "../protocol/hex.js";
import {
  appProof,
  bootProof,
  EXPECTED_PCRS,
  label,
  MANIFEST_DIGEST,
  NOW_MS,
  pcr,
  type AttestationOverrides,
} from "./boot-proof.testkit.js";

const verifyChainMock = vi.hoisted(() => vi.fn());

vi.mock("./internal/turnkey-proof-seam.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./internal/turnkey-proof-seam.js")>()),
  verifyTurnkeyAwsAttestation: verifyChainMock,
}));

const { verifyBootProof } = await import("./boot-proof.js");

function verify(overrides: AttestationOverrides = {}, input: Record<string, unknown> = {}) {
  return verifyBootProof({
    appProof: appProof(),
    bootProof: bootProof(overrides),
    allowedManifestSha256: [encodeLowerHex(MANIFEST_DIGEST)],
    expectedPcrs: EXPECTED_PCRS,
    nowMs: NOW_MS,
    ...input,
  } as Parameters<typeof verifyBootProof>[0]);
}

describe("verifyBootProof", () => {
  beforeEach(() => verifyChainMock.mockReset().mockResolvedValue(undefined));

  it("accepts a well-formed attestation and validates the chain on the verifier clock", async () => {
    await expect(verify()).resolves.toBeUndefined();
    expect(verifyChainMock).toHaveBeenCalledTimes(1);
    expect(verifyChainMock.mock.calls[0]?.[3]).toBe(Number(NOW_MS));
  });

  it("accepts old boot evidence when a current App Proof proves the attested key is live", async () => {
    await expect(verify({}, { nowMs: NOW_MS + 86_400_000n })).resolves.toBeUndefined();
    expect(verifyChainMock).toHaveBeenCalledTimes(1);
    expect(verifyChainMock.mock.calls[0]?.[3]).toBe(Number(NOW_MS + 86_400_000n));
  });

  it("rejects an attestation timestamped beyond the allowed clock skew", async () => {
    await expect(verify({}, { nowMs: NOW_MS - 3_600_000n })).rejects.toThrowError(
      /BootProofUnverified/,
    );
    expect(verifyChainMock).not.toHaveBeenCalled();
  });

  it("rejects a manifest digest outside the pinned release policy", async () => {
    await expect(
      verify({}, { allowedManifestSha256: [encodeLowerHex(label("other-manifest"))] }),
    ).rejects.toThrowError(/BootProofUnverified/);
    await expect(verify({}, { allowedManifestSha256: [] })).rejects.toThrowError(
      /BootProofUnverified/,
    );
    expect(verifyChainMock).not.toHaveBeenCalled();
  });

  it("rejects identity PCRs that do not match the independently pinned values", async () => {
    for (const index of [0, 1, 2, 3]) {
      verifyChainMock.mockClear();
      await expect(
        verify({ pcrOverrides: { [index]: pcr(0xee) } }),
      ).rejects.toThrowError(/BootProofUnverified/);
      expect(verifyChainMock).not.toHaveBeenCalled();
    }
  });

  it("rejects a live-manifest PCR17 that does not commit to this manifest and key", async () => {
    await expect(verify({ pcrOverrides: { 17: pcr(0x99) } })).rejects.toThrowError(
      /BootProofUnverified/,
    );
  });

  it("rejects an attested key that differs from the App Proof key", async () => {
    const other = Uint8Array.from([
      ...p256.getPublicKey(label("other-encryption"), false),
      ...p256.getPublicKey(label("other-signing"), false),
    ]);
    await expect(verify({ entries: { public_key: other } })).rejects.toThrowError(
      /BootProofUnverified/,
    );
  });

  it("rejects a Boot Proof whose advertised ephemeral key is not the attested one", async () => {
    const proof = bootProof();
    await expect(
      verify({}, { bootProof: { ...proof, ephemeralPublicKeyHex: "04".padEnd(260, "9") } }),
    ).rejects.toThrowError(/BootProofUnverified/);
  });

  it("rejects a non-null nonce, a non-SHA384 digest, and a missing module id", async () => {
    await expect(verify({ entries: { nonce: label("n") } })).rejects.toThrowError(
      /BootProofUnverified/,
    );
    await expect(verify({ entries: { digest: "SHA256" } })).rejects.toThrowError(
      /BootProofUnverified/,
    );
    await expect(verify({ entries: { module_id: "" } })).rejects.toThrowError(
      /BootProofUnverified/,
    );
  });

  it("rejects an attestation that does not carry all 32 attestable PCRs", async () => {
    await expect(verify({ pcrCount: 31 })).rejects.toThrowError(/BootProofUnverified/);
    await expect(verify({ pcrCount: 33 })).rejects.toThrowError(/BootProofUnverified/);
  });

  it("rejects a truncated COSE_Sign1 envelope and undecodable base64", async () => {
    await expect(verify({ coseLength: 3 })).rejects.toThrowError(/BootProofUnverified/);
    await expect(
      verify({}, { bootProof: { ...bootProof(), awsAttestationDocB64: "!!!not base64!!!" } }),
    ).rejects.toThrowError(/BootProofUnverified/);
    expect(verifyChainMock).not.toHaveBeenCalled();
  });

  it("rejects an App Proof that is not signed by the key it claims", async () => {
    const proof = appProof();
    await expect(
      verify({}, { appProof: { ...proof, signature: encodeLowerHex(new Uint8Array(64)) } }),
    ).rejects.toThrowError(/BootProofUnverified/);
    await expect(
      verify({}, { appProof: { ...proof, scheme: "SIGNATURE_SCHEME_TK_API_P256" } }),
    ).rejects.toThrowError(/BootProofUnverified/);
    await expect(
      verify({}, { appProof: { ...proof, proofPayload: '{"b":1,"a":2}' } }),
    ).rejects.toThrowError(/BootProofUnverified/);
    expect(verifyChainMock).not.toHaveBeenCalled();
  });
});
