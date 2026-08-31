import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "@noble/hashes/sha256";
import { describe, expect, it } from "vitest";
import { canonicalizeJsonValue, isRfc8785 } from "./jcs.js";
import { decodeDecimalU64, encodeDecimalU64 } from "./decimal.js";
import { decodeLowerHex, encodeLowerHex } from "./hex.js";
import { parseStrictJson } from "./json.js";
import {
  artifactDigest,
  clientAuthDigest,
  descriptorDigestFromWallet,
  descriptorOwnerEvidenceDigest,
  descriptorProvisioningAuthDigest,
  requestDigest,
  requestIdHash,
  resultDigest,
  stateCommitment,
  walletIdHash,
} from "./digest.js";
import { TvcError } from "./error.js";
import type { HealthResponseV1, ServiceInfoV1 } from "./types.js";
import { HEALTH_KEYS, SERVICE_INFO_KEYS } from "./types.js";
import {
  parseUncompressedSec1,
  rejectDoubleHashedSignature,
  verifyP256Prehash,
} from "../crypto/p256.js";
import {
  parseQosP256Public,
  qosDecrypt,
  qosEncryptWith,
} from "../crypto/qos.js";
import {
  classifyTurnkeyPolicyEvidence,
  computeQosLiveManifestCommitmentPcr,
  verifyBootProof,
} from "../verify/index.js";
import { createTvcWalletClient } from "../keyholder/index.js";
import { TURNKEY_TS_PROOF_PROFILE } from "../verify/internal/turnkey-proof-seam.js";
import {
  bindDiscoveryToPolicy,
  verifySignedReleasePolicy,
} from "../verify/release-policy.js";
import type {
  PinnedReleaseAuthoritiesV1,
  SignedReleasePolicyV1,
} from "./types.js";

const fixturesDir = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/protocol/fixtures"
);

function readFixture(name: string): string {
  return readFileSync(join(fixturesDir, name), "utf8");
}

function readJson(name: string): Record<string, unknown> {
  return JSON.parse(readFixture(name)) as Record<string, unknown>;
}

describe("content-addressed fixtures", () => {
  it("matches MANIFEST sha256 for every file", () => {
    const manifest = JSON.parse(readFixture("MANIFEST.json")) as {
      files: Record<string, string>;
    };
    for (const [name, digest] of Object.entries(manifest.files)) {
      const body = readFixture(name);
      expect(encodeLowerHex(sha256(new TextEncoder().encode(body)))).toBe(
        digest
      );
    }
  });
});

describe("RFC 8785 / JCS", () => {
  it("matches the Rust object-sort fixture", () => {
    const fixture = readJson("jcs-object-sort.json");
    expect(canonicalizeJsonValue(fixture.input)).toBe(fixture.canonical_json);
    expect(
      encodeLowerHex(
        sha256(new TextEncoder().encode(String(fixture.canonical_json)))
      )
    ).toBe(fixture.canonical_sha256);
  });
});

describe("canonical u64", () => {
  it("encodes the Rust vectors and rejects negatives", () => {
    const fixture = readJson("canonical-u64.json") as {
      values: { input: string; encoded: string }[];
      negative: string[];
    };
    for (const row of fixture.values) {
      const input = BigInt(row.input);
      expect(encodeDecimalU64(input)).toBe(row.encoded);
      expect(decodeDecimalU64(row.encoded)).toBe(input);
    }
    for (const bad of fixture.negative) {
      expect(() => decodeDecimalU64(bad)).toThrowError(TvcError);
    }
  });
});

describe("request digest", () => {
  it("matches Rust and includes client_key_id", () => {
    const fixture = readJson("request-digest.json");
    const request = fixture.request as Record<string, unknown>;
    const digest = requestDigest(request);
    expect(encodeLowerHex(digest)).toBe(fixture.request_digest);
    expect(encodeLowerHex(clientAuthDigest(digest))).toBe(
      fixture.client_auth_digest
    );
    const authorization = request.authorization as Record<string, unknown>;
    expect(authorization.client_key_id).toBe("client-1");
    expect(authorization.scheme).toBe("p256-sha256");
  });

  it("changes when client_key_id is mutated", () => {
    const original = readJson("request-digest.json");
    const mutated = readJson("authorization-mutation.json");
    const request = structuredClone(original.request) as Record<
      string,
      unknown
    >;
    (request.authorization as Record<string, unknown>).client_key_id =
      "client-2";
    expect(encodeLowerHex(requestDigest(request))).toBe(
      mutated.mutated_client_key_id_digest
    );
    expect(mutated.mutated_client_key_id_verifies).toBe(false);
  });
});

describe("P-256 authorization", () => {
  it("accepts raw low-S and rejects DER, high-S, compressed keys, and double hashing", () => {
    const fixture = readJson("p256-signatures.json");
    const publicKey = decodeLowerHex(String(fixture.public_key));
    const digest = decodeLowerHex(String(fixture.digest));
    const raw = decodeLowerHex(String(fixture.raw_low_s));
    verifyP256Prehash(publicKey, digest, raw);
    expect(() =>
      verifyP256Prehash(publicKey, digest, decodeLowerHex(String(fixture.der)))
    ).toThrowError(/DerSignatureRejected/);
    expect(() =>
      verifyP256Prehash(
        publicKey,
        digest,
        decodeLowerHex(String(fixture.high_s))
      )
    ).toThrowError(/HighSSignature/);
    expect(() =>
      parseUncompressedSec1(
        decodeLowerHex(String(fixture.compressed_public_key))
      )
    ).toThrowError(/CompressedKeyRejected/);
    rejectDoubleHashedSignature(
      publicKey,
      digest,
      decodeLowerHex(String(fixture.double_hash_signature))
    );
  });
});

describe("QOS envelope", () => {
  it("parses the 130-byte public key and matches the Borsh envelope", () => {
    const pub = readJson("qos-p256-public.json");
    const parsed = parseQosP256Public(decodeLowerHex(String(pub.public_key)));
    expect(parsed.encryption.length).toBe(65);
    expect(parsed.signing.length).toBe(65);
    expect(encodeLowerHex(parsed.encryption)).toBe(pub.encryption_sec1);
    const envelope = readJson("qos-borsh-envelope.json");
    const produced = qosEncryptWith(
      decodeLowerHex(String(envelope.receiver_encryption_public)),
      decodeLowerHex(String(envelope.plaintext)),
      decodeLowerHex(String(envelope.ephemeral_secret)),
      decodeLowerHex(String(envelope.nonce))
    );
    expect(encodeLowerHex(produced)).toBe(envelope.envelope);
  });

  it("rejects truncated ciphertext and the wrong receiver key", () => {
    const fixture = readJson("qos-negative.json");
    const envelope = decodeLowerHex(String(fixture.envelope));
    const truncated = decodeLowerHex(String(fixture.truncated_envelope));
    const wrong = decodeLowerHex(String(fixture.wrong_receiver_secret));
    expect(() => qosDecrypt(wrong, envelope)).toThrowError(
      /InvalidEncryptedEnvelope/
    );
    expect(() => qosDecrypt(wrong, truncated)).toThrowError(
      /InvalidEncryptedEnvelope/
    );
  });
});

describe("JSON reject", () => {
  it("rejects unknown and duplicate fields", () => {
    const fixture = readJson("json-reject.json");
    expect(() =>
      parseStrictJson<HealthResponseV1>(
        String(fixture.unknown_field),
        HEALTH_KEYS
      )
    ).toThrowError(/UnknownJsonField/);
    expect(() =>
      parseStrictJson<HealthResponseV1>(
        String(fixture.duplicate_field),
        HEALTH_KEYS
      )
    ).toThrowError(/DuplicateJsonField/);
  });
});

describe("bindings and HTTP skeleton", () => {
  function discoveryFixtures() {
    const info = parseStrictJson<ServiceInfoV1>(
      String(readJson("http-skeleton.json").info_body),
      SERVICE_INFO_KEYS
    );
    const signed = readJson("signed-release-policy.json")
      .signed as SignedReleasePolicyV1;
    return { info, signed };
  }

  it("accepts discovery that matches the pinned policy", () => {
    const { info, signed } = discoveryFixtures();
    expect(() => bindDiscoveryToPolicy(info, signed)).not.toThrow();
  });

  it("rejects every discovery drift case the Rust binder rejects", () => {
    const fixture = readJson("discovery-binding.json");
    const signed = {
      policy: fixture.policy,
      authoritySetId: "fixture",
      signatures: [],
    } as SignedReleasePolicyV1;
    expect(() =>
      bindDiscoveryToPolicy(fixture.info as ServiceInfoV1, signed)
    ).not.toThrow();
    const cases = fixture.cases as {
      name: string;
      info: ServiceInfoV1;
      error: string;
    }[];
    expect(cases.length).toBe(14);
    for (const { name, info, error } of cases) {
      expect(() => bindDiscoveryToPolicy(info, signed), name).toThrowError(
        new RegExp(error)
      );
    }
  });

  it("treats /health as readiness-only and /v1/info as untrusted discovery", () => {
    const fixture = readJson("http-skeleton.json");
    expect(fixture.health_body).toBe('{"status":"Healthy"}');
    expect(fixture.health_has_release_id).toBe(false);
    const info = parseStrictJson<ServiceInfoV1>(
      String(fixture.info_body),
      SERVICE_INFO_KEYS
    );
    expect(info.release_id).toBe("tvc-dev-phase0");
  });
});

describe("proof payload UTF-8", () => {
  it("preserves exact bytes and classifies evidence as unbound", () => {
    const fixture = readJson("proof-payload-utf8.json");
    const payload = String(fixture.proof_payload);
    expect(encodeLowerHex(new TextEncoder().encode(payload))).toBe(
      fixture.proof_payload_hex
    );
    expect(isRfc8785(payload)).toBe(true);
    const classification = classifyTurnkeyPolicyEvidence(
      payload,
      decodeLowerHex(String(fixture.public_key)),
      decodeLowerHex(String(fixture.signature))
    );
    expect(classification).toBe("CryptographicallyValidButUnbound");
    expect(TURNKEY_TS_PROOF_PROFILE.productionVerifier).toBe(false);
  });

  it("accepts the official Turnkey App Proof high-S compatibility form", () => {
    const fixture = readJson("proof-payload-utf8.json");
    expect(
      classifyTurnkeyPolicyEvidence(
        String(fixture.proof_payload),
        decodeLowerHex(String(fixture.public_key)),
        decodeLowerHex(String(fixture.high_s_signature)),
      ),
    ).toBe("CryptographicallyValidButUnbound");
  });

  it("verifies exact non-JCS Turnkey proof bytes without reserializing", () => {
    const fixture = readJson("proof-payload-utf8.json");
    const payload = String(fixture.non_jcs_payload);
    expect(isRfc8785(payload)).toBe(false);
    expect(
      classifyTurnkeyPolicyEvidence(
        payload,
        decodeLowerHex(String(fixture.public_key)),
        decodeLowerHex(String(fixture.non_jcs_signature)),
      ),
    ).toBe("CryptographicallyValidButUnbound");
  });
});

describe("remaining digests", () => {
  it("matches Rust domain-separated hashes", () => {
    const fixture = readJson("digests.json");
    expect(encodeLowerHex(walletIdHash("wallet-phase0-1"))).toBe(
      fixture.wallet_id_hash
    );
    const request = readJson("request-digest.json").request as {
      request_id: string;
    };
    expect(
      encodeLowerHex(requestIdHash(decodeLowerHex(request.request_id)))
    ).toBe(fixture.request_id_hash);
    expect(
      encodeLowerHex(resultDigest(new TextEncoder().encode("encrypted-result")))
    ).toBe(fixture.result_digest);
    expect(
      encodeLowerHex(artifactDigest(new TextEncoder().encode("artifact")))
    ).toBe(fixture.artifact_digest);
    const requestFull = readJson("request-digest.json").request as {
      wallet_descriptor: { expected_ed25519_public_key: string };
    };
    const label = (s: string) => sha256(new TextEncoder().encode(s));
    expect(
      encodeLowerHex(
        stateCommitment({
          walletEd25519PublicKey: decodeLowerHex(
            requestFull.wallet_descriptor.expected_ed25519_public_key
          ),
          generation: 1n,
          stateDigestBytes: label("state"),
          descriptorDigestBytes: label("descriptor"),
          quorumKeyEpoch: 1n,
          recoveryEpoch: 0n,
          sealedStateSalt: label("salt"),
        })
      )
    ).toBe(fixture.state_commitment);
  });
});

describe("signed release policy", () => {
  const fixture = readJson("signed-release-policy.json");
  const authorities = fixture.authorities as PinnedReleaseAuthoritiesV1;
  const nowMs = BigInt(String(fixture.now_ms));

  it("accepts the 1-of-3 development signature", () => {
    expect(() =>
      verifySignedReleasePolicy(
        fixture.signed as SignedReleasePolicyV1,
        authorities,
        nowMs
      )
    ).not.toThrow();
  });

  // Each case runs the same input Rust ran and must reach the same error code.
  it.each([
    ["empty_signatures", "empty_signatures_input"],
    ["duplicate_key_id", "duplicate_key_id_input"],
    ["unknown_key_id", "unknown_key_id_input"],
    ["mutated_policy", "mutated_policy_input"],
  ])("matches the Rust error code for %s", (expected, inputKey) => {
    expect(() =>
      verifySignedReleasePolicy(
        fixture[inputKey] as SignedReleasePolicyV1,
        authorities,
        nowMs
      )
    ).toThrowError(new RegExp(String(fixture[expected])));
  });

  it("matches the Rust error code for a zero threshold", () => {
    expect(() =>
      verifySignedReleasePolicy(
        fixture.signed as SignedReleasePolicyV1,
        fixture.zero_threshold_authorities as PinnedReleaseAuthoritiesV1,
        nowMs
      )
    ).toThrowError(new RegExp(String(fixture.zero_threshold)));
  });

  it("matches the Rust error code for an expired policy", () => {
    expect(() =>
      verifySignedReleasePolicy(
        fixture.signed as SignedReleasePolicyV1,
        authorities,
        BigInt(String(fixture.expired_now_ms))
      )
    ).toThrowError(new RegExp(String(fixture.expired)));
  });

  it("rejects a production environment claim", () => {
    const signed = structuredClone(fixture.signed) as SignedReleasePolicyV1;
    signed.policy.environment = "production";
    expect(() =>
      verifySignedReleasePolicy(signed, authorities, nowMs)
    ).toThrowError(/ProductionClaimRejected/);
  });
});

describe("descriptor provisioning digests", () => {
  it("matches the Rust descriptor, owner-evidence, and provisioning digests", () => {
    const fixture = readJson("descriptor-digest.json");
    const descriptorDigest = descriptorDigestFromWallet(
      fixture.descriptor as object
    );
    expect(encodeLowerHex(descriptorDigest)).toBe(fixture.descriptor_digest);

    const ownerEvidence = descriptorOwnerEvidenceDigest({
      ownerAuthorizationKey: null,
      ownerAuthorization: null,
      priorClientAuthorization: null,
    });
    expect(encodeLowerHex(ownerEvidence)).toBe(fixture.owner_evidence_digest);
    expect(
      encodeLowerHex(
        descriptorProvisioningAuthDigest(descriptorDigest, ownerEvidence)
      )
    ).toBe(fixture.provisioning_auth_digest);
  });

  it("changes when any signed descriptor field is mutated", () => {
    const fixture = readJson("descriptor-digest.json");
    const mutated = structuredClone(fixture.descriptor) as Record<string, unknown>;
    mutated.wallet_id = "wallet-phase0-2";
    expect(encodeLowerHex(descriptorDigestFromWallet(mutated))).not.toBe(
      fixture.descriptor_digest
    );
  });

  it("ignores the three authorization fields the Rust provisioner strips", () => {
    const fixture = readJson("descriptor-digest.json");
    const withAuth = {
      ...(fixture.descriptor as object),
      provisioning_signature: "ff".repeat(64),
    };
    expect(encodeLowerHex(descriptorDigestFromWallet(withAuth))).toBe(
      fixture.descriptor_digest
    );
  });
});

describe("connectAndVerify", () => {
  it("rejects an unsigned policy before Boot Proof", async () => {
    const policyFixture = readJson("signed-release-policy.json");
    const signed = structuredClone(
      policyFixture.signed
    ) as SignedReleasePolicyV1;
    signed.signatures = [];
    const client = createTvcWalletClient({
      endpoint: new URL("https://tvc.example.invalid"),
      releasePolicy: signed,
      releaseAuthorities:
        policyFixture.authorities as PinnedReleaseAuthoritiesV1,
      nowMs: () => BigInt(String(policyFixture.now_ms)),
      transport: {
        fetch: async () => {
          throw new Error("unsigned policy must not fetch discovery");
        },
      },
    });
    await expect(client.connectAndVerify()).rejects.toMatchObject({
      code: "ReleasePolicyInvalid",
    });
  });

  it("fails closed without Boot Proof verification after a valid policy", async () => {
    const http = readJson("http-skeleton.json");
    const policyFixture = readJson("signed-release-policy.json");
    const client = createTvcWalletClient({
      endpoint: new URL("https://tvc.example.invalid"),
      releasePolicy: policyFixture.signed as SignedReleasePolicyV1,
      releaseAuthorities:
        policyFixture.authorities as PinnedReleaseAuthoritiesV1,
      nowMs: () => BigInt(String(policyFixture.now_ms)),
      transport: {
        fetch: async () =>
          new Response(String(http.info_body), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
      },
    });
    await expect(client.connectAndVerify()).rejects.toMatchObject({
      code: "BootProofUnverified",
    });
    await expect(verifyBootProof({} as never)).rejects.toThrowError(
      /BootProofUnverified/
    );
  });
});

describe("QOS live manifest PCR commitment", () => {
  // Derived from qos_nsm `nitro::LIVE_MANIFEST_COMMITMENT_PCR_INDEX` (17),
  // domain "qos-live-manifest-pcr-commitment-v1", extended from
  // MANIFEST_COMMITMENT_INITIAL_PCR ([0u8; 48]). Verified byte-identical in
  // qos_nsm 0.12.2 (the version this repo pins), 0.13.0, and 0.14.0, so the
  // vector holds across the pinned version and every release since.
  it("matches the qos_nsm live-manifest PCR commitment", () => {
    const manifestDigest = new Uint8Array(32);
    const ephemeralPublicKey = new Uint8Array(130).fill(0x11);
    ephemeralPublicKey[0] = 0x04;
    expect(
      encodeLowerHex(
        computeQosLiveManifestCommitmentPcr(manifestDigest, ephemeralPublicKey)
      )
    ).toBe(
      "d19443155765a0795affb170c1e13a2360ea38202a5fa703950261f3d0a0c2321dd0ae2b8d7c9d1798d6898b1e25a94c"
    );
  });
});
