import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { qosDecrypt } from "../crypto/qos.js";
import { signP256Message, signP256Prehash } from "../crypto/p256.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type {
  PinnedReleaseAuthoritiesV1,
  ReleasePolicyV1,
  ServiceInfoV1,
  SignedReleasePolicyV1,
} from "../protocol/types.js";
import { policySigningDigest } from "../verify/release-policy.js";
import { createTvcWalletClient } from "./index.js";

const verifyBootProofMock = vi.hoisted(() => vi.fn());

vi.mock("../verify/index.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../verify/index.js")>()),
  verifyBootProof: verifyBootProofMock,
}));

function secret(label: string): Uint8Array {
  return sha256(new TextEncoder().encode(label));
}

function qosPublic(
  encryptionSecret: Uint8Array,
  signingSecret: Uint8Array
): string {
  return encodeLowerHex(
    Uint8Array.from([
      ...p256.getPublicKey(encryptionSecret, false),
      ...p256.getPublicKey(signingSecret, false),
    ])
  );
}

function oversizedResponse(onPull: () => void): Response {
  const chunk = new Uint8Array(64 * 1024).fill(0x61);
  let pulls = 0;
  return new Response(
    new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        onPull();
        if (pulls > 4_096) {
          controller.close();
          return;
        }
        controller.enqueue(chunk);
      },
    }),
    { status: 200 },
  );
}

describe("connectAndVerify development PoC", () => {
  beforeEach(() =>
    verifyBootProofMock.mockReset().mockResolvedValue(undefined)
  );

  it("runs encrypted QOS ping, resolves the Boot Proof, and returns an opaque connection", async () => {
    const quorumEncryptionSecret = secret("connect-quorum-encryption");
    const quorumSigningSecret = secret("connect-quorum-signing");
    const ephemeralEncryptionSecret = secret("connect-ephemeral-encryption");
    const ephemeralSigningSecret = secret("connect-ephemeral-signing");
    const discoveryEphemeralPublicKey = qosPublic(
      secret("connect-discovery-ephemeral-encryption"),
      secret("connect-discovery-ephemeral-signing")
    );
    const authoritySecret = secret("connect-release-authority");
    const quorumPublicKey = qosPublic(
      quorumEncryptionSecret,
      quorumSigningSecret
    );
    const ephemeralPublicKey = qosPublic(
      ephemeralEncryptionSecret,
      ephemeralSigningSecret
    );
    const manifestDigest = "11".repeat(32);
    const executableDigest = "22".repeat(32);

    const policy: ReleasePolicyV1 = {
      version: 1,
      releaseId: "connect-poc",
      environment: "development",
      tvcApplicationId: "wallet-dev",
      securityDomainId: "33".repeat(32),
      acceptedManifestDigests: [manifestDigest],
      acceptedExecutableDigests: [executableDigest],
      quorumKeyId: "quorum-connect",
      quorumKeyEpoch: "1",
      quorumPublicKey,
      allowedOperations: ["BootstrapClientEd25519"],
      maxEncryptedRequestBytes: 262_144,
      maxEncryptedResponseBytes: 262_144,
      turnkeyTrustRootId: "turnkey-dev",
      turnkeyProofSchemaVersions: ["v1"],
      turnkeyVerifierVersion: "ts-development-poc",
      validFromMs: "1700000000000",
      expiresAtMs: "1800000000000",
      revocationEpoch: "0",
    };
    const signedPolicy: SignedReleasePolicyV1 = {
      policy,
      authoritySetId: "connect-authorities",
      signatures: [
        {
          keyId: "connect-authority",
          scheme: "p256-sha256",
          signature: encodeLowerHex(
            signP256Prehash(authoritySecret, policySigningDigest(policy))
          ),
        },
      ],
    };
    const authorities: PinnedReleaseAuthoritiesV1 = {
      authoritySetId: "connect-authorities",
      threshold: 1,
      keys: [
        {
          keyId: "connect-authority",
          publicKey: encodeLowerHex(p256.getPublicKey(authoritySecret, false)),
        },
      ],
    };
    const info: ServiceInfoV1 = {
      version: 1,
      environment: "development",
      security_domain_id: policy.securityDomainId,
      release_id: policy.releaseId,
      manifest_digest: manifestDigest,
      executable_digest: executableDigest,
      quorum_public_key: quorumPublicKey,
      quorum_key_id: policy.quorumKeyId,
      quorum_key_epoch: policy.quorumKeyEpoch,
      // /v1/info and /v1/ping may be served by different healthy replicas.
      ephemeral_public_key: discoveryEphemeralPublicKey,
      supported_operations: ["BootstrapClientEd25519"],
      max_encrypted_request_bytes: "262144",
      max_encrypted_response_bytes: "262144",
      proof_type: "zolana.tvc.wallet_operation.v1",
      boot_proof_lookup_key: discoveryEphemeralPublicKey,
    };
    const expectedPcrs = {
      0: "44".repeat(48),
      1: "55".repeat(48),
      2: "66".repeat(48),
      3: "77".repeat(48),
    } as const;
    const bootProof = {
      ephemeralPublicKeyHex: ephemeralPublicKey,
      awsAttestationDocB64: "unused-by-mock",
      qosManifestB64: "unused-by-mock",
      qosManifestEnvelopeB64: "unused-by-mock",
      deploymentLabel: "connect-poc",
      enclaveApp: "wallet-dev",
      owner: "zolana",
      createdAt: { seconds: "1750000000", nanos: "0" },
    };

    const resolveBootProof = vi.fn().mockResolvedValue(bootProof);
    const client = createTvcWalletClient({
      endpoint: new URL("https://tvc.example.invalid/api/tvc/"),
      releasePolicy: signedPolicy,
      releaseAuthorities: authorities,
      qosIdentityPcrs: expectedPcrs,
      resolveBootProof,
      nowMs: () => 1_750_000_000_000n,
      transport: {
        fetch: async (url, init) => {
          if (url.pathname === "/api/tvc/v1/info") {
            return new Response(canonicalizeJsonValue(info), { status: 200 });
          }
          expect(url.pathname).toBe("/api/tvc/v1/ping");
          expect(init?.method).toBe("POST");
          const request = JSON.parse(String(init?.body)) as {
            encrypted_challenge: string;
          };
          const challengePayload = new TextDecoder().decode(
            qosDecrypt(
              quorumEncryptionSecret,
              decodeLowerHex(request.encrypted_challenge)
            )
          );
          return new Response(
            canonicalizeJsonValue({
              version: 1,
              tvc_app_proof: {
                scheme: "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256",
                public_key: ephemeralPublicKey,
                proof_payload: challengePayload,
                signature: encodeLowerHex(
                  signP256Message(
                    ephemeralSigningSecret,
                    new TextEncoder().encode(challengePayload)
                  )
                ),
              },
            }),
            { status: 200 }
          );
        },
      },
    });

    await expect(client.connectAndVerify()).resolves.toMatchObject({
      releaseId: "connect-poc",
      environment: "development",
    });
    expect(resolveBootProof).toHaveBeenCalledWith(
      expect.objectContaining({ bootProofLookupKey: ephemeralPublicKey })
    );
    expect(verifyBootProofMock).toHaveBeenCalledWith({
      appProof: expect.objectContaining({ publicKey: ephemeralPublicKey }),
      bootProof,
      allowedManifestSha256: [manifestDigest],
      expectedPcrs,
      nowMs: 1_750_000_000_000n,
    });

    let discoveryPulls = 0;
    const oversizedDiscoveryClient = createTvcWalletClient({
      endpoint: new URL("https://tvc.example.invalid/api/tvc/"),
      releasePolicy: signedPolicy,
      releaseAuthorities: authorities,
      qosIdentityPcrs: expectedPcrs,
      resolveBootProof,
      nowMs: () => 1_750_000_000_000n,
      transport: { fetch: async () => oversizedResponse(() => (discoveryPulls += 1)) },
    });
    await expect(oversizedDiscoveryClient.connectAndVerify()).rejects.toThrowError(
      "ResponseTooLarge",
    );
    expect(discoveryPulls).toBeLessThan(4);

    let pingPulls = 0;
    const oversizedPingClient = createTvcWalletClient({
      endpoint: new URL("https://tvc.example.invalid/api/tvc/"),
      releasePolicy: signedPolicy,
      releaseAuthorities: authorities,
      qosIdentityPcrs: expectedPcrs,
      resolveBootProof,
      nowMs: () => 1_750_000_000_000n,
      transport: {
        fetch: async (url) =>
          url.pathname.endsWith("/v1/info")
            ? new Response(canonicalizeJsonValue(info), { status: 200 })
            : oversizedResponse(() => (pingPulls += 1)),
      },
    });
    await expect(oversizedPingClient.connectAndVerify()).rejects.toThrowError(
      "ResponseTooLarge",
    );
    expect(pingPulls).toBeLessThan(4);
  });

  it("reads the clock per use instead of freezing one instant", async () => {
    // A scalar nowMs would pin every freshness check to a single moment for the
    // client's whole life, quietly disabling attestation-age enforcement.
    const seen: bigint[] = [];
    let tick = 1_750_000_000_000n;
    const clock = () => {
      seen.push(tick);
      tick += 1_000n;
      return tick;
    };

    const policyFixture = JSON.parse(
      readFileSync(
        join(
          dirname(fileURLToPath(import.meta.url)),
          "../../../../crates/protocol/fixtures/signed-release-policy.json",
        ),
        "utf8",
      ),
    ) as Record<string, unknown>;

    const client = createTvcWalletClient({
      endpoint: new URL("https://tvc.example.invalid"),
      releasePolicy: policyFixture.signed as SignedReleasePolicyV1,
      releaseAuthorities: policyFixture.authorities as PinnedReleaseAuthoritiesV1,
      nowMs: clock,
      transport: { fetch: async () => new Response("{}", { status: 500 }) },
    });

    await expect(client.connectAndVerify()).rejects.toThrow();
    expect(seen.length).toBeGreaterThan(0);
  });
});
