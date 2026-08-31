import { verifyP256Message } from "../crypto/p256.js";
import { parseQosP256Public, qosEncrypt } from "../crypto/qos.js";
import {
  API_VERSION,
  QOS_P256_PUBLIC_LEN,
  TVC_APP_PROOF_SCHEME,
  TVC_QOS_PING_PROOF_TYPE,
} from "../protocol/constants.js";
import { TvcError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { parseStrictJson } from "../protocol/json.js";
import {
  SERVICE_INFO_KEYS,
  type PinnedReleaseAuthoritiesV1,
  type ServiceInfoV1,
  type SignedReleasePolicyV1,
} from "../protocol/types.js";
import { createDefaultTransport, type TvcTransport } from "./transport.js";
import { verifyBootProof, type QosIdentityPcrs } from "../verify/index.js";
import type {
  TurnkeyAppProofWire,
  TurnkeyBootProofWire,
} from "../verify/internal/turnkey-proof-seam.js";
import { bindDiscoveryToPolicy, verifySignedReleasePolicy } from "../verify/release-policy.js";
import { assertExactObjectKeys, endpointUrl, readBoundedText } from "./http.js";
import {
  type TvcTrustVerifier,
  verifyTurnkeyCustodyProofs,
} from "./trust.js";

const PING_RESPONSE_KEYS = ["version", "tvc_app_proof"] as const;
const TVC_APP_PROOF_KEYS = ["scheme", "public_key", "proof_payload", "signature"] as const;
const MAX_DISCOVERY_RESPONSE_BYTES = 64n * 1024n;
const MAX_PING_RESPONSE_BYTES = 64n * 1024n;

type QosPingResponseV1 = {
  version: number;
  tvc_app_proof: {
    scheme: string;
    public_key: string;
    proof_payload: string;
    signature: string;
  };
};

export type ResolveBootProofInput = {
  readonly appProof: TurnkeyAppProofWire;
  readonly bootProofLookupKey: string;
};

export type BootProofResolver = (input: ResolveBootProofInput) => Promise<TurnkeyBootProofWire>;

export type TvcConnectionConfig = {
  endpoint: URL;
  releasePolicy: SignedReleasePolicyV1;
  releaseAuthorities: PinnedReleaseAuthoritiesV1;
  /** Independently pinned PCR0-3 values. Never copy them from discovery or a Boot Proof. */
  qosIdentityPcrs?: QosIdentityPcrs;
  /** Fetches the Boot Proof with the caller's existing authenticated Turnkey session. */
  resolveBootProof?: BootProofResolver;
  /**
   * Verifier clock. A function, not an instant: a fixed value would freeze
   * request timestamps and certificate-chain validation for the client's
   * whole life.
   */
  nowMs?: () => bigint;
  transport?: TvcTransport;
};

const verifiedConnectionBrand: unique symbol = Symbol("VerifiedConnection");

export type VerifiedConnection = {
  readonly [verifiedConnectionBrand]: true;
  readonly releaseId: string;
  readonly environment: "development";
};

export type ConnectedTvcRuntime = {
  readonly connection: VerifiedConnection;
  readonly endpoint: URL;
  readonly info: ServiceInfoV1;
  readonly transport: TvcTransport;
  readonly acceptedManifestDigests: readonly string[];
  readonly releasePolicyValidFromMs: bigint;
  readonly releasePolicyExpiresAtMs: bigint;
  readonly nowMs: () => bigint;
  readonly trustVerifier: TvcTrustVerifier;
};

export function createVerifiedConnection(releaseId: string): VerifiedConnection {
  return Object.freeze({
    [verifiedConnectionBrand]: true as const,
    releaseId,
    environment: "development" as const,
  });
}

export async function fetchServiceInfo(
  endpoint: URL,
  transport: TvcTransport,
): Promise<ServiceInfoV1> {
  const response = await transport.fetch(endpointUrl(endpoint, "/v1/info"));
  if (!response.ok) throw new TvcError("DiscoveryUntrusted");
  return parseStrictJson<ServiceInfoV1>(
    await readBoundedText(response, MAX_DISCOVERY_RESPONSE_BYTES),
    SERVICE_INFO_KEYS,
  );
}

function requireQosPublicKey(value: string): Uint8Array {
  const bytes = decodeLowerHex(value);
  if (bytes.length !== QOS_P256_PUBLIC_LEN) throw new TvcError("InvalidPublicKey");
  return bytes;
}

export async function fetchQosPingProof(
  endpoint: URL,
  info: ServiceInfoV1,
  transport: TvcTransport,
): Promise<TurnkeyAppProofWire> {
  const quorumPublic = parseQosP256Public(requireQosPublicKey(info.quorum_public_key));
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const challengePayload = canonicalizeJsonValue({
    type: TVC_QOS_PING_PROOF_TYPE,
    version: API_VERSION,
    challenge: encodeLowerHex(challenge),
  });
  const requestBody = canonicalizeJsonValue({
    version: API_VERSION,
    encrypted_challenge: encodeLowerHex(
      qosEncrypt(quorumPublic.encryption, new TextEncoder().encode(challengePayload)),
    ),
  });
  const response = await transport.fetch(endpointUrl(endpoint, "/v1/ping"), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: requestBody,
  });
  if (!response.ok) throw new TvcError("BootProofUnverified");

  const parsed = parseStrictJson<QosPingResponseV1>(
    await readBoundedText(response, MAX_PING_RESPONSE_BYTES),
    PING_RESPONSE_KEYS,
  );
  if (parsed.version !== API_VERSION) throw new TvcError("UnsupportedVersion");
  assertExactObjectKeys(parsed.tvc_app_proof, TVC_APP_PROOF_KEYS, "TurnkeyEvidenceInvalid");
  const proof = parsed.tvc_app_proof;
  if (proof.scheme !== TVC_APP_PROOF_SCHEME || proof.proof_payload !== challengePayload) {
    throw new TvcError("TurnkeyEvidenceInvalid");
  }
  // `proof.public_key` is self-asserted here and carries no weight until
  // verifyBootProof ties it to a pinned-PCR Nitro attestation. Discovery's
  // own `ephemeral_public_key` is never used as a verification input: /v1/info
  // and /v1/ping may be served by different healthy replicas, so it is an
  // advertisement, and comparing it against `boot_proof_lookup_key` from the
  // same untrusted document would prove nothing.
  verifyP256Message(
    parseQosP256Public(requireQosPublicKey(proof.public_key)).signing,
    new TextEncoder().encode(proof.proof_payload),
    decodeLowerHex(proof.signature),
  );
  return {
    scheme: TVC_APP_PROOF_SCHEME,
    publicKey: proof.public_key,
    proofPayload: proof.proof_payload,
    signature: proof.signature,
  };
}

export async function connectAndVerifyTvc(
  config: TvcConnectionConfig,
): Promise<ConnectedTvcRuntime> {
  const nowMs = config.nowMs ?? (() => BigInt(Date.now()));
  verifySignedReleasePolicy(config.releasePolicy, config.releaseAuthorities, nowMs());
  const transport = config.transport ?? createDefaultTransport();
  const info = await fetchServiceInfo(config.endpoint, transport);
  bindDiscoveryToPolicy(info, config.releasePolicy);
  const { resolveBootProof, qosIdentityPcrs } = config;
  if (!resolveBootProof || !qosIdentityPcrs) {
    throw new TvcError("BootProofUnverified");
  }

  const appProof = await fetchQosPingProof(config.endpoint, info, transport);
  const bootProof = await resolveBootProof({
    appProof,
    bootProofLookupKey: appProof.publicKey,
  });
  await verifyBootProof({
    appProof,
    bootProof,
    allowedManifestSha256: config.releasePolicy.policy.acceptedManifestDigests,
    expectedPcrs: qosIdentityPcrs,
    nowMs: nowMs(),
  });

  const releasePolicyValidFromMs = BigInt(config.releasePolicy.policy.validFromMs);
  const releasePolicyExpiresAtMs = BigInt(config.releasePolicy.policy.expiresAtMs);
  const trustVerifier: TvcTrustVerifier = Object.freeze({
    async verifyOperationAppProof(operationAppProof) {
      const verificationNow = nowMs();
      if (
        verificationNow < releasePolicyValidFromMs ||
        verificationNow > releasePolicyExpiresAtMs
      ) {
        throw new TvcError("ExpiredRequest");
      }
      const operationBootProof = await resolveBootProof({
        appProof: operationAppProof,
        bootProofLookupKey: operationAppProof.publicKey,
      });
      await verifyBootProof({
        appProof: operationAppProof,
        bootProof: operationBootProof,
        allowedManifestSha256: config.releasePolicy.policy.acceptedManifestDigests,
        expectedPcrs: qosIdentityPcrs,
        nowMs: verificationNow,
      });
    },
    verifyCustodyProofs: verifyTurnkeyCustodyProofs,
  });

  return {
    connection: createVerifiedConnection(info.release_id),
    endpoint: config.endpoint,
    info,
    transport,
    acceptedManifestDigests: config.releasePolicy.policy.acceptedManifestDigests,
    releasePolicyValidFromMs,
    releasePolicyExpiresAtMs,
    nowMs,
    trustVerifier,
  };
}
