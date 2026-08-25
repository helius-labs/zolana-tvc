import { verifyP256Message } from "../crypto/p256.js";
import { parseQosP256Public, qosEncrypt } from "../crypto/qos.js";
import { TVC_APP_PROOF_SCHEME } from "../protocol/constants.js";
import { TvcError } from "../protocol/error.js";
import { bytesEqual, decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { parseStrictJson } from "../protocol/json.js";
import {
  SERVICE_INFO_KEYS,
  type PinnedReleaseAuthoritiesV1,
  type ServiceInfoV1,
  type SignedReleasePolicyV1,
} from "../protocol/types.js";
import { createDefaultTransport, type TvcTransport } from "../platform/index.js";
import { verifyBootProof, type QosIdentityPcrs } from "../verify/index.js";
import type {
  TurnkeyAppProofWire,
  TurnkeyBootProofWire,
} from "../verify/internal/turnkey-proof-seam.js";
import { bindDiscoveryToPolicy, verifySignedReleasePolicy } from "../verify/release-policy.js";
import { assertExactObjectKeys, endpointUrl } from "./http.js";

const PING_RESPONSE_KEYS = ["version", "tvc_app_proof"] as const;
const TVC_APP_PROOF_KEYS = ["scheme", "public_key", "proof_payload", "signature"] as const;

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
  nowMs?: bigint;
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
  readonly resolveBootProof: BootProofResolver;
  readonly qosIdentityPcrs: QosIdentityPcrs;
  readonly acceptedManifestDigests: readonly string[];
  readonly nowMs: () => bigint;
};

async function fetchQosPingProof(
  endpoint: URL,
  info: ServiceInfoV1,
  transport: TvcTransport,
): Promise<TurnkeyAppProofWire> {
  const quorumPublic = parseQosP256Public(decodeLowerHex(info.quorum_public_key));
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const challengePayload = canonicalizeJsonValue({
    type: "zolana.tvc.qos_ping.v1",
    version: 1,
    challenge: encodeLowerHex(challenge),
  });
  const requestBody = canonicalizeJsonValue({
    version: 1,
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

  const parsed = parseStrictJson<QosPingResponseV1>(await response.text(), PING_RESPONSE_KEYS);
  if (parsed.version !== 1) throw new TvcError("UnsupportedVersion");
  assertExactObjectKeys(parsed.tvc_app_proof, TVC_APP_PROOF_KEYS, "TurnkeyEvidenceInvalid");
  const proof = parsed.tvc_app_proof;
  if (proof.scheme !== TVC_APP_PROOF_SCHEME || proof.proof_payload !== challengePayload) {
    throw new TvcError("TurnkeyEvidenceInvalid");
  }
  if (
    !bytesEqual(
      decodeLowerHex(info.ephemeral_public_key),
      decodeLowerHex(info.boot_proof_lookup_key),
    )
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  verifyP256Message(
    parseQosP256Public(decodeLowerHex(proof.public_key)).signing,
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
  verifySignedReleasePolicy(
    config.releasePolicy,
    config.releaseAuthorities,
    config.nowMs ?? BigInt(Date.now()),
  );
  const transport = config.transport ?? createDefaultTransport();
  const response = await transport.fetch(endpointUrl(config.endpoint, "/v1/info"));
  if (!response.ok) throw new TvcError("DiscoveryUntrusted");
  const info = parseStrictJson<ServiceInfoV1>(await response.text(), SERVICE_INFO_KEYS);
  bindDiscoveryToPolicy(info, config.releasePolicy);
  if (!config.resolveBootProof || !config.qosIdentityPcrs) {
    throw new TvcError("BootProofUnverified");
  }

  const appProof = await fetchQosPingProof(config.endpoint, info, transport);
  const bootProof = await config.resolveBootProof({
    appProof,
    bootProofLookupKey: appProof.publicKey,
  });
  await verifyBootProof({
    appProof,
    bootProof,
    allowedManifestSha256: config.releasePolicy.policy.acceptedManifestDigests,
    expectedPcrs: config.qosIdentityPcrs,
  });

  return {
    connection: Object.freeze({
      [verifiedConnectionBrand]: true as const,
      releaseId: info.release_id,
      environment: "development" as const,
    }),
    endpoint: config.endpoint,
    info,
    transport,
    resolveBootProof: config.resolveBootProof,
    qosIdentityPcrs: config.qosIdentityPcrs,
    acceptedManifestDigests: config.releasePolicy.policy.acceptedManifestDigests,
    nowMs: () => config.nowMs ?? BigInt(Date.now()),
  };
}
