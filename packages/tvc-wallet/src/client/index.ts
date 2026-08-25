import { parseStrictJson } from "../protocol/json.js";
import { TvcError } from "../protocol/error.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { bytesEqual, decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import { verifyP256Message } from "../crypto/p256.js";
import { parseQosP256Public, qosEncrypt } from "../crypto/qos.js";
import type {
  AuthorizeDefaultRingTransferResult,
  BootstrapClientEd25519Result,
  PinnedReleaseAuthoritiesV1,
  ServiceInfoV1,
  SignedReleasePolicyV1,
} from "../protocol/types.js";
import { SERVICE_INFO_KEYS } from "../protocol/types.js";
import { createDefaultTransport, type TvcTransport } from "../platform/index.js";
import { verifyBootProof, type QosIdentityPcrs } from "../verify/index.js";
import type {
  TurnkeyAppProofWire,
  TurnkeyBootProofWire,
} from "../verify/internal/turnkey-proof-seam.js";
import { bindDiscoveryToPolicy, verifySignedReleasePolicy } from "../verify/release-policy.js";
import { TVC_APP_PROOF_SCHEME } from "../protocol/constants.js";
import {
  authorizeDefaultRingTransferOperation,
  executeWalletOperation,
  type AuthorizeDefaultRingTransferInput,
  type OperationExecutionContext,
  type TvcWalletOperationsConfig,
} from "./operations.js";
import { assertExactObjectKeys, endpointUrl } from "./http.js";

export {
  defaultRingSolWithdrawalIntentDigest,
  defaultRingTransferIntentDigest,
} from "./transfer-intent.js";
export type {
  DefaultRingSolWithdrawalIntentInput,
  DefaultRingTransferIntentInput,
} from "./transfer-intent.js";

const PING_RESPONSE_KEYS = ["version", "tvc_app_proof"] as const;
const TVC_APP_PROOF_KEYS = ["scheme", "public_key", "proof_payload", "signature"] as const;

type TvcAppProofV1 = {
  scheme: string;
  public_key: string;
  proof_payload: string;
  signature: string;
};

type QosPingResponseV1 = {
  version: number;
  tvc_app_proof: TvcAppProofV1;
};

export type ResolveBootProofInput = {
  readonly appProof: TurnkeyAppProofWire;
  readonly bootProofLookupKey: string;
};

export type BootProofResolver = (input: ResolveBootProofInput) => Promise<TurnkeyBootProofWire>;

export type TvcWalletClientConfig = {
  endpoint: URL;
  releasePolicy: SignedReleasePolicyV1;
  releaseAuthorities: PinnedReleaseAuthoritiesV1;
  /** Independently pinned PCR0-3 values. Never copy them from `/v1/info` or a Boot Proof. */
  qosIdentityPcrs?: QosIdentityPcrs;
  /** Fetches the Boot Proof with the caller's existing authenticated Turnkey session. */
  resolveBootProof?: BootProofResolver;
  /** Typed wallet authority. Omit for verify-only clients. */
  operations?: TvcWalletOperationsConfig;
  nowMs?: bigint;
  transport?: TvcTransport;
};

const verifiedConnectionBrand: unique symbol = Symbol("VerifiedConnection");

export type VerifiedConnection = {
  readonly [verifiedConnectionBrand]: true;
  readonly releaseId: string;
  readonly environment: "development";
};

export type TvcWalletClient = {
  connectAndVerify(): Promise<VerifiedConnection>;
  bootstrapClientEd25519(connection: VerifiedConnection): Promise<BootstrapClientEd25519Result>;
  authorizeDefaultRingTransfer(
    connection: VerifiedConnection,
    input: AuthorizeDefaultRingTransferInput,
  ): Promise<AuthorizeDefaultRingTransferResult>;
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
  const encryptedChallenge = qosEncrypt(
    quorumPublic.encryption,
    new TextEncoder().encode(challengePayload),
  );
  const requestBody = canonicalizeJsonValue({
    version: 1,
    encrypted_challenge: encodeLowerHex(encryptedChallenge),
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

  const proofPublicKey = decodeLowerHex(proof.public_key);
  if (
    !bytesEqual(
      decodeLowerHex(info.ephemeral_public_key),
      decodeLowerHex(info.boot_proof_lookup_key),
    )
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  verifyP256Message(
    parseQosP256Public(proofPublicKey).signing,
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

export function createTvcWalletClient(config: TvcWalletClientConfig): TvcWalletClient {
  const transport = config.transport ?? createDefaultTransport();
  let activeConnection: VerifiedConnection | null = null;
  let operationContext: OperationExecutionContext | null = null;

  function requireOperationContext(connection: VerifiedConnection): OperationExecutionContext {
    if (connection !== activeConnection || !operationContext || !config.operations) {
      throw new TvcError("OperationNotConfigured");
    }
    return operationContext;
  }

  return {
    async connectAndVerify(): Promise<VerifiedConnection> {
      verifySignedReleasePolicy(
        config.releasePolicy,
        config.releaseAuthorities,
        config.nowMs ?? BigInt(Date.now()),
      );
      const response = await transport.fetch(endpointUrl(config.endpoint, "/v1/info"));
      if (!response.ok) {
        throw new TvcError("DiscoveryUntrusted");
      }
      const body = await response.text();
      const info = parseStrictJson<ServiceInfoV1>(body, SERVICE_INFO_KEYS);
      bindDiscoveryToPolicy(info, config.releasePolicy);
      if (!config.resolveBootProof || !config.qosIdentityPcrs) {
        throw new TvcError("BootProofUnverified");
      }

      const appProof = await fetchQosPingProof(config.endpoint, info, transport);
      const bootProof = await config.resolveBootProof({
        appProof,
        // Public ingress may route /v1/info and /v1/ping to different healthy
        // replicas. The signed ping proof identifies the exact replica whose
        // Boot Proof must be resolved.
        bootProofLookupKey: appProof.publicKey,
      });
      await verifyBootProof({
        appProof,
        bootProof,
        allowedManifestSha256: config.releasePolicy.policy.acceptedManifestDigests,
        expectedPcrs: config.qosIdentityPcrs,
      });

      const connection = Object.freeze({
        [verifiedConnectionBrand]: true as const,
        releaseId: info.release_id,
        environment: "development" as const,
      });
      activeConnection = connection;
      operationContext = {
        endpoint: config.endpoint,
        info,
        transport,
        operations: config.operations as TvcWalletOperationsConfig,
        resolveBootProof: config.resolveBootProof,
        qosIdentityPcrs: config.qosIdentityPcrs,
        acceptedManifestDigests: config.releasePolicy.policy.acceptedManifestDigests,
        nowMs: () => config.nowMs ?? BigInt(Date.now()),
      };
      return connection;
    },

    async bootstrapClientEd25519(
      connection: VerifiedConnection,
    ): Promise<BootstrapClientEd25519Result> {
      const result = await executeWalletOperation(requireOperationContext(connection), {
        type: "BootstrapClientEd25519",
      });
      if (result.type !== "BootstrapClientEd25519") {
        throw new TvcError("ReleaseBindingMismatch");
      }
      return result;
    },

    async authorizeDefaultRingTransfer(
      connection: VerifiedConnection,
      input: AuthorizeDefaultRingTransferInput,
    ): Promise<AuthorizeDefaultRingTransferResult> {
      const result = await executeWalletOperation(
        requireOperationContext(connection),
        authorizeDefaultRingTransferOperation(input),
      );
      if (result.type !== "AuthorizeDefaultRingTransfer") {
        throw new TvcError("ReleaseBindingMismatch");
      }
      return result;
    },
  };
}

export type {
  AuthorizeTvcRequestInput,
  AuthorizeDefaultRingTransferInput,
  TvcOperationAuthorizer,
  TvcWalletOperationsConfig,
} from "./operations.js";
