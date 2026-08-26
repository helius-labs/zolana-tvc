import { p256 } from "@noble/curves/p256";
import { parseQosP256Public, qosDecrypt, qosEncrypt } from "../crypto/qos.js";
import { verifyP256Message, verifyP256Prehash } from "../crypto/p256.js";
import {
  clientAuthDigest,
  clientAuthMessage,
  requestDigest,
  resultDigest,
} from "../protocol/digest.js";
import { encodeDecimalU64 } from "../protocol/decimal.js";
import { TvcError } from "../protocol/error.js";
import { bytesEqual, decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import { canonicalizeJsonValue, isRfc8785 } from "../protocol/jcs.js";
import { parseStrictJson } from "../protocol/json.js";
import {
  API_VERSION,
  MAX_REQUEST_AGE_MS,
  QOS_P256_PUBLIC_LEN,
  RAW_P256_SIGNATURE_LEN,
  SEC1_UNCOMPRESSED_LEN,
  SHA256_LEN,
  TVC_APP_PROOF_SCHEME,
  TVC_APP_PROOF_TYPE,
} from "../protocol/constants.js";
import type {
  WalletOperationV1,
  OperationKind,
  OperationRequestV1,
  ServiceInfoV1,
  TurnkeyVerifiedAppProofV1,
  TvcWalletCheckpoint,
  WalletDescriptorV1,
} from "../protocol/types.js";
import type { TvcTransport } from "./transport.js";
import { classifyTurnkeyPolicyEvidence, verifyBootProof } from "../verify/index.js";
import type { QosIdentityPcrs } from "../verify/index.js";
import type {
  TurnkeyAppProofWire,
  TurnkeyBootProofWire,
} from "../verify/internal/turnkey-proof-seam.js";
import { assertExactObjectKeys, endpointUrl, readBoundedText } from "./http.js";

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });
const ENCRYPTED_RESPONSE_KEYS = [
  "version",
  "request_id",
  "encrypted_result",
  "tvc_app_proof",
] as const;
const TVC_APP_PROOF_KEYS = ["scheme", "public_key", "proof_payload", "signature"] as const;
/** Room for the JSON envelope and App Proof around the hex ciphertext. */
const RESPONSE_ENVELOPE_SLACK = 65_536n;

const OPERATION_PROOF_KEYS = [
  "type",
  "version",
  "request_id",
  "request_digest",
  "result_digest",
  "operation",
  "state_digest",
] as const;

type EncryptedResponseV1 = {
  version: number;
  request_id: string;
  encrypted_result: string;
  tvc_app_proof: {
    scheme: string;
    public_key: string;
    proof_payload: string;
    signature: string;
  };
};

type OperationProofPayloadV1 = {
  type: string;
  version: number;
  request_id: string;
  request_digest: string;
  result_digest: string;
  operation: OperationKind;
  state_digest: string;
};

export type AuthorizeTvcRequestInput = {
  readonly operation: WalletOperationV1;
  readonly request: Readonly<OperationRequestV1>;
  readonly clientAuthDigest: Uint8Array;
  readonly clientAuthMessage: Uint8Array;
};

export type TvcOperationAuthorizer = {
  readonly clientKeyId: string;
  authorizeTvcRequest(input: AuthorizeTvcRequestInput): Promise<Uint8Array>;
};

export type TvcWalletOperationsConfig = {
  readonly walletDescriptor: WalletDescriptorV1;
  readonly authorizer: TvcOperationAuthorizer;
};

export type OperationExecutionContext = {
  readonly endpoint: URL;
  readonly info: ServiceInfoV1;
  readonly transport: TvcTransport;
  readonly operations: TvcWalletOperationsConfig;
  readonly resolveBootProof: (input: {
    appProof: TurnkeyAppProofWire;
    bootProofLookupKey: string;
  }) => Promise<TurnkeyBootProofWire>;
  readonly qosIdentityPcrs: QosIdentityPcrs;
  readonly acceptedManifestDigests: readonly string[];
  readonly releasePolicyValidFromMs: bigint;
  readonly releasePolicyExpiresAtMs: bigint;
  readonly nowMs: () => bigint;
};

function requireCurrentReleasePolicy(context: OperationExecutionContext, nowMs: bigint): void {
  if (
    nowMs < context.releasePolicyValidFromMs ||
    nowMs > context.releasePolicyExpiresAtMs
  ) {
    throw new TvcError("ExpiredRequest");
  }
}

export function requireHex(input: string, length?: number): Uint8Array {
  const decoded = decodeLowerHex(input);
  if (length !== undefined && decoded.length !== length) throw new TvcError("InvalidHex");
  return decoded;
}

function checkpointFields(checkpoint?: TvcWalletCheckpoint) {
  if (!checkpoint) {
    return {
      sealed_wallet_state: null,
      expected_state_version: null,
      expected_state_digest: null,
    };
  }
  requireHex(checkpoint.sealedWalletState);
  encodeDecimalU64(BigInt(checkpoint.stateVersion));
  requireHex(checkpoint.stateDigest, SHA256_LEN);
  return {
    sealed_wallet_state: checkpoint.sealedWalletState,
    expected_state_version: checkpoint.stateVersion,
    expected_state_digest: checkpoint.stateDigest,
  };
}

function matchingGrant(
  descriptor: WalletDescriptorV1,
  clientKeyId: string,
  operation: OperationKind,
) {
  const grant = descriptor.allowed_clients.find(
    (candidate) => candidate.client_key_id === clientKeyId,
  );
  if (!grant || grant.scheme !== "p256-sha256" || !grant.allowed_operations.includes(operation)) {
    throw new TvcError("OperationNotAllowed");
  }
  return grant;
}

async function prepareRequest(
  context: OperationExecutionContext,
  operation: WalletOperationV1,
  checkpoint?: TvcWalletCheckpoint,
): Promise<{ request: OperationRequestV1; responseSecret: Uint8Array }> {
  if (
    !context.info.supported_operations.includes(operation.type) ||
    !context.acceptedManifestDigests.includes(context.info.manifest_digest)
  ) {
    throw new TvcError("OperationNotAllowed");
  }
  const grant = matchingGrant(
    context.operations.walletDescriptor,
    context.operations.authorizer.clientKeyId,
    operation.type,
  );
  const issuedAt = context.nowMs();
  requireCurrentReleasePolicy(context, issuedAt);
  const responseSecret = p256.utils.randomPrivateKey();
  const responsePublic = p256.getPublicKey(responseSecret, false);
  let request: OperationRequestV1 = {
    version: API_VERSION,
    request_id: encodeLowerHex(crypto.getRandomValues(new Uint8Array(32))),
    issued_at_ms: encodeDecimalU64(issuedAt),
    expires_at_ms: encodeDecimalU64(issuedAt + MAX_REQUEST_AGE_MS),
    target_release_id: context.info.release_id,
    target_manifest_digest: context.info.manifest_digest,
    target_executable_digest: context.info.executable_digest,
    quorum_key_id: context.info.quorum_key_id,
    quorum_key_epoch: context.info.quorum_key_epoch,
    wallet_descriptor: context.operations.walletDescriptor,
    ...checkpointFields(checkpoint),
    client_response_public_key: encodeLowerHex(
      Uint8Array.from([...responsePublic, ...responsePublic]),
    ),
    operation,
    authorization: {
      client_key_id: context.operations.authorizer.clientKeyId,
      scheme: "p256-sha256",
      signature: "",
    },
  };
  const requestDigestBytes = requestDigest(request);
  const digest = clientAuthDigest(requestDigestBytes);
  const signature = await context.operations.authorizer.authorizeTvcRequest({
    operation,
    request,
    clientAuthDigest: digest.slice(),
    clientAuthMessage: clientAuthMessage(requestDigestBytes),
  });
  verifyP256Prehash(requireHex(grant.client_public_key, SEC1_UNCOMPRESSED_LEN), digest, signature);
  request = {
    ...request,
    authorization: { ...request.authorization, signature: encodeLowerHex(signature) },
  };
  return { request, responseSecret };
}

function asAppProof(proof: EncryptedResponseV1["tvc_app_proof"]): TurnkeyAppProofWire {
  return {
    scheme: TVC_APP_PROOF_SCHEME,
    publicKey: proof.public_key,
    proofPayload: proof.proof_payload,
    signature: proof.signature,
  };
}

async function verifyOperationProof(
  context: OperationExecutionContext,
  request: OperationRequestV1,
  response: EncryptedResponseV1,
): Promise<OperationProofPayloadV1> {
  assertExactObjectKeys(response.tvc_app_proof, TVC_APP_PROOF_KEYS, "InvalidCanonicalJson");
  const proof = response.tvc_app_proof;
  if (proof.scheme !== TVC_APP_PROOF_SCHEME || !isRfc8785(proof.proof_payload)) {
    throw new TvcError("TurnkeyEvidenceInvalid");
  }
  const proofPublic = parseQosP256Public(requireHex(proof.public_key, QOS_P256_PUBLIC_LEN));
  verifyP256Message(
    proofPublic.signing,
    te.encode(proof.proof_payload),
    requireHex(proof.signature, RAW_P256_SIGNATURE_LEN),
  );
  const appProof = asAppProof(proof);
  const bootProof = await context.resolveBootProof({
    appProof,
    bootProofLookupKey: appProof.publicKey,
  });
  const verificationNow = context.nowMs();
  requireCurrentReleasePolicy(context, verificationNow);
  await verifyBootProof({
    appProof,
    bootProof,
    allowedManifestSha256: context.acceptedManifestDigests,
    expectedPcrs: context.qosIdentityPcrs,
    nowMs: verificationNow,
  });
  const payload = parseStrictJson<OperationProofPayloadV1>(
    proof.proof_payload,
    OPERATION_PROOF_KEYS,
  );
  if (
    payload.type !== TVC_APP_PROOF_TYPE ||
    payload.version !== API_VERSION ||
    payload.request_id !== request.request_id ||
    payload.request_digest !== encodeLowerHex(requestDigest(request)) ||
    payload.result_digest !== encodeLowerHex(resultDigest(requireHex(response.encrypted_result))) ||
    payload.operation !== request.operation.type
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  return payload;
}

export function verifyTurnkeyProofs(proofs: readonly TurnkeyVerifiedAppProofV1[]): void {
  if (proofs.length === 0) throw new TvcError("TurnkeyEvidenceInvalid");
  for (const proof of proofs) {
    assertExactObjectKeys(proof, TVC_APP_PROOF_KEYS, "InvalidCanonicalJson");
    const classification = classifyTurnkeyPolicyEvidence(
      proof.proof_payload,
      requireHex(proof.public_key, QOS_P256_PUBLIC_LEN),
      requireHex(proof.signature, RAW_P256_SIGNATURE_LEN),
    );
    if (classification !== "CryptographicallyValidButUnbound") {
      throw new TvcError("TurnkeyEvidenceInvalid");
    }
  }
}

export async function executeOperationEnvelope(
  context: OperationExecutionContext,
  operation: WalletOperationV1,
  checkpoint?: TvcWalletCheckpoint,
): Promise<{ plaintext: string; stateDigest: string }> {
  const { request, responseSecret } = await prepareRequest(context, operation, checkpoint);
  try {
    const requestBody = canonicalizeJsonValue(request);
    const quorum = parseQosP256Public(
      requireHex(context.info.quorum_public_key, QOS_P256_PUBLIC_LEN),
    );
    const ciphertext = qosEncrypt(quorum.encryption, te.encode(requestBody));
    if (BigInt(ciphertext.length) > BigInt(context.info.max_encrypted_request_bytes)) {
      throw new TvcError("RequestTooLarge");
    }
    const httpResponse = await context.transport.fetch(
      endpointUrl(context.endpoint, "/v1/operations"),
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: canonicalizeJsonValue({
          version: API_VERSION,
          quorum_key_id: context.info.quorum_key_id,
          quorum_key_epoch: context.info.quorum_key_epoch,
          ciphertext: encodeLowerHex(ciphertext),
        }),
      },
    );
    if (!httpResponse.ok) throw new TvcError("OperationUnavailable");
    // The ciphertext is hex, so it cannot exceed twice the byte ceiling;
    // RESPONSE_ENVELOPE_SLACK covers the surrounding JSON and App Proof.
    const maxResponseBytes = BigInt(context.info.max_encrypted_response_bytes);
    const body = await readBoundedText(
      httpResponse,
      maxResponseBytes * 2n + RESPONSE_ENVELOPE_SLACK,
    );
    const response = parseStrictJson<EncryptedResponseV1>(body, ENCRYPTED_RESPONSE_KEYS);
    if (
      response.version !== API_VERSION ||
      !bytesEqual(
        requireHex(response.request_id, SHA256_LEN),
        requireHex(request.request_id, SHA256_LEN),
      )
    ) {
      throw new TvcError("ReleaseBindingMismatch");
    }
    const encryptedResult = requireHex(response.encrypted_result);
    if (BigInt(encryptedResult.length) > maxResponseBytes) {
      throw new TvcError("ResponseTooLarge");
    }
    const proof = await verifyOperationProof(context, request, response);
    let plaintext: string;
    try {
      plaintext = td.decode(qosDecrypt(responseSecret, encryptedResult));
    } catch {
      throw new TvcError("InvalidEncryptedEnvelope");
    }
    if (!isRfc8785(plaintext)) throw new TvcError("InvalidCanonicalJson");
    return { plaintext, stateDigest: proof.state_digest };
  } finally {
    responseSecret.fill(0);
  }
}
