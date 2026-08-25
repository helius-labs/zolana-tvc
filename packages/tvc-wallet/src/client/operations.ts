import { p256 } from "@noble/curves/p256";
import { ed25519 } from "@noble/curves/ed25519";
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
import type {
  AuthorizeDefaultRingTransferResult,
  BootstrapClientEd25519Result,
  OperationKind,
  OperationRequestV1,
  ServiceInfoV1,
  TurnkeyVerifiedAppProofV1,
  WalletDescriptorV1,
  WalletOperationResult,
  WalletOperationV1,
} from "../protocol/types.js";
import type { TvcTransport } from "../platform/index.js";
import { classifyTurnkeyPolicyEvidence, verifyBootProof } from "../verify/index.js";
import type { QosIdentityPcrs } from "../verify/index.js";
import type {
  TurnkeyAppProofWire,
  TurnkeyBootProofWire,
} from "../verify/internal/turnkey-proof-seam.js";
import {
  API_VERSION,
  CLIENT_ED25519_DERIVATION_SUITE,
  MAX_SOLANA_TRANSACTION_BYTES,
  TVC_APP_PROOF_SCHEME,
} from "../protocol/constants.js";
import { assertExactObjectKeys, endpointUrl } from "./http.js";

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });
const REQUEST_TTL_MS = 300_000n;
const NO_SERVER_STATE_DIGEST = "00".repeat(32);

const ENCRYPTED_RESPONSE_KEYS = [
  "version",
  "request_id",
  "encrypted_result",
  "tvc_app_proof",
] as const;
const TVC_APP_PROOF_KEYS = ["scheme", "public_key", "proof_payload", "signature"] as const;
const OPERATION_PROOF_KEYS = [
  "type",
  "version",
  "request_id",
  "request_digest",
  "result_digest",
  "operation",
  "state_digest",
] as const;
const RESULT_KEYS: Record<WalletOperationResult["type"], readonly string[]> = {
  BootstrapClientEd25519: [
    "type",
    "solana_address",
    "shielded_owner_hash",
    "shielded_nullifier_public_key",
    "shielded_viewing_public_key",
    "derivation_seed",
    "derivation_suite",
    "turnkey_activity_id",
    "turnkey_app_proofs",
    "evidence_classification",
  ],
  AuthorizeDefaultRingTransfer: [
    "type",
    "signed_transaction",
    "transaction_signature",
    "intent_digest",
    "turnkey_activity_id",
    "turnkey_app_proofs",
    "evidence_classification",
  ],
};

type TvcAppProofV1 = {
  scheme: string;
  public_key: string;
  proof_payload: string;
  signature: string;
};

type EncryptedResponseV1 = {
  version: number;
  request_id: string;
  encrypted_result: string;
  tvc_app_proof: TvcAppProofV1;
};

type TvcOperationProofPayloadV1 = {
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

export type AuthorizeDefaultRingTransferInput = {
  readonly intentDigest: Uint8Array;
  readonly unsignedTransaction: Uint8Array;
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
  readonly nowMs: () => bigint;
};

function requireHex(input: string, length?: number): Uint8Array {
  const decoded = decodeLowerHex(input);
  if (length !== undefined && decoded.length !== length) {
    throw new TvcError("InvalidHex");
  }
  return decoded;
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
  const responseSecret = p256.utils.randomPrivateKey();
  const responsePublic = p256.getPublicKey(responseSecret, false);
  let request: OperationRequestV1 = {
    version: API_VERSION,
    request_id: encodeLowerHex(crypto.getRandomValues(new Uint8Array(32))),
    issued_at_ms: encodeDecimalU64(issuedAt),
    expires_at_ms: encodeDecimalU64(issuedAt + REQUEST_TTL_MS),
    target_release_id: context.info.release_id,
    target_manifest_digest: context.info.manifest_digest,
    target_executable_digest: context.info.executable_digest,
    quorum_key_id: context.info.quorum_key_id,
    quorum_key_epoch: context.info.quorum_key_epoch,
    wallet_descriptor: context.operations.walletDescriptor,
    sealed_wallet_state: null,
    expected_state_version: null,
    expected_state_digest: null,
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
  verifyP256Prehash(requireHex(grant.client_public_key, 65), digest, signature);
  request = {
    ...request,
    authorization: {
      ...request.authorization,
      signature: encodeLowerHex(signature),
    },
  };
  return { request, responseSecret };
}

function asAppProof(proof: TvcAppProofV1): TurnkeyAppProofWire {
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
): Promise<void> {
  assertExactObjectKeys(response.tvc_app_proof, TVC_APP_PROOF_KEYS, "InvalidCanonicalJson");
  const proof = response.tvc_app_proof;
  if (proof.scheme !== TVC_APP_PROOF_SCHEME || !isRfc8785(proof.proof_payload)) {
    throw new TvcError("TurnkeyEvidenceInvalid");
  }
  const proofPublic = parseQosP256Public(requireHex(proof.public_key, 130));
  verifyP256Message(
    proofPublic.signing,
    te.encode(proof.proof_payload),
    requireHex(proof.signature, 64),
  );
  const appProof = asAppProof(proof);
  const bootProof = await context.resolveBootProof({
    appProof,
    bootProofLookupKey: appProof.publicKey,
  });
  await verifyBootProof({
    appProof,
    bootProof,
    allowedManifestSha256: context.acceptedManifestDigests,
    expectedPcrs: context.qosIdentityPcrs,
  });

  const payload = parseStrictJson<TvcOperationProofPayloadV1>(
    proof.proof_payload,
    OPERATION_PROOF_KEYS,
  );
  if (
    payload.type !== "zolana.tvc.wallet_operation.v1" ||
    payload.version !== API_VERSION ||
    payload.request_id !== request.request_id ||
    payload.request_digest !== encodeLowerHex(requestDigest(request)) ||
    payload.result_digest !== encodeLowerHex(resultDigest(requireHex(response.encrypted_result))) ||
    payload.operation !== request.operation.type ||
    payload.state_digest !== NO_SERVER_STATE_DIGEST
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }
}

function verifyTurnkeyProofs(proofs: readonly TurnkeyVerifiedAppProofV1[]): void {
  if (proofs.length === 0) throw new TvcError("TurnkeyEvidenceInvalid");
  for (const proof of proofs) {
    assertExactObjectKeys(proof, TVC_APP_PROOF_KEYS, "InvalidCanonicalJson");
    const classification = classifyTurnkeyPolicyEvidence(
      proof.proof_payload,
      requireHex(proof.public_key, 130),
      requireHex(proof.signature, 64),
    );
    if (classification !== "CryptographicallyValidButUnbound") {
      throw new TvcError("TurnkeyEvidenceInvalid");
    }
  }
}

function validateResult(result: WalletOperationResult, operation: WalletOperationV1): void {
  const allowed = RESULT_KEYS[result.type];
  if (!allowed) throw new TvcError("UnsupportedVersion");
  assertExactObjectKeys(result, allowed, "InvalidCanonicalJson");
  if (
    result.type !== operation.type ||
    result.evidence_classification !== "CryptographicallyValidButUnbound"
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  verifyTurnkeyProofs(result.turnkey_app_proofs);

  if (result.type === "BootstrapClientEd25519") {
    requireHex(result.shielded_owner_hash, 32);
    requireHex(result.shielded_nullifier_public_key, 32);
    requireHex(result.shielded_viewing_public_key, 33);
    requireHex(result.derivation_seed, 64);
    if (result.derivation_suite !== CLIENT_ED25519_DERIVATION_SUITE) {
      throw new TvcError("ReleaseBindingMismatch");
    }
  } else {
    requireHex(result.signed_transaction);
    requireHex(result.intent_digest, 32);
    if (
      operation.type !== "AuthorizeDefaultRingTransfer" ||
      result.intent_digest !== operation.intent_digest ||
      result.transaction_signature.length === 0
    ) {
      throw new TvcError("ReleaseBindingMismatch");
    }
  }
}

function encodeBase58(bytes: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let leadingZeroes = 0;
  while (leadingZeroes < bytes.length && bytes[leadingZeroes] === 0) {
    leadingZeroes += 1;
  }
  if (leadingZeroes === bytes.length) return "1".repeat(leadingZeroes);
  const digits = [0];
  for (let index = leadingZeroes; index < bytes.length; index += 1) {
    let carry = bytes[index] ?? 0;
    for (let digit = 0; digit < digits.length; digit += 1) {
      carry += (digits[digit] ?? 0) * 256;
      digits[digit] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  return (
    "1".repeat(leadingZeroes) +
    digits
      .reverse()
      .map((digit) => alphabet[digit])
      .join("")
  );
}

export function verifyDefaultRingAuthorizationResult(input: {
  readonly unsignedTransaction: Uint8Array;
  readonly result: AuthorizeDefaultRingTransferResult;
  readonly expectedEd25519PublicKey: Uint8Array;
}): void {
  const signed = requireHex(input.result.signed_transaction);
  const unsigned = input.unsignedTransaction;
  const signatureOffset = 1;
  const messageOffset = signatureOffset + 64;
  const signature = signed.slice(signatureOffset, messageOffset);
  if (
    input.expectedEd25519PublicKey.length !== 32 ||
    unsigned.length <= messageOffset ||
    signed.length !== unsigned.length ||
    unsigned[0] !== 1 ||
    signed[0] !== 1 ||
    unsigned.slice(signatureOffset, messageOffset).some((byte) => byte !== 0) ||
    signature.every((byte) => byte === 0) ||
    // A non-versioned message starts with its required-signatures header. A
    // versioned message has the high bit set and is outside this profile.
    (signed[messageOffset]! & 0x80) !== 0 ||
    !bytesEqual(unsigned.slice(messageOffset), signed.slice(messageOffset)) ||
    !ed25519.verify(signature, signed.slice(messageOffset), input.expectedEd25519PublicKey, {
      zip215: false,
    }) ||
    encodeBase58(signature) !== input.result.transaction_signature
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }
}

export async function executeWalletOperation(
  context: OperationExecutionContext,
  operation: WalletOperationV1,
): Promise<WalletOperationResult> {
  const { request, responseSecret } = await prepareRequest(context, operation);
  const requestBody = canonicalizeJsonValue(request);
  if (te.encode(requestBody).length > Number(context.info.max_encrypted_request_bytes)) {
    responseSecret.fill(0);
    throw new TvcError("RequestTooLarge");
  }
  const quorum = parseQosP256Public(requireHex(context.info.quorum_public_key, 130));
  const outer = canonicalizeJsonValue({
    version: API_VERSION,
    quorum_key_id: context.info.quorum_key_id,
    quorum_key_epoch: context.info.quorum_key_epoch,
    ciphertext: encodeLowerHex(qosEncrypt(quorum.encryption, te.encode(requestBody))),
  });
  try {
    const httpResponse = await context.transport.fetch(
      endpointUrl(context.endpoint, "/v1/operations"),
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: outer,
      },
    );
    if (!httpResponse.ok) throw new TvcError("OperationUnavailable");
    const response = parseStrictJson<EncryptedResponseV1>(
      await httpResponse.text(),
      ENCRYPTED_RESPONSE_KEYS,
    );
    if (
      response.version !== API_VERSION ||
      !bytesEqual(requireHex(response.request_id, 32), requireHex(request.request_id, 32))
    ) {
      throw new TvcError("ReleaseBindingMismatch");
    }
    const encryptedResult = requireHex(response.encrypted_result);
    if (encryptedResult.length > Number(context.info.max_encrypted_response_bytes)) {
      throw new TvcError("ResponseTooLarge");
    }
    await verifyOperationProof(context, request, response);
    let plaintext: string;
    try {
      plaintext = td.decode(qosDecrypt(responseSecret, encryptedResult));
    } catch {
      throw new TvcError("InvalidEncryptedEnvelope");
    }
    if (!isRfc8785(plaintext)) throw new TvcError("InvalidCanonicalJson");
    const result = parseStrictJson<WalletOperationResult>(plaintext);
    validateResult(result, operation);
    const target = context.operations.walletDescriptor.turnkey_signing_target;
    if (
      result.type === "BootstrapClientEd25519" &&
      (target.type !== "HdWalletAccount" || result.solana_address !== target.address)
    ) {
      throw new TvcError("ReleaseBindingMismatch");
    }
    if (
      result.type === "AuthorizeDefaultRingTransfer" &&
      operation.type === "AuthorizeDefaultRingTransfer"
    ) {
      verifyDefaultRingAuthorizationResult({
        unsignedTransaction: requireHex(operation.unsigned_transaction),
        result,
        expectedEd25519PublicKey: requireHex(
          context.operations.walletDescriptor.expected_ed25519_public_key,
          32,
        ),
      });
    }
    return result;
  } finally {
    responseSecret.fill(0);
  }
}

export function authorizeDefaultRingTransferOperation(
  input: AuthorizeDefaultRingTransferInput,
): WalletOperationV1 {
  if (
    input.intentDigest.length !== 32 ||
    input.intentDigest.every((byte) => byte === 0) ||
    input.unsignedTransaction.length === 0 ||
    input.unsignedTransaction.length > MAX_SOLANA_TRANSACTION_BYTES
  ) {
    throw new TvcError("InvalidTransferIntent");
  }
  return {
    type: "AuthorizeDefaultRingTransfer",
    intent_digest: encodeLowerHex(input.intentDigest),
    unsigned_transaction: encodeLowerHex(input.unsignedTransaction),
  };
}

export type { AuthorizeDefaultRingTransferResult, BootstrapClientEd25519Result };

export {
  defaultRingSolWithdrawalIntentDigest,
  defaultRingTransferIntentDigest,
  type DefaultRingSolWithdrawalIntentInput,
  type DefaultRingTransferIntentInput,
} from "./transfer-intent.js";
