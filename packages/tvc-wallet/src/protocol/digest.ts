import { sha256 } from "@noble/hashes/sha256";
import {
  CLIENT_AUTH_DOMAIN,
  REQUEST_DIGEST_DOMAIN,
  RESULT_DIGEST_DOMAIN,
  ARTIFACT_DIGEST_DOMAIN,
  WALLET_ID_HASH_DOMAIN,
  REQUEST_ID_HASH_DOMAIN,
  STATE_COMMITMENT_DOMAIN,
  RELEASE_POLICY_DOMAIN,
  TURNKEY_EVIDENCE_DIGEST_DOMAIN,
  STATE_DIGEST_DOMAIN,
  OWNER_AUTH_DOMAIN,
  OWNER_AUTH_EVIDENCE_DOMAIN,
  PROVISIONING_AUTH_DOMAIN,
  ROTATION_AUTH_DOMAIN,
  ACTIVITY_ID_HASH_DOMAIN,
  RELEASE_CHANNEL_DOMAIN,
  RECOVERY_INTENT_DOMAIN,
  QUORUM_ROTATION_DOMAIN,
} from "./constants.js";
import { canonicalizeJsonValue } from "./jcs.js";
import { TvcError } from "./error.js";

const te = new TextEncoder();

export function domainSeparatedHash(domain: string, payload: Uint8Array): Uint8Array {
  const domainBytes = te.encode(domain);
  const input = new Uint8Array(domainBytes.length + 1 + payload.length);
  input.set(domainBytes, 0);
  input[domainBytes.length] = 0;
  input.set(payload, domainBytes.length + 1);
  return sha256(input);
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function u64Be(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let n = value;
  for (let i = 7; i >= 0; i -= 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

export function requestDigest(request: object): Uint8Array {
  const cloned = structuredClone(request) as Record<string, unknown>;
  const authorization = cloned.authorization as Record<string, unknown> | undefined;
  if (!authorization || typeof authorization !== "object") {
    throw new TvcError("InvalidCanonicalJson");
  }
  delete authorization.signature;
  if (!("client_key_id" in authorization) || !("scheme" in authorization)) {
    throw new TvcError("InvalidCanonicalJson");
  }
  return domainSeparatedHash(REQUEST_DIGEST_DOMAIN, te.encode(canonicalizeJsonValue(cloned)));
}

export function clientAuthDigest(requestDigestBytes: Uint8Array): Uint8Array {
  return sha256(clientAuthMessage(requestDigestBytes));
}

/** Exact bytes that WebCrypto ECDSA hashes once with SHA-256 for client auth. */
export function clientAuthMessage(requestDigestBytes: Uint8Array): Uint8Array {
  if (requestDigestBytes.length !== 32) throw new TvcError("InvalidDigest");
  const domain = te.encode(CLIENT_AUTH_DOMAIN);
  return concatBytes([domain, Uint8Array.of(0), requestDigestBytes]);
}

export function resultDigest(encryptedResult: Uint8Array): Uint8Array {
  return domainSeparatedHash(RESULT_DIGEST_DOMAIN, encryptedResult);
}

export function artifactDigest(artifact: Uint8Array): Uint8Array {
  return domainSeparatedHash(ARTIFACT_DIGEST_DOMAIN, artifact);
}

export function walletIdHash(walletId: string): Uint8Array {
  return domainSeparatedHash(WALLET_ID_HASH_DOMAIN, te.encode(walletId));
}

export function requestIdHash(requestId: Uint8Array): Uint8Array {
  return domainSeparatedHash(REQUEST_ID_HASH_DOMAIN, requestId);
}

export function activityIdHash(activityId: string): Uint8Array {
  return domainSeparatedHash(ACTIVITY_ID_HASH_DOMAIN, te.encode(activityId));
}

export function releasePolicyDigest(policyJcs: Uint8Array): Uint8Array {
  return domainSeparatedHash(RELEASE_POLICY_DOMAIN, policyJcs);
}

export function releaseChannelDigest(channelJcs: Uint8Array): Uint8Array {
  return domainSeparatedHash(RELEASE_CHANNEL_DOMAIN, channelJcs);
}

export function recoveryIntentDigest(intentJcs: Uint8Array): Uint8Array {
  return domainSeparatedHash(RECOVERY_INTENT_DOMAIN, intentJcs);
}

export function quorumRotationDigest(planJcs: Uint8Array): Uint8Array {
  return domainSeparatedHash(QUORUM_ROTATION_DOMAIN, planJcs);
}

export function ownerAuthDigest(challengeJcs: Uint8Array): Uint8Array {
  return domainSeparatedHash(OWNER_AUTH_DOMAIN, challengeJcs);
}

export function ownerAuthEvidenceDigest(evidenceJcs: Uint8Array): Uint8Array {
  return domainSeparatedHash(OWNER_AUTH_EVIDENCE_DOMAIN, evidenceJcs);
}

export function provisioningAuthDigest(payload: Uint8Array): Uint8Array {
  return domainSeparatedHash(PROVISIONING_AUTH_DOMAIN, payload);
}

/** Exact `WalletDescriptorV1` digest used by the Rust provisioner. */
export function descriptorDigestFromWallet(descriptor: object): Uint8Array {
  const value = structuredClone(descriptor) as Record<string, unknown>;
  delete value.provisioning_signature;
  delete value.owner_authorization;
  delete value.prior_client_authorization;
  return domainSeparatedHash(PROVISIONING_AUTH_DOMAIN, te.encode(canonicalizeJsonValue(value)));
}

/** Exact owner-evidence digest for descriptor provisioning/rotation. */
export function descriptorOwnerEvidenceDigest(input: {
  ownerAuthorizationKey: unknown;
  ownerAuthorization: unknown;
  priorClientAuthorization: unknown;
}): Uint8Array {
  return domainSeparatedHash(
    OWNER_AUTH_EVIDENCE_DOMAIN,
    te.encode(
      canonicalizeJsonValue([
        input.ownerAuthorizationKey,
        input.ownerAuthorization,
        input.priorClientAuthorization,
      ]),
    ),
  );
}

/** Exact provisioning digest: SHA-256(domain || 0x00 || descriptor || owner evidence). */
export function descriptorProvisioningAuthDigest(
  descriptorDigestBytes: Uint8Array,
  ownerEvidenceDigestBytes: Uint8Array,
): Uint8Array {
  if (descriptorDigestBytes.length !== 32 || ownerEvidenceDigestBytes.length !== 32) {
    throw new TvcError("InvalidDigest");
  }
  return domainSeparatedHash(
    PROVISIONING_AUTH_DOMAIN,
    concatBytes([descriptorDigestBytes, ownerEvidenceDigestBytes]),
  );
}

export function rotationAuthDigest(payload: Uint8Array): Uint8Array {
  return domainSeparatedHash(ROTATION_AUTH_DOMAIN, payload);
}

export function turnkeyActivityEvidenceDigest(evidenceJcs: Uint8Array): Uint8Array {
  return domainSeparatedHash(TURNKEY_EVIDENCE_DIGEST_DOMAIN, evidenceJcs);
}

export function stateDigest(borshState: Uint8Array): Uint8Array {
  return domainSeparatedHash(STATE_DIGEST_DOMAIN, borshState);
}

export function stateCommitment(args: {
  walletEd25519PublicKey: Uint8Array;
  generation: bigint;
  stateDigestBytes: Uint8Array;
  descriptorDigestBytes: Uint8Array;
  quorumKeyEpoch: bigint;
  recoveryEpoch: bigint;
  sealedStateSalt: Uint8Array;
}): Uint8Array {
  return domainSeparatedHash(
    STATE_COMMITMENT_DOMAIN,
    concatBytes([
      args.walletEd25519PublicKey,
      u64Be(args.generation),
      args.stateDigestBytes,
      args.descriptorDigestBytes,
      u64Be(args.quorumKeyEpoch),
      u64Be(args.recoveryEpoch),
      args.sealedStateSalt,
    ]),
  );
}
