import { sha256 } from "@noble/hashes/sha256";
import {
  ARTIFACT_DIGEST_DOMAIN,
  CLIENT_AUTH_DOMAIN,
  PROVISIONING_AUTH_DOMAIN,
  RELEASE_POLICY_DOMAIN,
  REQUEST_DIGEST_DOMAIN,
  REQUEST_ID_HASH_DOMAIN,
  RESULT_DIGEST_DOMAIN,
  SHA256_LEN,
  STATE_COMMITMENT_DOMAIN,
  WALLET_ID_HASH_DOMAIN,
} from "./constants.js";
import { canonicalizeJsonValue } from "./jcs.js";
import { encodeLowerHex } from "./hex.js";
import { TvcError } from "./error.js";

const te = new TextEncoder();

function domainSeparatedHash(domain: string, payload: Uint8Array): Uint8Array {
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
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) throw new TvcError("InvalidDecimal");
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
  if (requestDigestBytes.length !== SHA256_LEN) throw new TvcError("InvalidDigest");
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

export function releasePolicyDigest(policyJcs: Uint8Array): Uint8Array {
  return domainSeparatedHash(RELEASE_POLICY_DOMAIN, policyJcs);
}

/** Exact `WalletDescriptorV1` digest the provisioner signs. */
export function descriptorDigestFromWallet(descriptor: object): Uint8Array {
  const value = structuredClone(descriptor) as Record<string, unknown>;
  delete value.provisioning_signature;
  return domainSeparatedHash(PROVISIONING_AUTH_DOMAIN, te.encode(canonicalizeJsonValue(value)));
}

/** Grant identity the enclave derives from the client public key. */
export function clientKeyIdFor(clientPublicKey: Uint8Array): string {
  return `tvc-browser-p256-${encodeLowerHex(sha256(clientPublicKey).slice(0, 16))}`;
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
  for (const field of [
    args.walletEd25519PublicKey,
    args.stateDigestBytes,
    args.descriptorDigestBytes,
    args.sealedStateSalt,
  ]) {
    if (field.length !== SHA256_LEN) throw new TvcError("InvalidDigest");
  }
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
