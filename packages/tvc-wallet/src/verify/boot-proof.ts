import { sha384 } from "@noble/hashes/sha512";
import CBOR from "cbor-js";
import { verifyP256Message } from "../crypto/p256.js";
import { parseQosP256Public } from "../crypto/qos.js";
import { TvcError } from "../protocol/error.js";
import { TVC_APP_PROOF_SCHEME } from "../protocol/constants.js";
import { bytesEqual, decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import { isRfc8785 } from "../protocol/jcs.js";
import {
  assertNotProductionVerifier,
  type TurnkeyAppProofWire,
  type TurnkeyBootProofWire,
  verifyTurnkeyAwsAttestation,
} from "./internal/turnkey-proof-seam.js";

const QOS_LIVE_MANIFEST_PCR_COMMITMENT_DOMAIN = "qos-live-manifest-pcr-commitment-v1";
const QOS_LIVE_MANIFEST_COMMITMENT_PCR_INDEX = 17;
const QOS_ATTESTABLE_PCR_COUNT = 32;
const SHA256_LENGTH = 32;
const SHA384_LENGTH = 48;
const QOS_EPHEMERAL_PUBLIC_KEY_LENGTH = 130;

export type QosIdentityPcrIndex = 0 | 1 | 2 | 3;

/**
 * Independently trusted Nitro measurements for the expected QOS deployment.
 * Never populate these values from `/v1/info` or from the Boot Proof itself.
 */
export type QosIdentityPcrs = Readonly<Record<QosIdentityPcrIndex, string>>;

export type VerifyBootProofInput = {
  appProof: TurnkeyAppProofWire;
  bootProof: TurnkeyBootProofWire;
  allowedManifestSha256: readonly string[];
  expectedPcrs: QosIdentityPcrs;
};

type AwsNitroAttestationDocument = {
  cabundle: unknown;
  certificate: unknown;
  digest: unknown;
  module_id: unknown;
  nonce?: unknown;
  pcrs: unknown;
  public_key: unknown;
  timestamp: unknown;
  user_data: unknown;
};

type DecodedBootProof = {
  coseSign1: unknown;
  attestation: AwsNitroAttestationDocument;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
};

/**
 * Development PoC verifier composed from Turnkey's AWS Nitro helpers plus
 * independently pinned QOS manifest/PCR checks.
 */
export async function verifyBootProof(input: VerifyBootProofInput): Promise<void> {
  assertNotProductionVerifier();
  try {
    verifyTvcAppProof(input.appProof);
    const decoded = decodeBootProof(input.bootProof);
    validateAttestationShape(decoded.attestation);

    await verifyTurnkeyAwsAttestation(
      decoded.coseSign1,
      decoded.certificate,
      decoded.cabundle,
      decoded.attestation.timestamp as number,
    );

    verifyProofBindings(input, decoded.attestation);
  } catch {
    throw new TvcError("BootProofUnverified");
  }
}

export function computeQosLiveManifestCommitmentPcr(
  manifestDigest: Uint8Array,
  ephemeralPublicKey: Uint8Array,
): Uint8Array {
  if (manifestDigest.length !== SHA256_LENGTH) {
    throw new TvcError("BootProofUnverified");
  }
  if (ephemeralPublicKey.length !== QOS_EPHEMERAL_PUBLIC_KEY_LENGTH) {
    throw new TvcError("BootProofUnverified");
  }
  const commitmentPreimage = new TextEncoder().encode(
    `{"domain":"${QOS_LIVE_MANIFEST_PCR_COMMITMENT_DOMAIN}","ephemeralPublicKey":"${encodeLowerHex(
      ephemeralPublicKey,
    )}","manifestHash":"${encodeLowerHex(manifestDigest)}"}`,
  );
  const commitment = sha384(commitmentPreimage);
  const extensionInput = new Uint8Array(SHA384_LENGTH + commitment.length);
  extensionInput.set(commitment, SHA384_LENGTH);
  return sha384(extensionInput);
}

function verifyTvcAppProof(appProof: TurnkeyAppProofWire): void {
  if (appProof.scheme !== TVC_APP_PROOF_SCHEME || !isRfc8785(appProof.proofPayload)) {
    throw new TvcError("BootProofUnverified");
  }
  const publicKey = decodeLowerHex(appProof.publicKey);
  const signature = decodeLowerHex(appProof.signature);
  const qosPublic = parseQosP256Public(publicKey);
  verifyP256Message(qosPublic.signing, new TextEncoder().encode(appProof.proofPayload), signature);
}

function decodeBootProof(bootProof: TurnkeyBootProofWire): DecodedBootProof {
  const coseBytes = decodeBase64(bootProof.awsAttestationDocB64);
  const coseSign1 = CBOR.decode(exactArrayBuffer(coseBytes));
  if (!Array.isArray(coseSign1) || coseSign1.length !== 4) {
    throw new TvcError("BootProofUnverified");
  }
  const payload = asBytes(coseSign1[2]);
  const decoded = CBOR.decode(exactArrayBuffer(payload));
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
    throw new TvcError("BootProofUnverified");
  }
  const attestation = decoded as AwsNitroAttestationDocument;
  const certificate = asBytes(attestation.certificate);
  if (!Array.isArray(attestation.cabundle)) {
    throw new TvcError("BootProofUnverified");
  }
  const cabundle = attestation.cabundle.map(asBytes);
  return { coseSign1, attestation, certificate, cabundle };
}

function validateAttestationShape(attestation: AwsNitroAttestationDocument): void {
  if (typeof attestation.module_id !== "string" || attestation.module_id.length === 0) {
    throw new TvcError("BootProofUnverified");
  }
  if (attestation.digest !== "SHA384") {
    throw new TvcError("BootProofUnverified");
  }
  if (
    typeof attestation.timestamp !== "number" ||
    !Number.isSafeInteger(attestation.timestamp) ||
    attestation.timestamp <= 0
  ) {
    throw new TvcError("BootProofUnverified");
  }
  if (attestation.nonce !== null && attestation.nonce !== undefined) {
    throw new TvcError("BootProofUnverified");
  }
  if (!attestation.pcrs || typeof attestation.pcrs !== "object") {
    throw new TvcError("BootProofUnverified");
  }
  if (Object.keys(attestation.pcrs).length !== QOS_ATTESTABLE_PCR_COUNT) {
    throw new TvcError("BootProofUnverified");
  }
  for (let index = 0; index < QOS_ATTESTABLE_PCR_COUNT; index += 1) {
    getPcr(attestation, index);
  }
}

function verifyProofBindings(
  input: VerifyBootProofInput,
  attestation: AwsNitroAttestationDocument,
): void {
  if (input.allowedManifestSha256.length === 0) {
    throw new TvcError("BootProofUnverified");
  }
  const allowed = input.allowedManifestSha256.map((value) =>
    decodeFixedLowerHex(value, SHA256_LENGTH),
  );
  // QOS commits VersionedManifest::manifest_hash(), not SHA-256 over the
  // serialized Borsh bytes carried in qosManifestB64.
  const manifestDigest = asBytes(attestation.user_data);
  if (
    manifestDigest.length !== SHA256_LENGTH ||
    !allowed.some((digest) => bytesEqual(digest, manifestDigest))
  ) {
    throw new TvcError("BootProofUnverified");
  }

  const attestedPublicKey = asBytes(attestation.public_key);
  if (attestedPublicKey.length !== QOS_EPHEMERAL_PUBLIC_KEY_LENGTH) {
    throw new TvcError("BootProofUnverified");
  }
  const appPublicKey = decodeFixedLowerHex(
    input.appProof.publicKey,
    QOS_EPHEMERAL_PUBLIC_KEY_LENGTH,
  );
  const bootPublicKey = decodeFixedLowerHex(
    input.bootProof.ephemeralPublicKeyHex,
    QOS_EPHEMERAL_PUBLIC_KEY_LENGTH,
  );
  if (!bytesEqual(appPublicKey, bootPublicKey) || !bytesEqual(bootPublicKey, attestedPublicKey)) {
    throw new TvcError("BootProofUnverified");
  }

  for (const index of [0, 1, 2, 3] as const) {
    const expected = decodeFixedLowerHex(input.expectedPcrs[index], SHA384_LENGTH);
    if (!bytesEqual(expected, getPcr(attestation, index))) {
      throw new TvcError("BootProofUnverified");
    }
  }

  const expectedLivePcr = computeQosLiveManifestCommitmentPcr(manifestDigest, attestedPublicKey);
  if (!bytesEqual(expectedLivePcr, getPcr(attestation, QOS_LIVE_MANIFEST_COMMITMENT_PCR_INDEX))) {
    throw new TvcError("BootProofUnverified");
  }
}

function getPcr(attestation: AwsNitroAttestationDocument, index: number): Uint8Array {
  const pcrs = attestation.pcrs as Record<string, unknown>;
  const value = pcrs[String(index)];
  const bytes = asBytes(value);
  if (bytes.length !== SHA384_LENGTH) {
    throw new TvcError("BootProofUnverified");
  }
  return bytes;
}

function decodeFixedLowerHex(value: string, length: number): Uint8Array {
  const bytes = decodeLowerHex(value);
  if (bytes.length !== length) {
    throw new TvcError("BootProofUnverified");
  }
  return bytes;
}

function decodeBase64(value: string): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new TvcError("BootProofUnverified");
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new TvcError("BootProofUnverified");
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function asBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new TvcError("BootProofUnverified");
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
