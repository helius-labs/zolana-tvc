import { gcm } from "@noble/ciphers/aes";
import { randomBytes } from "@noble/hashes/utils";

import { fetchWithSignal, gatewayUrl, httpError, readBoundedBytes, readBoundedText } from "../client/http.js";
import { createDefaultTransport, type TvcTransport } from "../client/transport.js";
import { TvcError, TvcHttpError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type {
  ProverRequest,
  ProverSealing,
  SealedProverRequest,
  SignedProverPolicy,
} from "../protocol/types.js";

/** The encrypted prover wire contract, v1 (zolana `prover/tee/WIRE_CONTRACT.md`). */
const HEADER_VERSION = "Zolana-Tee";
const HEADER_ENC = "Zolana-Tee-Enc";
const VERSION = "v1";
const ATTESTATION_PATH = "tee/v1/attestation";
/** The prover no longer holds the key the request was sealed to. */
const KEY_LOST = "tee_decryption_failed";
const MAX_ATTESTATION_BYTES = 1n << 20n;
const MAX_ANSWER_BYTES = 1n << 20n;
const MAX_ERROR_BYTES = 4096n;
const RESPONSE_NONCE_BYTES = 12;
/** Mirrors the enclave's `MAX_PROVER_TARGET_LEN`. */
const MAX_TARGET_LENGTH = 256;
const MAX_PROVE_INPUTS = 54;
const PLAIN_SEGMENT = /^[A-Za-z0-9_-]+$/;
const FAMILIES: Readonly<Record<string, string>> = {
  "transfer-confidential": "transfer_confidential",
  "transfer-ring": "transfer_ring",
  merge: "merge",
  "merge-ring": "merge_ring",
};

/**
 * Where the client proves and under which policy. `url` is the prover's base
 * URL, such as `https://<gatekeeper>/v1/zolana?api-key=<key>`: the attestation
 * and proof routes are appended to its path and its query is kept.
 */
export type TvcProverConfig = {
  readonly url: string;
  /**
   * The base path the prover itself receives requests on, such as `/v1/zolana`,
   * when a proxy serves `url` on another path. The enclave binds a sealed
   * request to `<proverPath>/prove/<key>`. Defaults to `url`'s path.
   */
  readonly proverPath?: string;
  readonly policy: SignedProverPolicy;
  readonly transport?: TvcTransport;
};

/** A prover's answer to a sealed request that could not be opened as a proof. */
export type ProverAnswer =
  | { readonly kind: "proof"; readonly body: unknown }
  | { readonly kind: "keyLost" };

function slotCount(value: unknown): number {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_PROVE_INPUTS) {
    throw new TvcError("InvalidProverRequest");
  }
  return value.length;
}

/** The proving key file name, without `.key`; mirrors the enclave's `proving_key`. */
export function provingKeyName(request: ProverRequest): string {
  const circuit = request["circuitType"];
  const family = typeof circuit === "string" && Object.hasOwn(FAMILIES, circuit) ? FAMILIES[circuit] : undefined;
  if (family === undefined || typeof circuit !== "string") throw new TvcError("InvalidProverRequest");
  const inputs = slotCount(request["inputs"]);
  const outputs = circuit.startsWith("merge") ? 1 : slotCount(request["outputs"]);
  return `${family}_${inputs}_${outputs}`;
}

/** The route a request for `key` is sealed to under the prover's base path. */
export function proverTarget(proverPath: string, key: string): string {
  return `${proverPath.replace(/\/+$/, "")}/prove/${key}`;
}

/** Mirrors the enclave's check: `key`'s route under plain path segments, no query. */
export function isProverTarget(target: string, key: string): boolean {
  const suffix = `/prove/${key}`;
  if (target.length > MAX_TARGET_LENGTH || !target.endsWith(suffix)) return false;
  const prefix = target.slice(0, target.length - suffix.length);
  if (prefix === "") return true;
  return prefix.startsWith("/") && prefix.slice(1).split("/").every((segment) => PLAIN_SEGMENT.test(segment));
}

/** A prover's attestation for one nonce, and when the client fetched it. */
export type ProverAttestation = {
  readonly nonce: string;
  readonly attestation: Readonly<Record<string, unknown>>;
  readonly fetchedAtMs: number;
};

/**
 * Asks the prover to attest for a fresh nonce. The enclave verifies the
 * attestation; the client only carries it.
 */
export async function fetchAttestation(
  config: TvcProverConfig,
  signal?: AbortSignal,
): Promise<ProverAttestation> {
  const nonce = encodeLowerHex(randomBytes(32));
  const url = gatewayUrl(new URL(config.url), ATTESTATION_PATH);
  url.searchParams.set("nonce", nonce);
  const transport = config.transport ?? createDefaultTransport();
  const response = await fetchWithSignal(transport, url, { method: "GET", redirect: "error" }, signal);
  if (!response.ok) throw httpError(response, "ProverAttestationUnavailable");
  let attestation: unknown;
  try {
    attestation = JSON.parse(await readBoundedText(response, MAX_ATTESTATION_BYTES, signal));
  } catch (error) {
    if (error instanceof TvcError && error.code === "ResponseTooLarge") throw error;
    throw new TvcError("ProverAttestationInvalid");
  }
  if (typeof attestation !== "object" || attestation === null || Array.isArray(attestation)) {
    throw new TvcError("ProverAttestationInvalid");
  }
  return { nonce, attestation: attestation as Record<string, unknown>, fetchedAtMs: Date.now() };
}

/** What the enclave needs to seal `request` to the attested prover. */
export function sealingFor(
  config: TvcProverConfig,
  attested: ProverAttestation,
  request: ProverRequest,
): ProverSealing {
  return {
    target: proverTarget(config.proverPath ?? new URL(config.url).pathname, provingKeyName(request)),
    nonce: attested.nonce,
    attestation: attested.attestation,
    policy: config.policy,
  };
}

/**
 * How long the policy lets one attestation serve further proofs: its
 * `max_age_secs`, and never past the policy's expiry. Zero without one.
 */
export function attestationReuseMs(policy: SignedProverPolicy, nowMs: number): number {
  const maxAgeSecs = policy.policy.tee["max_age_secs"];
  if (typeof maxAgeSecs !== "number" || !Number.isSafeInteger(maxAgeSecs) || maxAgeSecs <= 0) return 0;
  const untilExpiry = Number(policy.policy.expiresAtMs) - nowMs;
  return Math.max(0, Math.min(maxAgeSecs * 1_000, untilExpiry));
}

/**
 * Posts a sealed request to its proving key's route under `url` and opens the
 * answer. A prover that rebooted onto a new key answers `keyLost`, and the
 * caller attests again.
 */
export async function submitSealed(
  config: TvcProverConfig,
  sealed: SealedProverRequest,
  signal?: AbortSignal,
): Promise<ProverAnswer> {
  const key = sealed.target.slice(sealed.target.lastIndexOf("/prove/") + "/prove/".length);
  const url = gatewayUrl(new URL(config.url), `prove/${key}`);
  const transport = config.transport ?? createDefaultTransport();
  const response = await fetchWithSignal(
    transport,
    url,
    {
      method: "POST",
      headers: {
        [HEADER_VERSION]: VERSION,
        [HEADER_ENC]: sealed.enc,
        "content-type": "application/octet-stream",
      },
      body: new Uint8Array(decodeLowerHex(sealed.ciphertext)),
      redirect: "error",
    },
    signal,
  );
  if (response.headers.get(HEADER_VERSION) !== VERSION) {
    if (response.ok) {
      void response.body?.cancel().catch(() => undefined);
      throw new TvcError("ProverAnswerUnencrypted");
    }
    if (response.status === 400 && (await errorCode(response, signal)) === KEY_LOST) {
      return { kind: "keyLost" };
    }
    throw httpError(response, "ProverRefused");
  }
  const { status, body } = decryptProverAnswer(
    decodeLowerHex(sealed.response_key),
    await readBoundedBytes(response, MAX_ANSWER_BYTES, signal),
  );
  if (status < 200 || status >= 300) {
    throw new TvcHttpError("ProverRefused", status, response.headers.get("retry-after"));
  }
  try {
    return { kind: "proof", body: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)) };
  } catch {
    throw new TvcError("ProverAnswerInvalid");
  }
}

/**
 * Opens an answer under the wire contract: a 12-byte nonce, then AES-256-GCM
 * over the status as a big-endian `u16` followed by the body.
 */
export function decryptProverAnswer(
  responseKey: Uint8Array,
  encrypted: Uint8Array,
): { status: number; body: Uint8Array } {
  let plaintext: Uint8Array;
  try {
    plaintext = gcm(responseKey, encrypted.subarray(0, RESPONSE_NONCE_BYTES)).decrypt(
      encrypted.subarray(RESPONSE_NONCE_BYTES),
    );
  } catch {
    throw new TvcError("ProverAnswerInvalid");
  }
  if (plaintext.length < 2) throw new TvcError("ProverAnswerInvalid");
  return {
    status: new DataView(plaintext.buffer, plaintext.byteOffset).getUint16(0, false),
    body: plaintext.subarray(2),
  };
}

async function errorCode(response: Response, signal?: AbortSignal): Promise<string | undefined> {
  try {
    const answer: unknown = JSON.parse(await readBoundedText(response.clone(), MAX_ERROR_BYTES, signal));
    return typeof answer === "object" && answer !== null && "code" in answer && typeof answer.code === "string"
      ? answer.code
      : undefined;
  } catch {
    return undefined;
  }
}
