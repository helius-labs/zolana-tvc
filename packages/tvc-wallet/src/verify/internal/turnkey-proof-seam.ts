// THE SINGLE TURNKEY SEAM for @zolana/tvc-wallet.
//
// @turnkey/* may only be imported from this file. The composite development
// verifier uses Turnkey's pinned AWS Nitro COSE/X.509 helpers, then applies the
// Zolana release-policy and PCR checks outside this seam. It is still not a
// production verifier because production policy distribution and Turnkey
// decisionContextDigest binding are not available.

import * as turnkeyCrypto from "@turnkey/crypto";
import type {
  BaseAuthResult,
  v1AppProof,
  v1BootProof,
} from "@turnkey/sdk-types";
import * as x509 from "@peculiar/x509";
import CBOR from "cbor-js";

const AWS_NITRO_ROOT_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;

export const TURNKEY_TS_PROOF_PROFILE = {
  crypto: "2.11.3",
  sdkTypes: "1.5.1",
  productionVerifier: false,
  developmentBootProofVerifier: true,
  reason:
    "development composite verifier; production release-policy distribution and decisionContextDigest binding remain unavailable",
} as const;

export type TurnkeyAppProofWire = v1AppProof;
export type TurnkeyBootProofWire = v1BootProof;
export type TurnkeyBaseAuthAppProofWire = NonNullable<
  BaseAuthResult["appProofs"]
>[number];

export async function verifyTurnkeyAwsAttestation(
  coseSign1: unknown,
  certificate: Uint8Array,
  cabundle: Uint8Array[],
  timestampMs: number
): Promise<void> {
  await verifyCoseSign1Signature(coseSign1, certificate);
  await turnkeyCrypto.verifyCertificateChain(
    cabundle,
    AWS_NITRO_ROOT_CERT_PEM,
    certificate,
    timestampMs
  );
}

async function verifyCoseSign1Signature(
  coseSign1: unknown,
  leaf: Uint8Array
): Promise<void> {
  if (!Array.isArray(coseSign1) || coseSign1.length !== 4) {
    throw new Error("invalid COSE_Sign1");
  }
  const [protectedHeaders, , payload, signature] = coseSign1;
  const tbs = new Uint8Array(
    CBOR.encode([
      "Signature1",
      asBytes(protectedHeaders),
      new Uint8Array(0),
      asBytes(payload),
    ])
  );
  const cryptoInstance = await turnkeyCrypto.getCryptoInstance();
  const leafCertificate = new x509.X509Certificate(exactArrayBuffer(leaf));
  const publicKey = await cryptoInstance.subtle.importKey(
    "spki",
    leafCertificate.publicKey.rawData,
    { name: "ECDSA", namedCurve: "P-384" },
    false,
    ["verify"]
  );
  const valid = await cryptoInstance.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-384" } },
    publicKey,
    exactArrayBuffer(asBytes(signature)),
    exactArrayBuffer(tbs)
  );
  if (!valid) throw new Error("COSE_Sign1 ES384 verification failed");
}

function asBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new Error("expected CBOR byte string");
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}

export function assertNotProductionVerifier(): void {
  if (TURNKEY_TS_PROOF_PROFILE.productionVerifier) {
    throw new Error("production verifier flag must remain false");
  }
}
