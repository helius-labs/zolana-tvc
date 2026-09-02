import { parseQosP256Public } from "../crypto/qos.js";
import { verifyTurnkeyAppProofP256Message } from "../crypto/p256.js";
import { TvcError } from "../protocol/error.js";
import { assertNotProductionVerifier } from "./internal/turnkey-proof-seam.js";

export {
  computeQosLiveManifestCommitmentPcr,
  verifyBootProof,
} from "./boot-proof.js";
export type {
  QosIdentityPcrIndex,
  QosIdentityPcrs,
  VerifyBootProofInput,
} from "./boot-proof.js";

const POLICY_OUTCOME = "APP_PROOF_TYPE_POLICY_OUTCOME";
const ADDRESS_DERIVATION = "APP_PROOF_TYPE_ADDRESS_DERIVATION";

/**
 * Verifies a documented Turnkey App Proof over its exact UTF-8 payload bytes.
 * The proof is cryptographically valid but not yet bound to an activity or
 * intent: Turnkey signs the exact JSON bytes and claims no RFC 8785 ordering.
 */
export function verifyTurnkeyAppProof(
  proofPayloadUtf8: string,
  qosPublicKey: Uint8Array,
  signature: Uint8Array,
): void {
  assertNotProductionVerifier();
  let proofType: string;
  try {
    proofType = (JSON.parse(proofPayloadUtf8) as { type?: string }).type ?? "";
  } catch {
    throw new TvcError("TurnkeyEvidenceInvalid");
  }
  if (proofType !== POLICY_OUTCOME && proofType !== ADDRESS_DERIVATION) {
    throw new TvcError("UnsupportedProofPath");
  }
  const publicKey = parseQosP256Public(qosPublicKey);
  try {
    verifyTurnkeyAppProofP256Message(
      publicKey.signing,
      new TextEncoder().encode(proofPayloadUtf8),
      signature
    );
  } catch {
    throw new TvcError("TurnkeyEvidenceInvalid");
  }
}
