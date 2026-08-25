import { parseQosP256Public } from "../crypto/qos.js";
import { verifyTurnkeyAppProofP256Message } from "../crypto/p256.js";
import { TvcError } from "../protocol/error.js";
import type { TurnkeyEvidenceClassification } from "../protocol/types.js";
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

export function classifyTurnkeyPolicyEvidence(
  proofPayloadUtf8: string,
  qosPublicKey: Uint8Array,
  signature: Uint8Array
): TurnkeyEvidenceClassification {
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
  // Turnkey signs the exact JSON bytes but does not claim RFC 8785 ordering.
  // JCS remains mandatory for Zolana's own TVC App Proof payloads.
  return "CryptographicallyValidButUnbound";
}
