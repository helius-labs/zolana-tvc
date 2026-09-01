import {
  QOS_P256_PUBLIC_LEN,
  RAW_P256_SIGNATURE_LEN,
} from "../protocol/constants.js";
import { TvcError } from "../protocol/error.js";
import { decodeLowerHex } from "../protocol/hex.js";
import type { TurnkeyVerifiedAppProofV1 } from "../protocol/types.js";
import { classifyTurnkeyPolicyEvidence } from "../verify/index.js";
import type { TurnkeyAppProofWire } from "../verify/internal/turnkey-proof-seam.js";
import { assertExactObjectKeys } from "./http.js";

const TVC_APP_PROOF_KEYS = ["scheme", "public_key", "proof_payload", "signature"] as const;

export type TvcTrustVerifier = {
  verifyOperationAppProof(proof: TurnkeyAppProofWire): Promise<void>;
  verifyCustodyProofs(proofs: readonly TurnkeyVerifiedAppProofV1[]): void;
};

function requireHex(input: string, length: number): Uint8Array {
  const bytes = decodeLowerHex(input);
  if (bytes.length !== length) throw new TvcError("InvalidHex");
  return bytes;
}

export function verifyTurnkeyCustodyProofs(
  proofs: readonly TurnkeyVerifiedAppProofV1[],
): void {
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
