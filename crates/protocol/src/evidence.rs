//! Turnkey policy-evidence classification. No `Verified` outcome exists.

use serde::Deserialize;

use crate::crypto::{verify_p256_message, QosP256Public};
use crate::encoding::is_rfc8785;
use crate::error::{ErrorCode, TvcError};
use crate::types::TurnkeyEvidenceClassification;

#[derive(Debug, Deserialize)]
struct ProofPayloadType {
    #[serde(rename = "type")]
    proof_type: String,
}

const POLICY_OUTCOME: &str = "APP_PROOF_TYPE_POLICY_OUTCOME";
const ADDRESS_DERIVATION: &str = "APP_PROOF_TYPE_ADDRESS_DERIVATION";

/// Classify a documented Turnkey App Proof.
///
/// Signature verification uses the exact received UTF-8 bytes. The result is
/// never production-verified: `decisionContextDigest` cannot be bound to an
/// activity/key/intent, so success is `CryptographicallyValidButUnbound`.
pub fn classify_turnkey_policy_evidence(
    proof_payload_utf8: &str,
    qos_public_key: &[u8],
    signature: &[u8],
) -> Result<TurnkeyEvidenceClassification, TvcError> {
    let parsed: ProofPayloadType = serde_json::from_str(proof_payload_utf8)
        .map_err(|_| TvcError::new(ErrorCode::TurnkeyEvidenceInvalid))?;
    match parsed.proof_type.as_str() {
        POLICY_OUTCOME | ADDRESS_DERIVATION => {}
        _ => return Err(TvcError::new(ErrorCode::UnsupportedProofPath)),
    }

    let public = QosP256Public::from_bytes(qos_public_key)?;
    verify_p256_message(&public.signing, proof_payload_utf8.as_bytes(), signature)
        .map_err(|_| TvcError::new(ErrorCode::TurnkeyEvidenceInvalid))?;

    if !is_rfc8785(proof_payload_utf8) {
        return Err(TvcError::new(ErrorCode::InvalidCanonicalJson));
    }

    Ok(TurnkeyEvidenceClassification::CryptographicallyValidButUnbound)
}
