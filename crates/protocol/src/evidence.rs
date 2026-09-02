//! Turnkey App Proof signature checks.

use serde::Deserialize;

use crate::crypto::{verify_turnkey_app_proof_p256_message, QosP256Public};
use crate::error::{ErrorCode, TvcError};

#[derive(Debug, Deserialize)]
struct ProofPayloadType {
    #[serde(rename = "type")]
    proof_type: String,
}

const POLICY_OUTCOME: &str = "APP_PROOF_TYPE_POLICY_OUTCOME";
const ADDRESS_DERIVATION: &str = "APP_PROOF_TYPE_ADDRESS_DERIVATION";

/// Verifies a documented Turnkey App Proof over its exact UTF-8 payload bytes.
///
/// Turnkey promises neither RFC 8785 ordering nor low-S signatures, so both
/// forms verify. The proof is cryptographically valid but its
/// `decisionContextDigest` cannot yet be bound to an activity, key, or intent.
pub fn verify_turnkey_app_proof(
    proof_payload_utf8: &str,
    qos_public_key: &[u8],
    signature: &[u8],
) -> Result<(), TvcError> {
    let parsed: ProofPayloadType = serde_json::from_str(proof_payload_utf8)
        .map_err(|_| TvcError::new(ErrorCode::TurnkeyEvidenceInvalid))?;
    match parsed.proof_type.as_str() {
        POLICY_OUTCOME | ADDRESS_DERIVATION => {}
        _ => return Err(TvcError::new(ErrorCode::UnsupportedProofPath)),
    }
    let public = QosP256Public::from_bytes(qos_public_key)?;
    verify_turnkey_app_proof_p256_message(&public.signing, proof_payload_utf8.as_bytes(), signature)
        .map_err(|_| TvcError::new(ErrorCode::TurnkeyEvidenceInvalid))
}
