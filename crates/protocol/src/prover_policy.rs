//! The prover policy a `Prove` seals under: which measured provers the
//! enclave may encrypt a witness to, signed by the prover policy key the
//! enclave is built with.
//!
//! The signature covers `PROVER_POLICY_DOMAIN || 0x00 || JCS(policy)` with
//! 64-byte raw low-S P-256. A policy expires, so a retired prover drops out by
//! the operator signing no newer policy that names it.

use crate::constants::API_VERSION;
use crate::crypto::{sign_p256_prehash, verify_p256_prehash};
use crate::digest::prover_policy_digest;
use crate::encoding::{self, jcs_serialize};
use crate::error::{ErrorCode, TvcError};
use crate::types::{ClientAuthorizationScheme, ProverPolicy, SignedProverPolicy};

pub fn prover_policy_signing_digest(policy: &ProverPolicy) -> Result<[u8; 32], TvcError> {
    let canonical = jcs_serialize(policy)?;
    Ok(prover_policy_digest(canonical.as_bytes()))
}

pub fn sign_prover_policy(
    policy: ProverPolicy,
    secret: &[u8; 32],
) -> Result<SignedProverPolicy, TvcError> {
    let signature = sign_p256_prehash(secret, &prover_policy_signing_digest(&policy)?)?;
    Ok(SignedProverPolicy {
        policy,
        scheme: ClientAuthorizationScheme::P256Sha256,
        signature: signature.to_vec(),
    })
}

/// Accepts a policy signed by `policy_public` and current at `now_ms`.
pub fn verify_signed_prover_policy(
    signed: &SignedProverPolicy,
    policy_public: &[u8],
    now_ms: u64,
) -> Result<(), TvcError> {
    if signed.policy.version != API_VERSION {
        return Err(TvcError::new(ErrorCode::UnsupportedVersion));
    }
    if signed.scheme != ClientAuthorizationScheme::P256Sha256 {
        return Err(TvcError::new(ErrorCode::InvalidSignature));
    }
    if !signed.policy.tee.is_object() {
        return Err(TvcError::new(ErrorCode::ProverPolicyInvalid));
    }
    if signed.policy.valid_from_ms > signed.policy.expires_at_ms {
        return Err(TvcError::new(ErrorCode::ProverPolicyInvalid));
    }
    if now_ms < signed.policy.valid_from_ms || now_ms > signed.policy.expires_at_ms {
        return Err(TvcError::new(ErrorCode::ExpiredRequest));
    }
    let digest = prover_policy_signing_digest(&signed.policy)?;
    verify_p256_prehash(policy_public, &digest, &signed.signature)?;
    let _ = encoding::to_canonical_value(&signed.policy)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;

    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    fn key() -> ([u8; 32], Vec<u8>) {
        let secret = [7u8; 32];
        let public = SigningKey::from_slice(&secret)
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        (secret, public)
    }

    fn policy() -> ProverPolicy {
        ProverPolicy {
            version: API_VERSION,
            tee: serde_json::json!({
                "platform": "aws-nitro",
                "measurements": [{"pcr0": "01".repeat(48), "pcr1": "02".repeat(48), "pcr2": "03".repeat(48)}],
                "gpu": "optional",
                "max_age_secs": 600,
            }),
            valid_from_ms: NOW - 1_000,
            expires_at_ms: NOW + 1_000,
        }
    }

    #[test]
    fn a_signed_policy_verifies_only_under_its_key_and_lifetime() {
        let (secret, public) = key();
        let signed = sign_prover_policy(policy(), &secret).unwrap();
        verify_signed_prover_policy(&signed, &public, NOW).unwrap();

        let (_, other) = {
            let secret = [8u8; 32];
            (
                secret,
                SigningKey::from_slice(&secret)
                    .unwrap()
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
            )
        };
        assert_eq!(
            verify_signed_prover_policy(&signed, &other, NOW)
                .unwrap_err()
                .code,
            ErrorCode::InvalidSignature
        );
        for now in [NOW - 2_000, NOW + 2_000] {
            assert_eq!(
                verify_signed_prover_policy(&signed, &public, now)
                    .unwrap_err()
                    .code,
                ErrorCode::ExpiredRequest
            );
        }

        let mut tampered = signed.clone();
        tampered.policy.expires_at_ms += 1;
        assert_eq!(
            verify_signed_prover_policy(&tampered, &public, NOW)
                .unwrap_err()
                .code,
            ErrorCode::InvalidSignature
        );
    }

    #[test]
    fn a_policy_without_a_tee_object_or_with_an_inverted_lifetime_is_refused() {
        let (secret, public) = key();
        let mut bare = policy();
        bare.tee = serde_json::Value::Null;
        let signed = sign_prover_policy(bare, &secret).unwrap();
        assert_eq!(
            verify_signed_prover_policy(&signed, &public, NOW)
                .unwrap_err()
                .code,
            ErrorCode::ProverPolicyInvalid
        );

        let mut inverted = policy();
        inverted.valid_from_ms = inverted.expires_at_ms + 1;
        let signed = sign_prover_policy(inverted, &secret).unwrap();
        assert_eq!(
            verify_signed_prover_policy(&signed, &public, NOW)
                .unwrap_err()
                .code,
            ErrorCode::ProverPolicyInvalid
        );
    }
}
