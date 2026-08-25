//! Independently pinned release-policy signatures.
//!
//! Signatures cover `RELEASE_POLICY_DOMAIN || 0x00 || JCS(policy)` with
//! 64-byte raw low-S P-256. Empty signatures fail closed. Duplicate and
//! unknown key IDs do not count toward the threshold.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::constants::API_VERSION;
use crate::crypto::{sign_p256_prehash, verify_p256_prehash};
use crate::digest::release_policy_digest;
use crate::encoding::{self, hex_bytes, jcs_serialize};
use crate::error::{ErrorCode, TvcError};
use crate::types::{ClientAuthorizationScheme, ReleasePolicyV1, SignedReleasePolicyV1};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseAuthorityKeyV1 {
    pub key_id: String,
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedReleaseAuthoritiesV1 {
    pub authority_set_id: String,
    pub threshold: u8,
    pub keys: Vec<ReleaseAuthorityKeyV1>,
}

pub fn policy_signing_digest(policy: &ReleasePolicyV1) -> Result<[u8; 32], TvcError> {
    let canonical = jcs_serialize(policy)?;
    Ok(release_policy_digest(canonical.as_bytes()))
}

pub fn sign_release_policy(
    policy: &ReleasePolicyV1,
    secret: &[u8; 32],
) -> Result<[u8; 64], TvcError> {
    sign_p256_prehash(secret, &policy_signing_digest(policy)?)
}

pub fn verify_signed_release_policy(
    signed: &SignedReleasePolicyV1,
    authorities: &PinnedReleaseAuthoritiesV1,
    now_ms: u64,
) -> Result<(), TvcError> {
    if signed.policy.version != API_VERSION {
        return Err(TvcError::new(ErrorCode::UnsupportedVersion));
    }
    crate::types::reject_production_environment(signed.policy.environment)?;
    if authorities.threshold == 0 || authorities.keys.is_empty() {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }
    if signed.authority_set_id != authorities.authority_set_id {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }
    if now_ms < signed.policy.valid_from_ms || now_ms > signed.policy.expires_at_ms {
        return Err(TvcError::new(ErrorCode::ExpiredRequest));
    }
    if signed.signatures.is_empty() {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }

    let mut by_id = HashMap::new();
    for key in &authorities.keys {
        if by_id
            .insert(key.key_id.as_str(), key.public_key.as_slice())
            .is_some()
        {
            return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
        }
    }

    let mut seen = HashSet::new();
    let mut duplicates = HashSet::new();
    for signature in &signed.signatures {
        if !seen.insert(signature.key_id.as_str()) {
            duplicates.insert(signature.key_id.as_str());
        }
    }

    let digest = policy_signing_digest(&signed.policy)?;
    let mut accepted = 0u8;
    for signature in &signed.signatures {
        if duplicates.contains(signature.key_id.as_str()) {
            continue;
        }
        let Some(public) = by_id.get(signature.key_id.as_str()) else {
            continue;
        };
        if signature.scheme != ClientAuthorizationScheme::P256Sha256 {
            return Err(TvcError::new(ErrorCode::InvalidSignature));
        }
        verify_p256_prehash(public, &digest, &signature.signature)?;
        accepted = accepted
            .checked_add(1)
            .ok_or_else(|| TvcError::new(ErrorCode::ReleasePolicyInvalid))?;
    }
    if accepted < authorities.threshold {
        return Err(TvcError::new(ErrorCode::ReleasePolicyInvalid));
    }
    let _ = encoding::to_canonical_value(&signed.policy)?;
    Ok(())
}

pub fn bind_discovery_to_policy(
    info: &crate::types::ServiceInfoV1,
    policy: &ReleasePolicyV1,
) -> Result<(), TvcError> {
    crate::types::reject_production_environment(info.environment)?;
    crate::types::reject_production_environment(policy.environment)?;
    if info.release_id != policy.release_id
        || info.quorum_key_id != policy.quorum_key_id
        || info.quorum_public_key != policy.quorum_public_key
    {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if info.quorum_key_epoch != policy.quorum_key_epoch {
        return Err(TvcError::new(ErrorCode::QuorumKeyEpochMismatch));
    }
    let manifest = crate::encoding::encode_lower_hex(&info.manifest_digest);
    let executable = crate::encoding::encode_lower_hex(&info.executable_digest);
    if !policy
        .accepted_manifest_digests
        .iter()
        .any(|value| value == &manifest)
        || !policy
            .accepted_executable_digests
            .iter()
            .any(|value| value == &executable)
    {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    Ok(())
}
