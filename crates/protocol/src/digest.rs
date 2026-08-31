//! Domain-separated SHA-256 digest constructors.

use sha2::{Digest, Sha256};

use crate::constants::{
    ARTIFACT_DIGEST_DOMAIN, CLIENT_AUTH_DOMAIN, OWNER_AUTH_EVIDENCE_DOMAIN,
    PROVISIONING_AUTH_DOMAIN, RELEASE_POLICY_DOMAIN, REQUEST_DIGEST_DOMAIN, REQUEST_ID_HASH_DOMAIN,
    RESULT_DIGEST_DOMAIN, STATE_COMMITMENT_DOMAIN, STATE_DIGEST_DOMAIN, WALLET_ID_HASH_DOMAIN,
};
use crate::encoding::{self, canonicalize_json_value};
use crate::error::{ErrorCode, TvcError};
use crate::types::{
    DescriptorRotationAuthorizationV1, OperationRequestV1, OwnerAuthorizationKeyV1,
    OwnerAuthorizationV1, SealedWalletStateV1,
};

pub fn domain_separated_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0u8]);
    hasher.update(payload);
    hasher.finalize().into()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn u64_be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// `request_digest` omits only `authorization.signature`. `client_key_id` and scheme stay.
pub fn request_digest(request: &OperationRequestV1) -> Result<[u8; 32], TvcError> {
    let mut value = encoding::to_canonical_value(request)?;
    let authorization = value
        .get_mut("authorization")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
    if authorization.remove("signature").is_none() {
        return Err(TvcError::new(ErrorCode::InvalidCanonicalJson));
    }
    if !authorization.contains_key("client_key_id") || !authorization.contains_key("scheme") {
        return Err(TvcError::new(ErrorCode::InvalidCanonicalJson));
    }
    let canonical = canonicalize_json_value(&value)?;
    Ok(domain_separated_hash(
        REQUEST_DIGEST_DOMAIN,
        canonical.as_bytes(),
    ))
}

pub fn client_auth_digest(request_digest_bytes: &[u8; 32]) -> [u8; 32] {
    domain_separated_hash(CLIENT_AUTH_DOMAIN, request_digest_bytes)
}

pub fn owner_auth_evidence_digest(
    owner_key: &Option<OwnerAuthorizationKeyV1>,
    owner_authorization: &Option<OwnerAuthorizationV1>,
    prior_client_authorization: &Option<DescriptorRotationAuthorizationV1>,
) -> Result<[u8; 32], TvcError> {
    let value = serde_json::json!([
        encoding::to_canonical_value(owner_key)?,
        encoding::to_canonical_value(owner_authorization)?,
        encoding::to_canonical_value(prior_client_authorization)?,
    ]);
    let canonical = canonicalize_json_value(&value)?;
    Ok(domain_separated_hash(
        OWNER_AUTH_EVIDENCE_DOMAIN,
        canonical.as_bytes(),
    ))
}

pub fn descriptor_digest_bytes(
    descriptor_without_auth: &serde_json::Value,
) -> Result<[u8; 32], TvcError> {
    let canonical = canonicalize_json_value(descriptor_without_auth)?;
    Ok(domain_separated_hash(
        PROVISIONING_AUTH_DOMAIN,
        canonical.as_bytes(),
    ))
}

pub fn descriptor_digest_from_wallet(
    descriptor: &crate::types::WalletDescriptorV1,
) -> Result<[u8; 32], TvcError> {
    let mut value = encoding::to_canonical_value(descriptor)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
    object.remove("provisioning_signature");
    object.remove("owner_authorization");
    object.remove("prior_client_authorization");
    descriptor_digest_bytes(&value)
}

pub fn provisioning_auth_digest(
    descriptor_digest: &[u8; 32],
    owner_evidence_digest: &[u8; 32],
) -> [u8; 32] {
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(descriptor_digest);
    payload[32..].copy_from_slice(owner_evidence_digest);
    domain_separated_hash(PROVISIONING_AUTH_DOMAIN, &payload)
}

pub fn result_digest(encrypted_result: &[u8]) -> [u8; 32] {
    domain_separated_hash(RESULT_DIGEST_DOMAIN, encrypted_result)
}

pub fn state_digest(state: &SealedWalletStateV1) -> Result<[u8; 32], TvcError> {
    let encoded =
        borsh::to_vec(state).map_err(|_| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
    Ok(domain_separated_hash(STATE_DIGEST_DOMAIN, &encoded))
}

pub fn artifact_digest(artifact: &[u8]) -> [u8; 32] {
    domain_separated_hash(ARTIFACT_DIGEST_DOMAIN, artifact)
}

pub fn wallet_id_hash(wallet_id: &str) -> [u8; 32] {
    domain_separated_hash(WALLET_ID_HASH_DOMAIN, wallet_id.as_bytes())
}

pub fn request_id_hash(request_id: &[u8; 32]) -> [u8; 32] {
    domain_separated_hash(REQUEST_ID_HASH_DOMAIN, request_id)
}

pub fn release_policy_digest(policy_jcs: &[u8]) -> [u8; 32] {
    domain_separated_hash(RELEASE_POLICY_DOMAIN, policy_jcs)
}

pub fn state_commitment(
    wallet_ed25519_public_key: &[u8; 32],
    generation: u64,
    state_digest_bytes: &[u8; 32],
    descriptor_digest_bytes: &[u8; 32],
    quorum_key_epoch: u64,
    recovery_epoch: u64,
    sealed_state_salt: &[u8; 32],
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(32 + 8 + 32 + 32 + 8 + 8 + 32);
    payload.extend_from_slice(wallet_ed25519_public_key);
    payload.extend_from_slice(&u64_be(generation));
    payload.extend_from_slice(state_digest_bytes);
    payload.extend_from_slice(descriptor_digest_bytes);
    payload.extend_from_slice(&u64_be(quorum_key_epoch));
    payload.extend_from_slice(&u64_be(recovery_epoch));
    payload.extend_from_slice(sealed_state_salt);
    domain_separated_hash(STATE_COMMITMENT_DOMAIN, &payload)
}
