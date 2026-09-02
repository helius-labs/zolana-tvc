//! Domain-separated SHA-256 digest constructors.

use sha2::{Digest, Sha256};

use crate::constants::{
    CLIENT_AUTH_DOMAIN, PROVISIONING_AUTH_DOMAIN, RELEASE_POLICY_DOMAIN, REQUEST_DIGEST_DOMAIN,
    REQUEST_ID_HASH_DOMAIN, RESULT_DIGEST_DOMAIN, STATE_DIGEST_DOMAIN, WALLET_ID_HASH_DOMAIN,
};
use crate::encoding::{self, canonicalize_json_value};
use crate::error::{ErrorCode, TvcError};
use crate::types::OperationRequest;

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

/// `request_digest` omits only `authorization.signature`. `client_key_id` and scheme stay.
pub fn request_digest(request: &OperationRequest) -> Result<[u8; 32], TvcError> {
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

pub fn descriptor_digest_bytes(
    descriptor_without_auth: &serde_json::Value,
) -> Result<[u8; 32], TvcError> {
    let canonical = canonicalize_json_value(descriptor_without_auth)?;
    Ok(domain_separated_hash(
        PROVISIONING_AUTH_DOMAIN,
        canonical.as_bytes(),
    ))
}

pub fn descriptor_digest(
    descriptor: &crate::types::WalletDescriptor,
) -> Result<[u8; 32], TvcError> {
    let mut value = encoding::to_canonical_value(descriptor)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
    object.remove("provisioning_signature");
    descriptor_digest_bytes(&value)
}

pub fn result_digest(encrypted_result: &[u8]) -> [u8; 32] {
    domain_separated_hash(RESULT_DIGEST_DOMAIN, encrypted_result)
}

/// Digest of the exact sealed-state wire bytes.
pub fn state_digest(sealed_state: &[u8]) -> [u8; 32] {
    domain_separated_hash(STATE_DIGEST_DOMAIN, sealed_state)
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
