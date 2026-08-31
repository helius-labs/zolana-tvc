//! Request bindings against the running enclave / independently accepted release.

use crate::error::{ErrorCode, TvcError};
use crate::types::{EncryptedRequestV1, Environment, OperationRequestV1};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningEnclave {
    pub release_id: String,
    pub manifest_digest: [u8; 32],
    pub executable_digest: [u8; 32],
    pub security_domain_id: [u8; 32],
    pub quorum_key_id: String,
    pub quorum_key_epoch: u64,
    pub environment: Environment,
}

pub fn check_encrypted_request_bindings(
    outer: &EncryptedRequestV1,
    running: &RunningEnclave,
) -> Result<(), TvcError> {
    if outer.version != crate::constants::API_VERSION {
        return Err(TvcError::new(ErrorCode::UnsupportedVersion));
    }
    if outer.quorum_key_id != running.quorum_key_id {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if outer.quorum_key_epoch != running.quorum_key_epoch {
        return Err(TvcError::new(ErrorCode::QuorumKeyEpochMismatch));
    }
    Ok(())
}

pub fn check_request_bindings(
    request: &OperationRequestV1,
    running: &RunningEnclave,
) -> Result<(), TvcError> {
    if request.version != crate::constants::API_VERSION {
        return Err(TvcError::new(ErrorCode::UnsupportedVersion));
    }
    crate::types::reject_production_environment(request.wallet_descriptor.environment)?;
    if request.wallet_descriptor.environment != running.environment {
        return Err(TvcError::new(ErrorCode::WalletBindingMismatch));
    }
    if request.target_release_id != running.release_id
        || request.target_manifest_digest != running.manifest_digest
        || request.target_executable_digest != running.executable_digest
    {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if request.wallet_descriptor.security_domain_id != running.security_domain_id {
        return Err(TvcError::new(ErrorCode::WalletBindingMismatch));
    }
    if request.wallet_descriptor.wallet_id.is_empty() {
        return Err(TvcError::new(ErrorCode::InvalidWalletDescriptor));
    }
    if request.quorum_key_id != running.quorum_key_id {
        return Err(TvcError::new(ErrorCode::ReleaseBindingMismatch));
    }
    if request.quorum_key_epoch != running.quorum_key_epoch {
        return Err(TvcError::new(ErrorCode::QuorumKeyEpochMismatch));
    }
    Ok(())
}
