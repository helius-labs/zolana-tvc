//! Direct P-256/SHA-256 client authorization. No generic signer API.

use crate::crypto::{sign_p256_prehash, verify_p256_prehash};
use crate::digest::{client_auth_digest, request_digest};
use crate::error::{ErrorCode, TvcError};
use crate::types::{ClientAuthorizationScheme, OperationRequestV1};

pub fn authorize_operation_request(
    mut request: OperationRequestV1,
    client_secret: &[u8; 32],
) -> Result<OperationRequestV1, TvcError> {
    if request.authorization.scheme != ClientAuthorizationScheme::P256Sha256 {
        return Err(TvcError::new(ErrorCode::UnauthorizedClient));
    }
    let digest = client_auth_digest(&request_digest(&request)?);
    request.authorization.signature = sign_p256_prehash(client_secret, &digest)?.to_vec();
    Ok(request)
}

pub fn verify_client_authorization(
    request: &OperationRequestV1,
    client_public_sec1: &[u8],
) -> Result<(), TvcError> {
    if request.authorization.scheme != ClientAuthorizationScheme::P256Sha256 {
        return Err(TvcError::new(ErrorCode::UnauthorizedClient));
    }
    if request.authorization.client_key_id.is_empty() {
        return Err(TvcError::new(ErrorCode::UnauthorizedClient));
    }
    let digest = client_auth_digest(&request_digest(request)?);
    verify_p256_prehash(
        client_public_sec1,
        &digest,
        &request.authorization.signature,
    )
    .map_err(|_| TvcError::new(ErrorCode::UnauthorizedClient))
}
