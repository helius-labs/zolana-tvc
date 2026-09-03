//! Bounded unauthenticated HTTP skeleton for `/health` and `/v1/info`.

use crate::constants::{API_VERSION, DEVNET_MAX_ENCRYPTED_REQUEST_BYTES};
use crate::encoding::jcs_serialize;
use crate::error::PublicError;
use crate::types::{HealthResponse, HealthStatus, ServiceInfo};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicHttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

pub fn public_http_error(error: PublicError) -> PublicHttpResponse {
    let body = format!("{{\"error\":\"{}\"}}", error.as_str());
    PublicHttpResponse {
        status: error.status(),
        content_type: "application/json",
        body: body.into_bytes(),
    }
}

fn json_ok(body: String) -> PublicHttpResponse {
    PublicHttpResponse {
        status: 200,
        content_type: "application/json",
        body: body.into_bytes(),
    }
}

/// Process-readiness and untrusted discovery only.
///
/// `/health` MUST NOT include release, key, or deployment identifiers.
/// `/v1/info` is discovery data, not a trust root.
pub fn handle_public_http(
    method: &str,
    path: &str,
    body: &[u8],
    ready: bool,
    info: &ServiceInfo,
) -> PublicHttpResponse {
    let limit = info
        .max_encrypted_request_bytes
        .min(DEVNET_MAX_ENCRYPTED_REQUEST_BYTES);
    if body.len() as u64 > limit {
        return public_http_error(PublicError::RequestTooLarge);
    }

    match (method, path) {
        ("GET", "/health") => {
            if !ready {
                return public_http_error(PublicError::Unavailable);
            }
            match jcs_serialize(&HealthResponse {
                status: HealthStatus::Healthy,
            }) {
                Ok(body) => json_ok(body),
                Err(_) => public_http_error(PublicError::Unavailable),
            }
        }
        ("GET", "/v1/info") => {
            if info.version != API_VERSION {
                return public_http_error(PublicError::InvalidRequest);
            }
            match jcs_serialize(info) {
                Ok(body) => json_ok(body),
                Err(_) => public_http_error(PublicError::InvalidRequest),
            }
        }
        ("POST", "/health" | "/v1/info") | ("PUT", "/health" | "/v1/info") => {
            public_http_error(PublicError::MethodNotAllowed)
        }
        (_, "/health" | "/v1/info") => public_http_error(PublicError::MethodNotAllowed),
        _ => public_http_error(PublicError::NotFound),
    }
}
