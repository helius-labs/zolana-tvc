use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Every failure the gateway returns. The body is `{"error": "<variant>"}`.
///
/// Gatekeeper re-sends any 5xx up to twice. A failure after the request
/// reached the enclave or Turnkey is a 424, never a 5xx.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, strum::IntoStaticStr)]
pub enum ApiError {
    #[error("the body is not the JSON this endpoint takes")]
    InvalidJson,
    #[error("the enrollment names an invalid organization, wallet, address or client key")]
    InvalidEnrollmentRequest,
    #[error("the enrollment names another parent organization")]
    UnexpectedParentOrganization,
    #[error("the enrollment is more than five minutes old or more than 30 seconds ahead")]
    StaleEnrollment,
    #[error("the wallet address did not sign this enrollment")]
    InvalidOwnerEnrollmentSignature,

    #[error("the request did not come through gatekeeper")]
    OriginAuthRequired,
    #[error("the request names no valid project")]
    ProjectRequired,

    #[error("this gateway did not provision the descriptor for the current release")]
    InvalidDescriptor,
    #[error("the descriptor's client key is revoked")]
    ClientKeyRevoked,
    #[error("the wallet does not hold the claimed address")]
    WalletNotOwned,
    #[error("the wallet's sub-organization belongs to another project")]
    SubOrganizationNotOwned,
    #[error("Turnkey refused the ownership check")]
    TurnkeyRejected,

    #[error("no such endpoint")]
    NotFound,
    #[error("this ciphertext was already sent")]
    ReplayedRequest,
    #[error("the body is too large")]
    RequestTooLarge,
    #[error("too many requests in flight")]
    TooManyInFlight,

    #[error("the enclave did not answer")]
    EnclaveUnavailable,
    #[error("the enclave's answer is malformed")]
    InvalidEnclaveAnswer,
    #[error("the enclave's answer is too large")]
    UpstreamResponseTooLarge,
    #[error("Turnkey has no Boot Proof for the replica that answered")]
    BootProofUnavailable,
    #[error("Turnkey did not answer")]
    TurnkeyUnavailable,
    #[error("Turnkey refused this gateway's API key")]
    TurnkeyUnauthorized,
    #[error("Turnkey rate-limited this gateway")]
    TurnkeyRateLimited,
    #[error("the replay guard did not answer")]
    ReplayGuardUnavailable,
    #[error("the descriptor could not be signed")]
    ProvisionerUnavailable,
    #[error("the wallet grant could not be signed")]
    WalletGrantUnavailable,

    #[error("the gateway clock is unavailable")]
    ClockUnavailable,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

impl ApiError {
    #[inline]
    pub fn code(self) -> &'static str {
        self.into()
    }

    pub const fn status(self) -> StatusCode {
        match self {
            Self::InvalidJson
            | Self::InvalidEnrollmentRequest
            | Self::UnexpectedParentOrganization
            | Self::StaleEnrollment
            | Self::InvalidOwnerEnrollmentSignature => StatusCode::BAD_REQUEST,
            Self::OriginAuthRequired | Self::ProjectRequired => StatusCode::UNAUTHORIZED,
            Self::InvalidDescriptor
            | Self::ClientKeyRevoked
            | Self::WalletNotOwned
            | Self::SubOrganizationNotOwned
            | Self::TurnkeyRejected => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::ReplayedRequest => StatusCode::CONFLICT,
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::TooManyInFlight => StatusCode::TOO_MANY_REQUESTS,
            Self::EnclaveUnavailable
            | Self::InvalidEnclaveAnswer
            | Self::UpstreamResponseTooLarge
            | Self::BootProofUnavailable
            | Self::TurnkeyUnavailable
            | Self::TurnkeyUnauthorized
            | Self::TurnkeyRateLimited
            | Self::ReplayGuardUnavailable
            | Self::ProvisionerUnavailable
            | Self::WalletGrantUnavailable => StatusCode::FAILED_DEPENDENCY,
            Self::ClockUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status(), Json(ErrorBody { error: self.code() })).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_code_is_the_variant_name_and_no_failure_is_retried_by_gatekeeper() {
        assert_eq!(ApiError::StaleEnrollment.code(), "StaleEnrollment");
        for error in [ApiError::EnclaveUnavailable, ApiError::TurnkeyUnavailable] {
            assert_eq!(error.status(), StatusCode::FAILED_DEPENDENCY);
        }
    }
}
