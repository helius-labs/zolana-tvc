use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Every failure the gateway returns. The body is `{"error": code}`.
///
/// Gatekeeper re-sends any 5xx up to twice. A failure after the request
/// reached the enclave or Turnkey is `Upstream` (424), never a 5xx.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    #[error("not found")]
    NotFound,
    #[error("request too large")]
    RequestTooLarge,
    #[error("replayed request")]
    ReplayedRequest,
    #[error("too many in-flight requests")]
    TooManyInFlight,
    #[error("upstream failure: {0}")]
    Upstream(&'static str),
    #[error("unavailable: {0}")]
    Unavailable(&'static str),
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

impl ApiError {
    #[inline]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::ReplayedRequest => StatusCode::CONFLICT,
            Self::TooManyInFlight => StatusCode::TOO_MANY_REQUESTS,
            Self::Upstream(_) => StatusCode::FAILED_DEPENDENCY,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    #[inline]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BadRequest(code)
            | Self::Unauthorized(code)
            | Self::Forbidden(code)
            | Self::Upstream(code)
            | Self::Unavailable(code) => code,
            Self::NotFound => "NotFound",
            Self::RequestTooLarge => "RequestTooLarge",
            Self::ReplayedRequest => "ReplayedRequest",
            Self::TooManyInFlight => "TooManyInFlight",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (self.status(), Json(ErrorBody { error: self.code() })).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}
