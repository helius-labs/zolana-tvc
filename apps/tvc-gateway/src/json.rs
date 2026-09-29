use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use bytes::Bytes;
use serde::de::DeserializeOwned;

use crate::error::ApiError;

/// A JSON request body, refused with an [`ApiError`]. Unlike `axum::Json`, it
/// does not require a JSON content type.
pub struct ApiJson<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let body =
            Bytes::from_request(request, state)
                .await
                .map_err(|rejection| match rejection.status() {
                    StatusCode::PAYLOAD_TOO_LARGE => ApiError::RequestTooLarge,
                    _ => ApiError::InvalidJson,
                })?;
        serde_json::from_slice(&body)
            .map(Self)
            .map_err(|_| ApiError::InvalidJson)
    }
}
