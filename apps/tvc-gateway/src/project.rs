use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use cadence_macros::statsd_count;
use subtle::ConstantTimeEq;

use crate::app::AppState;
use crate::error::ApiError;

pub const PROJECT_ID_HEADER: &str = "x-helius-project-id";
const MAX_PROJECT_ID_LEN: usize = 64;

/// The Helius project gatekeeper authenticated the caller's API key as.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectId(Arc<str>);

impl ProjectId {
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn parse(value: &str) -> Option<Self> {
        let valid = !value.is_empty()
            && value.len() <= MAX_PROJECT_ID_LEN
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        valid.then(|| Self(Arc::from(value)))
    }

    #[cfg(test)]
    pub fn for_tests(value: &str) -> Self {
        Self(Arc::from(value))
    }
}

/// A request that arrived through gatekeeper: it carries gatekeeper's origin
/// credential and the project the caller's API key belongs to.
pub struct Gatekeeper(pub ProjectId);

impl FromRequestParts<Arc<AppState>> for Gatekeeper {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let expected = state.origin_auth_header.as_bytes();
        let presented = parts
            .headers
            .get(AUTHORIZATION)
            .map(|value| value.as_bytes());
        let accepted = presented.is_some_and(|got| bool::from(got.ct_eq(expected)));
        if !accepted {
            statsd_count!("origin_auth_rejected", 1);
            return Err(ApiError::Unauthorized("OriginAuthRequired"));
        }
        let project = parts
            .headers
            .get(PROJECT_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(ProjectId::parse)
            .ok_or(ApiError::Unauthorized("ProjectRequired"))?;
        Ok(Self(project))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_id_accepts_uuid_and_rejects_junk() {
        assert!(ProjectId::parse("0b4a3a9e-5f7e-4b4f-9c1e-0d9f2a1b3c4d").is_some());
        assert!(ProjectId::parse("").is_none());
        assert!(ProjectId::parse("a b").is_none());
        assert!(ProjectId::parse(&"a".repeat(65)).is_none());
    }
}
