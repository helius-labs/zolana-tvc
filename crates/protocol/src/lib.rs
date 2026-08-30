//! Protocol and cryptographic foundations for development Zolana TVC wallets.
//!
//! This crate does not verify AWS Nitro Boot Proofs or bind Turnkey policy
//! evidence to an activity. It must not be described as production-verified.

#![forbid(unsafe_code)]

pub mod auth;
pub mod bindings;
pub mod constants;
pub mod crypto;
pub mod digest;
pub mod encoding;
pub mod error;
pub mod evidence;
pub mod fixtures;
pub mod http;
pub mod release;
pub mod types;

pub use auth::{authorize_operation_request, verify_client_authorization};
pub use bindings::{check_encrypted_request_bindings, check_request_bindings, RunningEnclave};
pub use error::{ErrorCode, PublicError, TvcError};
pub use evidence::classify_turnkey_policy_evidence;
pub use http::{handle_public_http, public_http_error, PublicHttpResponse};
pub use release::{
    bind_discovery_to_policy, policy_signing_digest, sign_release_policy,
    verify_signed_release_policy, PinnedReleaseAuthoritiesV1, ReleaseAuthorityKeyV1,
};
pub use types::{
    AuthorizeSpendRequestV1, ClientAuthorizationScheme, ClientAuthorizationV1, ClientGrantV1,
    EncryptedRequestV1, EncryptedResponseV1, Environment, HealthResponseV1, HealthStatus,
    OperationKind, OperationRequestV1, OperationV1, PreparedSpendV1, QosPingChallengeV1,
    QosPingRequestV1, QosPingResponseV1, ReleasePolicyV1, SealedSpendAuthorizationV1,
    ServiceInfoV1, SignedReleasePolicyV1, SpendPlanV1, SppMessageV1, SppPlanInputV1,
    SppPlanOutputV1, SppPlanV1, SppProgramAuthorityV1, SppShapeV1, TurnkeySigningTargetV1,
    WalletDescriptorV1,
};
