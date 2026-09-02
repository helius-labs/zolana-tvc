//! Wire types, canonical encoding, digests, and P-256/QOS primitives shared by
//! the TVC application and its clients.
//!
//! This crate does not verify AWS Nitro Boot Proofs or bind Turnkey policy
//! evidence to an activity.

#![forbid(unsafe_code)]

pub mod auth;
pub mod bindings;
pub mod constants;
pub mod crypto;
pub mod digest;
pub mod encoding;
pub mod error;
pub mod evidence;
pub mod http;
pub mod release;
pub mod types;

pub use auth::{authorize_operation_request, verify_client_authorization};
pub use bindings::{check_encrypted_request_bindings, check_request_bindings, RunningEnclave};
pub use error::{ErrorCode, PublicError, TvcError};
pub use evidence::verify_turnkey_app_proof;
pub use http::{handle_public_http, public_http_error, PublicHttpResponse};
pub use release::{
    bind_discovery_to_policy, policy_signing_digest, sign_release_policy,
    verify_signed_release_policy, PinnedReleaseAuthorities, ReleaseAuthorityKey,
};
pub use types::{
    AppProof, ClientAuthorization, ClientAuthorizationScheme, ClientGrant, DecryptPayload,
    DecryptedPayload, EncryptedRequest, EncryptedResponse, Environment, FailureStage,
    HealthResponse, HealthStatus, Operation, OperationKind, OperationProofPayload,
    OperationRequest, OperationResult, QosPingChallenge, QosPingRequest, QosPingResponse,
    ReleaseAuthoritySignature, ReleasePolicy, SealedWalletState, ServiceInfo, SignedReleasePolicy,
    SpendAction, SpendInput, SplAsset, TurnkeyAppProof, WalletDescriptor,
};
