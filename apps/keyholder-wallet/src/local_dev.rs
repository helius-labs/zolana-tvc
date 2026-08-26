//! Compile-time-only, explicitly unattested local wallet harness.
//!
//! This module is absent unless `local-dev` is enabled. It uses the real
//! `zolana-keypair-turnkey` Ed25519 bootstrap path, but supplies a disposable
//! in-process signer instead of a Turnkey transport. No secret material is
//! returned by the endpoint or written to disk.

use std::fs::File;
use std::io::{self, Read as _};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
use zolana_keypair::ShieldedKeypairTrait as _;
use zolana_keypair_turnkey::{
    PayloadHashFunction, RawSignature, RemoteKey, TurnkeyActivities, TurnkeyCurve,
    TurnkeyEd25519ShieldedKeypair, TurnkeyKeyRef, TurnkeyKeypairError,
};
use zolana_tvc_protocol::encoding::{
    encode_lower_hex, hex32, is_rfc8785, jcs_serialize, parse_strict_json,
};
use zolana_tvc_protocol::{public_http_error, PublicError, PublicHttpResponse};

use crate::into_response;

const LOCAL_ORGANIZATION_ID: &str = "local-mock-organization";
const LOCAL_PRIVATE_KEY_ID: &str = "local-mock-ed25519-key";
const LOCAL_TRUST: &str = "local-unattested";
const LOCAL_CUSTODY: &str = "disposable-in-process-mock-turnkey";

pub(crate) struct LocalWalletState {
    activities: Arc<dyn TurnkeyActivities>,
}

impl LocalWalletState {
    pub(crate) fn generate() -> io::Result<Self> {
        let mut secret = Zeroizing::new([0_u8; 32]);
        File::open("/dev/urandom")?.read_exact(secret.as_mut())?;
        Ok(Self::from_secret(*secret))
    }

    #[cfg(test)]
    pub(crate) fn deterministic(secret: [u8; 32]) -> Self {
        Self::from_secret(secret)
    }

    fn from_secret(secret: [u8; 32]) -> Self {
        Self {
            activities: Arc::new(LocalMockTurnkey {
                signing_key: SigningKey::from_bytes(&secret),
            }),
        }
    }

    async fn bootstrap(&self) -> Result<LocalBootstrapResponseV1, TurnkeyKeypairError> {
        let key_ref = TurnkeyKeyRef::new(LOCAL_ORGANIZATION_ID, LOCAL_PRIVATE_KEY_ID);
        let wallet =
            TurnkeyEd25519ShieldedKeypair::bootstrap(Arc::clone(&self.activities), key_ref).await?;
        let shielded = wallet.shielded_address()?;
        let owner_hash = wallet.owner_hash()?;
        let compressed_address_hash = wallet.compressed_address()?.hash()?;

        Ok(LocalBootstrapResponseV1 {
            version: 1,
            trust: LOCAL_TRUST.to_owned(),
            custody: LOCAL_CUSTODY.to_owned(),
            mock_turnkey_organization_id: LOCAL_ORGANIZATION_ID.to_owned(),
            mock_turnkey_private_key_id: LOCAL_PRIVATE_KEY_ID.to_owned(),
            solana_address: wallet.solana_address().to_string(),
            signing_public_key: wallet.signing_pubkey().as_ed25519()?,
            viewing_public_key: encode_lower_hex(wallet.viewing_pubkey().as_bytes()),
            nullifier_public_key: shielded.nullifier_pubkey,
            owner_hash,
            compressed_address_hash,
        })
    }
}

struct LocalMockTurnkey {
    signing_key: SigningKey,
}

#[async_trait]
impl TurnkeyActivities for LocalMockTurnkey {
    async fn get_private_key(
        &self,
        organization_id: &str,
        private_key_id: &str,
    ) -> Result<RemoteKey, TurnkeyKeypairError> {
        check_key_ref(organization_id, private_key_id)?;
        Ok(RemoteKey {
            curve: TurnkeyCurve::Ed25519,
            public_key: self.signing_key.verifying_key().as_bytes().to_vec(),
        })
    }

    async fn sign_raw_payload(
        &self,
        organization_id: &str,
        private_key_id: &str,
        payload: &[u8],
        hash_function: PayloadHashFunction,
    ) -> Result<RawSignature, TurnkeyKeypairError> {
        check_key_ref(organization_id, private_key_id)?;
        if hash_function != PayloadHashFunction::NotApplicable {
            return Err(TurnkeyKeypairError::Transport(
                "local mock received the wrong hash function".to_owned(),
            ));
        }
        let signature = self.signing_key.sign(payload).to_bytes();
        let (r, s) = signature.split_at(32);
        Ok(RawSignature {
            r: r.to_vec(),
            s: s.to_vec(),
        })
    }

    async fn resume_sign_raw_payload(
        &self,
        _organization_id: &str,
        _activity_id: &str,
    ) -> Result<RawSignature, TurnkeyKeypairError> {
        Err(TurnkeyKeypairError::Transport(
            "the local mock has no approval activities".to_owned(),
        ))
    }
}

fn check_key_ref(organization_id: &str, private_key_id: &str) -> Result<(), TurnkeyKeypairError> {
    if organization_id != LOCAL_ORGANIZATION_ID || private_key_id != LOCAL_PRIVATE_KEY_ID {
        return Err(TurnkeyKeypairError::Transport(
            "local mock received an unknown key reference".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalBootstrapRequestV1 {
    version: u8,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalBootstrapResponseV1 {
    version: u8,
    trust: String,
    custody: String,
    mock_turnkey_organization_id: String,
    mock_turnkey_private_key_id: String,
    solana_address: String,
    #[serde(with = "hex32")]
    signing_public_key: [u8; 32],
    viewing_public_key: String,
    #[serde(with = "hex32")]
    nullifier_public_key: [u8; 32],
    #[serde(with = "hex32")]
    owner_hash: [u8; 32],
    #[serde(with = "hex32")]
    compressed_address_hash: [u8; 32],
}

pub(crate) async fn handle_local_bootstrap(
    state: Option<&LocalWalletState>,
    body: &[u8],
) -> Response<Body> {
    let Some(state) = state else {
        return into_response(public_http_error(PublicError::NotFound));
    };
    let Ok(body) = std::str::from_utf8(body) else {
        return into_response(public_http_error(PublicError::InvalidRequest));
    };
    let Ok(request) = parse_strict_json::<LocalBootstrapRequestV1>(body) else {
        return into_response(public_http_error(PublicError::InvalidRequest));
    };
    if request.version != 1 || !is_rfc8785(body) {
        return into_response(public_http_error(PublicError::InvalidRequest));
    }

    let Ok(response) = state.bootstrap().await else {
        return into_response(public_http_error(PublicError::Unavailable));
    };
    let Ok(body) = jcs_serialize(&response) else {
        return into_response(public_http_error(PublicError::Unavailable));
    };
    into_response(PublicHttpResponse {
        status: StatusCode::OK.as_u16(),
        content_type: "application/json",
        body: body.into_bytes(),
    })
}
