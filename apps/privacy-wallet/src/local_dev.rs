//! Compile-time-only custody backend for the local TVC testkit.
//!
//! The testkit runs the real encrypted operation handlers, sealed-state logic,
//! wallet synchronization, proof construction, and transaction validation. It
//! replaces only Nitro attestation and Turnkey custody with pinned local keys.
//! This module is not linked into the production `tvc_app` binary.

use std::sync::Arc;

use async_trait::async_trait;
use ed25519_dalek::{Signer as _, SigningKey};
use zolana_keypair_turnkey::{
    PayloadHashFunction, RawSignature, RemoteKey, TurnkeyActivities, TurnkeyCurve,
    TurnkeyKeypairError,
};

/// Public, disposable local provisioner scalar. It has no authority in a
/// production image; the local SDK uses the same value to create descriptors.
const LOCAL_PROVISIONING_SECRET: [u8; 32] = [0x11; 32];

pub(crate) struct LocalWalletState {
    signing_key: Arc<SigningKey>,
    activities: Arc<dyn TurnkeyActivities>,
}

impl LocalWalletState {
    pub(crate) fn from_secret(secret: [u8; 32]) -> Self {
        let signing_key = Arc::new(SigningKey::from_bytes(&secret));
        Self {
            activities: Arc::new(LocalMockTurnkey {
                signing_key: Arc::clone(&signing_key),
            }),
            signing_key,
        }
    }

    pub(crate) fn public_key(&self) -> [u8; 32] {
        *self.signing_key.verifying_key().as_bytes()
    }

    pub(crate) fn activities(&self) -> Arc<dyn TurnkeyActivities> {
        Arc::clone(&self.activities)
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

pub(crate) fn local_provisioning_public() -> [u8; 65] {
    let signing = p256::ecdsa::SigningKey::from_slice(&LOCAL_PROVISIONING_SECRET)
        .expect("the fixed local provisioner scalar is valid");
    let encoded = signing.verifying_key().to_encoded_point(false);
    let mut output = [0_u8; 65];
    output.copy_from_slice(encoded.as_bytes());
    output
}

struct LocalMockTurnkey {
    signing_key: Arc<SigningKey>,
}

#[async_trait]
impl TurnkeyActivities for LocalMockTurnkey {
    async fn get_private_key(
        &self,
        _organization_id: &str,
        _private_key_id: &str,
    ) -> Result<RemoteKey, TurnkeyKeypairError> {
        Ok(RemoteKey {
            curve: TurnkeyCurve::Ed25519,
            public_key: self.signing_key.verifying_key().as_bytes().to_vec(),
        })
    }

    async fn sign_raw_payload(
        &self,
        _organization_id: &str,
        _private_key_id: &str,
        payload: &[u8],
        hash_function: PayloadHashFunction,
    ) -> Result<RawSignature, TurnkeyKeypairError> {
        if hash_function != PayloadHashFunction::NotApplicable {
            return Err(TurnkeyKeypairError::Transport(
                "local custody received the wrong hash function".to_owned(),
            ));
        }
        let signature = self.signing_key.sign(payload).to_bytes();
        Ok(RawSignature {
            r: signature[..32].to_vec(),
            s: signature[32..].to_vec(),
        })
    }

    async fn resume_sign_raw_payload(
        &self,
        _organization_id: &str,
        _activity_id: &str,
    ) -> Result<RawSignature, TurnkeyKeypairError> {
        Err(TurnkeyKeypairError::Transport(
            "local custody has no approval activities".to_owned(),
        ))
    }
}
