//! Compile-time-only custody backend for the local TVC testkit.
//!
//! The testkit runs the real encrypted operation handlers, sealed-state logic,
//! wallet synchronization, proof construction, and transaction validation. It
//! replaces only Nitro attestation and Turnkey custody with pinned local keys.
//! This module is not linked into the production `tvc_app` binary.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use ed25519_dalek::{Signer as _, SigningKey};
use qos_p256::P256Pair;
use serde::Deserialize;
use zeroize::Zeroizing;
use zolana_keypair_turnkey::{
    PayloadHashFunction, RawSignature, RemoteKey, TurnkeyActivities, TurnkeyCurve,
    TurnkeyKeypairError,
};
use zolana_tvc_protocol::types::OperationKind;

const LOCAL_TESTKIT_JSON: &str = include_str!("../../../fixtures/local-testkit-v1.json");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LocalTestkitFixture {
    version: u8,
    pub(crate) release_id: String,
    pub(crate) quorum_key_id: String,
    pub(crate) security_domain_label: String,
    pub(crate) manifest_label: String,
    pub(crate) executable_label: String,
    provisioning_private_key_hex: String,
    ephemeral_seed_hex: String,
    quorum_seed_hex: String,
    quorum_public_key: String,
    ephemeral_public_key: String,
    pub(crate) operations: Vec<OperationKind>,
}

fn decode_32(value: &str) -> [u8; 32] {
    zolana_tvc_protocol::encoding::decode_lower_hex_array(value)
        .expect("local testkit key must be 32-byte lowercase hex")
}

pub(crate) fn local_testkit_fixture() -> &'static LocalTestkitFixture {
    static FIXTURE: OnceLock<LocalTestkitFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let fixture: LocalTestkitFixture =
            serde_json::from_str(LOCAL_TESTKIT_JSON).expect("local testkit fixture must be valid");
        assert_eq!(fixture.version, zolana_tvc_protocol::constants::API_VERSION);
        assert_eq!(fixture.operations, crate::operations::KEYHOLDER_OPERATIONS);

        let (ephemeral_seed, quorum_seed) = local_testkit_qos_seeds_from(&fixture);
        let ephemeral = P256Pair::from_master_seed(&Zeroizing::new(ephemeral_seed))
            .expect("local ephemeral seed must be valid");
        let quorum = P256Pair::from_master_seed(&Zeroizing::new(quorum_seed))
            .expect("local quorum seed must be valid");
        assert_eq!(
            hex::encode(ephemeral.public_key().to_bytes()),
            fixture.ephemeral_public_key
        );
        assert_eq!(
            hex::encode(quorum.public_key().to_bytes()),
            fixture.quorum_public_key
        );
        fixture
    })
}

fn local_testkit_qos_seeds_from(fixture: &LocalTestkitFixture) -> ([u8; 32], [u8; 32]) {
    (
        decode_32(&fixture.ephemeral_seed_hex),
        decode_32(&fixture.quorum_seed_hex),
    )
}

pub fn local_testkit_qos_seeds() -> ([u8; 32], [u8; 32]) {
    local_testkit_qos_seeds_from(local_testkit_fixture())
}

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
    let secret = decode_32(&local_testkit_fixture().provisioning_private_key_hex);
    let signing = p256::ecdsa::SigningKey::from_slice(&secret)
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
