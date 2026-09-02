//! The custodian of the wallet's Ed25519 key: Turnkey in the enclave, a local
//! mock in the testkit. It signs exactly one thing, the fixed derivation
//! message at bootstrap. Solana transactions are signed by the client's own
//! session with the wallet key; the enclave never asks for a signature over
//! anything else.

use std::sync::Arc;

use async_trait::async_trait;
use qos_p256::P256Pair;
use turnkey_client::generated::immutable::{
    activity::v1::SignRawPayloadIntentV2,
    common::v1::{HashFunction, PayloadEncoding},
};
use turnkey_client::{ActivityResult, TurnkeyClient};
use zolana_tvc_protocol::types::TurnkeyAppProof;

use crate::turnkey::QosTurnkeyStamper;

/// The Turnkey key a descriptor names. `sign_with` is the wallet's Solana
/// address, which Turnkey accepts as the key selector.
pub(crate) struct WalletKey<'a> {
    pub organization_id: &'a str,
    pub sign_with: &'a str,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CustodyError {
    /// The custodian could not be reached or answered unusably.
    Unavailable,
    /// The custodian declined to sign.
    Declined,
}

pub(crate) struct Evidence {
    pub activity_id: String,
    pub app_proofs: Vec<TurnkeyAppProof>,
}

pub(crate) struct RawSignature {
    pub signature: [u8; 64],
    pub evidence: Evidence,
}

#[async_trait]
pub(crate) trait Custody: Send + Sync {
    async fn sign_raw(
        &self,
        wallet: &WalletKey<'_>,
        payload: &[u8],
        timestamp_ms: u64,
    ) -> Result<RawSignature, CustodyError>;
}

pub(crate) struct TurnkeyCustody {
    quorum: Arc<P256Pair>,
}

impl TurnkeyCustody {
    pub(crate) fn new(quorum: Arc<P256Pair>) -> Self {
        Self { quorum }
    }

    fn client(&self) -> Result<TurnkeyClient<QosTurnkeyStamper>, CustodyError> {
        TurnkeyClient::builder()
            .api_key(QosTurnkeyStamper::new(Arc::clone(&self.quorum)))
            .build()
            .map(TurnkeyClient::with_app_proofs)
            .map_err(|_| CustodyError::Unavailable)
    }
}

fn evidence<T>(activity: &ActivityResult<T>) -> Result<Evidence, CustodyError> {
    if activity.app_proofs.is_empty() {
        return Err(CustodyError::Unavailable);
    }
    Ok(Evidence {
        activity_id: activity.activity_id.clone(),
        app_proofs: activity
            .app_proofs
            .iter()
            .map(|proof| TurnkeyAppProof {
                scheme: proof.scheme.as_str_name().to_owned(),
                public_key: proof.public_key.clone(),
                proof_payload: proof.proof_payload.clone(),
                signature: proof.signature.clone(),
            })
            .collect(),
    })
}

fn decode_hex(value: &str) -> Result<Vec<u8>, CustodyError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).map_err(|_| CustodyError::Unavailable)
}

#[async_trait]
impl Custody for TurnkeyCustody {
    async fn sign_raw(
        &self,
        wallet: &WalletKey<'_>,
        payload: &[u8],
        timestamp_ms: u64,
    ) -> Result<RawSignature, CustodyError> {
        let activity = self
            .client()?
            .sign_raw_payload(
                wallet.organization_id.to_owned(),
                u128::from(timestamp_ms),
                SignRawPayloadIntentV2 {
                    sign_with: wallet.sign_with.to_owned(),
                    payload: hex::encode(payload),
                    encoding: PayloadEncoding::Hexadecimal,
                    hash_function: HashFunction::NotApplicable,
                },
            )
            .await
            .map_err(|_| CustodyError::Unavailable)?;
        let evidence = evidence(&activity)?;
        let (r, s) = (
            decode_hex(&activity.result.r)?,
            decode_hex(&activity.result.s)?,
        );
        if r.len() != 32 || s.len() != 32 {
            return Err(CustodyError::Unavailable);
        }
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r);
        signature[32..].copy_from_slice(&s);
        Ok(RawSignature {
            signature,
            evidence,
        })
    }
}
