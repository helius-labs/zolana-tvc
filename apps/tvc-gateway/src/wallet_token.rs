//! Wallet tokens gate the enclave operations. One is issued with each
//! descriptor, and renewed by the descriptor's client key signing
//! `WALLET_TOKEN_RENEWAL_DOMAIN || 0x00 || descriptor_digest || be_u64(issued_at_ms)`
//! (ECDSA P-256 / SHA-256, raw 64-byte `r || s`).

use std::collections::HashSet;

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zolana_tvc_protocol::WalletDescriptor;
use zolana_tvc_protocol::digest::{descriptor_digest, domain_separated_hash};

use crate::config::WalletTokenConfig;
use crate::error::ApiError;
use crate::project::ProjectId;
use crate::sealed_token::{Purpose, SealingKey};

pub const WALLET_TOKEN_RENEWAL_DOMAIN: &[u8] = b"HELIUS_TVC_GATEWAY_WALLET_TOKEN_RENEWAL_V1";
const CLIENT_KEY_ID_PREFIX: &str = "tvc-browser-p256-";
const MAX_RENEWAL_SKEW_MS: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedWalletToken {
    pub token: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Renewal {
    pub descriptor: WalletDescriptor,
    pub issued_at_ms: u64,
    /// Raw 64-byte P-256 signature by the descriptor's client key, hex.
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    v: u8,
    project: String,
    organization: String,
    wallet: String,
    client_key_id: String,
    exp: u64,
}

pub struct WalletTokens {
    key: SealingKey,
    ttl_ms: u64,
    revoked_client_key_ids: HashSet<String>,
}

impl WalletTokens {
    pub fn new(config: &WalletTokenConfig) -> anyhow::Result<Self> {
        Ok(Self {
            key: SealingKey::new(Purpose::WalletToken, &config.secret)?,
            ttl_ms: config.ttl_secs.saturating_mul(1_000),
            revoked_client_key_ids: config.revoked_client_key_ids.iter().cloned().collect(),
        })
    }

    pub fn issue(
        &self,
        project: &ProjectId,
        descriptor: &WalletDescriptor,
        now_ms: u64,
    ) -> Result<IssuedWalletToken, ApiError> {
        let client_key_id = self.unrevoked_client_key_id(descriptor)?;
        let expires_at_ms = now_ms.saturating_add(self.ttl_ms);
        let claims = Claims {
            v: 1,
            project: project.as_str().to_owned(),
            organization: descriptor.turnkey_organization_id.clone(),
            wallet: descriptor.turnkey_wallet_id.clone(),
            client_key_id,
            exp: expires_at_ms,
        };
        let token = self.key.seal(&claims).map_err(|error| {
            tracing::error!(%error, "wallet token did not serialize");
            ApiError::Upstream("WalletTokenUnavailable")
        })?;
        Ok(IssuedWalletToken {
            token,
            expires_at_ms,
        })
    }

    /// Accepts an unexpired, unrevoked token issued to `project`.
    pub fn verify(&self, token: &str, project: &ProjectId, now_ms: u64) -> Result<(), ApiError> {
        let invalid = ApiError::Unauthorized("InvalidWalletToken");
        let claims: Claims = self.key.open(token).ok_or(invalid)?;
        if claims.v != 1 || claims.exp < now_ms || claims.project != project.as_str() {
            return Err(invalid);
        }
        if self.revoked_client_key_ids.contains(&claims.client_key_id) {
            return Err(ApiError::Forbidden("ClientKeyRevoked"));
        }
        Ok(())
    }

    /// Refuses a revoked client key before any Turnkey call is spent on it.
    pub fn check_client_key(&self, client_public_key: &[u8]) -> Result<(), ApiError> {
        self.unrevoked(client_key_id(client_public_key)).map(|_| ())
    }

    fn unrevoked_client_key_id(&self, descriptor: &WalletDescriptor) -> Result<String, ApiError> {
        let [grant] = descriptor.allowed_clients.as_slice() else {
            return Err(ApiError::Forbidden("InvalidDescriptor"));
        };
        self.unrevoked(client_key_id(&grant.client_public_key))
    }

    fn unrevoked(&self, client_key_id: String) -> Result<String, ApiError> {
        if self.revoked_client_key_ids.contains(&client_key_id) {
            return Err(ApiError::Forbidden("ClientKeyRevoked"));
        }
        Ok(client_key_id)
    }
}

/// Checks the client key's renewal signature and freshness. The caller has
/// already verified the descriptor's provisioning signature.
pub fn verify_renewal(renewal: &Renewal, now_ms: u64) -> Result<(), ApiError> {
    let invalid = ApiError::Unauthorized("InvalidRenewalSignature");
    let skew = now_ms.abs_diff(renewal.issued_at_ms);
    if skew > MAX_RENEWAL_SKEW_MS {
        return Err(ApiError::Unauthorized("StaleRenewal"));
    }
    let [grant] = renewal.descriptor.allowed_clients.as_slice() else {
        return Err(ApiError::Forbidden("InvalidDescriptor"));
    };
    let digest = renewal_digest(&renewal.descriptor, renewal.issued_at_ms)?;
    let key = VerifyingKey::from_sec1_bytes(&grant.client_public_key).map_err(|_| invalid)?;
    let mut raw = [0u8; 64];
    hex::decode_to_slice(&renewal.signature, &mut raw).map_err(|_| invalid)?;
    let signature = Signature::from_slice(&raw).map_err(|_| invalid)?;
    let signature = signature.normalize_s().unwrap_or(signature);
    key.verify_prehash(&digest, &signature).map_err(|_| invalid)
}

pub fn renewal_digest(
    descriptor: &WalletDescriptor,
    issued_at_ms: u64,
) -> Result<[u8; 32], ApiError> {
    let descriptor_digest =
        descriptor_digest(descriptor).map_err(|_| ApiError::Forbidden("InvalidDescriptor"))?;
    let mut payload = [0u8; 40];
    payload[..32].copy_from_slice(&descriptor_digest);
    payload[32..].copy_from_slice(&issued_at_ms.to_be_bytes());
    Ok(domain_separated_hash(WALLET_TOKEN_RENEWAL_DOMAIN, &payload))
}

/// The enclave's name for a client key.
pub fn client_key_id(client_public_key: &[u8]) -> String {
    let digest = Sha256::digest(client_public_key);
    format!("{CLIENT_KEY_ID_PREFIX}{}", hex::encode(&digest[..16]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    const NOW: u64 = 1_800_000_000_000;

    fn tokens(revoked: Vec<String>) -> WalletTokens {
        let config = WalletTokenConfig {
            secret: "0123456789abcdef0123456789abcdef".to_owned(),
            ttl_secs: 900,
            revoked_client_key_ids: revoked,
        };
        let Ok(tokens) = WalletTokens::new(&config) else {
            panic!("wallet token key is invalid");
        };
        tokens
    }

    fn descriptor() -> WalletDescriptor {
        let provisioner = crate::provisioner::tests::provisioner();
        let Ok(descriptor) = provisioner.sign(&crate::enrollment::tests::input()) else {
            panic!("signing failed");
        };
        descriptor
    }

    fn client() -> SigningKey {
        let Ok(key) = SigningKey::from_slice(&[5; 32]) else {
            panic!("test client key is invalid");
        };
        key
    }

    fn renewal(issued_at_ms: u64, signer: &SigningKey) -> Renewal {
        let descriptor = descriptor();
        let Ok(digest) = renewal_digest(&descriptor, issued_at_ms) else {
            panic!("digest failed");
        };
        let signed: Result<Signature, _> = signer.sign_prehash(&digest);
        let Ok(signature) = signed else {
            panic!("signing failed");
        };
        Renewal {
            descriptor,
            issued_at_ms,
            signature: hex::encode(signature.to_bytes()),
        }
    }

    #[test]
    fn a_token_verifies_for_its_project_until_it_expires() {
        let tokens = tokens(Vec::new());
        let project = ProjectId::for_tests("project-a");
        let Ok(issued) = tokens.issue(&project, &descriptor(), NOW) else {
            panic!("issue failed");
        };
        assert_eq!(tokens.verify(&issued.token, &project, NOW + 1), Ok(()));
        let invalid = Err(ApiError::Unauthorized("InvalidWalletToken"));
        let other = ProjectId::for_tests("project-b");
        assert_eq!(tokens.verify(&issued.token, &other, NOW + 1), invalid);
        assert_eq!(
            tokens.verify(&issued.token, &project, issued.expires_at_ms + 1),
            invalid
        );
    }

    #[test]
    fn a_revoked_client_key_gets_no_token_and_its_tokens_stop_working() {
        let project = ProjectId::for_tests("project-a");
        let descriptor = descriptor();
        let Ok(issued) = tokens(Vec::new()).issue(&project, &descriptor, NOW) else {
            panic!("issue failed");
        };
        let key_id = client_key_id(&descriptor.allowed_clients[0].client_public_key);
        let revoking = tokens(vec![key_id]);
        let revoked = Err(ApiError::Forbidden("ClientKeyRevoked"));
        assert_eq!(revoking.issue(&project, &descriptor, NOW), revoked);
        assert_eq!(
            revoking.verify(&issued.token, &project, NOW),
            revoked.map(|_| ())
        );
    }

    #[test]
    fn a_renewal_needs_the_descriptors_client_key_and_a_fresh_timestamp() {
        assert_eq!(
            verify_renewal(&renewal(NOW, &client()), NOW + 1_000),
            Ok(())
        );
        let Ok(intruder) = SigningKey::from_slice(&[6; 32]) else {
            panic!("intruder key is invalid");
        };
        assert_eq!(
            verify_renewal(&renewal(NOW, &intruder), NOW),
            Err(ApiError::Unauthorized("InvalidRenewalSignature"))
        );
        assert_eq!(
            verify_renewal(&renewal(NOW, &client()), NOW + MAX_RENEWAL_SKEW_MS + 1),
            Err(ApiError::Unauthorized("StaleRenewal"))
        );
    }

    #[test]
    fn client_key_id_matches_the_enclave_format() {
        let id = client_key_id(&[4; 65]);
        assert!(id.starts_with(CLIENT_KEY_ID_PREFIX));
        assert_eq!(id.len(), CLIENT_KEY_ID_PREFIX.len() + 32);
    }
}
