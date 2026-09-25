use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bytes::Bytes;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use zeroize::Zeroizing;
use zolana_tvc_protocol::constants::API_VERSION;
use zolana_tvc_protocol::crypto::{
    parse_uncompressed_sec1, sign_p256_prehash, verify_p256_prehash,
};
use zolana_tvc_protocol::digest::descriptor_digest;
use zolana_tvc_protocol::{
    ClientGrant, PinnedReleaseAuthorities, ReleasePolicy, SignedReleasePolicy, WalletDescriptor,
    verify_signed_release_policy,
};

use crate::config::ProvisioningConfig;
use crate::enrollment::EnrollmentInput;
use crate::error::ApiError;

/// Holds the provisioning key and the release policy descriptors are issued
/// under. Signed descriptors are the enclave's only grant of access to a wallet.
pub struct Provisioner {
    secret: Zeroizing<[u8; 32]>,
    public_key: [u8; 65],
    policy: ReleasePolicy,
    signed_policy_json: Bytes,
}

impl Provisioner {
    pub fn new(config: &ProvisioningConfig) -> anyhow::Result<Self> {
        let secret = decode_secret(&config.private_key)?;
        let public_key = public_key_of(&secret)?;
        anyhow::ensure!(
            hex::encode(public_key) == config.expected_public_key,
            "provisioning.private_key does not match provisioning.expected_public_key"
        );
        let signed: SignedReleasePolicy = read_json(&config.release_policy_path)?;
        let authorities: PinnedReleaseAuthorities = read_json(&config.release_authorities_path)?;
        verify_signed_release_policy(&signed, &authorities, now_ms()?)
            .map_err(|error| anyhow::anyhow!("release policy does not verify: {error:?}"))?;
        let signed_policy_json = Bytes::from(serde_json::to_vec(&signed)?);
        Ok(Self {
            secret,
            public_key,
            policy: signed.policy,
            signed_policy_json,
        })
    }

    #[inline]
    pub fn signed_policy_json(&self) -> Bytes {
        self.signed_policy_json.clone()
    }

    /// One client key may drive every operation the release allows, for one
    /// Turnkey wallet. The enclave refuses a narrowed or reordered list.
    pub fn sign(&self, input: &EnrollmentInput) -> Result<WalletDescriptor, ApiError> {
        let mut descriptor = WalletDescriptor {
            version: API_VERSION,
            security_domain_id: self.policy.security_domain_id,
            environment: self.policy.environment,
            turnkey_organization_id: input.organization_id.clone(),
            turnkey_wallet_id: input.turnkey_wallet_id.clone(),
            address: input.solana_address.clone(),
            allowed_clients: vec![ClientGrant {
                client_public_key: input.client_public_key.to_vec(),
                allowed_operations: self.policy.allowed_operations.clone(),
            }],
            provisioning_signature: Vec::new(),
        };
        let digest = descriptor_digest(&descriptor).map_err(|error| {
            tracing::error!(?error, "descriptor did not canonicalize");
            ApiError::BadRequest("InvalidDescriptor")
        })?;
        let signature = sign_p256_prehash(&self.secret, &digest).map_err(|error| {
            tracing::error!(?error, "descriptor signing failed");
            ApiError::Upstream("ProvisionerUnavailable")
        })?;
        descriptor.provisioning_signature = signature.to_vec();
        Ok(descriptor)
    }

    /// Accepts a descriptor this provisioner signed under the current release.
    pub fn verify(&self, descriptor: &WalletDescriptor) -> Result<(), ApiError> {
        let invalid = ApiError::Forbidden("InvalidDescriptor");
        if descriptor.version != API_VERSION
            || descriptor.security_domain_id != self.policy.security_domain_id
            || descriptor.environment != self.policy.environment
            || descriptor.allowed_clients.len() != 1
        {
            return Err(invalid);
        }
        let digest = descriptor_digest(descriptor).map_err(|_| invalid)?;
        verify_p256_prehash(
            &self.public_key,
            &digest,
            &descriptor.provisioning_signature,
        )
        .map_err(|_| invalid)
    }
}

pub fn now_ms() -> anyhow::Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    Ok(u64::try_from(elapsed.as_millis())?)
}

fn decode_secret(value: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let trimmed = value.trim().trim_start_matches("0x");
    let mut secret = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(trimmed, secret.as_mut_slice())
        .context("provisioning.private_key must be 32 bytes of hex")?;
    Ok(secret)
}

fn public_key_of(secret: &[u8; 32]) -> anyhow::Result<[u8; 65]> {
    let secret_key = SecretKey::from_slice(secret).context("invalid P-256 provisioning key")?;
    let encoded = secret_key.public_key().to_encoded_point(false);
    let public_key: [u8; 65] = encoded
        .as_bytes()
        .try_into()
        .context("P-256 public key is not 65 bytes")?;
    parse_uncompressed_sec1(&public_key)
        .map_err(|error| anyhow::anyhow!("invalid provisioning public key: {error:?}"))?;
    Ok(public_key)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> anyhow::Result<T> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use zolana_tvc_protocol::OperationKind;

    pub const TEST_SECRET: [u8; 32] = [7; 32];

    pub fn provisioner() -> Provisioner {
        let secret = Zeroizing::new(TEST_SECRET);
        let public_key = public_key_of(&secret).unwrap_or([0; 65]);
        Provisioner {
            secret,
            public_key,
            policy: test_policy(),
            signed_policy_json: Bytes::new(),
        }
    }

    pub fn test_policy() -> ReleasePolicy {
        ReleasePolicy {
            version: 1,
            release_id: "test".to_owned(),
            environment: zolana_tvc_protocol::Environment::Development,
            tvc_application_id: "test".to_owned(),
            security_domain_id: [9; 32],
            accepted_manifest_digests: Vec::new(),
            accepted_executable_digests: Vec::new(),
            quorum_key_id: "test".to_owned(),
            quorum_key_epoch: 1,
            quorum_public_key: Vec::new(),
            allowed_operations: vec![
                OperationKind::Bootstrap,
                OperationKind::Decrypt,
                OperationKind::Derive,
                OperationKind::TransactionKeys,
                OperationKind::Prove,
            ],
            max_encrypted_request_bytes: 262_144,
            max_encrypted_response_bytes: 262_144,
            turnkey_trust_root_id: "aws-nitro-root-g1".to_owned(),
            turnkey_proof_schema_versions: Vec::new(),
            valid_from_ms: 0,
            expires_at_ms: u64::MAX,
            revocation_epoch: 0,
        }
    }

    #[test]
    fn signed_descriptor_verifies_and_tampering_fails() {
        let provisioner = provisioner();
        let input = crate::enrollment::tests::input();
        let Ok(mut descriptor) = provisioner.sign(&input) else {
            panic!("signing failed");
        };
        assert_eq!(provisioner.verify(&descriptor), Ok(()));
        assert_eq!(
            descriptor.allowed_clients[0].allowed_operations,
            test_policy().allowed_operations
        );
        descriptor.turnkey_wallet_id.push('x');
        assert_eq!(
            provisioner.verify(&descriptor),
            Err(ApiError::Forbidden("InvalidDescriptor"))
        );
    }

    #[test]
    fn secret_decoding_accepts_prefixed_hex_and_rejects_short_keys() {
        assert!(decode_secret(&format!("0x{}", "07".repeat(32))).is_ok());
        assert!(decode_secret(&"07".repeat(31)).is_err());
    }
}

#[cfg(test)]
mod committed_policy_tests {
    use super::*;

    #[test]
    fn the_committed_release_policy_verifies_against_the_committed_authorities() {
        let Ok(signed) =
            read_json::<SignedReleasePolicy>(std::path::Path::new("configs/release-policy.json"))
        else {
            panic!("configs/release-policy.json does not parse");
        };
        let Ok(authorities) = read_json::<PinnedReleaseAuthorities>(std::path::Path::new(
            "configs/release-authorities.json",
        )) else {
            panic!("configs/release-authorities.json does not parse");
        };
        let during_validity = signed.policy.valid_from_ms.saturating_add(1);
        assert_eq!(
            verify_signed_release_policy(&signed, &authorities, during_validity),
            Ok(())
        );
    }
}
