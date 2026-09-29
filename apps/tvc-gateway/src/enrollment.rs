//! Enrollment: the wallet owner signs, through Turnkey, a message naming the
//! wallet, the client key and the time, and the gateway answers with a
//! descriptor for that client key.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zolana_tvc_protocol::crypto::parse_uncompressed_sec1;

use crate::error::ApiError;

/// Prefix of the message the wallet owner signs, followed by
/// `"\n" || hex(sha256(fields))`; see [`enrollment_message`].
pub const ENROLLMENT_DOMAIN: &str = "ZOLANA_TVC_WALLET_ENROLLMENT_V2";
pub const WALLET_NAME: &str = "Solana Wallet";
const MAX_ENROLLMENT_AGE_MS: u64 = 5 * 60 * 1_000;
const MAX_CLOCK_SKEW_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub parent_organization_id: String,
    pub organization_id: String,
    pub wallet_name: String,
    pub turnkey_wallet_id: String,
    pub solana_address: String,
    /// Uncompressed SEC1 P-256 key, lowercase hex.
    pub client_public_key: String,
    pub issued_at_ms: u64,
    /// Ed25519 signature by the wallet address over [`enrollment_message`], hex.
    pub owner_signature: String,
}

/// A validated enrollment request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentInput {
    pub organization_id: String,
    pub turnkey_wallet_id: String,
    pub solana_address: String,
    pub owner_public_key: [u8; 32],
    pub client_public_key: [u8; 65],
}

pub struct Enrollment {
    parent_organization_id: String,
}

impl Enrollment {
    pub fn new(parent_organization_id: &str) -> Self {
        Self {
            parent_organization_id: parent_organization_id.to_owned(),
        }
    }

    /// The enrollment the wallet address signed within the last five minutes,
    /// and the message it signed.
    pub fn verify(
        &self,
        request: &EnrollmentRequest,
        now_ms: u64,
    ) -> Result<(EnrollmentInput, String), ApiError> {
        let fresh = request.issued_at_ms <= now_ms.saturating_add(MAX_CLOCK_SKEW_MS)
            && now_ms.saturating_sub(request.issued_at_ms) <= MAX_ENROLLMENT_AGE_MS;
        if !fresh {
            return Err(ApiError::StaleEnrollment);
        }
        let input = self.validate(request)?;
        let message = enrollment_message(request);
        verify_owner_signature(&input, &message, &request.owner_signature)?;
        Ok((input, message))
    }

    fn validate(&self, request: &EnrollmentRequest) -> Result<EnrollmentInput, ApiError> {
        let invalid = ApiError::InvalidEnrollmentRequest;
        if !is_canonical_uuid(&request.organization_id)
            || !is_canonical_uuid(&request.turnkey_wallet_id)
            || request.wallet_name != WALLET_NAME
        {
            return Err(invalid);
        }
        if request.parent_organization_id != self.parent_organization_id {
            return Err(ApiError::UnexpectedParentOrganization);
        }
        let owner_public_key = solana_public_key(&request.solana_address).ok_or(invalid)?;
        let client_public_key = client_public_key(&request.client_public_key).ok_or(invalid)?;
        Ok(EnrollmentInput {
            organization_id: request.organization_id.clone(),
            turnkey_wallet_id: request.turnkey_wallet_id.clone(),
            solana_address: request.solana_address.clone(),
            owner_public_key,
            client_public_key,
        })
    }
}

/// `ENROLLMENT_DOMAIN || "\n" || hex(sha256(fields))`, where `fields` are the
/// parent organization, organization, wallet name, wallet id, Solana address,
/// client public key and decimal `issuedAtMs`, joined by `"\n"`.
pub fn enrollment_message(request: &EnrollmentRequest) -> String {
    let fields = [
        request.parent_organization_id.as_str(),
        request.organization_id.as_str(),
        request.wallet_name.as_str(),
        request.turnkey_wallet_id.as_str(),
        request.solana_address.as_str(),
        request.client_public_key.as_str(),
        &request.issued_at_ms.to_string(),
    ]
    .join("\n");
    format!(
        "{ENROLLMENT_DOMAIN}\n{}",
        hex::encode(Sha256::digest(fields.as_bytes()))
    )
}

fn verify_owner_signature(
    input: &EnrollmentInput,
    message: &str,
    signature_hex: &str,
) -> Result<(), ApiError> {
    let invalid = ApiError::InvalidOwnerEnrollmentSignature;
    let mut signature = [0u8; 64];
    hex::decode_to_slice(signature_hex, &mut signature).map_err(|_| invalid)?;
    let owner = VerifyingKey::from_bytes(&input.owner_public_key).map_err(|_| invalid)?;
    owner
        .verify_strict(message.as_bytes(), &Signature::from_bytes(&signature))
        .map_err(|_| invalid)
}

fn solana_public_key(address: &str) -> Option<[u8; 32]> {
    let mut bytes = [0u8; 32];
    let written = bs58::decode(address).onto(&mut bytes).ok()?;
    (written == 32 && bs58::encode(bytes).into_string() == address).then_some(bytes)
}

fn client_public_key(value: &str) -> Option<[u8; 65]> {
    let mut bytes = [0u8; 65];
    let lowercase = value.bytes().all(|b| !b.is_ascii_uppercase());
    hex::decode_to_slice(value, &mut bytes).ok()?;
    parse_uncompressed_sec1(&bytes).ok()?;
    lowercase.then_some(bytes)
}

fn is_canonical_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    pub const PARENT: &str = "9b98a0d8-04a4-47a3-9dc3-afa84c686de4";
    pub const NOW: u64 = 1_800_000_000_000;

    pub fn owner() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    pub fn client_public_hex() -> String {
        let secret = p256::SecretKey::from_slice(&[5; 32]).expect("test client key is invalid");
        hex::encode(secret.public_key().to_encoded_point(false).as_bytes())
    }

    /// An enrollment signed by [`owner`] at `issued_at_ms`.
    pub fn signed_request(issued_at_ms: u64) -> EnrollmentRequest {
        let mut request = EnrollmentRequest {
            parent_organization_id: PARENT.to_owned(),
            organization_id: "1f0e6b1e-2a4c-4f7e-8d2b-3c4d5e6f7a8b".to_owned(),
            wallet_name: WALLET_NAME.to_owned(),
            turnkey_wallet_id: "2a1b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d".to_owned(),
            solana_address: bs58::encode(owner().verifying_key().to_bytes()).into_string(),
            client_public_key: client_public_hex(),
            issued_at_ms,
            owner_signature: String::new(),
        };
        request.owner_signature = hex::encode(
            owner()
                .sign(enrollment_message(&request).as_bytes())
                .to_bytes(),
        );
        request
    }

    pub fn input() -> EnrollmentInput {
        let (input, _) = Enrollment::new(PARENT)
            .verify(&signed_request(NOW), NOW)
            .expect("test request is invalid");
        input
    }

    #[test]
    fn a_recent_owner_signature_enrolls() {
        let enrollment = Enrollment::new(PARENT);
        for now in [NOW, NOW + MAX_ENROLLMENT_AGE_MS, NOW - MAX_CLOCK_SKEW_MS] {
            assert!(
                enrollment.verify(&signed_request(NOW), now).is_ok(),
                "{now}"
            );
        }
    }

    #[test]
    fn an_old_or_future_enrollment_is_refused() {
        let enrollment = Enrollment::new(PARENT);
        for now in [NOW + MAX_ENROLLMENT_AGE_MS + 1, NOW - MAX_CLOCK_SKEW_MS - 1] {
            assert_eq!(
                enrollment.verify(&signed_request(NOW), now).err(),
                Some(ApiError::StaleEnrollment)
            );
        }
    }

    #[test]
    fn a_signature_by_another_key_or_over_other_fields_is_refused() {
        let enrollment = Enrollment::new(PARENT);
        let invalid = Some(ApiError::InvalidOwnerEnrollmentSignature);
        let mut intruder = signed_request(NOW);
        intruder.owner_signature = hex::encode(
            SigningKey::from_bytes(&[4; 32])
                .sign(enrollment_message(&intruder).as_bytes())
                .to_bytes(),
        );
        assert_eq!(enrollment.verify(&intruder, NOW).err(), invalid);
        let mut other_key = signed_request(NOW);
        let secret = p256::SecretKey::from_slice(&[6; 32]).expect("test client key is invalid");
        other_key.client_public_key =
            hex::encode(secret.public_key().to_encoded_point(false).as_bytes());
        assert_eq!(enrollment.verify(&other_key, NOW).err(), invalid);
        let mut other_time = signed_request(NOW);
        other_time.issued_at_ms += 1;
        assert_eq!(enrollment.verify(&other_time, NOW).err(), invalid);
    }

    #[test]
    fn requests_outside_the_parent_organization_or_malformed_are_refused() {
        let enrollment = Enrollment::new(PARENT);
        let mut foreign = signed_request(NOW);
        foreign.parent_organization_id = "00000000-0000-4000-8000-000000000000".to_owned();
        assert_eq!(
            enrollment.verify(&foreign, NOW).err(),
            Some(ApiError::UnexpectedParentOrganization)
        );
        let mut uppercase = signed_request(NOW);
        uppercase.client_public_key = uppercase.client_public_key.to_uppercase();
        assert!(enrollment.verify(&uppercase, NOW).is_err());
        let mut compressed = signed_request(NOW);
        compressed.client_public_key.truncate(66);
        assert!(enrollment.verify(&compressed, NOW).is_err());
    }

    #[test]
    fn the_message_matches_the_shared_test_vector() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/wallet-enrollment.json"))
                .expect("the test vector parses");
        let mut enrollment = fixture["enrollment"].clone();
        enrollment["ownerSignature"] = "".into();
        let request: EnrollmentRequest =
            serde_json::from_value(enrollment).expect("the test vector is an enrollment");
        assert_eq!(
            Some(enrollment_message(&request).as_str()),
            fixture["message"].as_str()
        );
    }
}
