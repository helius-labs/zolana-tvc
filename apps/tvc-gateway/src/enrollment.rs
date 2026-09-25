//! Enrollment: the gateway issues a challenge naming the wallet and the
//! client key, the wallet owner signs it through Turnkey, and the signed
//! challenge is redeemed for a descriptor.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zolana_tvc_protocol::crypto::parse_uncompressed_sec1;

use crate::error::ApiError;
use crate::project::ProjectId;
use crate::sealed_token::{Purpose, SealingKey};

/// Prefix of the message the wallet owner signs, followed by
/// `"\n" || hex(sha256(token))`.
pub const ENROLLMENT_DOMAIN: &str = "ZOLANA_TVC_WALLET_ENROLLMENT_V1";
pub const WALLET_NAME: &str = "Solana Wallet";
const ENROLLMENT_TTL_MS: u64 = 5 * 60 * 1_000;
const MAX_CLOCK_SKEW_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub parent_organization_id: String,
    pub organization_id: String,
    pub wallet_name: String,
    pub turnkey_wallet_id: String,
    pub solana_address: String,
    /// Uncompressed SEC1 P-256 key, lowercase hex.
    pub client_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Redemption {
    pub token: String,
    /// Ed25519 signature by the wallet address over the challenge message, hex.
    pub owner_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Challenge {
    pub token: String,
    pub message: String,
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChallengePayload {
    version: u8,
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: String,
    project_id: String,
    request: EnrollmentRequest,
}

pub struct Enrollment {
    key: SealingKey,
    parent_organization_id: String,
}

impl Enrollment {
    pub fn new(secret: &str, parent_organization_id: &str) -> anyhow::Result<Self> {
        Ok(Self {
            key: SealingKey::new(Purpose::Enrollment, secret)?,
            parent_organization_id: parent_organization_id.to_owned(),
        })
    }

    pub fn challenge(
        &self,
        request: EnrollmentRequest,
        project: &ProjectId,
        now_ms: u64,
        nonce: [u8; 16],
    ) -> Result<Challenge, ApiError> {
        self.validate(&request)?;
        let payload = ChallengePayload {
            version: 1,
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ENROLLMENT_TTL_MS),
            nonce: hex::encode(nonce),
            project_id: project.as_str().to_owned(),
            request,
        };
        let token = self.key.seal(&payload).map_err(|error| {
            tracing::error!(%error, "enrollment challenge did not serialize");
            ApiError::BadRequest("InvalidEnrollmentRequest")
        })?;
        let message = enrollment_message(&token);
        Ok(Challenge { token, message })
    }

    /// The enrollment a signed challenge names, if this gateway issued it to
    /// `project`, it is unexpired, and the wallet address signed it.
    pub fn redeem(
        &self,
        redemption: &Redemption,
        project: &ProjectId,
        now_ms: u64,
    ) -> Result<EnrollmentInput, ApiError> {
        let invalid = ApiError::BadRequest("InvalidEnrollmentToken");
        let payload: ChallengePayload = self.key.open(&redemption.token).ok_or(invalid)?;
        let fresh = payload.version == 1
            && payload.expires_at_ms.saturating_sub(payload.issued_at_ms) == ENROLLMENT_TTL_MS
            && payload.issued_at_ms <= now_ms.saturating_add(MAX_CLOCK_SKEW_MS)
            && payload.expires_at_ms >= now_ms;
        if !fresh || payload.project_id != project.as_str() {
            return Err(invalid);
        }
        let input = self.validate(&payload.request)?;
        verify_owner_signature(&input, &redemption.token, &redemption.owner_signature)?;
        Ok(input)
    }

    fn validate(&self, request: &EnrollmentRequest) -> Result<EnrollmentInput, ApiError> {
        let invalid = ApiError::BadRequest("InvalidEnrollmentRequest");
        if !is_canonical_uuid(&request.organization_id)
            || !is_canonical_uuid(&request.turnkey_wallet_id)
            || request.wallet_name != WALLET_NAME
        {
            return Err(invalid);
        }
        if request.parent_organization_id != self.parent_organization_id {
            return Err(ApiError::BadRequest("UnexpectedParentOrganization"));
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

pub fn enrollment_message(token: &str) -> String {
    format!(
        "{ENROLLMENT_DOMAIN}\n{}",
        hex::encode(Sha256::digest(token.as_bytes()))
    )
}

fn verify_owner_signature(
    input: &EnrollmentInput,
    token: &str,
    signature_hex: &str,
) -> Result<(), ApiError> {
    let invalid = ApiError::BadRequest("InvalidOwnerEnrollmentSignature");
    let mut signature = [0u8; 64];
    hex::decode_to_slice(signature_hex, &mut signature).map_err(|_| invalid)?;
    let owner = VerifyingKey::from_bytes(&input.owner_public_key).map_err(|_| invalid)?;
    owner
        .verify_strict(
            enrollment_message(token).as_bytes(),
            &Signature::from_bytes(&signature),
        )
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
    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const NOW: u64 = 1_800_000_000_000;

    pub fn owner() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    pub fn client_public_hex() -> String {
        let Ok(secret) = p256::SecretKey::from_slice(&[5; 32]) else {
            panic!("test client key is invalid");
        };
        hex::encode(secret.public_key().to_encoded_point(false).as_bytes())
    }

    pub fn request() -> EnrollmentRequest {
        EnrollmentRequest {
            parent_organization_id: PARENT.to_owned(),
            organization_id: "1f0e6b1e-2a4c-4f7e-8d2b-3c4d5e6f7a8b".to_owned(),
            wallet_name: WALLET_NAME.to_owned(),
            turnkey_wallet_id: "2a1b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d".to_owned(),
            solana_address: bs58::encode(owner().verifying_key().to_bytes()).into_string(),
            client_public_key: client_public_hex(),
        }
    }

    pub fn input() -> EnrollmentInput {
        let Ok(input) = enrollment().validate(&request()) else {
            panic!("test request is invalid");
        };
        input
    }

    fn enrollment() -> Enrollment {
        let Ok(enrollment) = Enrollment::new(SECRET, PARENT) else {
            panic!("enrollment key is invalid");
        };
        enrollment
    }

    fn signed_redemption(challenge: &Challenge) -> Redemption {
        let signature = owner().sign(challenge.message.as_bytes());
        Redemption {
            token: challenge.token.clone(),
            owner_signature: hex::encode(signature.to_bytes()),
        }
    }

    fn issue(project: &ProjectId) -> Challenge {
        let Ok(challenge) = enrollment().challenge(request(), project, NOW, [1; 16]) else {
            panic!("challenge failed");
        };
        challenge
    }

    #[test]
    fn a_signed_challenge_redeems_for_the_same_project() {
        let project = ProjectId::for_tests("project-a");
        let redemption = signed_redemption(&issue(&project));
        assert_eq!(
            enrollment().redeem(&redemption, &project, NOW + 1_000),
            Ok(input())
        );
    }

    #[test]
    fn a_challenge_does_not_redeem_for_another_project() {
        let redemption = signed_redemption(&issue(&ProjectId::for_tests("project-a")));
        let other = ProjectId::for_tests("project-b");
        assert_eq!(
            enrollment().redeem(&redemption, &other, NOW),
            Err(ApiError::BadRequest("InvalidEnrollmentToken"))
        );
    }

    #[test]
    fn an_expired_challenge_does_not_redeem() {
        let project = ProjectId::for_tests("project-a");
        let redemption = signed_redemption(&issue(&project));
        assert_eq!(
            enrollment().redeem(&redemption, &project, NOW + ENROLLMENT_TTL_MS + 1),
            Err(ApiError::BadRequest("InvalidEnrollmentToken"))
        );
    }

    #[test]
    fn a_signature_by_another_key_does_not_redeem() {
        let project = ProjectId::for_tests("project-a");
        let challenge = issue(&project);
        let intruder = SigningKey::from_bytes(&[4; 32]);
        let redemption = Redemption {
            token: challenge.token,
            owner_signature: hex::encode(intruder.sign(challenge.message.as_bytes()).to_bytes()),
        };
        assert_eq!(
            enrollment().redeem(&redemption, &project, NOW),
            Err(ApiError::BadRequest("InvalidOwnerEnrollmentSignature"))
        );
    }

    #[test]
    fn requests_outside_the_parent_organization_or_malformed_are_refused() {
        let project = ProjectId::for_tests("project-a");
        let mut foreign = request();
        foreign.parent_organization_id = "00000000-0000-4000-8000-000000000000".to_owned();
        assert_eq!(
            enrollment().challenge(foreign, &project, NOW, [1; 16]),
            Err(ApiError::BadRequest("UnexpectedParentOrganization"))
        );
        let mut uppercase = request();
        uppercase.client_public_key = uppercase.client_public_key.to_uppercase();
        assert!(
            enrollment()
                .challenge(uppercase, &project, NOW, [1; 16])
                .is_err()
        );
        let mut compressed = request();
        compressed.client_public_key.truncate(66);
        assert!(
            enrollment()
                .challenge(compressed, &project, NOW, [1; 16])
                .is_err()
        );
    }
}
