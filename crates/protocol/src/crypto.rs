//! P-256 client authorization, QOS envelope, and secret-bearing types.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use borsh::{BorshDeserialize, BorshSerialize};
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::constants::{
    AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN, QOS_ENCRYPTION_HMAC_MESSAGE, QOS_P256_PUBLIC_LEN,
    RAW_P256_SIGNATURE_LEN, SEC1_UNCOMPRESSED_LEN,
};
use crate::error::{ErrorCode, TvcError};

type HmacSha512 = Hmac<Sha512>;

/// Secret bytes that zeroize on drop and redact in Debug.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes([redacted])")
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey32(Zeroizing<[u8; 32]>);

impl SecretKey32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey32([redacted])")
    }
}

pub fn parse_uncompressed_sec1(bytes: &[u8]) -> Result<PublicKey, TvcError> {
    if bytes.len() == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03) {
        return Err(TvcError::new(ErrorCode::CompressedKeyRejected));
    }
    if bytes.len() != SEC1_UNCOMPRESSED_LEN || bytes[0] != 0x04 {
        return Err(TvcError::new(ErrorCode::InvalidPublicKey));
    }
    let point =
        EncodedPoint::from_bytes(bytes).map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?;
    if point.is_compressed() {
        return Err(TvcError::new(ErrorCode::CompressedKeyRejected));
    }
    PublicKey::from_encoded_point(&point)
        .into_option()
        .ok_or_else(|| TvcError::new(ErrorCode::InvalidPublicKey))
}

pub fn public_key_uncompressed(public: &PublicKey) -> [u8; SEC1_UNCOMPRESSED_LEN] {
    let point = public.to_encoded_point(false);
    let bytes = point.as_bytes();
    let mut out = [0u8; SEC1_UNCOMPRESSED_LEN];
    out.copy_from_slice(bytes);
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QosP256Public {
    pub encryption: [u8; SEC1_UNCOMPRESSED_LEN],
    pub signing: [u8; SEC1_UNCOMPRESSED_LEN],
}

impl QosP256Public {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TvcError> {
        if bytes.len() != QOS_P256_PUBLIC_LEN {
            return Err(TvcError::new(ErrorCode::InvalidPublicKey));
        }
        let encryption: [u8; SEC1_UNCOMPRESSED_LEN] = bytes[..SEC1_UNCOMPRESSED_LEN]
            .try_into()
            .map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?;
        let signing: [u8; SEC1_UNCOMPRESSED_LEN] = bytes[SEC1_UNCOMPRESSED_LEN..]
            .try_into()
            .map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?;
        parse_uncompressed_sec1(&encryption)?;
        parse_uncompressed_sec1(&signing)?;
        Ok(Self {
            encryption,
            signing,
        })
    }

    pub fn to_bytes(self) -> [u8; QOS_P256_PUBLIC_LEN] {
        let mut out = [0u8; QOS_P256_PUBLIC_LEN];
        out[..SEC1_UNCOMPRESSED_LEN].copy_from_slice(&self.encryption);
        out[SEC1_UNCOMPRESSED_LEN..].copy_from_slice(&self.signing);
        out
    }
}

fn reject_der(signature: &[u8]) -> Result<(), TvcError> {
    if signature.len() != RAW_P256_SIGNATURE_LEN {
        if !signature.is_empty() && signature[0] == 0x30 {
            return Err(TvcError::new(ErrorCode::DerSignatureRejected));
        }
        return Err(TvcError::new(ErrorCode::InvalidSignature));
    }
    Ok(())
}

/// Client authorization and release signatures stay low-S only, Turnkey app
/// proofs arrive in either S half.
enum SignaturePolicy {
    LowSOnly,
    NormalizeHighS,
}

fn verify_p256_raw(
    public_sec1: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
    policy: SignaturePolicy,
) -> Result<(), TvcError> {
    let public = parse_uncompressed_sec1(public_sec1)?;
    let verifying_key = VerifyingKey::from(public);
    reject_der(signature)?;
    let parsed =
        Signature::from_slice(signature).map_err(|_| TvcError::new(ErrorCode::InvalidSignature))?;
    let parsed = match (policy, parsed.normalize_s()) {
        (SignaturePolicy::LowSOnly, Some(_)) => {
            return Err(TvcError::new(ErrorCode::HighSSignature))
        }
        (SignaturePolicy::NormalizeHighS, Some(normalized)) => normalized,
        (_, None) => parsed,
    };
    verifying_key
        .verify_prehash(digest, &parsed)
        .map_err(|_| TvcError::new(ErrorCode::InvalidSignature))
}

/// Sign `digest` with a prehash API. The digest MUST already be SHA-256(message).
pub fn sign_p256_prehash(
    secret: &[u8; 32],
    digest: &[u8; 32],
) -> Result<[u8; RAW_P256_SIGNATURE_LEN], TvcError> {
    let signing_key =
        SigningKey::from_slice(secret).map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?;
    let signature: Signature = signing_key
        .sign_prehash(digest)
        .map_err(|_| TvcError::new(ErrorCode::InvalidSignature))?;
    let normalized = signature.normalize_s().unwrap_or(signature);
    Ok(normalized.to_bytes().into())
}

/// Verify a 64-byte raw low-S signature over an already hashed digest.
pub fn verify_p256_prehash(
    public_sec1: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<(), TvcError> {
    verify_p256_raw(public_sec1, digest, signature, SignaturePolicy::LowSOnly)
}

/// Hash-internally APIs receive the raw domain-separated message, not a digest.
pub fn sign_p256_message(
    secret: &[u8; 32],
    message: &[u8],
) -> Result<[u8; RAW_P256_SIGNATURE_LEN], TvcError> {
    let digest: [u8; 32] = Sha256::digest(message).into();
    sign_p256_prehash(secret, &digest)
}

pub fn verify_p256_message(
    public_sec1: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TvcError> {
    let digest: [u8; 32] = Sha256::digest(message).into();
    verify_p256_prehash(public_sec1, &digest, signature)
}

pub fn verify_turnkey_app_proof_p256_message(
    public_sec1: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), TvcError> {
    let digest: [u8; 32] = Sha256::digest(message).into();
    verify_p256_raw(
        public_sec1,
        &digest,
        signature,
        SignaturePolicy::NormalizeHighS,
    )
}

/// A signature created by hashing `digest` again MUST fail prehash verification.
pub fn reject_double_hashed_signature(
    public_sec1: &[u8],
    digest: &[u8; 32],
    double_hashed_signature: &[u8],
) -> Result<(), TvcError> {
    match verify_p256_prehash(public_sec1, digest, double_hashed_signature) {
        Ok(()) => Err(TvcError::new(ErrorCode::DoubleHashRejected)),
        Err(error) if error.code == ErrorCode::InvalidSignature => Ok(()),
        Err(error) => Err(error),
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct QosEnvelope {
    pub nonce: [u8; AES_GCM_NONCE_LEN],
    pub ephemeral_sender_public: [u8; SEC1_UNCOMPRESSED_LEN],
    pub encrypted_message: Vec<u8>,
}

fn create_cipher_key(
    ephemeral_sender_public: &[u8],
    receiver_public: &[u8],
    shared_secret: &[u8],
) -> Result<[u8; 32], TvcError> {
    let mut pre_image = Zeroizing::new(Vec::with_capacity(
        ephemeral_sender_public.len() + receiver_public.len() + shared_secret.len(),
    ));
    pre_image.extend_from_slice(ephemeral_sender_public);
    pre_image.extend_from_slice(receiver_public);
    pre_image.extend_from_slice(shared_secret);
    let mut mac = <HmacSha512 as Mac>::new_from_slice(pre_image.as_slice())
        .map_err(|_| TvcError::new(ErrorCode::InvalidEncryptedEnvelope))?;
    mac.update(QOS_ENCRYPTION_HMAC_MESSAGE);
    let output = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&output[..32]);
    Ok(key)
}

fn create_aad(ephemeral_sender_public: &[u8], receiver_public: &[u8]) -> Result<Vec<u8>, TvcError> {
    let sender_len = u8::try_from(ephemeral_sender_public.len())
        .map_err(|_| TvcError::new(ErrorCode::InvalidEncryptedEnvelope))?;
    let receiver_len = u8::try_from(receiver_public.len())
        .map_err(|_| TvcError::new(ErrorCode::InvalidEncryptedEnvelope))?;
    let mut aad = Vec::with_capacity(ephemeral_sender_public.len() + receiver_public.len() + 2);
    aad.extend_from_slice(ephemeral_sender_public);
    aad.push(sender_len);
    aad.extend_from_slice(receiver_public);
    aad.push(receiver_len);
    Ok(aad)
}

fn ecdh_x(secret: &SecretKey, public: &PublicKey) -> Zeroizing<[u8; 32]> {
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(shared.raw_secret_bytes().as_slice());
    out
}

/// QOS `P256Public::encrypt` construction with caller-supplied nonce and ephemeral key.
///
/// This is the pinned QOS P-256 ECDH + HMAC-SHA-512 + AES-GCM envelope, not HPKE.
pub fn qos_encrypt_with(
    receiver_encryption_sec1: &[u8],
    plaintext: &[u8],
    ephemeral_secret: &[u8; 32],
    nonce: &[u8; AES_GCM_NONCE_LEN],
) -> Result<Vec<u8>, TvcError> {
    let receiver = parse_uncompressed_sec1(receiver_encryption_sec1)?;
    let receiver_bytes = public_key_uncompressed(&receiver);
    let ephemeral = SecretKey::from_slice(ephemeral_secret)
        .map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?;
    let ephemeral_public = public_key_uncompressed(&ephemeral.public_key());
    let shared = ecdh_x(&ephemeral, &receiver);
    let cipher_key = create_cipher_key(&ephemeral_public, &receiver_bytes, shared.as_slice())?;
    let aad = create_aad(&ephemeral_public, &receiver_bytes)?;
    let cipher = Aes256Gcm::new_from_slice(&cipher_key)
        .map_err(|_| TvcError::new(ErrorCode::InvalidEncryptedEnvelope))?;
    let payload = Payload {
        msg: plaintext,
        aad: &aad,
    };
    let encrypted_message = cipher
        .encrypt(Nonce::from_slice(nonce), payload)
        .map_err(|_| TvcError::new(ErrorCode::InvalidEncryptedEnvelope))?;
    if encrypted_message.len() < AES_GCM_TAG_LEN {
        return Err(TvcError::new(ErrorCode::InvalidEncryptedEnvelope));
    }
    let envelope = QosEnvelope {
        nonce: *nonce,
        ephemeral_sender_public: ephemeral_public,
        encrypted_message,
    };
    borsh::to_vec(&envelope).map_err(|_| TvcError::new(ErrorCode::InvalidEncryptedEnvelope))
}

pub fn qos_encrypt(receiver_encryption_sec1: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TvcError> {
    let ephemeral = SecretKey::random(&mut OsRng);
    let ephemeral_bytes: [u8; 32] = ephemeral.to_bytes().into();
    let mut nonce = [0u8; AES_GCM_NONCE_LEN];
    p256::elliptic_curve::rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce);
    qos_encrypt_with(
        receiver_encryption_sec1,
        plaintext,
        &ephemeral_bytes,
        &nonce,
    )
}

pub fn qos_decrypt(
    receiver_secret: &[u8; 32],
    envelope_bytes: &[u8],
) -> Result<SecretBytes, TvcError> {
    let envelope = QosEnvelope::try_from_slice(envelope_bytes)
        .map_err(|_| TvcError::new(ErrorCode::InvalidEncryptedEnvelope))?;
    if envelope.encrypted_message.len() < AES_GCM_TAG_LEN {
        return Err(TvcError::new(ErrorCode::InvalidEncryptedEnvelope));
    }
    parse_uncompressed_sec1(&envelope.ephemeral_sender_public)?;
    let receiver_secret = SecretKey::from_slice(receiver_secret)
        .map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?;
    let receiver_public = public_key_uncompressed(&receiver_secret.public_key());
    let ephemeral_public = parse_uncompressed_sec1(&envelope.ephemeral_sender_public)?;
    let shared = ecdh_x(&receiver_secret, &ephemeral_public);
    let cipher_key = create_cipher_key(
        &envelope.ephemeral_sender_public,
        &receiver_public,
        shared.as_slice(),
    )?;
    let aad = create_aad(&envelope.ephemeral_sender_public, &receiver_public)?;
    let cipher = Aes256Gcm::new_from_slice(&cipher_key)
        .map_err(|_| TvcError::new(ErrorCode::InvalidEncryptedEnvelope))?;
    let payload = Payload {
        msg: &envelope.encrypted_message,
        aad: &aad,
    };
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&envelope.nonce), payload)
        .map_err(|_| TvcError::new(ErrorCode::InvalidEncryptedEnvelope))?;
    Ok(SecretBytes::new(plaintext))
}

pub fn qos_public_from_secrets(
    encryption_secret: &[u8; 32],
    signing_secret: &[u8; 32],
) -> Result<QosP256Public, TvcError> {
    let enc = SecretKey::from_slice(encryption_secret)
        .map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?;
    let sign = SigningKey::from_slice(signing_secret)
        .map_err(|_| TvcError::new(ErrorCode::InvalidPublicKey))?;
    let signing_point = sign.verifying_key().to_encoded_point(false);
    let mut signing = [0u8; SEC1_UNCOMPRESSED_LEN];
    signing.copy_from_slice(signing_point.as_bytes());
    Ok(QosP256Public {
        encryption: public_key_uncompressed(&enc.public_key()),
        signing,
    })
}
