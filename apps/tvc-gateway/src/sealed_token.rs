//! `base64url(payload) "." base64url(HMAC-SHA256(key, purpose || 0x00 || base64url(payload)))`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::Sha256;

const MAX_TOKEN_LEN: usize = 8_192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Enrollment,
}

impl Purpose {
    #[inline]
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Enrollment => b"HELIUS_TVC_GATEWAY_ENROLLMENT_V1",
        }
    }
}

pub struct SealingKey {
    keyed: Hmac<Sha256>,
}

impl SealingKey {
    pub fn new(purpose: Purpose, secret: &str) -> anyhow::Result<Self> {
        let mut keyed = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())?;
        keyed.update(purpose.label());
        keyed.update(&[0]);
        Ok(Self { keyed })
    }

    pub fn seal<T: Serialize>(&self, payload: &T) -> Result<String, serde_json::Error> {
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload)?);
        let tag = URL_SAFE_NO_PAD.encode(self.tag(&encoded));
        Ok(format!("{encoded}.{tag}"))
    }

    /// The payload of a token this key sealed, or `None`.
    pub fn open<T: DeserializeOwned>(&self, token: &str) -> Option<T> {
        if token.len() > MAX_TOKEN_LEN {
            return None;
        }
        let (encoded, tag) = token.split_once('.')?;
        let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
        self.mac(encoded).verify_slice(&tag).ok()?;
        let payload = URL_SAFE_NO_PAD.decode(encoded).ok()?;
        serde_json::from_slice(&payload).ok()
    }

    fn tag(&self, encoded: &str) -> [u8; 32] {
        self.mac(encoded).finalize().into_bytes().into()
    }

    fn mac(&self, encoded: &str) -> Hmac<Sha256> {
        let mut mac = self.keyed.clone();
        mac.update(encoded.as_bytes());
        mac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn key(purpose: Purpose, secret: &str) -> SealingKey {
        let Ok(key) = SealingKey::new(purpose, secret) else {
            panic!("hmac accepts any key length");
        };
        key
    }

    #[test]
    fn a_sealed_payload_opens_only_with_the_same_key() {
        let enrollment = key(Purpose::Enrollment, SECRET);
        let Ok(token) = enrollment.seal(&42u32) else {
            panic!("seal failed");
        };
        assert_eq!(enrollment.open::<u32>(&token), Some(42));
        let other = key(Purpose::Enrollment, "fedcba9876543210fedcba9876543210");
        assert_eq!(other.open::<u32>(&token), None);
    }

    #[test]
    fn a_modified_payload_does_not_open() {
        let key = key(Purpose::Enrollment, SECRET);
        let Ok(token) = key.seal(&42u32) else {
            panic!("seal failed");
        };
        let Some((_, tag)) = token.split_once('.') else {
            panic!("malformed token");
        };
        let forged = format!("{}.{tag}", URL_SAFE_NO_PAD.encode(b"43"));
        assert_eq!(key.open::<u32>(&forged), None);
    }
}
