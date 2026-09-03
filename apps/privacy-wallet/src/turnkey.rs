//! Turnkey API stamping backed directly by the QOS Quorum signing subkey.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::ecdsa::Signature;
use qos_p256::P256Pair;
use serde::Serialize;
use turnkey_api_key_stamper::{
    Stamp, StampHeader, StamperError, API_KEY_STAMP_HEADER_NAME, SIGNATURE_SCHEME_P256,
};

#[derive(Clone)]
pub(crate) struct QosTurnkeyStamper {
    quorum: Arc<P256Pair>,
}

impl std::fmt::Debug for QosTurnkeyStamper {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QosTurnkeyStamper([redacted])")
    }
}

impl QosTurnkeyStamper {
    pub(crate) fn new(quorum: Arc<P256Pair>) -> Self {
        Self { quorum }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TurnkeyApiStamp<'a> {
    public_key: String,
    signature: String,
    scheme: &'a str,
}

impl Stamp for QosTurnkeyStamper {
    fn stamp(&self, body: &[u8]) -> Result<StampHeader, StamperError> {
        let signature = self
            .quorum
            .sign(body)
            .map_err(|_| StamperError::InvalidPrivateKeyBytes("QOS signing failed".to_owned()))?;
        let signature = Signature::from_slice(&signature).map_err(|_| {
            StamperError::InvalidPrivateKeyBytes("QOS returned an invalid signature".to_owned())
        })?;
        let public_key = self
            .quorum
            .public_key()
            .signing_key()
            .to_encoded_point(true);
        let stamp = TurnkeyApiStamp {
            public_key: hex::encode(public_key.as_bytes()),
            signature: hex::encode(signature.to_der()),
            scheme: SIGNATURE_SCHEME_P256,
        };
        let stamp = serde_json::to_vec(&stamp).map_err(|_| {
            StamperError::InvalidPrivateKeyBytes("failed to encode API stamp".to_owned())
        })?;
        Ok(StampHeader {
            name: API_KEY_STAMP_HEADER_NAME.to_owned(),
            value: URL_SAFE_NO_PAD.encode(stamp),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DecodedStamp {
        public_key: String,
        signature: String,
        scheme: String,
    }

    #[test]
    fn stamps_with_the_qos_signing_subkey() {
        let pair = Arc::new(P256Pair::generate().unwrap());
        let expected = pair
            .public_key()
            .signing_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let stamper = QosTurnkeyStamper::new(pair);
        let body = br#"{"hello":"turnkey"}"#;
        let header = stamper.stamp(body).unwrap();
        assert_eq!(header.name, API_KEY_STAMP_HEADER_NAME);
        let decoded: DecodedStamp =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header.value).unwrap()).unwrap();
        assert_eq!(decoded.scheme, SIGNATURE_SCHEME_P256);
        assert_eq!(hex::decode(&decoded.public_key).unwrap(), expected);
        let verifying_key = VerifyingKey::from_sec1_bytes(&expected).unwrap();
        let signature = Signature::from_der(&hex::decode(decoded.signature).unwrap()).unwrap();
        verifying_key.verify(body, &signature).unwrap();
    }
}
