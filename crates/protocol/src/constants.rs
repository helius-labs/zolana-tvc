//! Domain separators and protocol limits from spec.md.

pub const API_VERSION: u8 = 1;
pub const TVC_APP_PROOF_TYPE: &str = "zolana.tvc.wallet_operation.v1";
pub const TVC_APP_PROOF_SCHEME: &str = "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256";
pub const TVC_QOS_PING_PROOF_TYPE: &str = "zolana.tvc.qos_ping.v1";

pub const CLIENT_AUTH_DOMAIN: &[u8] = b"ZOLANA_TVC_CLIENT_AUTH_V1";
pub const PROVISIONING_AUTH_DOMAIN: &[u8] = b"ZOLANA_TVC_PROVISIONING_AUTH_V1";
pub const OWNER_AUTH_DOMAIN: &[u8] = b"ZOLANA_TVC_OWNER_AUTH_V1";
pub const OWNER_AUTH_EVIDENCE_DOMAIN: &[u8] = b"ZOLANA_TVC_OWNER_AUTH_EVIDENCE_V1";
pub const ROTATION_AUTH_DOMAIN: &[u8] = b"ZOLANA_TVC_ROTATION_AUTH_V1";
pub const REQUEST_DIGEST_DOMAIN: &[u8] = b"ZOLANA_TVC_REQUEST_V1";
pub const RESULT_DIGEST_DOMAIN: &[u8] = b"ZOLANA_TVC_RESULT_V1";
pub const TURNKEY_EVIDENCE_DIGEST_DOMAIN: &[u8] = b"ZOLANA_TVC_TURNKEY_EVIDENCE_V1";
pub const STATE_DIGEST_DOMAIN: &[u8] = b"ZOLANA_TVC_STATE_DIGEST_V1";
pub const ARTIFACT_DIGEST_DOMAIN: &[u8] = b"ZOLANA_TVC_ARTIFACT_V1";
pub const WALLET_ID_HASH_DOMAIN: &[u8] = b"ZOLANA_TVC_WALLET_ID_V1";
pub const REQUEST_ID_HASH_DOMAIN: &[u8] = b"ZOLANA_TVC_REQUEST_ID_V1";
pub const ACTIVITY_ID_HASH_DOMAIN: &[u8] = b"ZOLANA_TVC_ACTIVITY_ID_V1";
pub const OPERATION_RANDOMNESS_DOMAIN: &[u8] = b"ZOLANA_TVC_OPERATION_V1";
pub const STATE_CONTEXT: &[u8] = b"ZOLANA_TVC_WALLET_STATE_V1";
pub const CONTINUATION_CONTEXT: &[u8] = b"ZOLANA_TVC_CONTINUATION_V1";
pub const RELEASE_POLICY_DOMAIN: &[u8] = b"ZOLANA_TVC_RELEASE_POLICY_V1";
pub const RELEASE_CHANNEL_DOMAIN: &[u8] = b"ZOLANA_TVC_RELEASE_CHANNEL_V1";
pub const RECOVERY_INTENT_DOMAIN: &[u8] = b"ZOLANA_TVC_RECOVERY_INTENT_V1";
pub const STATE_COMMITMENT_DOMAIN: &[u8] = b"ZOLANA_TVC_STATE_COMMITMENT_V1";
pub const QUORUM_ROTATION_DOMAIN: &[u8] = b"ZOLANA_TVC_QUORUM_ROTATION_V1";

pub const MAX_REQUEST_AGE_MS: u64 = 300_000;
pub const MAX_CLOCK_SKEW_MS: u64 = 60_000;
pub const MAX_TRANSACTION_CONTINUATION_AGE_MS: u64 = 86_400_000;
pub const PHASE0_MAX_ENCRYPTED_REQUEST_BYTES: u64 = 262_144;
pub const PHASE0_MAX_ENCRYPTED_RESPONSE_BYTES: u64 = 262_144;
pub const ABSOLUTE_MAX_ENCRYPTED_REQUEST_BYTES: u64 = 16_777_216;
pub const ABSOLUTE_MAX_ENCRYPTED_RESPONSE_BYTES: u64 = 16_777_216;
pub const MAX_DESCRIPTOR_BYTES: u64 = 65_536;

/// Caps one `DecryptUtxos` batch. The envelope limit already bounds the request,
/// but it bounds bytes rather than work: a small request can still ask for a
/// large number of decryptions. This is the bound on work, and clients page
/// against it. `DeriveViewTags` needs no such cap; it answers with one tag per
/// viewing key the application holds.
pub const MAX_DECRYPT_PAYLOADS_PER_BATCH: u64 = 256;

pub const SEC1_UNCOMPRESSED_LEN: usize = 65;
pub const QOS_P256_PUBLIC_LEN: usize = 130;
pub const RAW_P256_SIGNATURE_LEN: usize = 64;
pub const SHA256_LEN: usize = 32;
pub const AES_GCM_NONCE_LEN: usize = 12;
pub const AES_GCM_TAG_LEN: usize = 16;

pub const QOS_ENCRYPTION_HMAC_MESSAGE: &[u8] = b"qos_encryption_hmac_message";
pub const AES_GCM_256_HMAC_SHA512_TAG: &[u8] = b"qos_aes_gcm_256_hmac_sha512";

pub const CLIENT_AUTH_SCHEME_WIRE: &str = "p256-sha256";
