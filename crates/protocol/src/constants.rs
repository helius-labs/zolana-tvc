//! Domain separators and protocol limits from spec.md.

pub const API_VERSION: u8 = 1;
pub const TVC_APP_PROOF_TYPE: &str = "zolana.tvc.wallet_operation.v1";
pub const TVC_APP_PROOF_SCHEME: &str = "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256";
pub const TVC_QOS_PING_PROOF_TYPE: &str = "zolana.tvc.qos_ping.v1";
pub const EXPECTED_TURNKEY_TRUST_ROOT_ID: &str = "aws-nitro-root-g1";

pub const CLIENT_AUTH_DOMAIN: &[u8] = b"ZOLANA_TVC_CLIENT_AUTH_V1";
pub const PROVISIONING_AUTH_DOMAIN: &[u8] = b"ZOLANA_TVC_PROVISIONING_AUTH_V1";
pub const REQUEST_DIGEST_DOMAIN: &[u8] = b"ZOLANA_TVC_REQUEST_V1";
pub const RESULT_DIGEST_DOMAIN: &[u8] = b"ZOLANA_TVC_RESULT_V1";
pub const STATE_DIGEST_DOMAIN: &[u8] = b"ZOLANA_TVC_STATE_DIGEST_V1";
pub const ARTIFACT_DIGEST_DOMAIN: &[u8] = b"ZOLANA_TVC_ARTIFACT_V1";
pub const WALLET_ID_HASH_DOMAIN: &[u8] = b"ZOLANA_TVC_WALLET_ID_V1";
pub const REQUEST_ID_HASH_DOMAIN: &[u8] = b"ZOLANA_TVC_REQUEST_ID_V1";
pub const RELEASE_POLICY_DOMAIN: &[u8] = b"ZOLANA_TVC_RELEASE_POLICY_V1";
pub const STATE_COMMITMENT_DOMAIN: &[u8] = b"ZOLANA_TVC_STATE_COMMITMENT_V1";

pub const MAX_REQUEST_AGE_MS: u64 = 300_000;
pub const MAX_CLOCK_SKEW_MS: u64 = 60_000;
pub const DEVNET_MAX_ENCRYPTED_REQUEST_BYTES: u64 = 262_144;
pub const DEVNET_MAX_ENCRYPTED_RESPONSE_BYTES: u64 = 262_144;

/// Caps one `DecryptUtxos` batch. The envelope limit already bounds the request,
/// but it bounds bytes rather than work: a small request can still ask for a
/// large number of decryptions. This is the bound on work, and clients page
/// against it. `DeriveViewTags` needs no such cap; it answers with one tag per
/// viewing key the application holds.
pub const MAX_DECRYPT_PAYLOADS_PER_BATCH: u64 = 256;
/// Caps the spendable-output snapshot returned by `DecryptUtxos`. A snapshot
/// is intentionally bounded independently from ciphertext decryption so a
/// wallet with pathological UTXO fragmentation cannot exceed the encrypted
/// response envelope.
pub const MAX_SPENDABLE_OUTPUTS: u64 = 512;

pub const SEC1_UNCOMPRESSED_LEN: usize = 65;
pub const QOS_P256_PUBLIC_LEN: usize = 130;
pub const RAW_P256_SIGNATURE_LEN: usize = 64;
pub const SHA256_LEN: usize = 32;
pub const AES_GCM_NONCE_LEN: usize = 12;
pub const AES_GCM_TAG_LEN: usize = 16;

pub const QOS_ENCRYPTION_HMAC_MESSAGE: &[u8] = b"qos_encryption_hmac_message";
