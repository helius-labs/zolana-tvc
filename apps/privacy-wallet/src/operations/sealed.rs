use super::*;

/// Borsh-sealed contents of the key state. The seed is the only secret; every
/// other field exists so the blob cannot be replayed against a different
/// descriptor, wallet, or Quorum key epoch.
#[derive(BorshSerialize, BorshDeserialize)]
pub(super) struct KeyStatePlaintextV1 {
    pub(super) version: u8,
    pub(super) quorum_key_id: String,
    pub(super) quorum_key_epoch: u64,
    pub(super) wallet_id: String,
    pub(super) descriptor_digest: [u8; 32],
    pub(super) ed25519_public_key: [u8; 32],
    pub(super) derivation_suite: String,
    pub(super) derivation_seed: [u8; 64],
}
impl Drop for KeyStatePlaintextV1 {
    fn drop(&mut self) {
        self.derivation_seed.zeroize();
    }
}
/// Enclave-only contents of a prepared-spend capsule. It commits to one exact
/// direct transaction or one exact program SPP transition, plus all ambient
/// authority that made preparation valid. Finalization is stateless: the
/// caller stores and returns the sealed capsule but cannot alter these fields.
#[derive(BorshSerialize, BorshDeserialize)]
pub(super) struct SpendAuthorizationPlaintextV1 {
    pub(super) version: u8,
    pub(super) quorum_key_id: String,
    pub(super) quorum_key_epoch: u64,
    pub(super) wallet_id: String,
    pub(super) descriptor_digest: [u8; 32],
    pub(super) state_digest: [u8; 32],
    pub(super) target_release_id: String,
    pub(super) target_manifest_digest: [u8; 32],
    pub(super) target_executable_digest: [u8; 32],
    pub(super) prepare_request_id: [u8; 32],
    pub(super) expires_at_ms: u64,
    pub(super) artifact: SpendAuthorizationArtifactV1,
    pub(super) shielded_balance_before: u64,
}
#[derive(BorshSerialize, BorshDeserialize)]
pub(super) enum SpendAuthorizationArtifactV1 {
    ExactTransaction {
        transaction_digest: [u8; 32],
    },
    Spp {
        program_id: [u8; 32],
        input_tree: [u8; 32],
        program_authorities: Vec<[u8; 32]>,
        plan_digest: [u8; 32],
        prepared_transact: Vec<u8>,
        transact_digest: [u8; 32],
        private_tx_hash: [u8; 32],
    },
}
pub(super) fn seal_state(
    keys: &RuntimeKeys,
    inner: KeyStatePlaintextV1,
) -> Result<(SealedWalletStateV1, Vec<u8>, [u8; 32]), OperationFailure> {
    let plaintext =
        Zeroizing::new(borsh::to_vec(&inner).map_err(|_| OperationFailure::Unavailable)?);
    let ciphertext = keys
        .quorum
        .public_key()
        .encrypt(&plaintext)
        .map_err(|_| OperationFailure::Unavailable)?;
    let sealed = SealedWalletStateV1 {
        version: API_VERSION,
        quorum_key_id: inner.quorum_key_id.clone(),
        quorum_key_epoch: inner.quorum_key_epoch,
        wallet_id_hash: wallet_id_hash(&inner.wallet_id),
        ciphertext,
    };
    let bytes = borsh::to_vec(&sealed).map_err(|_| OperationFailure::Unavailable)?;
    let digest = state_digest(&bytes);
    Ok((sealed, bytes, digest))
}
/// Unseals the key state and checks it twice: the envelope against the request,
/// then the decrypted contents against both the envelope and the descriptor. A
/// blob is therefore usable only by the descriptor and Quorum key epoch it was
/// issued under.
pub(super) fn unseal_state(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
    sealed_bytes: &[u8],
) -> Result<(KeyStatePlaintextV1, [u8; 32]), OperationFailure> {
    let sealed =
        SealedWalletStateV1::try_from_slice(sealed_bytes).map_err(|_| OperationFailure::Invalid)?;
    let digest = state_digest(sealed_bytes);
    if sealed.version != API_VERSION
        || sealed.quorum_key_id != request.quorum_key_id
        || sealed.quorum_key_epoch != request.quorum_key_epoch
        || sealed.wallet_id_hash != wallet_id_hash(&request.wallet_descriptor.wallet_id())
    {
        return Err(OperationFailure::Invalid);
    }
    let plaintext = Zeroizing::new(
        keys.quorum
            .decrypt(&sealed.ciphertext)
            .map_err(|_| OperationFailure::Invalid)?,
    );
    let inner =
        KeyStatePlaintextV1::try_from_slice(&plaintext).map_err(|_| OperationFailure::Invalid)?;
    let descriptor_hash = descriptor_digest_from_wallet(&request.wallet_descriptor)
        .map_err(|_| OperationFailure::Invalid)?;
    let expected_ed25519 = Pubkey::from_str(&request.wallet_descriptor.address)
        .map_err(|_| OperationFailure::Invalid)?
        .to_bytes();
    if inner.version != API_VERSION
        || inner.quorum_key_id != sealed.quorum_key_id
        || inner.quorum_key_epoch != sealed.quorum_key_epoch
        || inner.wallet_id != request.wallet_descriptor.wallet_id()
        || inner.descriptor_digest != descriptor_hash
        || inner.ed25519_public_key != expected_ed25519
        || inner.derivation_suite != DERIVATION_SUITE
    {
        return Err(OperationFailure::Invalid);
    }
    Ok((inner, digest))
}
pub(super) fn current_time_ms() -> Result<u64, OperationFailure> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OperationFailure::Unavailable)?
        .as_millis();
    u64::try_from(millis).map_err(|_| OperationFailure::Unavailable)
}
pub(super) fn seal_spend_authorization(
    keys: &RuntimeKeys,
    inner: SpendAuthorizationPlaintextV1,
) -> Result<Vec<u8>, OperationFailure> {
    let plaintext =
        Zeroizing::new(borsh::to_vec(&inner).map_err(|_| OperationFailure::Unavailable)?);
    let ciphertext = keys
        .quorum
        .public_key()
        .encrypt(&plaintext)
        .map_err(|_| OperationFailure::Unavailable)?;
    let sealed = SealedSpendAuthorizationV1 {
        version: API_VERSION,
        quorum_key_id: inner.quorum_key_id,
        quorum_key_epoch: inner.quorum_key_epoch,
        wallet_id_hash: wallet_id_hash(&inner.wallet_id),
        prepare_request_id: inner.prepare_request_id,
        expires_at_ms: inner.expires_at_ms,
        ciphertext,
    };
    borsh::to_vec(&sealed).map_err(|_| OperationFailure::Unavailable)
}
pub(super) fn unseal_spend_authorization(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
    sealed_bytes: &[u8],
    state_digest_bytes: [u8; 32],
) -> Result<SpendAuthorizationPlaintextV1, OperationFailure> {
    let sealed = SealedSpendAuthorizationV1::try_from_slice(sealed_bytes)
        .map_err(|_| OperationFailure::Invalid)?;
    if sealed.version != API_VERSION
        || sealed.quorum_key_id != request.quorum_key_id
        || sealed.quorum_key_epoch != request.quorum_key_epoch
        || sealed.wallet_id_hash != wallet_id_hash(&request.wallet_descriptor.wallet_id())
        || sealed.expires_at_ms < current_time_ms()?
    {
        return Err(OperationFailure::Invalid);
    }
    let plaintext = Zeroizing::new(
        keys.quorum
            .decrypt(&sealed.ciphertext)
            .map_err(|_| OperationFailure::Invalid)?,
    );
    let inner = SpendAuthorizationPlaintextV1::try_from_slice(&plaintext)
        .map_err(|_| OperationFailure::Invalid)?;
    let descriptor_hash = descriptor_digest_from_wallet(&request.wallet_descriptor)
        .map_err(|_| OperationFailure::Invalid)?;
    if inner.version != API_VERSION
        || inner.quorum_key_id != sealed.quorum_key_id
        || inner.quorum_key_epoch != sealed.quorum_key_epoch
        || inner.wallet_id != request.wallet_descriptor.wallet_id()
        || inner.descriptor_digest != descriptor_hash
        || inner.state_digest != state_digest_bytes
        || inner.target_release_id != request.target_release_id
        || inner.target_manifest_digest != request.target_manifest_digest
        || inner.target_executable_digest != request.target_executable_digest
        || inner.prepare_request_id != sealed.prepare_request_id
        || inner.expires_at_ms != sealed.expires_at_ms
    {
        return Err(OperationFailure::Invalid);
    }
    Ok(inner)
}
