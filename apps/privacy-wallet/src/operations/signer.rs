use super::*;

pub(super) fn turnkey_client(
    keys: &RuntimeKeys,
) -> Result<Arc<TvcTurnkeyClient>, OperationFailure> {
    let stamper = QosTurnkeyStamper::new(Arc::clone(&keys.quorum));
    let client = TurnkeyClient::builder()
        .api_key(stamper)
        .build()
        .map_err(|_| OperationFailure::Unavailable)?
        .with_app_proofs();
    Ok(Arc::new(client))
}
/// Rebuilds the wallet's registered Ed25519 identity from sealed state.
///
/// The deployed custom-ring program authorizes `RingEddsa`: the same Turnkey
/// wallet key is both the ring owner and the Solana fee payer. The derivation
/// seed supplies the private nullifier and viewing roles without exposing
/// either role to the browser.
pub(super) fn default_keypair(
    client: &Arc<TvcTurnkeyClient>,
    wallet: &ValidatedWallet<'_>,
    inner: &KeyStatePlaintextV1,
) -> Result<TurnkeyEd25519ShieldedKeypair, OperationFailure> {
    let activities: Arc<dyn TurnkeyActivities> =
        Arc::new(TurnkeyApiActivities::new(Arc::clone(client)));
    TurnkeyEd25519ShieldedKeypair::restore_from_seed(
        activities,
        TurnkeyKeyRef::new(wallet.organization_id, wallet.sign_with),
        inner.ed25519_public_key,
        &inner.derivation_seed,
    )
    .map_err(|_| OperationFailure::Invalid)
}
/// Signs a v0 transaction through Turnkey.
///
/// A custom-ring transact needs a v0 message so an address lookup table can
/// keep it within Solana's packet limit. Turnkey accepts both Solana message
/// formats for the same signing intent; only the encoding-specific validation
/// differs below.
pub(super) async fn sign_versioned_transaction(
    client: &TvcTurnkeyClient,
    wallet: &ValidatedWallet<'_>,
    timestamp_ms: u64,
    unsigned: VersionedTransaction,
) -> Result<ActivityResult<(VersionedTransaction, Vec<TurnkeyVerifiedAppProofV1>)>, OperationFailure>
{
    if unsigned.signatures.len() != 1 || unsigned.signatures[0] != Signature::default() {
        return Err(OperationFailure::Unavailable);
    }
    let unsigned_bytes =
        bincode1::serialize(&unsigned).map_err(|_| OperationFailure::Unavailable)?;
    // Turnkey declining to sign and Turnkey signing something else are
    // different problems with different owners, so they are different stages.
    let activity = client
        .sign_transaction(
            wallet.organization_id.to_owned(),
            u128::from(timestamp_ms),
            SignTransactionIntentV2 {
                sign_with: wallet.sign_with.to_owned(),
                unsigned_transaction: hex::encode(unsigned_bytes),
                r#type: TransactionType::Solana,
            },
        )
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::TurnkeySigning))?;
    if activity.app_proofs.is_empty() {
        return Err(OperationFailure::Failed(FailureStage::TurnkeySigning));
    }
    let signed: VersionedTransaction = bincode1::deserialize(
        &hex::decode(&activity.result.signed_transaction)
            .map_err(|_| OperationFailure::Failed(FailureStage::SignedTransactionMismatch))?,
    )
    .map_err(|_| OperationFailure::Failed(FailureStage::SignedTransactionMismatch))?;
    // The message must come back byte for byte: Turnkey is asked to sign this
    // transaction, not to produce one. Verifying the signature over a message
    // it chose would prove nothing about what was authorized.
    if signed.message != unsigned.message
        || signed.signatures.len() != 1
        || signed.signatures[0] == Signature::default()
        || !signed.signatures[0].verify(
            wallet.expected_ed25519_public_key.as_ref(),
            &signed.message.serialize(),
        )
    {
        return Err(OperationFailure::Failed(
            FailureStage::SignedTransactionMismatch,
        ));
    }
    let proofs = app_proofs(&activity);
    Ok(ActivityResult {
        result: (signed, proofs),
        activity_id: activity.activity_id,
        status: activity.status,
        app_proofs: activity.app_proofs,
    })
}
/// Decodes straight into the caller's buffer, the seed halves never live in a
/// temporary allocation.
pub(super) fn decode_signature_component(
    encoded: &str,
    output: &mut [u8],
) -> Result<(), OperationFailure> {
    hex::decode_to_slice(encoded.strip_prefix("0x").unwrap_or(encoded), output)
        .map_err(|_| OperationFailure::Unavailable)
}
pub(super) fn app_proofs<T>(activity: &ActivityResult<T>) -> Vec<TurnkeyVerifiedAppProofV1> {
    activity.app_proofs.iter().map(convert_app_proof).collect()
}
pub(super) fn convert_app_proof(
    proof: &turnkey_client::generated::external::data::v1::AppProof,
) -> TurnkeyVerifiedAppProofV1 {
    TurnkeyVerifiedAppProofV1 {
        scheme: proof.scheme.as_str_name().to_owned(),
        public_key: proof.public_key.clone(),
        proof_payload: proof.proof_payload.clone(),
        signature: proof.signature.clone(),
    }
}
