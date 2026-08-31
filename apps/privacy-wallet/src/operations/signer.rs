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

pub(super) struct CustodyRawSignature {
    pub(super) r: Vec<u8>,
    pub(super) s: Vec<u8>,
    pub(super) activity_id: String,
    pub(super) app_proofs: Vec<TurnkeyVerifiedAppProofV1>,
}

pub(super) struct CustodySignedTransaction {
    pub(super) transaction: VersionedTransaction,
    pub(super) activity_id: String,
    pub(super) app_proofs: Vec<TurnkeyVerifiedAppProofV1>,
}

pub(super) async fn sign_derivation_payload(
    _state: &AppState,
    keys: &RuntimeKeys,
    wallet: &ValidatedWallet<'_>,
    timestamp_ms: u64,
    payload: &[u8],
) -> Result<CustodyRawSignature, OperationFailure> {
    #[cfg(feature = "local-dev")]
    if let Some(local_wallet) = _state.local_wallet.as_deref() {
        let signature = local_wallet
            .activities()
            .sign_raw_payload(
                wallet.organization_id,
                wallet.sign_with,
                payload,
                zolana_keypair_turnkey::PayloadHashFunction::NotApplicable,
            )
            .await
            .map_err(|_| OperationFailure::Unavailable)?;
        return Ok(CustodyRawSignature {
            r: signature.r,
            s: signature.s,
            activity_id: "local-custody-bootstrap".to_owned(),
            app_proofs: Vec::new(),
        });
    }

    let client = turnkey_client(keys)?;
    let activity = client
        .sign_raw_payload(
            wallet.organization_id.to_owned(),
            u128::from(timestamp_ms),
            SignRawPayloadIntentV2 {
                sign_with: wallet.sign_with.to_owned(),
                payload: hex::encode(payload),
                encoding: PayloadEncoding::Hexadecimal,
                hash_function: HashFunction::NotApplicable,
            },
        )
        .await
        .map_err(|_| OperationFailure::Unavailable)?;
    if activity.app_proofs.is_empty() {
        return Err(OperationFailure::Unavailable);
    }
    Ok(CustodyRawSignature {
        r: hex::decode(
            activity
                .result
                .r
                .strip_prefix("0x")
                .unwrap_or(&activity.result.r),
        )
        .map_err(|_| OperationFailure::Unavailable)?,
        s: hex::decode(
            activity
                .result
                .s
                .strip_prefix("0x")
                .unwrap_or(&activity.result.s),
        )
        .map_err(|_| OperationFailure::Unavailable)?,
        activity_id: activity.activity_id.clone(),
        app_proofs: app_proofs(&activity),
    })
}

pub(super) fn custody_activities(
    _state: &AppState,
    keys: &RuntimeKeys,
) -> Result<Arc<dyn TurnkeyActivities>, OperationFailure> {
    #[cfg(feature = "local-dev")]
    if let Some(local_wallet) = _state.local_wallet.as_deref() {
        return Ok(local_wallet.activities());
    }

    let client = turnkey_client(keys)?;
    Ok(Arc::new(TurnkeyApiActivities::new(client)))
}
/// Rebuilds the wallet's registered Ed25519 identity from sealed state.
///
/// The deployed custom-ring program authorizes `RingEddsa`: the same Turnkey
/// wallet key is both the ring owner and the Solana fee payer. The derivation
/// seed supplies the private nullifier and viewing roles without exposing
/// either role to the browser.
pub(super) fn default_keypair(
    state: &AppState,
    keys: &RuntimeKeys,
    wallet: &ValidatedWallet<'_>,
    inner: &KeyStatePlaintextV1,
) -> Result<TurnkeyEd25519ShieldedKeypair, OperationFailure> {
    TurnkeyEd25519ShieldedKeypair::restore_from_seed(
        custody_activities(state, keys)?,
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
    _state: &AppState,
    keys: &RuntimeKeys,
    wallet: &ValidatedWallet<'_>,
    timestamp_ms: u64,
    unsigned: VersionedTransaction,
) -> Result<CustodySignedTransaction, OperationFailure> {
    if unsigned.signatures.len() != 1 || unsigned.signatures[0] != Signature::default() {
        return Err(OperationFailure::Unavailable);
    }
    #[cfg(feature = "local-dev")]
    if let Some(local_wallet) = _state.local_wallet.as_deref() {
        let mut signed = unsigned;
        signed.signatures[0] = Signature::from(local_wallet.sign(&signed.message.serialize()));
        if !signed.signatures[0].verify(
            wallet.expected_ed25519_public_key.as_ref(),
            &signed.message.serialize(),
        ) {
            return Err(OperationFailure::Failed(
                FailureStage::SignedTransactionMismatch,
            ));
        }
        return Ok(CustodySignedTransaction {
            transaction: signed,
            activity_id: "local-custody-sign-transaction".to_owned(),
            app_proofs: Vec::new(),
        });
    }

    let client = turnkey_client(keys)?;
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
    let app_proofs = app_proofs(&activity);
    Ok(CustodySignedTransaction {
        transaction: signed,
        activity_id: activity.activity_id,
        app_proofs,
    })
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
