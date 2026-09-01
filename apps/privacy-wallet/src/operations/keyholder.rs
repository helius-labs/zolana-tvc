use super::*;

pub(super) async fn bootstrap_keyholder(
    request: &OperationRequestV1,
    wallet: &ValidatedWallet<'_>,
    state: &AppState,
    keys: &RuntimeKeys,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    // A bootstrap request must not carry a prior state: accepting one would let
    // a caller pick which key state a fresh derivation appears to continue.
    if request.sealed_wallet_state.is_some() {
        return Err(OperationFailure::Invalid);
    }

    let envelope = derivation::ed25519_derivation_message(&wallet.expected_ed25519_public_key);
    let activity =
        sign_derivation_payload(state, keys, wallet, request.issued_at_ms, &envelope).await?;

    let mut seed = Zeroizing::new([0u8; 64]);
    if activity.r.len() != 32 || activity.s.len() != 32 {
        return Err(OperationFailure::Unavailable);
    }
    seed[..32].copy_from_slice(&activity.r);
    seed[32..].copy_from_slice(&activity.s);
    let keypair = TurnkeyEd25519ShieldedKeypair::restore_from_seed(
        custody_activities(state, keys)?,
        TurnkeyKeyRef::new(wallet.organization_id, wallet.sign_with),
        wallet.expected_ed25519_public_key,
        &seed,
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    let shielded_address = keypair
        .shielded_address()
        .map_err(|_| OperationFailure::Unavailable)?;
    let descriptor_hash = descriptor_digest_from_wallet(&request.wallet_descriptor)
        .map_err(|_| OperationFailure::Unavailable)?;
    let (_, sealed_bytes, digest) = seal_state(
        keys,
        KeyStatePlaintextV1 {
            version: API_VERSION,
            quorum_key_id: request.quorum_key_id.clone(),
            quorum_key_epoch: request.quorum_key_epoch,
            wallet_id: request.wallet_descriptor.wallet_id(),
            descriptor_digest: descriptor_hash,
            ed25519_public_key: wallet.expected_ed25519_public_key,
            derivation_suite: DERIVATION_SUITE.to_owned(),
            derivation_seed: *seed,
        },
    )?;

    Ok((
        OperationResultV1::BootstrapKeyholder {
            solana_address: wallet.sign_with.to_owned(),
            shielded_owner_hash: shielded_address
                .owner_hash()
                .map_err(|_| OperationFailure::Unavailable)?,
            shielded_nullifier_public_key: shielded_address.nullifier_pubkey,
            shielded_viewing_public_key: shielded_address.viewing_pubkey.as_bytes().to_vec(),
            sealed_wallet_state: sealed_bytes,
            derivation_suite: DERIVATION_SUITE.to_owned(),
            turnkey_activity_id: activity.activity_id,
            turnkey_app_proofs: activity.app_proofs,
            evidence_classification:
                TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
        },
        digest,
    ))
}
/// Recovers the viewing key for one request. The seed is unsealed, expanded,
/// and dropped with the returned `Zeroizing` seed at the end of the call.
pub(super) fn viewing_key_for(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
) -> Result<(ViewingKey, [u8; 32]), OperationFailure> {
    let sealed_bytes = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (inner, digest) = unseal_state(request, keys, sealed_bytes)?;
    let (_nullifier_key, viewing_key) =
        derivation::expand_roles(&inner.derivation_seed, Curve::Ed25519)
            .map_err(|_| OperationFailure::Invalid)?;
    Ok((viewing_key, digest))
}
/// Derives the wallet's recipient bootstrap view tags. No outbound call: the
/// tags come straight from the unsealed seed.
///
/// One tag per viewing key the application holds. These are the stable tags a
/// wallet is found by, so the client queries the indexer with them directly.
/// The scan's other tag is the identity tag, which derives from the signing
/// *public* key; the client computes that itself rather than asking, so this
/// operation never reveals more than it must.
pub(super) fn derive_view_tags(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    let (viewing_key, digest) = viewing_key_for(request, keys)?;
    Ok((
        OperationResultV1::DeriveViewTags {
            view_tags: vec![viewing_key.recipient_bootstrap_view_tag()],
        },
        digest,
    ))
}
/// Decrypts one batch of ciphertexts the client fetched.
///
/// The shielded-pool transport cipher is AES-CTR with no authentication tag, so
/// this operation cannot tell a payload addressed to this wallet from one
/// addressed to another -- the second decrypts to garbage rather than failing.
/// It therefore never asserts ownership. The client deserializes each plaintext
/// and checks the recovered owner against its own; that check is the one that
/// decides, and it belongs where the SDK already lives.
pub(super) async fn decrypt_utxos(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    state: &AppState,
    keys: &RuntimeKeys,
    payloads: &[EncryptedPayloadV1],
    include_spendable_outputs: bool,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    if (payloads.is_empty() && !include_spendable_outputs)
        || payloads.len() as u64 > MAX_DECRYPT_PAYLOADS_PER_BATCH
    {
        return Err(OperationFailure::Invalid);
    }
    let sealed_bytes = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (inner, digest) = unseal_state(request, keys, sealed_bytes)?;
    let (_nullifier_key, viewing_key) =
        derivation::expand_roles(&inner.derivation_seed, Curve::Ed25519)
            .map_err(|_| OperationFailure::Invalid)?;

    let mut results = Vec::with_capacity(payloads.len());
    for (position, payload) in payloads.iter().enumerate() {
        let index = position as u64;
        let plaintext = match payload {
            EncryptedPayloadV1::Utxo {
                ciphertext,
                transaction_viewing_public_key,
                salt,
                slot_index,
            } => {
                let slot = u32::try_from(*slot_index).map_err(|_| OperationFailure::Invalid)?;
                viewing_key
                    .decrypt_utxo(
                        ciphertext,
                        &transaction_viewing_key(transaction_viewing_public_key)?,
                        decode_salt(salt)?,
                        slot,
                    )
                    .ok()
            }
            EncryptedPayloadV1::RingDeposit {
                ciphertext,
                transaction_viewing_public_key,
                salt,
            } => viewing_key
                .decrypt_ring_deposit(
                    ciphertext,
                    &transaction_viewing_key(transaction_viewing_public_key)?,
                    decode_salt(salt)?,
                )
                .ok(),
        };
        results.push(match plaintext {
            Some(plaintext) => DecryptedPayloadV1::Plaintext { index, plaintext },
            // Reached only when the ciphertext is structurally unusable, for
            // example shorter than its scheme's minimum.
            None => DecryptedPayloadV1::Malformed { index },
        });
    }
    let spendable_outputs = if include_spendable_outputs {
        let payer = Address::new_from_array(target.address.to_bytes());
        let authority =
            ClientEd25519WalletAuthority::from_derivation_seed(payer, &inner.derivation_seed)
                .map_err(|_| OperationFailure::Invalid)?;
        let tree = Address::from_str(&state.services.default_tree)
            .map_err(|_| OperationFailure::Unavailable)?;
        let rpc = SolanaRpc::new(
            &state.services.solana_rpc_url,
            state.services.allow_insecure_http,
        )
        .map_err(|_| OperationFailure::Unavailable)?;
        let zolana = pinned_zolana_client(state, rpc, tree);
        let wallet = indexed_wallet_snapshot(
            authority
                .shielded_address()
                .await
                .map_err(|_| OperationFailure::Unavailable)?,
            &authority,
            &zolana,
        )
        .await?;
        let mut outputs = wallet
            .utxos
            .iter()
            .filter(|entry| !entry.spent)
            .map(|entry| {
                let asset = if entry.utxo.asset == SOL_MINT {
                    AssetV1::Sol
                } else {
                    AssetV1::Spl {
                        mint: entry.utxo.asset.to_string(),
                        asset_id: wallet
                            .registry
                            .asset_id(&entry.utxo.asset)
                            .map_err(|_| OperationFailure::Failed(FailureStage::AssetRegistry))?,
                    }
                };
                Ok(SpendableOutputV1 {
                    commitment: entry.output_context.hash,
                    asset,
                    amount: entry.utxo.amount,
                    ring_program_id: entry.utxo.ring_program_id.map(|id| id.to_string()),
                })
            })
            .collect::<Result<Vec<_>, OperationFailure>>()?;
        if outputs.len() as u64 > MAX_SPENDABLE_OUTPUTS {
            return Err(OperationFailure::Failed(
                FailureStage::WalletSnapshotTooLarge,
            ));
        }
        outputs.sort_unstable_by_key(|output| output.commitment);
        Some(outputs)
    } else {
        None
    };

    Ok((
        OperationResultV1::DecryptUtxos {
            payloads: results,
            spendable_outputs,
        },
        digest,
    ))
}
pub(super) fn transaction_viewing_key(bytes: &[u8]) -> Result<P256Pubkey, OperationFailure> {
    let encoded: [u8; 33] = bytes.try_into().map_err(|_| OperationFailure::Invalid)?;
    P256Pubkey::from_bytes(encoded).map_err(|_| OperationFailure::Invalid)
}
pub(super) fn decode_salt(bytes: &[u8]) -> Result<Salt, OperationFailure> {
    bytes.try_into().map_err(|_| OperationFailure::Invalid)
}
