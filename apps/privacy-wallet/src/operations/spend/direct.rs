use super::*;

/// Builds and proves the existing default/custom-ring spend, but deliberately
/// stops before the only billable Turnkey transaction-signing activity.
pub(in crate::operations) async fn prepare_direct_spend(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    intent: &SpendIntentV1,
    state: &AppState,
    keys: &RuntimeKeys,
) -> Result<PreparedDirectSpend, OperationFailure> {
    let (recipient, amount) = match &intent.settlement {
        SpendSettlementV1::Transfer {
            recipient, amount, ..
        }
        | SpendSettlementV1::Withdrawal {
            recipient, amount, ..
        } => (Some(recipient.as_str()), Some(*amount)),
        SpendSettlementV1::Consolidate { .. } => (None, None),
    };
    if amount == Some(0) {
        return Err(OperationFailure::Invalid);
    }
    let consolidates = matches!(&intent.settlement, SpendSettlementV1::Consolidate { .. });
    if consolidates && !matches!(intent.source, PrivateDomainV1::Default) {
        return Err(OperationFailure::Invalid);
    }
    let transaction_ring = transaction_ring(intent)?;
    let enters_ring = matches!(intent.source, PrivateDomainV1::Default)
        && matches!(
            intent.settlement,
            SpendSettlementV1::Transfer {
                destination: PrivateDomainV1::Ring { .. },
                ..
            }
        );
    if (enters_ring && intent.input_commitments.is_empty())
        || (!enters_ring && !intent.input_commitments.is_empty())
    {
        return Err(OperationFailure::Invalid);
    }
    let recipient = recipient
        .map(Pubkey::from_str)
        .transpose()
        .map_err(|_| OperationFailure::Invalid)?;
    let sealed_bytes = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (inner, digest) = unseal_state(request, keys, sealed_bytes)?;
    let keypair = default_keypair(state, keys, target, &inner)?;

    let tree = Address::from_str(&state.services.default_tree)
        .map_err(|_| OperationFailure::Unavailable)?;
    let rpc = SolanaRpc::new(
        &state.services.solana_rpc_url,
        state.services.allow_insecure_http,
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    let (asset, asset_registry) = match &intent.settlement {
        SpendSettlementV1::Transfer { asset, .. }
        | SpendSettlementV1::Withdrawal { asset, .. }
        | SpendSettlementV1::Consolidate { asset } => resolve_asset(&rpc, asset).await?,
    };
    let zolana = pinned_zolana_client(state, rpc, tree);
    let payer = Address::new_from_array(target.address.to_bytes());
    let authority = KeypairWalletAuthority::with_viewing_keys(
        payer,
        &keypair,
        vec![keypair.viewing_key().clone()],
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    let mut wallet = synced_wallet(
        keypair
            .shielded_address()
            .map_err(|_| OperationFailure::Unavailable)?,
        &authority,
        asset_registry,
        &zolana,
    )
    .await?;
    let selected_ring = match &intent.source {
        PrivateDomainV1::Default => None,
        PrivateDomainV1::Ring { program_id, .. } => {
            Some(Address::from_str(program_id).map_err(|_| OperationFailure::Invalid)?)
        }
    };
    let shielded_balance_before = wallet
        .utxos
        .iter()
        .filter(|entry| {
            !entry.spent && entry.utxo.asset == asset && entry.utxo.ring_program_id == selected_ring
        })
        .fold(0u64, |total, entry| total.saturating_add(entry.utxo.amount));

    let unsigned = if consolidates {
        build_merge_transaction(
            &keypair,
            &wallet,
            &zolana,
            &state.services.prover_url,
            payer,
            asset,
            tree,
        )
        .await?
    } else if transaction_ring.is_some() {
        let prover = AsyncProverClient::new(state.services.custom_ring_prover_url.clone());
        build_ring_transaction(
            intent,
            amount.ok_or(OperationFailure::Invalid)?,
            RingSpendContext {
                keypair: &keypair,
                wallet: &wallet,
                zolana: &zolana,
                rpc: zolana.rpc(),
                prover: &prover,
                assets: &wallet.registry,
                tree,
                asset,
                payer,
                recipient: recipient.ok_or(OperationFailure::Invalid)?,
            },
        )
        .await?
    } else {
        prioritize_default_spend_inputs(&mut wallet, asset);
        build_default_transaction(
            intent,
            amount.ok_or(OperationFailure::Invalid)?,
            DefaultSpendContext {
                wallet: &wallet,
                authority: &authority,
                zolana: &zolana,
                payer,
                recipient: recipient.ok_or(OperationFailure::Invalid)?,
                asset,
            },
        )
        .await?
    };
    Ok(PreparedDirectSpend {
        unsigned,
        state_digest: digest,
        shielded_balance_before,
    })
}
pub(in crate::operations) fn prepared_direct_spend_result(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
    prepared: PreparedDirectSpend,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    let unsigned_transaction =
        bincode1::serialize(&prepared.unsigned).map_err(|_| OperationFailure::Unavailable)?;
    if unsigned_transaction.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err(OperationFailure::Unavailable);
    }
    let transaction_digest = artifact_digest(&unsigned_transaction);
    let descriptor_digest = descriptor_digest_from_wallet(&request.wallet_descriptor)
        .map_err(|_| OperationFailure::Invalid)?;
    // Five minutes leaves room for a normal program proof while sharply
    // limiting how long an abandoned authorization remains signable.
    let expires_at_ms = current_time_ms()?
        .checked_add(MAX_REQUEST_AGE_MS)
        .ok_or(OperationFailure::Unavailable)?;
    let sealed_authorization_capsule = seal_spend_authorization(
        keys,
        SpendAuthorizationPlaintextV1 {
            version: API_VERSION,
            quorum_key_id: request.quorum_key_id.clone(),
            quorum_key_epoch: request.quorum_key_epoch,
            wallet_id: request.wallet_descriptor.wallet_id(),
            descriptor_digest,
            state_digest: prepared.state_digest,
            target_release_id: request.target_release_id.clone(),
            target_manifest_digest: request.target_manifest_digest,
            target_executable_digest: request.target_executable_digest,
            prepare_request_id: request.request_id,
            expires_at_ms,
            artifact: SpendAuthorizationArtifactV1::ExactTransaction { transaction_digest },
            shielded_balance_before: prepared.shielded_balance_before,
        },
    )?;
    Ok((
        OperationResultV1::AuthorizeSpend {
            result: AuthorizeSpendResultV1::Prepare {
                prepared: PreparedSpendV1::ExactTransaction {
                    unsigned_transaction,
                    transaction_digest,
                },
                sealed_authorization_capsule,
                shielded_balance_before: prepared.shielded_balance_before,
            },
        },
        prepared.state_digest,
    ))
}
/// Builds and proves a default-ring transaction without exposing any spend
/// role to the caller. The returned Solana legacy-format message has exactly
/// one empty signature slot, shared by the shielded owner and fee payer.
pub(in crate::operations) async fn build_default_transaction(
    intent: &SpendIntentV1,
    amount: u64,
    cx: DefaultSpendContext<'_>,
) -> Result<VersionedTransaction, OperationFailure> {
    let DefaultSpendContext {
        wallet,
        authority,
        zolana,
        payer,
        recipient,
        asset,
    } = cx;
    let unsigned = match &intent.settlement {
        SpendSettlementV1::Transfer { .. } => {
            let created = create_transfer(TransferParams {
                rpc: zolana.rpc(),
                wallet,
                payer,
                recipient,
                asset,
                amount,
            })
            .await
            .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?;
            if created.recipient.is_public_withdrawal() {
                return Err(OperationFailure::Invalid);
            }
            created.transaction
        }
        SpendSettlementV1::Withdrawal { .. } => {
            create_withdrawal(WithdrawalParams {
                wallet,
                payer,
                legs: vec![WithdrawalLeg {
                    recipient,
                    asset,
                    amount,
                    spl_token_program: (asset != SOL_MINT).then(pda::spl_token_program_id),
                }],
            })
            .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?
            .transaction
        }
        SpendSettlementV1::Consolidate { .. } => return Err(OperationFailure::Invalid),
    };
    let shielded = sign_shielded_transaction(unsigned, wallet, authority)
        .await
        // Despite the upstream name, this assembles the proved private
        // transition; the only Solana owner signature is requested from
        // Turnkey during AuthorizeSpend::Finalize.
        .map_err(|error| OperationFailure::Failed(private_transition_stage(&error)))?;
    let transaction = zolana
        .finish_submission_unsigned(&shielded, Pubkey::new_from_array(payer.to_bytes()))
        .await
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    Ok(VersionedTransaction {
        signatures: transaction.signatures,
        message: VersionedMessage::Legacy(transaction.message),
    })
}
pub(in crate::operations) struct DefaultSpendContext<'a> {
    wallet: &'a Wallet,
    authority: &'a KeypairWalletAuthority<'a, TurnkeyEd25519ShieldedKeypair>,
    zolana: &'a ZolanaClient<SolanaRpc>,
    payer: Address,
    recipient: Pubkey,
    asset: Address,
}
