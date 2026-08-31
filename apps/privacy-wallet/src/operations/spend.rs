use super::*;

/// The one spend authority exposed by the enclave. Prepare proves and seals an
/// exact unsigned transaction; finalize independently revalidates the capsule
/// and transaction before invoking Turnkey once. There is no one-call protocol
/// variant.
///
/// The development implementation performs pinned Photon, Solana RPC, and
/// prover calls inside this operation. Its common prover still receives the
/// plaintext witness, including the long-lived nullifier secret; this boundary
/// must change before a production privacy claim.
pub(super) async fn authorize_spend(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    spend: &AuthorizeSpendRequestV1,
    keys: &RuntimeKeys,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    match spend {
        AuthorizeSpendRequestV1::Prepare { plan } => match plan {
            SpendPlanV1::Direct { transition } => {
                let prepared = prepare_direct_spend(request, target, transition, keys).await?;
                prepared_direct_spend_result(request, keys, prepared)
            }
            SpendPlanV1::Program { transition } => {
                let prepared = prepare_generic_spp(request, target, transition, keys).await?;
                prepared_generic_spend_result(request, keys, prepared)
            }
        },
        AuthorizeSpendRequestV1::Finalize {
            sealed_authorization_capsule,
            unsigned_transaction,
        } => {
            finalize_prepared_transaction(
                request,
                target,
                keys,
                sealed_authorization_capsule,
                unsigned_transaction,
            )
            .await
        }
    }
}
pub(super) struct PreparedDirectSpend {
    unsigned: VersionedTransaction,
    state_digest: [u8; 32],
    shielded_balance_before: u64,
}
pub(super) struct PreparedGenericSpend {
    program_id: Address,
    input_tree: Address,
    program_authorities: Vec<Address>,
    plan_digest: [u8; 32],
    transact: Vec<u8>,
    private_tx_hash: [u8; 32],
    external_data_hash: [u8; 32],
    state_digest: [u8; 32],
    shielded_balance_before: u64,
    expires_at_ms: u64,
}
pub(super) struct AuthorizedSpend {
    signed_transaction: Vec<u8>,
    transaction_signature: String,
    shielded_balance_before: u64,
    turnkey_activity_id: String,
    turnkey_app_proofs: Vec<TurnkeyVerifiedAppProofV1>,
    evidence_classification: TurnkeyEvidenceClassification,
}
pub(super) fn domain_ring(domain: &PrivateDomainV1) -> Option<(&str, &str)> {
    match domain {
        PrivateDomainV1::Default => None,
        PrivateDomainV1::Ring {
            program_id,
            lookup_table,
        } => Some((program_id, lookup_table)),
    }
}
/// Returns the one custom-ring boundary involved in a direct transition.
/// Direct Ring(A) -> Ring(B) is intentionally impossible: the wallet composes
/// two independent transitions through an exact self-owned default UTXO.
pub(super) fn transaction_ring(
    intent: &SpendIntentV1,
) -> Result<Option<(&str, &str)>, OperationFailure> {
    let source = domain_ring(&intent.source);
    let destination = match &intent.settlement {
        SpendSettlementV1::Transfer { destination, .. } => domain_ring(destination),
        SpendSettlementV1::Withdrawal { .. } | SpendSettlementV1::Consolidate { .. } => None,
    };
    match (source, destination) {
        (Some(source), Some(destination)) if source != destination => {
            Err(OperationFailure::Invalid)
        }
        (Some(ring), _) | (_, Some(ring)) => Ok(Some(ring)),
        (None, None) => Ok(None),
    }
}
/// Builds and proves the existing default/custom-ring spend, but deliberately
/// stops before the only billable Turnkey transaction-signing activity.
pub(super) async fn prepare_direct_spend(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    intent: &SpendIntentV1,
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
    let client = turnkey_client(keys)?;
    let keypair = default_keypair(&client, target, &inner)?;

    let tree = Address::from_str(DEVNET_DEFAULT_TREE).map_err(|_| OperationFailure::Unavailable)?;
    let rpc = SolanaRpc::new().map_err(|_| OperationFailure::Unavailable)?;
    let (asset, asset_registry) = match &intent.settlement {
        SpendSettlementV1::Transfer { asset, .. }
        | SpendSettlementV1::Withdrawal { asset, .. }
        | SpendSettlementV1::Consolidate { asset } => resolve_asset(&rpc, asset).await?,
    };
    let zolana = pinned_zolana_client(rpc, tree);
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
        build_merge_transaction(&keypair, &wallet, &zolana, payer, asset, tree).await?
    } else if transaction_ring.is_some() {
        let prover = AsyncProverClient::new(EXPECTED_CUSTOM_RING_PROVER_ORIGIN.to_owned());
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
/// Builds the common SPP transition for an arbitrary private program without
/// interpreting that program's data. Wallet inputs are independently
/// rediscovered; program inputs must be owned by a PDA derived under the target
/// program and provide a commitment opening. No public interface transfer is
/// admitted on this path.
pub(super) async fn prepare_generic_spp(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    plan: &SppPlanV1,
    keys: &RuntimeKeys,
) -> Result<PreparedGenericSpend, OperationFailure> {
    if plan.inputs.is_empty()
        || plan.outputs.is_empty()
        || plan.outputs.len() != usize::from(plan.shape.outputs)
        || plan.inputs.len() > usize::from(plan.shape.inputs)
        || plan.messages.len() > MAX_GENERIC_MESSAGES
        || plan.program_authorities.len() > MAX_GENERIC_PROGRAM_AUTHORITIES
    {
        return Err(OperationFailure::Invalid);
    }
    let now_ms = current_time_ms()?;
    let latest_expiry = now_ms
        .checked_add(MAX_REQUEST_AGE_MS)
        .ok_or(OperationFailure::Unavailable)?;
    if plan.expires_at_ms < now_ms || plan.expires_at_ms > latest_expiry {
        return Err(OperationFailure::Invalid);
    }

    let program_id = Address::from_str(&plan.program_id).map_err(|_| OperationFailure::Invalid)?;
    if program_id.to_bytes() == SHIELDED_POOL_PROGRAM_ID || reserved_signer_program(program_id) {
        return Err(OperationFailure::Invalid);
    }
    let input_tree = Address::from_str(&plan.input_tree).map_err(|_| OperationFailure::Invalid)?;
    let shape = Shape::new(
        usize::from(plan.shape.inputs),
        usize::from(plan.shape.outputs),
    );
    if !SPP_SUPPORTED_SHAPES.contains(&shape) {
        return Err(OperationFailure::Invalid);
    }
    if plan
        .messages
        .iter()
        .any(|message| message.data.len() > MAX_GENERIC_DATA_BYTES)
        || plan.outputs.iter().any(|output| {
            output.data.len() > MAX_GENERIC_DATA_BYTES
                || output.memo.len() > MAX_GENERIC_DATA_BYTES
                || (!output.data.is_empty() && output.data_hash.is_none())
        })
    {
        return Err(OperationFailure::Invalid);
    }

    let sealed_bytes = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (inner, state_digest_bytes) = unseal_state(request, keys, sealed_bytes)?;
    let client = turnkey_client(keys)?;
    let keypair = default_keypair(&client, target, &inner)?;
    let rpc = SolanaRpc::new().map_err(|_| OperationFailure::Unavailable)?;
    let registry = generic_asset_registry(&rpc, plan).await?;
    let zolana = pinned_zolana_client(rpc, input_tree);
    let payer = Address::new_from_array(target.address.to_bytes());
    let authority = KeypairWalletAuthority::with_viewing_keys(
        payer,
        &keypair,
        vec![keypair.viewing_key().clone()],
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    let wallet = synced_wallet(
        keypair
            .shielded_address()
            .map_err(|_| OperationFailure::Unavailable)?,
        &authority,
        registry.clone(),
        &zolana,
    )
    .await?;

    let mut input_utxos = Vec::with_capacity(usize::from(plan.shape.inputs));
    let mut seen_commitments = Vec::with_capacity(plan.inputs.len());
    let mut input_totals: Vec<(Address, u128)> = Vec::new();
    let program = Pubkey::new_from_array(program_id.to_bytes());
    let mut program_authorities = Vec::with_capacity(plan.program_authorities.len());
    for authority in &plan.program_authorities {
        let pda = derive_program_authority(&program, &authority.seeds)?;
        if program_authorities.contains(&pda) {
            return Err(OperationFailure::Invalid);
        }
        program_authorities.push(pda);
    }
    let mut shielded_balance_before = 0u64;
    for input in &plan.inputs {
        let (commitment, spend) = match input {
            SppPlanInputV1::Wallet { commitment } => {
                let entry = wallet
                    .utxos
                    .iter()
                    .find(|entry| {
                        !entry.spent
                            && entry.output_context.tree == input_tree
                            && entry.output_context.hash == *commitment
                    })
                    .ok_or(OperationFailure::Invalid)?;
                if entry.utxo.owner != keypair.signing_pubkey()
                    || entry.utxo.ring_program_id.is_some()
                {
                    return Err(OperationFailure::Invalid);
                }
                shielded_balance_before = shielded_balance_before
                    .checked_add(entry.utxo.amount)
                    .ok_or(OperationFailure::Unavailable)?;
                add_asset_amount(&mut input_totals, entry.utxo.asset, entry.utxo.amount)?;
                let mut spend = SppProofInputUtxo::new(entry.utxo.clone(), keypair.nullifier_key());
                if let Some(data_hash) = entry.data_hash {
                    spend = spend.with_data_hash(data_hash);
                }
                if let Some(ring_data_hash) = entry.ring_data_hash {
                    spend = spend.with_ring_data_hash(ring_data_hash);
                }
                (*commitment, spend)
            }
            SppPlanInputV1::Program {
                commitment,
                authority_seeds,
                asset,
                amount,
                blinding,
                data_hash,
                nullifier_secret,
            } => {
                let pda_address = derive_program_authority(&program, authority_seeds)?;
                if !program_authorities.contains(&pda_address) {
                    if program_authorities.len() == MAX_GENERIC_PROGRAM_AUTHORITIES {
                        return Err(OperationFailure::Invalid);
                    }
                    program_authorities.push(pda_address);
                }
                let asset = generic_asset_address(asset)?;
                add_asset_amount(&mut input_totals, asset, *amount)?;
                let secret: [u8; BLINDING_LEN] = nullifier_secret
                    .as_slice()
                    .try_into()
                    .map_err(|_| OperationFailure::Invalid)?;
                let utxo = Utxo {
                    owner: PublicKey::from_pda(&pda_address),
                    asset,
                    amount: *amount,
                    blinding: *blinding,
                    ring_program_id: None,
                    data: Default::default(),
                };
                let mut spend = SppProofInputUtxo::new(utxo, NullifierKey::from_secret(secret));
                if let Some(data_hash) = data_hash {
                    spend = spend.with_data_hash(*data_hash);
                }
                if spend.hash().map_err(|_| OperationFailure::Invalid)? != *commitment {
                    return Err(OperationFailure::Invalid);
                }
                (*commitment, spend)
            }
        };
        if seen_commitments.contains(&commitment) {
            return Err(OperationFailure::Invalid);
        }
        seen_commitments.push(commitment);
        input_utxos.push(spend);
    }
    while input_utxos.len() < usize::from(plan.shape.inputs) {
        input_utxos.push(SppProofInputUtxo::new_dummy());
    }

    let mut outputs = Vec::with_capacity(plan.outputs.len());
    let mut output_totals: Vec<(Address, u128)> = Vec::new();
    let mut output_commitments = Vec::with_capacity(plan.outputs.len());
    for output in &plan.outputs {
        let recipient =
            ShieldedAddress::from_str(&output.recipient).map_err(|_| OperationFailure::Invalid)?;
        let asset = generic_asset_address(&output.asset)?;
        add_asset_amount(&mut output_totals, asset, output.amount)?;
        let mut prepared = SppProofOutputUtxo {
            asset,
            amount: output.amount,
            blinding: output.blinding,
            owner_address: Some(recipient),
            owner_tag: Some(
                recipient
                    .signing_pubkey
                    .confidential_view_tag()
                    .map_err(|_| OperationFailure::Invalid)?,
            ),
            ..Default::default()
        };
        if let Some(data_hash) = output.data_hash {
            prepared = prepared.with_utxo_data(output.data.clone(), data_hash);
        }
        if !output.memo.is_empty() {
            prepared = prepared.with_memo(output.memo.clone());
        }
        let commitment = prepared.hash().map_err(|_| OperationFailure::Invalid)?;
        if output_commitments.contains(&commitment) {
            return Err(OperationFailure::Invalid);
        }
        output_commitments.push(commitment);
        outputs.push(prepared);
    }
    if input_totals != output_totals {
        sort_asset_totals(&mut input_totals);
        sort_asset_totals(&mut output_totals);
        if input_totals != output_totals {
            return Err(OperationFailure::Invalid);
        }
    }

    let transaction_viewing_key = get_transaction_viewing_key(&keypair, &input_utxos)
        .map_err(|_| OperationFailure::Invalid)?;
    let encoded = encrypt_transaction_data(&outputs, &registry, &transaction_viewing_key)
        .map_err(|_| OperationFailure::Invalid)?;
    let messages = plan
        .messages
        .iter()
        .map(|message| MessageData {
            view_tag: message.view_tag,
            data: message.data.clone(),
        })
        .collect();
    let mut external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        messages,
    );
    external_data.expiry_unix_ts = plan.expires_at_ms.div_ceil(1_000);
    let proof_inputs = SppProofInputs::new(input_utxos, encoded.output_utxos, external_data, payer);
    proof_inputs
        .check_shape()
        .map_err(|_| OperationFailure::Invalid)?;
    let external_data_hash = proof_inputs
        .external_data
        .hash()
        .map_err(|_| OperationFailure::Invalid)?;
    let input_contexts = proof_inputs
        .input_utxo_hashes()
        .map_err(|_| OperationFailure::Invalid)?;
    let input_proofs = zolana
        .get_input_merkle_proofs_for_tree(input_tree, &input_contexts, None)
        .await
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let dummy_nullifiers = proof_inputs
        .dummy_nullifiers()
        .map_err(|_| OperationFailure::Invalid)?;
    let dummy_proofs = if dummy_nullifiers.is_empty() {
        Vec::new()
    } else {
        zolana
            .get_non_inclusion_proofs(input_tree, dummy_nullifiers, None)
            .await
            .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?
            .proofs
    };
    let assembled = assemble(proof_inputs, &input_proofs, &dummy_proofs)
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let prover = AsyncProverClient::new(EXPECTED_EXTERNAL_ORIGIN.to_owned());
    let proof = match &assembled.prover_inputs {
        ProverInputs::Eddsa(inputs) => {
            let proof = prover
                .prove_transfer(inputs)
                .await
                .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
            verify_confidential_transfer_inputs(inputs, assembled.public_input_hash, &proof)
                .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
            proof
        }
    };
    let transact = assembled.with_proof(
        ProofCompressed::try_from(proof)
            .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?
            .to_transact_proof(),
    );
    let private_tx_hash = transact.private_tx_hash;
    let transact = wincode::serialize(&transact).map_err(|_| OperationFailure::Unavailable)?;
    let plan_json = jcs_serialize(plan).map_err(|_| OperationFailure::Invalid)?;
    Ok(PreparedGenericSpend {
        program_id,
        input_tree,
        program_authorities,
        plan_digest: artifact_digest(plan_json.as_bytes()),
        transact,
        private_tx_hash,
        external_data_hash,
        state_digest: state_digest_bytes,
        shielded_balance_before,
        expires_at_ms: plan.expires_at_ms,
    })
}
pub(super) fn derive_program_authority(
    program: &Pubkey,
    authority_seeds: &[Vec<u8>],
) -> Result<Address, OperationFailure> {
    if authority_seeds.is_empty()
        || authority_seeds.len() > 16
        || authority_seeds.iter().any(|seed| seed.len() > 32)
    {
        return Err(OperationFailure::Invalid);
    }
    let seed_refs = authority_seeds
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let pda = Pubkey::create_program_address(&seed_refs, program)
        .map_err(|_| OperationFailure::Invalid)?;
    Ok(Address::new_from_array(pda.to_bytes()))
}
pub(super) fn prepared_direct_spend_result(
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
pub(super) fn prepared_generic_spend_result(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
    prepared: PreparedGenericSpend,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    let transact_digest = artifact_digest(&prepared.transact);
    let descriptor_digest = descriptor_digest_from_wallet(&request.wallet_descriptor)
        .map_err(|_| OperationFailure::Invalid)?;
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
            expires_at_ms: prepared.expires_at_ms,
            artifact: SpendAuthorizationArtifactV1::Spp {
                program_id: prepared.program_id.to_bytes(),
                input_tree: prepared.input_tree.to_bytes(),
                program_authorities: prepared
                    .program_authorities
                    .iter()
                    .map(Address::to_bytes)
                    .collect(),
                plan_digest: prepared.plan_digest,
                prepared_transact: prepared.transact.clone(),
                transact_digest,
                private_tx_hash: prepared.private_tx_hash,
            },
            shielded_balance_before: prepared.shielded_balance_before,
        },
    )?;
    Ok((
        OperationResultV1::AuthorizeSpend {
            result: AuthorizeSpendResultV1::Prepare {
                prepared: PreparedSpendV1::Spp {
                    program_id: prepared.program_id.to_string(),
                    input_tree: prepared.input_tree.to_string(),
                    plan_digest: prepared.plan_digest,
                    transact: prepared.transact,
                    transact_digest,
                    private_tx_hash: prepared.private_tx_hash,
                    external_data_hash: prepared.external_data_hash,
                },
                sealed_authorization_capsule,
                shielded_balance_before: prepared.shielded_balance_before,
            },
        },
        prepared.state_digest,
    ))
}
pub(super) async fn finalize_prepared_transaction(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    keys: &RuntimeKeys,
    sealed_authorization_capsule: &[u8],
    unsigned_transaction: &[u8],
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    let sealed_wallet_state = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    // Unseal the wallet state independently. A valid capsule alone is never a
    // bearer credential for Turnkey signing.
    let (_, state_digest_bytes) = unseal_state(request, keys, sealed_wallet_state)?;
    let authorization = unseal_spend_authorization(
        request,
        keys,
        sealed_authorization_capsule,
        state_digest_bytes,
    )?;
    if unsigned_transaction.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err(OperationFailure::Invalid);
    }
    let mut unsigned: VersionedTransaction =
        bincode1::deserialize(unsigned_transaction).map_err(|_| OperationFailure::Invalid)?;
    if bincode1::serialize(&unsigned).map_err(|_| OperationFailure::Invalid)?
        != unsigned_transaction
        || unsigned.signatures.as_slice() != [Signature::default()]
        || unsigned.message.sanitize().is_err()
        || unsigned.message.header().num_required_signatures != 1
        || unsigned.message.static_account_keys().first().copied()
            != Some(Address::new_from_array(target.address.to_bytes()))
    {
        return Err(OperationFailure::Invalid);
    }
    let shielded_balance_before = authorization.shielded_balance_before;
    match authorization.artifact {
        SpendAuthorizationArtifactV1::ExactTransaction { transaction_digest } => {
            // A direct capsule commits to every byte, including its blockhash.
            if artifact_digest(unsigned_transaction) != transaction_digest {
                return Err(OperationFailure::Invalid);
            }
        }
        SpendAuthorizationArtifactV1::Spp {
            program_id,
            input_tree,
            program_authorities,
            plan_digest: _,
            prepared_transact,
            transact_digest,
            private_tx_hash,
        } => {
            if prepared_transact.is_empty()
                || artifact_digest(&prepared_transact) != transact_digest
                || !prepared_transact
                    .windows(private_tx_hash.len())
                    .any(|window| window == private_tx_hash)
            {
                return Err(OperationFailure::Invalid);
            }
            let rpc = SolanaRpc::new().map_err(|_| OperationFailure::Unavailable)?;
            validate_private_program_transaction(
                &rpc,
                Address::new_from_array(target.address.to_bytes()),
                Address::new_from_array(program_id),
                Address::new_from_array(input_tree),
                &program_authorities,
                private_tx_hash,
                &mut unsigned,
            )
            .await?;
        }
    }
    if bincode1::serialize(&unsigned)
        .map_err(|_| OperationFailure::Unavailable)?
        .len()
        > MAX_SOLANA_TRANSACTION_BYTES
    {
        return Err(OperationFailure::Invalid);
    }
    let client = turnkey_client(keys)?;
    let signed =
        sign_versioned_transaction(&client, target, request.issued_at_ms, unsigned).await?;
    let authorized = authorized_spend(signed, shielded_balance_before)?;
    Ok((
        OperationResultV1::AuthorizeSpend {
            result: AuthorizeSpendResultV1::Finalize {
                signed_transaction: authorized.signed_transaction,
                transaction_signature: authorized.transaction_signature,
                shielded_balance_before: authorized.shielded_balance_before,
                turnkey_activity_id: authorized.turnkey_activity_id,
                turnkey_app_proofs: authorized.turnkey_app_proofs,
                evidence_classification: authorized.evidence_classification,
            },
        },
        state_digest_bytes,
    ))
}
pub(super) async fn validate_private_program_transaction(
    rpc: &SolanaRpc,
    payer: Address,
    authorized_program: Address,
    authorized_tree: Address,
    authorized_program_accounts: &[[u8; 32]],
    private_tx_hash: [u8; 32],
    unsigned: &mut VersionedTransaction,
) -> Result<(), OperationFailure> {
    if reserved_signer_program(authorized_program) {
        return Err(OperationFailure::Invalid);
    }
    let program_account = rpc
        .get_account(authorized_program)
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::RpcValidation))?
        .ok_or(OperationFailure::Invalid)?;
    if !program_account.executable {
        return Err(OperationFailure::Invalid);
    }

    let loaded = load_transaction_addresses(rpc, &unsigned.message).await?;
    validate_private_program_message(
        payer,
        authorized_program,
        authorized_tree,
        authorized_program_accounts,
        private_tx_hash,
        &unsigned.message,
        &loaded,
    )?;
    let shielded_pool = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let tree = rpc
        .get_account(authorized_tree)
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::RpcValidation))?
        .ok_or(OperationFailure::Invalid)?;
    let pool = rpc
        .get_account(shielded_pool)
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::RpcValidation))?
        .ok_or(OperationFailure::Invalid)?;
    if tree.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID || !pool.executable {
        return Err(OperationFailure::Invalid);
    }

    // The caller approves the instruction set; TVC supplies only transaction
    // freshness. Program-specific proofs bind private effects to the prepared
    // hash, while any additional public behavior follows normal wallet trust.
    let (blockhash, _) = rpc
        .get_latest_blockhash()
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::LatestBlockhash))?;
    unsigned.message.set_recent_blockhash(blockhash);
    Ok(())
}
pub(super) fn validate_private_program_message(
    payer: Address,
    authorized_program: Address,
    authorized_tree: Address,
    authorized_program_accounts: &[[u8; 32]],
    private_tx_hash: [u8; 32],
    message: &VersionedMessage,
    loaded: &LoadedAddresses,
) -> Result<(), OperationFailure> {
    if reserved_signer_program(authorized_program) {
        return Err(OperationFailure::Invalid);
    }
    let account_keys = AccountKeys::new(message.static_account_keys(), Some(loaded));
    let hash_occurrences = message
        .instructions()
        .iter()
        .map(|instruction| {
            instruction
                .data
                .windows(private_tx_hash.len())
                .filter(|window| *window == private_tx_hash)
                .count()
        })
        .sum::<usize>();
    if hash_occurrences != 1 {
        return Err(OperationFailure::Invalid);
    }
    let binding = message
        .instructions()
        .iter()
        .find(|instruction| {
            account_keys
                .get(usize::from(instruction.program_id_index))
                .is_some_and(|program_id| *program_id == authorized_program)
                && instruction
                    .data
                    .windows(private_tx_hash.len())
                    .any(|window| window == private_tx_hash)
        })
        .ok_or(OperationFailure::Invalid)?;
    if binding.accounts.is_empty()
        || binding.accounts.len() > MAX_GENERIC_ACCOUNTS
        || binding.data.len() > MAX_GENERIC_INSTRUCTION_BYTES
    {
        return Err(OperationFailure::Invalid);
    }

    let system_program = Address::default();
    let shielded_pool = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut payer_signer = false;
    let mut shielded_pool_present = false;
    let mut system_program_present = false;
    let mut authorized_tree_present = false;
    let mut seen_program_accounts = vec![false; authorized_program_accounts.len()];
    for account_index in &binding.accounts {
        let index = usize::from(*account_index);
        let address = *account_keys.get(index).ok_or(OperationFailure::Invalid)?;
        let is_signer = message.is_signer(index);
        let is_writable = message_account_is_writable(message, loaded, index);
        if is_signer {
            if address != payer {
                return Err(OperationFailure::Invalid);
            }
            payer_signer = true;
        }
        if address == shielded_pool {
            if is_signer || is_writable {
                return Err(OperationFailure::Invalid);
            }
            shielded_pool_present = true;
        }
        if address == system_program {
            if is_signer || is_writable {
                return Err(OperationFailure::Invalid);
            }
            system_program_present = true;
        }
        if address == authorized_tree {
            if is_signer || !is_writable {
                return Err(OperationFailure::Invalid);
            }
            authorized_tree_present = true;
        }
        for (index, authorized) in authorized_program_accounts.iter().enumerate() {
            if address.to_bytes() == *authorized {
                seen_program_accounts[index] = true;
            }
        }
    }
    if !payer_signer
        || !shielded_pool_present
        || !system_program_present
        || !authorized_tree_present
        || seen_program_accounts.iter().any(|seen| !seen)
    {
        return Err(OperationFailure::Invalid);
    }
    Ok(())
}
pub(super) async fn load_transaction_addresses(
    rpc: &SolanaRpc,
    message: &VersionedMessage,
) -> Result<LoadedAddresses, OperationFailure> {
    let message = match message {
        VersionedMessage::Legacy(_) => return Ok(LoadedAddresses::default()),
        VersionedMessage::V1(_) => return Err(OperationFailure::Invalid),
        VersionedMessage::V0(message) => message,
    };
    if message.address_table_lookups.len() > MAX_GENERIC_LOOKUP_TABLES {
        return Err(OperationFailure::Invalid);
    }
    let mut seen = Vec::with_capacity(message.address_table_lookups.len());
    let mut writable = Vec::new();
    let mut readonly = Vec::new();
    for lookup in &message.address_table_lookups {
        if seen.contains(&lookup.account_key) {
            return Err(OperationFailure::Invalid);
        }
        seen.push(lookup.account_key);
        let table = read_generic_lookup_table(rpc, lookup.account_key).await?;
        for index in &lookup.writable_indexes {
            writable.push(
                *table
                    .addresses
                    .get(usize::from(*index))
                    .ok_or(OperationFailure::Invalid)?,
            );
        }
        for index in &lookup.readonly_indexes {
            readonly.push(
                *table
                    .addresses
                    .get(usize::from(*index))
                    .ok_or(OperationFailure::Invalid)?,
            );
        }
    }
    Ok(LoadedAddresses { writable, readonly })
}
pub(super) fn message_account_is_writable(
    message: &VersionedMessage,
    loaded: &LoadedAddresses,
    index: usize,
) -> bool {
    let static_len = message.static_account_keys().len();
    if index >= static_len {
        return index - static_len < loaded.writable.len();
    }
    let header = message.header();
    let signed = usize::from(header.num_required_signatures);
    if index < signed {
        index < signed.saturating_sub(usize::from(header.num_readonly_signed_accounts))
    } else {
        index < static_len.saturating_sub(usize::from(header.num_readonly_unsigned_accounts))
    }
}
pub(super) fn reserved_signer_program(program_id: Address) -> bool {
    const RESERVED: [&str; 10] = [
        "11111111111111111111111111111111",
        "ComputeBudget111111111111111111111111111111",
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        "NativeLoader1111111111111111111111111111111",
        "BPFLoader1111111111111111111111111111111111",
        "BPFLoader2111111111111111111111111111111111",
        "BPFLoaderUpgradeab1e11111111111111111111111",
        "LoaderV411111111111111111111111111111111111",
    ];
    RESERVED
        .iter()
        .any(|reserved| Address::from_str(reserved).is_ok_and(|address| address == program_id))
}
/// Reads a caller-named table from the pinned chain without treating its
/// entries as authority. Message compilation matches entries only to literal
/// accounts in the enclave-built instruction; missing entries remain static
/// keys, and unrelated entries are ignored.
pub(super) async fn read_generic_lookup_table(
    rpc: &SolanaRpc,
    address: Address,
) -> Result<AddressLookupTableAccount, OperationFailure> {
    let account = rpc
        .get_account(address)
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::LookupTable))?
        .ok_or(OperationFailure::Failed(FailureStage::LookupTable))?;
    if account.owner.to_bytes() != solana_address_lookup_table_interface::program::ID.to_bytes() {
        return Err(OperationFailure::Invalid);
    }
    let parsed =
        AddressLookupTable::deserialize(&account.data).map_err(|_| OperationFailure::Invalid)?;
    Ok(AddressLookupTableAccount {
        key: address,
        addresses: parsed.addresses.to_vec(),
    })
}
/// Builds and proves a default-ring transaction without exposing any spend
/// role to the caller. The returned Solana legacy-format message has exactly
/// one empty signature slot, shared by the shielded owner and fee payer.
pub(super) async fn build_default_transaction(
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
/// Consolidate up to eight plain default-domain UTXOs through Zolana's
/// dedicated `merge_8_1` circuit. This path is balance-neutral and needs no
/// shielded transaction signature: ownership is proven from the enclave-held
/// nullifier key, while the public wallet remains the transaction fee payer.
pub(super) async fn build_merge_transaction(
    keypair: &TurnkeyEd25519ShieldedKeypair,
    wallet: &Wallet,
    zolana: &ZolanaClient<SolanaRpc>,
    payer: Address,
    asset: Address,
    tree: Address,
) -> Result<VersionedTransaction, OperationFailure> {
    let mut candidates = wallet
        .utxos
        .iter()
        .filter(|entry| {
            !entry.spent
                && entry.utxo.asset == asset
                && entry.output_context.tree == tree
                && entry.utxo.ring_program_id.is_none()
                && entry.data_hash.is_none()
                && entry.ring_data_hash.is_none()
                && entry.utxo.data.is_empty()
        })
        .collect::<Vec<_>>();
    // This rail is entered because a concrete transfer could not fit the
    // ordinary <=5-input circuit. Merging the largest fragments makes the
    // saved transfer resumable with the fewest extra transactions.
    candidates.sort_by_key(|entry| std::cmp::Reverse(entry.utxo.amount));
    candidates.truncate(MERGE_INPUTS);
    if candidates.len() < 2 {
        return Err(OperationFailure::Failed(
            FailureStage::UnsupportedProofShape,
        ));
    }

    let inputs = candidates
        .into_iter()
        .map(|entry| SppProofInputUtxo::new(entry.utxo.clone(), keypair.nullifier_key()))
        .collect();
    let prepared = Merge::new(keypair, inputs)
        .map_err(|_| OperationFailure::Failed(FailureStage::PrivateTransitionAssembly))?
        .prepare();
    let commitments = prepared
        .input_utxo_hashes()
        .map_err(|_| OperationFailure::Failed(FailureStage::ProofAssembly))?;
    let proofs = zolana
        .get_input_merkle_proofs_for_tree(tree, &commitments, None)
        .await
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    ensure_merge_proofs_match_tree(&proofs, tree)?;

    let nullifier_key = keypair.nullifier_key();
    let dummy_nullifiers = prepared
        .dummy_nullifiers(&nullifier_key)
        .map_err(|_| OperationFailure::Failed(FailureStage::ProofAssembly))?;
    let dummy_nullifier_proofs = if dummy_nullifiers.is_empty() {
        Vec::new()
    } else {
        zolana
            .get_non_inclusion_proofs(tree, dummy_nullifiers, None)
            .await
            .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?
            .proofs
    };
    if dummy_nullifier_proofs
        .iter()
        .any(|proof| proof.merkle_context.tree != tree)
    {
        return Err(OperationFailure::Failed(FailureStage::InputTree));
    }

    let built = MergeProver::try_from(MergeWitness {
        prepared,
        nullifier_key,
        proofs,
        dummy_nullifier_proofs,
    })
    .and_then(MergeProver::build)
    .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let prover = AsyncProverClient::new(EXPECTED_EXTERNAL_ORIGIN.to_owned());
    let proof = prover
        .prove_merge(&built.inputs)
        .await
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let packed = ProofCompressed::try_from(proof)
        .and_then(|proof| proof.to_merge_proof())
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let payer = Pubkey::new_from_array(payer.to_bytes());
    let merge = MergeTransact {
        input_tree: Pubkey::new_from_array(tree.to_bytes()),
        output_tree: Pubkey::new_from_array(tree.to_bytes()),
        payer,
        user_record: user_record_pda(&payer).0,
        data: built.instruction_data(packed),
    }
    .instruction();
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let (blockhash, _) = zolana
        .rpc()
        .get_latest_blockhash()
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::LatestBlockhash))?;
    let message = Message::new_with_blockhash(&[compute, merge], Some(&payer), &blockhash);
    Ok(VersionedTransaction {
        signatures: vec![Signature::default()],
        message: VersionedMessage::Legacy(message),
    })
}
pub(super) fn ensure_merge_proofs_match_tree(
    proofs: &[SpendProof],
    tree: Address,
) -> Result<(), OperationFailure> {
    if proofs.iter().any(|proof| {
        proof.state.merkle_context.tree != tree || proof.nullifier.merkle_context.tree != tree
    }) {
        return Err(OperationFailure::Failed(FailureStage::InputTree));
    }
    Ok(())
}
pub(super) struct DefaultSpendContext<'a> {
    wallet: &'a Wallet,
    authority: &'a KeypairWalletAuthority<'a, TurnkeyEd25519ShieldedKeypair>,
    zolana: &'a ZolanaClient<SolanaRpc>,
    payer: Address,
    recipient: Pubkey,
    asset: Address,
}
pub(super) struct RingSpendContext<'a> {
    keypair: &'a TurnkeyEd25519ShieldedKeypair,
    wallet: &'a Wallet,
    zolana: &'a ZolanaClient<SolanaRpc>,
    rpc: &'a SolanaRpc,
    prover: &'a AsyncProverClient,
    assets: &'a AssetRegistry,
    tree: Address,
    asset: Address,
    payer: Address,
    recipient: Pubkey,
}
/// Builds one custom-ring spend and returns the unsigned v0 transaction.
///
/// Separate from the default-ring path rather than a flag on it: a ring spend
/// runs the ring circuit over an auditor-encrypted transaction viewing key and
/// needs a v0 message so an address lookup table can keep it within Solana's
/// packet limit.
pub(super) async fn build_ring_transaction(
    intent: &SpendIntentV1,
    amount: u64,
    cx: RingSpendContext<'_>,
) -> Result<VersionedTransaction, OperationFailure> {
    let (ring_program_id, ring_lookup_table) =
        transaction_ring(intent)?.ok_or(OperationFailure::Invalid)?;
    let RingSpendContext {
        keypair,
        wallet,
        zolana,
        rpc,
        prover,
        assets,
        tree,
        asset,
        payer,
        recipient,
    } = cx;
    let program_id = Address::from_str(ring_program_id).map_err(|_| OperationFailure::Invalid)?;
    let table_address =
        Address::from_str(ring_lookup_table).map_err(|_| OperationFailure::Invalid)?;
    let custom_ring = CustomRing::new(program_id);

    let nullifier_key = keypair.nullifier_key();
    let (inputs, available) = match &intent.source {
        PrivateDomainV1::Ring { .. } => {
            if !intent.input_commitments.is_empty() {
                return Err(OperationFailure::Invalid);
            }
            let mut candidates = wallet
                .utxos
                .iter()
                .filter(|entry| {
                    !entry.spent
                        && entry.utxo.asset == asset
                        && entry.utxo.ring_program_id == Some(program_id)
                        && entry.output_context.tree == tree
                })
                .collect::<Vec<_>>();
            candidates.sort_by_key(|entry| std::cmp::Reverse(entry.utxo.amount));
            let mut inputs = Vec::new();
            let mut available: u64 = 0;
            for entry in candidates {
                inputs.push(SppProofInputUtxo::new(entry.utxo.clone(), &nullifier_key));
                available = available
                    .checked_add(entry.utxo.amount)
                    .ok_or(OperationFailure::Unavailable)?;
                if available >= amount {
                    break;
                }
            }
            (inputs, available)
        }
        PrivateDomainV1::Default => {
            if intent.input_commitments.is_empty() || intent.input_commitments.len() > 5 {
                return Err(OperationFailure::Invalid);
            }
            let mut seen = std::collections::BTreeSet::new();
            let mut inputs = Vec::with_capacity(intent.input_commitments.len());
            let mut available: u64 = 0;
            for commitment in &intent.input_commitments {
                if !seen.insert(*commitment) {
                    return Err(OperationFailure::Invalid);
                }
                let entry = wallet
                    .utxos
                    .iter()
                    .find(|entry| {
                        !entry.spent
                            && entry.utxo.asset == asset
                            && entry.utxo.ring_program_id.is_none()
                            && entry.output_context.tree == tree
                            && entry.output_context.hash == *commitment
                    })
                    .ok_or(OperationFailure::Failed(
                        FailureStage::ShieldedBalanceNotReady,
                    ))?;
                available = available
                    .checked_add(entry.utxo.amount)
                    .ok_or(OperationFailure::Unavailable)?;
                inputs.push(SppProofInputUtxo::new(entry.utxo.clone(), &nullifier_key));
            }
            // The bridge output is deliberately exact. Accepting change here
            // would silently move unrelated default-pool value into the ring.
            if available != amount {
                return Err(OperationFailure::Invalid);
            }
            (inputs, available)
        }
    };
    if available < amount {
        return Err(OperationFailure::Failed(
            FailureStage::ShieldedBalanceNotReady,
        ));
    }

    let owner = keypair
        .shielded_address()
        .map_err(|_| OperationFailure::Unavailable)?;
    // A padded change slot pushes the instruction past the packet limit even
    // behind a lookup table, and every published slot must be one the auditor
    // can open, so the ring path requires compact change.
    let mut transfer = ConfidentialTransfer::new(owner, inputs, payer)
        .with_compact_change()
        .with_ring_program_id(program_id);
    let interface_transfer_accounts = match &intent.settlement {
        SpendSettlementV1::Transfer { destination, .. } => {
            let recipient_address = try_resolve_registered_address_async(
                zolana,
                Address::new_from_array(recipient.to_bytes()),
            )
            .await
            .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?
            .ok_or(OperationFailure::Invalid)?;
            match destination {
                PrivateDomainV1::Ring { .. } => transfer
                    .send(&recipient_address.address, asset, amount)
                    .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?,
                PrivateDomainV1::Default => transfer
                    .send_default_ring(&recipient_address.address, asset, amount)
                    .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?,
            };
            Vec::new()
        }
        SpendSettlementV1::Withdrawal { .. } => {
            let (target, accounts) = if asset == SOL_MINT {
                (
                    SettlementTarget::Sol {
                        user_sol_account: Address::new_from_array(recipient.to_bytes()),
                    },
                    TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                        recipient,
                    }),
                )
            } else {
                let mint = Pubkey::new_from_array(asset.to_bytes());
                let token_program = pda::spl_token_program_id();
                let user_spl_token =
                    pda::associated_token_address_with_program(&recipient, &mint, &token_program);
                let spl_interface = pda::spl_interface(&mint);
                (
                    SettlementTarget::Spl {
                        user_spl_token: Address::new_from_array(user_spl_token.to_bytes()),
                        spl_token_interface: Address::new_from_array(spl_interface.to_bytes()),
                    },
                    TransactInterfaceTransferAccounts::SplWithdrawal(
                        TransactSplWithdrawalAccounts {
                            mint,
                            spl_interface,
                            user_token_account: user_spl_token,
                            token_program,
                        },
                    ),
                )
            };
            transfer
                .withdraw(asset, amount, target)
                .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?;
            vec![accounts]
        }
        SpendSettlementV1::Consolidate { .. } => return Err(OperationFailure::Invalid),
    };
    let prepared = transfer
        .prepare()
        .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?;

    let proven = CustomRingTransfer::new(CustomRingTransferInput {
        ring: custom_ring,
        sender: keypair,
        prepared,
    })
    .with_tree(tree)
    .with_assets(assets)
    .with_interface_transfer_accounts(interface_transfer_accounts)
    .prove_async(AsyncTransferProofEnvironment {
        indexer: zolana,
        rpc: zolana,
        prover,
    })
    .await
    // Proving walks the indexer, the tree proofs and the prover in turn, and
    // any of them can be the one that failed. Naming the prover for all of
    // them sends the reader to the wrong service.
    .map_err(|error| OperationFailure::Failed(ring_transfer_stage(&error)))?;

    let instruction = proven
        .instruction()
        .map_err(|_| OperationFailure::Unavailable)?;
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(
        custom_ring_sdk::TRANSACT_COMPUTE_UNIT_LIMIT,
    );
    // The browser creates one reusable table for the ring's stable accounts.
    // Settlement accounts such as a withdrawal recipient are deliberately
    // absent: `try_compile` keeps those keys in the static account list while
    // resolving every matching stable key through the table.
    let table = read_generic_lookup_table(rpc, table_address).await?;
    let (blockhash, _) = zolana
        .rpc()
        .get_latest_blockhash()
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::LatestBlockhash))?;
    let message = v0::Message::try_compile(
        &payer,
        &[compute, instruction],
        core::slice::from_ref(&table),
        blockhash,
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    Ok(VersionedTransaction {
        signatures: vec![Signature::default()],
        message: VersionedMessage::V0(message),
    })
}
pub(super) fn authorized_spend(
    signed: ActivityResult<(VersionedTransaction, Vec<TurnkeyVerifiedAppProofV1>)>,
    shielded_balance_before: u64,
) -> Result<AuthorizedSpend, OperationFailure> {
    let (transaction, turnkey_app_proofs) = signed.result;
    let signed_bytes =
        bincode1::serialize(&transaction).map_err(|_| OperationFailure::Unavailable)?;
    // A v0 message over a lookup table is what keeps this inside the packet
    // limit; past it, nothing can submit the transaction.
    if signed_bytes.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err(OperationFailure::Unavailable);
    }
    let transaction_signature = transaction
        .signatures
        .first()
        .ok_or(OperationFailure::Unavailable)?
        .to_string();
    Ok(AuthorizedSpend {
        transaction_signature,
        signed_transaction: signed_bytes,
        shielded_balance_before,
        turnkey_activity_id: signed.activity_id,
        turnkey_app_proofs,
        evidence_classification: TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
    })
}
