use super::*;

pub(in crate::operations) async fn finalize_prepared_transaction(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    state: &AppState,
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
            let rpc = SolanaRpc::new(
                &state.services.solana_rpc_url,
                state.services.allow_insecure_http,
            )
            .map_err(|_| OperationFailure::Unavailable)?;
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
    let signed =
        sign_versioned_transaction(state, keys, target, request.issued_at_ms, unsigned).await?;
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
pub(in crate::operations) async fn validate_private_program_transaction(
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
pub(in crate::operations) fn validate_private_program_message(
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
