use super::*;

const RING_CIRCUIT_MAX_INPUTS: usize = 5;

pub(super) struct RingSpendContext<'a> {
    pub(super) keypair: &'a TurnkeyEd25519ShieldedKeypair,
    pub(super) wallet: &'a Wallet,
    pub(super) zolana: &'a ZolanaClient<SolanaRpc>,
    pub(super) rpc: &'a SolanaRpc,
    pub(super) prover: &'a AsyncProverClient,
    pub(super) assets: &'a AssetRegistry,
    pub(super) tree: Address,
    pub(super) asset: Address,
    pub(super) payer: Address,
    pub(super) recipient: Pubkey,
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
            for entry in candidates.into_iter().take(RING_CIRCUIT_MAX_INPUTS) {
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
            let (selected, available) = select_exact_default_ring_inputs(
                wallet,
                asset,
                tree,
                &intent.input_commitments,
                amount,
            )?;
            let inputs = selected
                .into_iter()
                .map(|entry| SppProofInputUtxo::new(entry.utxo.clone(), &nullifier_key))
                .collect();
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

pub(in crate::operations) fn select_exact_default_ring_inputs<'a>(
    wallet: &'a Wallet,
    asset: Address,
    tree: Address,
    commitments: &[[u8; 32]],
    amount: u64,
) -> Result<(Vec<&'a WalletUtxo>, u64), OperationFailure> {
    if commitments.is_empty() || commitments.len() > RING_CIRCUIT_MAX_INPUTS {
        return Err(OperationFailure::Invalid);
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut selected = Vec::with_capacity(commitments.len());
    let mut available = 0u64;
    for commitment in commitments {
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
        selected.push(entry);
    }
    // The bridge output is deliberately exact. Accepting change here would
    // silently move unrelated default-pool value into the ring.
    if available != amount {
        return Err(OperationFailure::Invalid);
    }
    Ok((selected, available))
}
