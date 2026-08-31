use super::*;

/// Syncs a fresh wallet for one shielded identity.
pub(super) async fn synced_wallet<A: WalletAuthority + ?Sized>(
    owner: ShieldedAddress,
    authority: &A,
    assets: AssetRegistry,
    zolana: &ZolanaClient<SolanaRpc>,
) -> Result<Wallet, OperationFailure> {
    let mut wallet = Wallet::new(owner, assets).map_err(|_| OperationFailure::Unavailable)?;
    // Pin every indexer query to a slot already observed through the chain RPC.
    // Without this gate, a just-confirmed spend can be absent from the
    // indexer's nullifier stream and the fresh wallet may select that UTXO
    // again. SPP then rejects the duplicate nullifier on chain as 7002.
    tokio::time::timeout(WALLET_SYNC_TIMEOUT, async {
        let require_slot = zolana
            .rpc()
            .get_slot()
            .await
            .map_err(|_| OperationFailure::Failed(FailureStage::WalletSync))?;
        sync_wallet_with_config_async(
            &mut wallet,
            authority,
            zolana,
            SyncWalletConfig::at_slot(require_slot),
        )
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::WalletSync))
    })
    .await
    .map_err(|_| OperationFailure::Failed(FailureStage::WalletSync))??;
    Ok(wallet)
}
/// Reads the latest internally consistent snapshot already available from the
/// private index.
///
/// Balance display must not require the index to have reached a separately
/// sampled Solana RPC slot. A small, normal indexing delay would otherwise
/// turn a read-only refresh into a hard failure. Spend preparation continues
/// to use `synced_wallet`, whose chain-tip gate prevents selection of a UTXO
/// that has already been spent on chain but is not indexed yet.
pub(super) async fn indexed_wallet_snapshot<A: WalletAuthority + ?Sized>(
    owner: ShieldedAddress,
    authority: &A,
    zolana: &ZolanaClient<SolanaRpc>,
) -> Result<Wallet, OperationFailure> {
    // Ring deposits publish the mint address directly, so decoding them does
    // not produce the `unknown_asset_ids` signal used by the SDK's lazy
    // registry refresh. Load the small canonical pool registry up front so
    // both ring deposits and compact-id confidential outputs have the same
    // complete, chain-derived mapping.
    let accounts = zolana
        .rpc()
        .get_program_accounts(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID))
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::AssetRegistry))?;
    let assets = AssetRegistry::new(accounts.into_iter().filter_map(|(_, account)| {
        SplAssetRegistry::from_account_bytes(&account.data)
            .ok()
            .map(|registry| (registry.asset_id, registry.mint))
    }))
    .map_err(|_| OperationFailure::Failed(FailureStage::AssetRegistry))?;
    let mut wallet = Wallet::new(owner, assets).map_err(|_| OperationFailure::Unavailable)?;
    tokio::time::timeout(WALLET_SYNC_TIMEOUT, async {
        // Balance display needs owned outputs, not the wallet's complete
        // counterparty history. With a fresh wallet and a zero tag window the
        // first round queries exactly the two stable discovery tags: the
        // Ed25519 owner tag and the viewing-key bootstrap tag. Expanding every
        // historical sender/recipient window on every stateless refresh made
        // read cost grow with transaction history and eventually timed out.
        sync_wallet_with_config_async(
            &mut wallet,
            authority,
            zolana,
            SyncWalletConfig {
                tag_window: 0,
                rounds: 1,
                ..SyncWalletConfig::default()
            },
        )
        .await
        .map_err(|error| {
            OperationFailure::Failed(match error {
                ClientError::Transaction(_) | ClientError::Keypair(_) | ClientError::Hasher(_) => {
                    FailureStage::WalletReconstruction
                }
                _ => FailureStage::WalletIndexRead,
            })
        })?;

        // The one bounded discovery round computes nullifiers inside TVC but
        // cannot observe a spend with no self-owned change output. Reconcile
        // those nullifiers directly against the pinned index. A nullifier is
        // used at most once, so chunks never need to replay wallet history.
        let candidates = wallet
            .utxos
            .iter()
            .filter(|entry| !entry.spent)
            .map(|entry| entry.nullifier)
            .collect::<Vec<_>>();
        let mut spent = HashSet::new();
        for chunk in candidates.chunks(SNAPSHOT_NULLIFIER_CHUNK) {
            let mut cursor = None;
            loop {
                let response = zolana
                    .get_shielded_transactions_by_nullifiers(
                        chunk.to_vec(),
                        cursor,
                        Some(SNAPSHOT_PAGE_LIMIT),
                        None,
                    )
                    .await
                    .map_err(|_| OperationFailure::Failed(FailureStage::WalletNullifierRead))?;
                for transaction in response.transactions {
                    spent.extend(transaction.nullifiers);
                }
                let Some(next) = response.next_cursor else {
                    break;
                };
                cursor = Some(next);
            }
        }
        for entry in &mut wallet.utxos {
            entry.spent |= spent.contains(&entry.nullifier);
        }
        Ok::<(), OperationFailure>(())
    })
    .await
    .map_err(|_| OperationFailure::Failed(FailureStage::WalletSync))??;
    Ok(wallet)
}
/// Prefer larger default-ring UTXOs before the SDK's stable input scan.
///
/// The installed SPP circuits accept at most five inputs. Index order can pick
/// six pieces of dust even when a later UTXO covers the spend by itself.
pub(super) fn prioritize_default_spend_inputs(wallet: &mut Wallet, asset: Address) {
    wallet.utxos.sort_by(|left, right| {
        let left_eligible =
            !left.spent && left.utxo.asset == asset && left.utxo.ring_program_id.is_none();
        let right_eligible =
            !right.spent && right.utxo.asset == asset && right.utxo.ring_program_id.is_none();
        right_eligible
            .cmp(&left_eligible)
            .then_with(|| right.utxo.amount.cmp(&left.utxo.amount))
    });
}
