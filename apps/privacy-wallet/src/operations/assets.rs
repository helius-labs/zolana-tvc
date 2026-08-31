use super::*;

pub(super) fn add_asset_amount(
    totals: &mut Vec<(Address, u128)>,
    asset: Address,
    amount: u64,
) -> Result<(), OperationFailure> {
    if let Some((_, total)) = totals.iter_mut().find(|(existing, _)| *existing == asset) {
        *total = total
            .checked_add(u128::from(amount))
            .ok_or(OperationFailure::Unavailable)?;
    } else {
        totals.push((asset, u128::from(amount)));
    }
    Ok(())
}
pub(super) fn sort_asset_totals(totals: &mut [(Address, u128)]) {
    totals.sort_by_key(|(asset, _)| asset.to_bytes());
}
pub(super) fn generic_asset_address(asset: &AssetV1) -> Result<Address, OperationFailure> {
    match asset {
        AssetV1::Sol => Ok(SOL_MINT),
        AssetV1::Spl { mint, .. } => Address::from_str(mint).map_err(|_| OperationFailure::Invalid),
    }
}
pub(super) async fn generic_asset_registry(
    rpc: &SolanaRpc,
    plan: &SppPlanV1,
) -> Result<AssetRegistry, OperationFailure> {
    let mut registry = AssetRegistry::default();
    for asset in plan
        .inputs
        .iter()
        .filter_map(|input| match input {
            SppPlanInputV1::Program { asset, .. } => Some(asset),
            SppPlanInputV1::Wallet { .. } => None,
        })
        .chain(plan.outputs.iter().map(|output| &output.asset))
    {
        let (mint, _) = resolve_asset(rpc, asset).await?;
        if let AssetV1::Spl { asset_id, .. } = asset {
            match registry.asset_id(&mint) {
                Ok(existing) if existing == *asset_id => {}
                Ok(_) => return Err(OperationFailure::Invalid),
                Err(_) => registry
                    .insert(*asset_id, mint)
                    .map_err(|_| OperationFailure::Invalid)?,
            }
        }
    }
    Ok(registry)
}
pub(super) async fn resolve_asset(
    rpc: &SolanaRpc,
    requested: &AssetV1,
) -> Result<(Address, AssetRegistry), OperationFailure> {
    match requested {
        AssetV1::Sol => Ok((SOL_MINT, AssetRegistry::default())),
        AssetV1::Spl { mint, asset_id } => {
            if *asset_id <= 1 {
                return Err(OperationFailure::Invalid);
            }
            let mint = Pubkey::from_str(mint).map_err(|_| OperationFailure::Invalid)?;
            let mint_address = Address::new_from_array(mint.to_bytes());
            let mint_account = rpc
                .get_account(mint_address)
                .await
                .map_err(|_| OperationFailure::Failed(FailureStage::AssetRegistry))?
                .ok_or(OperationFailure::Invalid)?;
            if mint_account.owner.to_bytes() != pda::spl_token_program_id().to_bytes() {
                return Err(OperationFailure::Invalid);
            }
            let registry_address = pda::spl_asset_registry(&mint);
            let account = rpc
                .get_account(Address::new_from_array(registry_address.to_bytes()))
                .await
                .map_err(|_| OperationFailure::Failed(FailureStage::AssetRegistry))?
                .ok_or(OperationFailure::Invalid)?;
            if account.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID {
                return Err(OperationFailure::Invalid);
            }
            let registry = SplAssetRegistry::from_account_bytes(&account.data)
                .map_err(|_| OperationFailure::Invalid)?;
            if registry.mint != mint_address || registry.asset_id != *asset_id {
                return Err(OperationFailure::Invalid);
            }
            let assets = AssetRegistry::new([(*asset_id, mint_address)])
                .map_err(|_| OperationFailure::Invalid)?;
            Ok((mint_address, assets))
        }
    }
}
