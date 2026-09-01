use super::*;

pub(in crate::operations) async fn load_transaction_addresses(
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
pub(in crate::operations) fn message_account_is_writable(
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
/// An entry must stay canonical base58 or its denial is silently lost.
pub(in crate::operations) const RESERVED_SIGNER_PROGRAMS: [&str; 10] = [
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
pub(in crate::operations) fn reserved_signer_program(program_id: Address) -> bool {
    let program_id = program_id.to_string();
    RESERVED_SIGNER_PROGRAMS.contains(&program_id.as_str())
}
/// Reads a caller-named table from the pinned chain without treating its
/// entries as authority. Message compilation matches entries only to literal
/// accounts in the enclave-built instruction; missing entries remain static
/// keys, and unrelated entries are ignored.
pub(in crate::operations) async fn read_generic_lookup_table(
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
