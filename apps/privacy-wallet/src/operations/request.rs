use super::*;

pub(super) fn validate_request<'a>(
    request: &'a OperationRequestV1,
    running: &RunningEnclave,
    state: &AppState,
) -> Result<ValidatedWallet<'a>, OperationFailure> {
    check_request_bindings(request, running).map_err(|_| OperationFailure::Invalid)?;
    if running.environment != Environment::Development
        || !state
            .info
            .supported_operations
            .contains(&request.operation.kind())
        || !operation_state_fields_are_valid(request)
    {
        return Err(OperationFailure::Invalid);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OperationFailure::Unavailable)?
        .as_millis();
    let now = u64::try_from(now).map_err(|_| OperationFailure::Unavailable)?;
    if request.expires_at_ms < now
        || request.issued_at_ms > now.saturating_add(MAX_CLOCK_SKEW_MS)
        || request.expires_at_ms < request.issued_at_ms
        || request.expires_at_ms - request.issued_at_ms > MAX_REQUEST_AGE_MS
    {
        return Err(OperationFailure::Invalid);
    }

    let wallet = validate_descriptor(request)?;
    let grant = request
        .wallet_descriptor
        .allowed_clients
        .first()
        .ok_or(OperationFailure::Invalid)?;
    let expected_client_key_id = format!(
        "{BROWSER_CLIENT_KEY_ID_PREFIX}{}",
        hex::encode(&Sha256::digest(&grant.client_public_key)[..16])
    );
    if request.authorization.client_key_id != expected_client_key_id {
        return Err(OperationFailure::Invalid);
    }
    zolana_tvc_protocol::verify_client_authorization(request, &grant.client_public_key)
        .map_err(|_| OperationFailure::Invalid)?;
    if !grant.allowed_operations.contains(&request.operation.kind()) {
        return Err(OperationFailure::Invalid);
    }
    Ok(wallet)
}
/// Oracle operations answer against a presented sealed key state; bootstrap
/// must stay independent of caller-selected state.
pub(super) fn operation_state_fields_are_valid(request: &OperationRequestV1) -> bool {
    match &request.operation {
        OperationV1::BootstrapKeyholder => request.sealed_wallet_state.is_none(),
        OperationV1::DeriveViewTags
        | OperationV1::DecryptUtxos { .. }
        | OperationV1::AuthorizeSpend { .. } => request.sealed_wallet_state.is_some(),
    }
}
pub(super) fn validate_descriptor(
    request: &OperationRequestV1,
) -> Result<ValidatedWallet<'_>, OperationFailure> {
    let descriptor = &request.wallet_descriptor;
    let address_pubkey =
        Pubkey::from_str(&descriptor.address).map_err(|_| OperationFailure::Invalid)?;
    if descriptor.version != API_VERSION
        || !is_uuid(&descriptor.turnkey_organization_id)
        || descriptor.turnkey_wallet_id.is_empty()
        || descriptor.turnkey_wallet_id.len() > 128
        || descriptor.environment != Environment::Development
        || descriptor.allowed_clients.len() != 1
    {
        return Err(OperationFailure::Invalid);
    }

    let descriptor_hash =
        descriptor_digest_from_wallet(descriptor).map_err(|_| OperationFailure::Invalid)?;
    verify_p256_prehash(
        &PROVISIONING_PUBLIC,
        &descriptor_hash,
        &descriptor.provisioning_signature,
    )
    .map_err(|_| OperationFailure::Invalid)?;

    let grant = descriptor
        .allowed_clients
        .first()
        .ok_or(OperationFailure::Invalid)?;
    if grant.client_public_key.len() != 65 || grant.allowed_operations != KEYHOLDER_OPERATIONS {
        return Err(OperationFailure::Invalid);
    }

    Ok(ValidatedWallet {
        organization_id: &descriptor.turnkey_organization_id,
        sign_with: &descriptor.address,
        address: address_pubkey,
        expected_ed25519_public_key: address_pubkey.to_bytes(),
    })
}
pub(super) fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
        })
}
