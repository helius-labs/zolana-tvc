//! Operator-only attested TVC -> Turnkey -> default-ring devnet E2E.

#[path = "e2e/state_file.rs"]
mod state_file;

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use clap::Parser;
use p256::SecretKey;
use p256::elliptic_curve::rand_core::{OsRng, RngCore as _};
use qos_core::protocol::services::boot::VersionedManifest;
use qos_nsm::nitro::unsafe_attestation_doc_from_der;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use turnkey_client::generated::external::data::v1::{AppProof, BootProof, SignatureScheme};
use turnkey_client::generated::immutable::common::v1::{AddressFormat, Curve, PathFormat};
use turnkey_client::generated::services::coordinator::public::v1::{
    GetWalletAccountsRequest, GetWalletRequest,
};
use turnkey_client::{TurnkeyClient, TurnkeyP256ApiKey};
use turnkey_proofs::{get_boot_proof_for_app_proof, verify};
use zolana_tvc_protocol::constants::{API_VERSION, TVC_APP_PROOF_SCHEME, TVC_QOS_PING_PROOF_TYPE};
use zolana_tvc_protocol::crypto::{
    QosP256Public, public_key_uncompressed, qos_decrypt, qos_encrypt, sign_p256_prehash,
    verify_p256_message,
};
use zolana_tvc_protocol::digest::{
    descriptor_digest_from_wallet, owner_auth_evidence_digest, provisioning_auth_digest,
    request_digest, result_digest,
};
use zolana_tvc_protocol::encoding::{is_rfc8785, jcs_serialize, parse_strict_json};
use zolana_tvc_protocol::types::{
    ClientAuthorizationScheme, ClientAuthorizationV1, ClientGrantV1, DevelopmentAssetV1,
    DevelopmentFailureStage, DevelopmentTransferIntentV1, EncryptedRequestV1, EncryptedResponseV1,
    Environment, OperationKind, OperationRequestV1, OperationResultV1, OperationV1,
    QosPingChallengeV1, QosPingRequestV1, QosPingResponseV1, ServiceInfoV1,
    TurnkeyEvidenceClassification, TurnkeySigningTargetV1, TurnkeyVerifiedAppProofV1,
    TvcAppProofV1, TvcOperationProofPayloadV1, WalletDescriptorV1,
};

use state_file::{
    DevelopmentStateFileV1, FinalizedTransferV1, LockedStateFile, PendingTransferV1,
    STATE_FILE_TYPE,
};

const ACK: &str = "I_UNDERSTAND_THIS_SPENDS_DEVNET_FUNDS";
const ORGANIZATION_ID: &str = "69febc39-7ac1-42c1-9786-f20f9cc52c5b";
const WALLET_ID: &str = "wallet-dev-e2e-0690e9e7";
const TURNKEY_WALLET_ID: &str = "0690e9e7-8e6c-5e81-ab19-93c53a9acc74";
const TURNKEY_WALLET_ACCOUNT_ID: &str = "1f9a1265-49bb-4f6a-899c-85409119035b";
const TURNKEY_ADDRESS: &str = "D3Es9fdLDxtxA6dWRNdJt5uzoVtxuMHHYYoDWrhNGAp";
const TURNKEY_DERIVATION_PATH: &str = "m/44'/501'/0'/0'";
const TURNKEY_SERVICE_USER_ID: &str = "9d86106d-5340-46d6-a05d-9e5ea9f5e019";
const TURNKEY_API_KEY_ID: &str = "218b879b-5e81-4843-bee7-7811a7fd0979";
const CLIENT_KEY_ID: &str = "wallet-dev-e2e-client-v1";
const PROVISIONING_KEY_ID: &str = "wallet-dev-e2e-provisioner-v1";
const PROVER_PROFILE_ID: &str = "zolnet-devnet-external-http-v1";
const ZDEV_MINT: &str = "BEZe5CuQxzjwTHoqobHA3XJw34GJTph8nrXqP9zJRLjx";
const ZDEV_ASSET_ID: u64 = 14;
const TRANSFER_AMOUNT: u64 = 50_000_000_000;
const EXPECTED_ED25519_PUBLIC_KEY: [u8; 32] = [
    0x03, 0x15, 0x80, 0x5c, 0x22, 0x06, 0x41, 0x2e, 0x1a, 0x2b, 0x16, 0xe4, 0xae, 0x11, 0xa4, 0x29,
    0xed, 0x59, 0x40, 0x7d, 0x50, 0x6e, 0x0a, 0x73, 0x52, 0x12, 0x84, 0x28, 0x29, 0x77, 0xfd, 0xfd,
];

#[derive(Debug, Parser)]
#[command(name = "zolana-tvc-e2e")]
struct Cli {
    #[arg(long)]
    endpoint: String,
    #[arg(long)]
    api_key_path: PathBuf,
    #[arg(long)]
    expected_release_id: String,
    #[arg(long)]
    expected_manifest_digest: String,
    #[arg(long)]
    expected_executable_digest: String,
    #[arg(long)]
    expected_quorum_public_key: String,
    #[arg(long)]
    expected_quorum_key_id: String,
    #[arg(long, default_value = "https://api.devnet.solana.com")]
    rpc_url: String,
    #[arg(long, default_value_t = false)]
    create_wallet_only: bool,
    /// Verify only discovery, QOS ping, and its official Boot Proof.
    #[arg(long, default_value_t = false)]
    verify_connection_only: bool,
    /// Create a mode-0600 JSON file containing the public Boot Proof fixture.
    #[arg(long, requires = "verify_connection_only")]
    boot_proof_output: Option<PathBuf>,
    /// Bootstrap the fixed wallet and persist only its opaque sealed state.
    #[arg(long, default_value_t = false)]
    bootstrap_save_only: bool,
    /// Load a persisted sealed state and make or exactly resume one transfer.
    #[arg(long, default_value_t = false)]
    resume_transfer: bool,
    /// Owner-only local development checkpoint used by the save/resume modes.
    #[arg(long)]
    state_file: Option<PathBuf>,
    #[arg(long)]
    acknowledgement: String,
}

#[derive(Deserialize)]
struct StoredApiKey {
    private_key: String,
    public_key: String,
}

struct HostContext {
    http: reqwest::Client,
    endpoint: String,
    turnkey: TurnkeyClient<TurnkeyP256ApiKey>,
    client_secret: [u8; 32],
    client_public: Vec<u8>,
}

struct PreparedRequest {
    request: OperationRequestV1,
    response_secret: [u8; 32],
}

struct CompletedTransfer {
    wire: Vec<u8>,
    signature: String,
    request_id: [u8; 32],
    request_digest: [u8; 32],
    turnkey_activity_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(cli.acknowledgement == ACK, "wrong acknowledgement");
    let state_mode_count = usize::from(cli.bootstrap_save_only) + usize::from(cli.resume_transfer);
    ensure!(state_mode_count <= 1, "select only one state-file mode");
    ensure!(
        !(cli.create_wallet_only && cli.verify_connection_only),
        "select only one terminal mode"
    );
    ensure!(
        (!cli.create_wallet_only && !cli.verify_connection_only) || state_mode_count == 0,
        "terminal modes cannot be combined with a state-file mode"
    );
    ensure!(
        cli.state_file.is_some() == (state_mode_count == 1),
        "--state-file is required exactly for --bootstrap-save-only or --resume-transfer"
    );
    ensure!(
        cli.endpoint.starts_with("https://"),
        "endpoint must use HTTPS"
    );
    ensure!(cli.rpc_url.starts_with("https://"), "RPC must use HTTPS");
    let stored: StoredApiKey = serde_json::from_slice(
        &fs::read(&cli.api_key_path)
            .with_context(|| format!("failed to read {}", cli.api_key_path.display()))?,
    )?;
    let client_secret: [u8; 32] = hex::decode(stored.private_key.trim_start_matches("0x"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("API private key must be 32 bytes"))?;
    let secret = SecretKey::from_slice(&client_secret)?;
    let client_public = public_key_uncompressed(&secret.public_key()).to_vec();
    let turnkey_key =
        TurnkeyP256ApiKey::from_strings(&stored.private_key, Some(&stored.public_key))?;
    let turnkey = TurnkeyClient::builder().api_key(turnkey_key).build()?;
    let context = HostContext {
        http: reqwest::Client::builder().https_only(true).build()?,
        endpoint: cli.endpoint.trim_end_matches('/').to_owned(),
        turnkey,
        client_secret,
        client_public,
    };

    let info: ServiceInfoV1 = context.get_json("/v1/info").await?;
    bind_info(&cli, &info)?;
    let boot_proof = verify_qos_ping(&context, &info).await?;
    println!("tvc_boot_proof_verification=passed");
    if cli.verify_connection_only {
        print_qos_identity_pcrs(&boot_proof)?;
        if let Some(path) = &cli.boot_proof_output {
            write_boot_proof(path, &boot_proof)?;
        }
        println!("tvc_connection_e2e=passed");
        return Ok(());
    }

    let descriptor = signed_descriptor(&context, &info)?;
    if cli.create_wallet_only {
        let request = signed_request(
            &context,
            &info,
            descriptor,
            None,
            None,
            None,
            OperationV1::CreateWallet,
        )?;
        match execute_operation(&context, &info, &request).await? {
            OperationResultV1::CreateWallet {
                wallet_name,
                turnkey_wallet_id,
                turnkey_wallet_account_id,
                solana_address,
                derivation_path,
                turnkey_activity_id,
                turnkey_app_proofs,
                evidence_classification,
            } => {
                ensure!(
                    evidence_classification
                        == TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
                    "unexpected Turnkey evidence classification"
                );
                ensure!(
                    derivation_path == TURNKEY_DERIVATION_PATH,
                    "created wallet derivation path mismatch"
                );
                verify_turnkey_app_proofs(&context, &turnkey_app_proofs).await?;
                let wallet_account_id = verify_created_wallet(
                    &context,
                    &turnkey_wallet_id,
                    &wallet_name,
                    &solana_address,
                )
                .await?;
                ensure!(
                    turnkey_wallet_account_id == wallet_account_id,
                    "created wallet account id mismatch"
                );
                println!("create_wallet_activity_id={turnkey_activity_id}");
                println!("created_wallet_name={wallet_name}");
                println!("created_turnkey_wallet_id={turnkey_wallet_id}");
                println!("created_wallet_account_id={wallet_account_id}");
                println!("created_solana_address={solana_address}");
                println!("wallet_creation_e2e=passed");
                return Ok(());
            }
            OperationResultV1::DevelopmentFailure { operation, stage } => {
                bail!("TVC development operation {operation:?} failed at {stage:?}")
            }
            _ => bail!("unexpected wallet creation result"),
        }
    }
    if cli.resume_transfer {
        resume_transfer_from_state_file(
            &context,
            &cli,
            &info,
            descriptor,
            cli.state_file.as_deref().context("state file missing")?,
        )
        .await?;
        return Ok(());
    }

    let state_guard = if cli.bootstrap_save_only {
        let guard =
            LockedStateFile::acquire(cli.state_file.as_deref().context("state file missing")?)?;
        guard.ensure_absent()?;
        Some(guard)
    } else {
        None
    };
    let bootstrap_request = signed_request(
        &context,
        &info,
        descriptor.clone(),
        None,
        None,
        None,
        OperationV1::BootstrapEd25519,
    )?;
    let bootstrap = execute_operation(&context, &info, &bootstrap_request).await?;
    let (sealed_state, state_version, state_digest) = match bootstrap {
        OperationResultV1::BootstrapEd25519 {
            solana_address,
            shielded_owner_hash,
            shielded_nullifier_public_key,
            shielded_viewing_public_key,
            sealed_wallet_state,
            state_version,
            state_digest,
            turnkey_activity_id,
            turnkey_app_proofs,
            evidence_classification,
        } => {
            ensure!(
                solana_address == TURNKEY_ADDRESS,
                "bootstrap address mismatch"
            );
            ensure!(
                evidence_classification
                    == TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
                "unexpected Turnkey evidence classification"
            );
            verify_turnkey_app_proofs(&context, &turnkey_app_proofs).await?;
            ensure!(
                shielded_nullifier_public_key != [0; 32],
                "zero shielded nullifier public key"
            );
            ensure!(
                shielded_viewing_public_key.len() == 33
                    && matches!(shielded_viewing_public_key[0], 0x02 | 0x03),
                "invalid compressed shielded viewing public key"
            );
            println!("bootstrap_activity_id={turnkey_activity_id}");
            println!("shielded_owner_hash={}", hex::encode(shielded_owner_hash));
            (sealed_wallet_state, state_version, state_digest)
        }
        _ => bail!("unexpected bootstrap result"),
    };

    if let Some(guard) = state_guard {
        let state = initial_state_file(
            &context,
            &info,
            &descriptor,
            sealed_state,
            state_version,
            state_digest,
        )?;
        let file_digest = guard.create(&state)?;
        println!("state_version={state_version}");
        println!("state_digest={}", hex::encode(state_digest));
        println!("state_file_digest={}", hex::encode(file_digest));
        println!("bootstrap_state_persistence=passed");
        return Ok(());
    }

    let recent_blockhash = latest_blockhash(&context.http, &cli.rpc_url).await?;
    let prepare_request = signed_request(
        &context,
        &info,
        descriptor.clone(),
        Some(sealed_state.clone()),
        Some(state_version),
        Some(state_digest),
        OperationV1::PrepareWallet { recent_blockhash },
    )?;
    let prepare = execute_operation(&context, &info, &prepare_request).await?;
    match prepare {
        OperationResultV1::PrepareWallet {
            signed_registration_transaction,
            registration_signature,
            registration_activity_id,
            registration_app_proofs,
            state_version: returned_state_version,
            state_digest: returned_state_digest,
            evidence_classification,
            ..
        } => {
            ensure!(
                evidence_classification
                    == TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
                "unexpected Turnkey evidence classification"
            );
            ensure!(
                returned_state_version == state_version && returned_state_digest == state_digest,
                "setup changed sealed wallet state"
            );
            verify_turnkey_app_proofs(&context, &registration_app_proofs).await?;
            let rpc_registration = send_transaction(
                &context.http,
                &cli.rpc_url,
                &signed_registration_transaction,
            )
            .await?;
            ensure!(
                rpc_registration == registration_signature,
                "registration RPC signature mismatch"
            );
            let registration_slot =
                wait_for_finalization(&context.http, &cli.rpc_url, &registration_signature).await?;
            println!("registration_activity_id={registration_activity_id}");
            println!("registration_signature={registration_signature}");
            println!("registration_slot={registration_slot}");
        }
        OperationResultV1::DevelopmentFailure { operation, stage } => {
            bail!("TVC development operation {operation:?} failed at {stage:?}")
        }
        _ => bail!("unexpected development setup result"),
    }

    let completed = build_transfer_until_ready(
        &context,
        &info,
        descriptor,
        &sealed_state,
        state_version,
        state_digest,
    )
    .await?;
    let rpc_signature = send_transaction(&context.http, &cli.rpc_url, &completed.wire).await?;
    ensure!(
        rpc_signature == completed.signature,
        "RPC signature mismatch"
    );
    let slot = wait_for_finalization(&context.http, &cli.rpc_url, &completed.signature).await?;
    println!("transfer_signature={}", completed.signature);
    println!("transfer_slot={slot}");
    println!("e2e=passed");
    Ok(())
}

fn initial_state_file(
    context: &HostContext,
    info: &ServiceInfoV1,
    descriptor: &WalletDescriptorV1,
    sealed_wallet_state: Vec<u8>,
    state_version: u64,
    state_digest: [u8; 32],
) -> Result<DevelopmentStateFileV1> {
    let state = DevelopmentStateFileV1 {
        r#type: STATE_FILE_TYPE.to_owned(),
        version: API_VERSION,
        endpoint: context.endpoint.clone(),
        release_id: info.release_id.clone(),
        security_domain_id: info.security_domain_id,
        manifest_digest: info.manifest_digest,
        executable_digest: info.executable_digest,
        quorum_key_id: info.quorum_key_id.clone(),
        quorum_key_epoch: info.quorum_key_epoch,
        quorum_public_key: info.quorum_public_key.clone(),
        wallet_id: WALLET_ID.to_owned(),
        turnkey_wallet_id: TURNKEY_WALLET_ID.to_owned(),
        turnkey_wallet_account_id: TURNKEY_WALLET_ACCOUNT_ID.to_owned(),
        solana_address: TURNKEY_ADDRESS.to_owned(),
        expected_ed25519_public_key: EXPECTED_ED25519_PUBLIC_KEY,
        descriptor_digest: descriptor_digest_from_wallet(descriptor)?,
        state_version,
        state_digest,
        sealed_wallet_state,
        local_generation: 0,
        pending_transfer: None,
        last_finalized_transfer: None,
    };
    state.validate_sealed_state()?;
    Ok(state)
}

fn validate_state_file_bindings(
    state: &DevelopmentStateFileV1,
    context: &HostContext,
    info: &ServiceInfoV1,
    descriptor: &WalletDescriptorV1,
) -> Result<()> {
    ensure!(
        state.endpoint == context.endpoint,
        "state endpoint mismatch"
    );
    ensure!(
        state.release_id == info.release_id,
        "state release mismatch"
    );
    ensure!(
        state.security_domain_id == info.security_domain_id,
        "state security domain mismatch"
    );
    ensure!(
        state.manifest_digest == info.manifest_digest,
        "state manifest mismatch"
    );
    ensure!(
        state.executable_digest == info.executable_digest,
        "state executable mismatch"
    );
    ensure!(
        state.quorum_key_id == info.quorum_key_id
            && state.quorum_key_epoch == info.quorum_key_epoch
            && state.quorum_public_key == info.quorum_public_key,
        "state Quorum binding mismatch"
    );
    ensure!(state.wallet_id == WALLET_ID, "state wallet ID mismatch");
    ensure!(
        state.turnkey_wallet_id == TURNKEY_WALLET_ID
            && state.turnkey_wallet_account_id == TURNKEY_WALLET_ACCOUNT_ID,
        "state Turnkey wallet binding mismatch"
    );
    ensure!(
        state.solana_address == TURNKEY_ADDRESS,
        "state Solana address mismatch"
    );
    ensure!(
        state.expected_ed25519_public_key == EXPECTED_ED25519_PUBLIC_KEY,
        "state Ed25519 public key mismatch"
    );
    ensure!(
        state.descriptor_digest == descriptor_digest_from_wallet(descriptor)?,
        "state descriptor mismatch"
    );
    state.validate_sealed_state()
}

async fn resume_transfer_from_state_file(
    context: &HostContext,
    cli: &Cli,
    info: &ServiceInfoV1,
    descriptor: WalletDescriptorV1,
    path: &std::path::Path,
) -> Result<()> {
    let guard = LockedStateFile::acquire(path)?;
    let (mut state, mut file_digest) = guard.load()?;
    validate_state_file_bindings(&state, context, info, &descriptor)?;
    println!("loaded_state_version={}", state.state_version);
    println!("loaded_state_digest={}", hex::encode(state.state_digest));
    println!("loaded_local_generation={}", state.local_generation);

    let pending = if let Some(pending) = state.pending_transfer.clone() {
        println!("pending_artifact_resume=exact");
        pending
    } else {
        let completed = build_transfer_until_ready(
            context,
            info,
            descriptor,
            &state.sealed_wallet_state,
            state.state_version,
            state.state_digest,
        )
        .await?;
        let pending = PendingTransferV1 {
            request_id: completed.request_id,
            request_digest: completed.request_digest,
            signed_transaction: completed.wire,
            transaction_signature: completed.signature,
            turnkey_activity_id: completed.turnkey_activity_id,
        };
        state.pending_transfer = Some(pending.clone());
        file_digest = guard.replace(file_digest, &state)?;
        println!("pending_artifact_persistence=passed");
        pending
    };

    let slot = broadcast_or_confirm_pending(context, &cli.rpc_url, &pending).await?;
    let persisted = state
        .pending_transfer
        .as_ref()
        .context("pending transfer disappeared from checkpoint")?;
    ensure!(persisted == &pending, "pending transfer checkpoint changed");
    state.pending_transfer = None;
    state.local_generation = state
        .local_generation
        .checked_add(1)
        .context("local generation overflow")?;
    state.last_finalized_transfer = Some(FinalizedTransferV1 {
        request_id: pending.request_id,
        request_digest: pending.request_digest,
        transaction_signature: pending.transaction_signature.clone(),
        turnkey_activity_id: pending.turnkey_activity_id.clone(),
        slot,
    });
    let final_file_digest = guard.replace(file_digest, &state)?;
    println!("transfer_signature={}", pending.transaction_signature);
    println!("transfer_slot={slot}");
    println!("local_generation={}", state.local_generation);
    println!("state_file_digest={}", hex::encode(final_file_digest));
    println!("restart_resume_transfer=passed");
    Ok(())
}

async fn build_transfer_until_ready(
    context: &HostContext,
    info: &ServiceInfoV1,
    descriptor: WalletDescriptorV1,
    sealed_wallet_state: &[u8],
    state_version: u64,
    state_digest_checkpoint: [u8; 32],
) -> Result<CompletedTransfer> {
    for _ in 0..120 {
        let build_request = signed_request(
            context,
            info,
            descriptor.clone(),
            Some(sealed_wallet_state.to_vec()),
            Some(state_version),
            Some(state_digest_checkpoint),
            OperationV1::BuildTransfer {
                intent: DevelopmentTransferIntentV1 {
                    asset: DevelopmentAssetV1::Spl {
                        mint: ZDEV_MINT.to_owned(),
                        asset_id: ZDEV_ASSET_ID,
                    },
                    recipient: TURNKEY_ADDRESS.to_owned(),
                    amount: TRANSFER_AMOUNT,
                    prover_profile_id: PROVER_PROFILE_ID.to_owned(),
                },
            },
        )?;
        match execute_operation(context, info, &build_request).await? {
            OperationResultV1::BuildTransfer {
                signed_transaction,
                transaction_signature,
                sealed_wallet_state: returned_sealed_state,
                state_version: returned_state_version,
                state_digest: returned_state_digest,
                shielded_balance_before,
                turnkey_activity_id,
                turnkey_app_proofs,
                evidence_classification,
            } => {
                ensure!(
                    evidence_classification
                        == TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
                    "unexpected Turnkey evidence classification"
                );
                ensure!(
                    returned_sealed_state == sealed_wallet_state
                        && returned_state_version == state_version
                        && returned_state_digest == state_digest_checkpoint,
                    "transfer changed the sealed-state checkpoint"
                );
                verify_turnkey_app_proofs(context, &turnkey_app_proofs).await?;
                println!("shielded_balance_before={shielded_balance_before}");
                println!("transfer_activity_id={turnkey_activity_id}");
                return Ok(CompletedTransfer {
                    wire: signed_transaction,
                    signature: transaction_signature,
                    request_id: build_request.request.request_id,
                    request_digest: request_digest(&build_request.request)?,
                    turnkey_activity_id,
                });
            }
            OperationResultV1::DevelopmentFailure {
                stage:
                    DevelopmentFailureStage::SyncWallet
                    | DevelopmentFailureStage::ShieldedBalanceNotReady,
                ..
            } => tokio::time::sleep(Duration::from_secs(1)).await,
            OperationResultV1::DevelopmentFailure { operation, stage } => {
                bail!("TVC development operation {operation:?} failed at {stage:?}")
            }
            _ => bail!("unexpected transfer result"),
        }
    }
    bail!("shielded balance was not ready within 120s")
}

async fn broadcast_or_confirm_pending(
    context: &HostContext,
    rpc_url: &str,
    pending: &PendingTransferV1,
) -> Result<u64> {
    if let Some(slot) =
        finalized_slot(&context.http, rpc_url, &pending.transaction_signature).await?
    {
        println!("pending_artifact_already_confirmed=true");
        return Ok(slot);
    }
    let rpc_signature =
        send_transaction(&context.http, rpc_url, &pending.signed_transaction).await?;
    ensure!(
        rpc_signature == pending.transaction_signature,
        "RPC signature mismatch"
    );
    wait_for_finalization(&context.http, rpc_url, &pending.transaction_signature).await
}

impl HostContext {
    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .http
            .get(format!("{}{path}", self.endpoint))
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "GET {path}: {}",
            response.status()
        );
        let body = response.text().await?;
        parse_strict_json(&body).map_err(|error| anyhow::anyhow!("GET {path}: {error}"))
    }

    async fn post_json<T: DeserializeOwned>(&self, path: &str, body: String) -> Result<T> {
        let response = self
            .http
            .post(format!("{}{path}", self.endpoint))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        ensure!(status.is_success(), "POST {path}: {status} {body}");
        parse_strict_json(&body).map_err(|error| anyhow::anyhow!("POST {path}: {error}"))
    }
}

fn bind_info(cli: &Cli, info: &ServiceInfoV1) -> Result<()> {
    ensure!(info.version == API_VERSION, "wrong API version");
    ensure!(
        info.environment == Environment::Development,
        "not development"
    );
    ensure!(
        info.release_id == cli.expected_release_id,
        "release mismatch"
    );
    ensure!(
        hex::encode(info.manifest_digest) == cli.expected_manifest_digest,
        "manifest mismatch"
    );
    ensure!(
        hex::encode(info.executable_digest) == cli.expected_executable_digest,
        "executable mismatch"
    );
    ensure!(
        hex::encode(&info.quorum_public_key) == cli.expected_quorum_public_key,
        "quorum public key mismatch"
    );
    ensure!(
        info.quorum_key_id == cli.expected_quorum_key_id,
        "quorum ID mismatch"
    );
    ensure!(
        info.supported_operations
            == [
                OperationKind::CreateWallet,
                OperationKind::BootstrapEd25519,
                OperationKind::PrepareWallet,
                OperationKind::ShieldSol,
                OperationKind::BuildTransfer
            ],
        "operation allow-list mismatch"
    );
    Ok(())
}

async fn verify_qos_ping(context: &HostContext, info: &ServiceInfoV1) -> Result<BootProof> {
    let challenge = QosPingChallengeV1 {
        r#type: TVC_QOS_PING_PROOF_TYPE.to_owned(),
        version: API_VERSION,
        challenge: random32(),
    };
    let payload = jcs_serialize(&challenge)?;
    let quorum = QosP256Public::from_bytes(&info.quorum_public_key)?;
    let request = QosPingRequestV1 {
        version: API_VERSION,
        encrypted_challenge: qos_encrypt(&quorum.encryption, payload.as_bytes())?,
    };
    let response: QosPingResponseV1 = context
        .post_json("/v1/ping", jcs_serialize(&request)?)
        .await?;
    ensure!(
        response.tvc_app_proof.proof_payload == payload,
        "ping payload mismatch"
    );
    verify_tvc_app_proof(context, info, &response.tvc_app_proof).await
}

fn signed_descriptor(context: &HostContext, info: &ServiceInfoV1) -> Result<WalletDescriptorV1> {
    let mut descriptor = WalletDescriptorV1 {
        version: API_VERSION,
        wallet_id: WALLET_ID.to_owned(),
        security_domain_id: info.security_domain_id,
        turnkey_parent_organization_id: ORGANIZATION_ID.to_owned(),
        turnkey_organization_id: ORGANIZATION_ID.to_owned(),
        turnkey_signing_target: TurnkeySigningTargetV1::HdWalletAccount {
            turnkey_wallet_id: TURNKEY_WALLET_ID.to_owned(),
            wallet_account_id: TURNKEY_WALLET_ACCOUNT_ID.to_owned(),
            address: TURNKEY_ADDRESS.to_owned(),
            derivation_path: TURNKEY_DERIVATION_PATH.to_owned(),
        },
        turnkey_service_user_id: TURNKEY_SERVICE_USER_ID.to_owned(),
        turnkey_api_key_id: TURNKEY_API_KEY_ID.to_owned(),
        expected_ed25519_public_key: EXPECTED_ED25519_PUBLIC_KEY,
        allowed_clients: vec![ClientGrantV1 {
            client_key_id: CLIENT_KEY_ID.to_owned(),
            scheme: ClientAuthorizationScheme::P256Sha256,
            client_public_key: context.client_public.clone(),
            allowed_operations: vec![
                OperationKind::CreateWallet,
                OperationKind::BootstrapEd25519,
                OperationKind::PrepareWallet,
                OperationKind::ShieldSol,
                OperationKind::BuildTransfer,
            ],
            may_rotate_descriptor: false,
        }],
        policy_version: 1,
        previous_descriptor_digest: None,
        environment: Environment::Development,
        provisioning_key_id: PROVISIONING_KEY_ID.to_owned(),
        owner_authorization_key: None,
        recovery_binding: None,
        provisioning_signature: Vec::new(),
        owner_authorization: None,
        prior_client_authorization: None,
    };
    let descriptor_digest = descriptor_digest_from_wallet(&descriptor)?;
    let owner_digest = owner_auth_evidence_digest(&None, &None, &None)?;
    descriptor.provisioning_signature = sign_p256_prehash(
        &context.client_secret,
        &provisioning_auth_digest(&descriptor_digest, &owner_digest),
    )?
    .to_vec();
    Ok(descriptor)
}

fn signed_request(
    context: &HostContext,
    info: &ServiceInfoV1,
    descriptor: WalletDescriptorV1,
    sealed_wallet_state: Option<Vec<u8>>,
    expected_state_version: Option<u64>,
    expected_state_digest: Option<[u8; 32]>,
    operation: OperationV1,
) -> Result<PreparedRequest> {
    let now = now_ms()?;
    let response_secret = SecretKey::random(&mut OsRng);
    let response_public = public_key_uncompressed(&response_secret.public_key());
    let mut qos_response_public = Vec::with_capacity(130);
    qos_response_public.extend_from_slice(&response_public);
    qos_response_public.extend_from_slice(&response_public);
    let mut request = OperationRequestV1 {
        version: API_VERSION,
        request_id: random32(),
        issued_at_ms: now,
        expires_at_ms: now + 300_000,
        target_release_id: info.release_id.clone(),
        target_manifest_digest: info.manifest_digest,
        target_executable_digest: info.executable_digest,
        quorum_key_id: info.quorum_key_id.clone(),
        quorum_key_epoch: info.quorum_key_epoch,
        wallet_descriptor: descriptor,
        sealed_wallet_state,
        expected_state_version,
        expected_state_digest,
        client_response_public_key: qos_response_public,
        operation,
        authorization: ClientAuthorizationV1 {
            client_key_id: CLIENT_KEY_ID.to_owned(),
            scheme: ClientAuthorizationScheme::P256Sha256,
            signature: Vec::new(),
        },
    };
    request = zolana_tvc_protocol::authorize_operation_request(request, &context.client_secret)?;
    Ok(PreparedRequest {
        request,
        response_secret: response_secret.to_bytes().into(),
    })
}

async fn execute_operation(
    context: &HostContext,
    info: &ServiceInfoV1,
    prepared: &PreparedRequest,
) -> Result<OperationResultV1> {
    let request = &prepared.request;
    let request_json = jcs_serialize(request)?;
    let quorum = QosP256Public::from_bytes(&info.quorum_public_key)?;
    let outer = EncryptedRequestV1 {
        version: API_VERSION,
        quorum_key_id: info.quorum_key_id.clone(),
        quorum_key_epoch: info.quorum_key_epoch,
        ciphertext: qos_encrypt(&quorum.encryption, request_json.as_bytes())?,
    };
    let response: EncryptedResponseV1 = context
        .post_json("/v1/operations", jcs_serialize(&outer)?)
        .await?;
    ensure!(
        response.request_id == request.request_id,
        "response request ID mismatch"
    );
    verify_operation_proof(context, info, request, &response).await?;
    let plaintext = qos_decrypt(&prepared.response_secret, &response.encrypted_result)?;
    let plaintext = std::str::from_utf8(plaintext.as_slice())?;
    ensure!(is_rfc8785(plaintext), "result was not JCS");
    parse_strict_json(plaintext).map_err(|error| anyhow::anyhow!("result decode: {error}"))
}

async fn verify_operation_proof(
    context: &HostContext,
    info: &ServiceInfoV1,
    request: &OperationRequestV1,
    response: &EncryptedResponseV1,
) -> Result<()> {
    verify_tvc_app_proof(context, info, &response.tvc_app_proof).await?;
    let payload: TvcOperationProofPayloadV1 =
        parse_strict_json(&response.tvc_app_proof.proof_payload)?;
    ensure!(
        payload.request_id == request.request_id,
        "proof request ID mismatch"
    );
    ensure!(
        payload.request_digest == request_digest(request)?,
        "request digest mismatch"
    );
    ensure!(
        payload.result_digest == result_digest(&response.encrypted_result),
        "result digest mismatch"
    );
    ensure!(
        payload.operation == request.operation.kind(),
        "operation mismatch"
    );
    Ok(())
}

async fn verify_tvc_app_proof(
    context: &HostContext,
    info: &ServiceInfoV1,
    proof: &TvcAppProofV1,
) -> Result<BootProof> {
    ensure!(
        proof.scheme == TVC_APP_PROOF_SCHEME,
        "wrong TVC proof scheme"
    );
    ensure!(
        is_rfc8785(&proof.proof_payload),
        "TVC proof payload was not JCS"
    );
    let public = QosP256Public::from_bytes(&proof.public_key)?;
    verify_p256_message(
        &public.signing,
        proof.proof_payload.as_bytes(),
        &proof.signature,
    )?;
    let app_proof = AppProof {
        scheme: SignatureScheme::from_str_name(&proof.scheme)
            .context("unknown TVC proof scheme")?,
        public_key: hex::encode(&proof.public_key),
        proof_payload: proof.proof_payload.clone(),
        signature: hex::encode(&proof.signature),
    };
    let boot_proof = verify_official(context, &app_proof).await?;
    ensure!(
        boot_proof_manifest_digest(&boot_proof)? == info.manifest_digest,
        "TVC Boot Proof manifest mismatch"
    );
    Ok(boot_proof)
}

async fn verify_turnkey_app_proofs(
    context: &HostContext,
    proofs: &[TurnkeyVerifiedAppProofV1],
) -> Result<()> {
    ensure!(!proofs.is_empty(), "Turnkey returned no App Proofs");
    for proof in proofs {
        let app_proof = AppProof {
            scheme: SignatureScheme::from_str_name(&proof.scheme)
                .context("unknown Turnkey proof scheme")?,
            public_key: proof.public_key.clone(),
            proof_payload: proof.proof_payload.clone(),
            signature: proof.signature.clone(),
        };
        let _boot_proof = verify_official(context, &app_proof).await?;
    }
    Ok(())
}

async fn verify_created_wallet(
    context: &HostContext,
    wallet_id: &str,
    wallet_name: &str,
    solana_address: &str,
) -> Result<String> {
    let wallet = context
        .turnkey
        .get_wallet(GetWalletRequest {
            organization_id: ORGANIZATION_ID.to_owned(),
            wallet_id: wallet_id.to_owned(),
        })
        .await?
        .wallet
        .context("created Turnkey wallet was not found")?;
    ensure!(wallet.wallet_id == wallet_id, "created wallet ID mismatch");
    ensure!(
        wallet.wallet_name == wallet_name,
        "created wallet name mismatch"
    );
    ensure!(!wallet.exported, "created wallet was unexpectedly exported");
    ensure!(!wallet.imported, "created wallet was unexpectedly imported");

    let accounts = context
        .turnkey
        .get_wallet_accounts(GetWalletAccountsRequest {
            organization_id: ORGANIZATION_ID.to_owned(),
            wallet_id: Some(wallet_id.to_owned()),
            include_wallet_details: Some(false),
            pagination_options: None,
        })
        .await?
        .accounts;
    ensure!(accounts.len() == 1, "expected one created wallet account");
    let account = &accounts[0];
    ensure!(account.wallet_id == wallet_id, "wallet account ID mismatch");
    ensure!(
        account.organization_id == ORGANIZATION_ID,
        "wallet account organization mismatch"
    );
    ensure!(account.curve == Curve::Ed25519, "wallet curve mismatch");
    ensure!(
        account.path_format == PathFormat::Bip32,
        "wallet path format mismatch"
    );
    ensure!(
        account.path == TURNKEY_DERIVATION_PATH,
        "wallet path mismatch"
    );
    ensure!(
        account.address_format == AddressFormat::Solana,
        "wallet address format mismatch"
    );
    ensure!(account.address == solana_address, "wallet address mismatch");
    Ok(account.wallet_account_id.clone())
}

async fn verify_official(context: &HostContext, app_proof: &AppProof) -> Result<BootProof> {
    let boot_proof =
        get_boot_proof_for_app_proof(&context.turnkey, ORGANIZATION_ID.to_owned(), app_proof)
            .await?
            .boot_proof
            .context("Boot Proof was not found")?;
    verify(app_proof, &boot_proof)
        .map_err(|error| anyhow::anyhow!("official proof verification failed: {error}"))?;
    Ok(boot_proof)
}

fn boot_proof_manifest_digest(boot_proof: &BootProof) -> Result<[u8; 32]> {
    let bytes = STANDARD
        .decode(&boot_proof.qos_manifest_b64)
        .context("invalid Boot Proof QOS manifest base64")?;
    let manifest = VersionedManifest::try_from_slice_compat(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid Boot Proof QOS manifest: {error}"))?;
    Ok(manifest.manifest_hash())
}

fn print_qos_identity_pcrs(boot_proof: &BootProof) -> Result<()> {
    let bytes = STANDARD
        .decode(&boot_proof.aws_attestation_doc_b64)
        .context("invalid Boot Proof attestation base64")?;
    let attestation = unsafe_attestation_doc_from_der(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid Boot Proof attestation: {error}"))?;
    for index in 0..=3 {
        let pcr = attestation
            .pcrs
            .get(&index)
            .with_context(|| format!("Boot Proof PCR{index} missing"))?;
        println!("qos_pcr{index}={}", hex::encode(pcr));
    }
    Ok(())
}

fn write_boot_proof(path: &PathBuf, boot_proof: &BootProof) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    let bytes = serde_json::to_vec(boot_proof)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    println!("boot_proof_output={}", path.display());
    Ok(())
}

async fn rpc_call<T: DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    method: &str,
    params: Value,
) -> Result<T> {
    let response: Value = http
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await?
        .json()
        .await?;
    if let Some(error) = response.get("error") {
        bail!("RPC {method} failed: {error}");
    }
    serde_json::from_value(
        response
            .get("result")
            .cloned()
            .context("RPC result missing")?,
    )
    .context("RPC result decode")
}

async fn latest_blockhash(http: &reqwest::Client, rpc_url: &str) -> Result<[u8; 32]> {
    let result: Value = rpc_call(
        http,
        rpc_url,
        "getLatestBlockhash",
        json!([{"commitment":"confirmed"}]),
    )
    .await?;
    let encoded = result
        .get("value")
        .and_then(|value| value.get("blockhash"))
        .and_then(Value::as_str)
        .context("latest blockhash missing")?;
    bs58::decode(encoded)
        .into_vec()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("latest blockhash was not 32 bytes"))
}

async fn send_transaction(http: &reqwest::Client, rpc_url: &str, wire: &[u8]) -> Result<String> {
    rpc_call(
        http,
        rpc_url,
        "sendTransaction",
        json!([
            STANDARD.encode(wire),
            {
                "encoding": "base64",
                "skipPreflight": false,
                "preflightCommitment": "confirmed",
                "maxRetries": 3
            }
        ]),
    )
    .await
}

async fn wait_for_finalization(
    http: &reqwest::Client,
    rpc_url: &str,
    signature: &str,
) -> Result<u64> {
    for _ in 0..120 {
        if let Some(slot) = finalized_slot(http, rpc_url, signature).await? {
            return Ok(slot);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    bail!("transaction did not confirm")
}

async fn finalized_slot(
    http: &reqwest::Client,
    rpc_url: &str,
    signature: &str,
) -> Result<Option<u64>> {
    let statuses: Value = rpc_call(
        http,
        rpc_url,
        "getSignatureStatuses",
        json!([[signature], {"searchTransactionHistory": true}]),
    )
    .await?;
    let Some(status) = statuses
        .get("value")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
        .filter(|status| !status.is_null())
    else {
        return Ok(None);
    };
    ensure!(
        status.get("err").is_none_or(Value::is_null),
        "transaction failed: {status}"
    );
    let is_finalized = status
        .get("confirmationStatus")
        .and_then(Value::as_str)
        .is_some_and(|value| value == "finalized")
        || (status.get("confirmationStatus").is_none()
            && status.get("confirmations").is_some_and(Value::is_null));
    if !is_finalized {
        return Ok(None);
    }
    Ok(Some(
        status
            .get("slot")
            .and_then(Value::as_u64)
            .context("confirmed status has no slot")?,
    ))
}

fn random32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
