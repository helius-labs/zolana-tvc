//! Host-side verifier for Turnkey App Proof / Boot Proof pairs.
//!
//! This deliberately lives in a standalone workspace because the official
//! `turnkey_proofs` QOS graph is incompatible with the current Solana RPC
//! dependency graph. It is a relying-party tool and is never linked into the
//! TVC enclave that emits an App Proof.

use std::{fs, path::PathBuf};

use anyhow::{Context as _, Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use turnkey_client::generated::immutable::common::v1::{AddressFormat, Curve, PathFormat};
use turnkey_client::generated::services::coordinator::public::v1::{
    GetAppProofsRequest, GetBootProofRequest, GetWalletAccountsRequest, GetWalletRequest,
};
use turnkey_client::{TurnkeyClient, TurnkeyP256ApiKey};
use turnkey_proofs::{get_boot_proof_for_app_proof, verify};
use zolana_interface::{SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE};
use zolana_user_registry_interface::{user_record_pda, user_registry_program_id};

#[derive(Debug, Parser)]
#[command(name = "zolana-tvc-proof-verifier")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Query every App Proof for an activity, fetch its Boot Proof, and verify
    /// the complete official Turnkey proof chain.
    Activity {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        activity_id: String,
        #[arg(long)]
        api_key_path: PathBuf,
    },
    /// Fetch the raw public Boot Proof for one Ephemeral key. Verification is
    /// performed by the relying-party client that requested it.
    BootProof {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        ephemeral_key: String,
        #[arg(long)]
        api_key_path: PathBuf,
    },
    /// Re-query and validate the exact disposable Solana HD wallet account
    /// before a development descriptor is provisioned for it.
    WalletAccount {
        #[arg(long, value_enum, default_value_t = WalletAccountProfile::TvcCreated)]
        profile: WalletAccountProfile,
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        wallet_id: String,
        #[arg(long)]
        wallet_name: String,
        #[arg(long)]
        wallet_account_id: String,
        #[arg(long)]
        solana_address: String,
        #[arg(long)]
        api_key_path: PathBuf,
    },
    /// Read the public name of an existing non-exported wallet so an interrupted
    /// development provisioning run can resume without creating another wallet.
    InspectWallet {
        #[arg(long)]
        organization_id: String,
        #[arg(long)]
        wallet_id: String,
        #[arg(long)]
        api_key_path: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum WalletAccountProfile {
    TvcCreated,
    EmbeddedWallet,
}

#[derive(Deserialize)]
struct StoredApiKey {
    private_key: String,
    public_key: String,
}

#[derive(Serialize)]
struct VerifiedWalletAccount {
    version: u8,
    organization_id: String,
    wallet_id: String,
    wallet_name: String,
    wallet_account_id: String,
    solana_address: String,
    derivation_path: String,
    expected_ed25519_public_key: String,
    user_record: String,
    sol_interface: String,
    user_registry_program: String,
    shielded_program: String,
}

#[derive(Serialize)]
struct InspectedWallet {
    version: u8,
    organization_id: String,
    wallet_id: String,
    wallet_name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cli { command } = Cli::parse();
    match command {
        Command::Activity {
            organization_id,
            activity_id,
            api_key_path,
        } => verify_activity(organization_id, activity_id, api_key_path).await,
        Command::BootProof {
            organization_id,
            ephemeral_key,
            api_key_path,
        } => fetch_boot_proof(organization_id, ephemeral_key, api_key_path).await,
        Command::WalletAccount {
            profile,
            organization_id,
            wallet_id,
            wallet_name,
            wallet_account_id,
            solana_address,
            api_key_path,
        } => {
            verify_wallet_account(
                profile,
                organization_id,
                wallet_id,
                wallet_name,
                wallet_account_id,
                solana_address,
                api_key_path,
            )
            .await
        }
        Command::InspectWallet {
            organization_id,
            wallet_id,
            api_key_path,
        } => inspect_wallet(organization_id, wallet_id, api_key_path).await,
    }
}

async fn inspect_wallet(
    organization_id: String,
    wallet_id: String,
    api_key_path: PathBuf,
) -> Result<()> {
    let client = load_client(&api_key_path)?;
    let wallet = client
        .get_wallet(GetWalletRequest {
            organization_id: organization_id.clone(),
            wallet_id: wallet_id.clone(),
        })
        .await?
        .wallet
        .context("Turnkey wallet was not found")?;
    ensure!(wallet.wallet_id == wallet_id, "Turnkey wallet id mismatch");
    ensure!(!wallet.exported, "exported wallets are not accepted");
    ensure!(!wallet.imported, "imported wallets are not accepted");
    ensure!(
        tvc_wallet_name_suffix(&wallet.wallet_name).is_some(),
        "wallet name does not match the TVC request-bound profile"
    );
    println!(
        "{}",
        serde_json::to_string(&InspectedWallet {
            version: 1,
            organization_id,
            wallet_id,
            wallet_name: wallet.wallet_name,
        })?
    );
    Ok(())
}

fn load_client(api_key_path: &PathBuf) -> Result<TurnkeyClient<TurnkeyP256ApiKey>> {
    let stored: StoredApiKey = serde_json::from_slice(
        &fs::read(api_key_path)
            .with_context(|| format!("failed to read {}", api_key_path.display()))?,
    )?;
    let api_key = TurnkeyP256ApiKey::from_strings(&stored.private_key, Some(&stored.public_key))?;
    TurnkeyClient::builder()
        .api_key(api_key)
        .build()
        .map_err(Into::into)
}

fn is_lower_hex_exact(value: &str, byte_len: usize) -> bool {
    hex::decode(value)
        .is_ok_and(|decoded| decoded.len() == byte_len && hex::encode(decoded) == value)
}

fn tvc_wallet_name_suffix(wallet_name: &str) -> Option<&str> {
    wallet_name
        .strip_prefix("zolana-tvc-")
        .filter(|suffix| is_lower_hex_exact(suffix, 8))
}

async fn fetch_boot_proof(
    organization_id: String,
    ephemeral_key: String,
    api_key_path: PathBuf,
) -> Result<()> {
    ensure!(
        is_lower_hex_exact(&ephemeral_key, 130),
        "Ephemeral key must be 130-byte lowercase hex"
    );
    let client = load_client(&api_key_path)?;
    let response = client
        .get_boot_proof(GetBootProofRequest {
            organization_id,
            ephemeral_key,
        })
        .await?;
    let boot_proof = response.boot_proof.context("Boot Proof was not found")?;
    println!("{}", serde_json::to_string(&boot_proof)?);
    Ok(())
}

async fn verify_activity(
    organization_id: String,
    activity_id: String,
    api_key_path: PathBuf,
) -> Result<()> {
    let client = load_client(&api_key_path)?;
    let response = client
        .get_app_proofs(GetAppProofsRequest {
            organization_id: organization_id.clone(),
            activity_id: activity_id.clone(),
        })
        .await?;
    ensure!(
        !response.app_proofs.is_empty(),
        "activity returned no App Proofs"
    );

    for app_proof in &response.app_proofs {
        let boot_proof = get_boot_proof_for_app_proof(&client, organization_id.clone(), app_proof)
            .await?
            .boot_proof
            .context("Boot Proof was not found")?;
        verify(app_proof, &boot_proof)
            .map_err(|error| anyhow::anyhow!("official proof verification failed: {error}"))?;
    }

    println!("activity_id={activity_id}");
    println!("verified_app_proofs={}", response.app_proofs.len());
    println!("boot_proof_verification=passed");
    Ok(())
}

async fn verify_wallet_account(
    profile: WalletAccountProfile,
    organization_id: String,
    wallet_id: String,
    wallet_name: String,
    wallet_account_id: String,
    solana_address: String,
    api_key_path: PathBuf,
) -> Result<()> {
    const DERIVATION_PATH: &str = "m/44'/501'/0'/0'";

    let client = load_client(&api_key_path)?;
    let wallet = client
        .get_wallet(GetWalletRequest {
            organization_id: organization_id.clone(),
            wallet_id: wallet_id.clone(),
        })
        .await?
        .wallet
        .context("Turnkey wallet was not found")?;
    ensure!(wallet.wallet_id == wallet_id, "Turnkey wallet id mismatch");
    ensure!(
        wallet.wallet_name == wallet_name,
        "Turnkey wallet name mismatch"
    );
    let wallet_name_suffix = match profile {
        WalletAccountProfile::TvcCreated => Some(
            tvc_wallet_name_suffix(&wallet_name)
                .context("wallet name does not match the TVC request-bound profile")?,
        ),
        WalletAccountProfile::EmbeddedWallet => {
            ensure!(
                wallet_name == "Solana Wallet",
                "wallet name does not match the embedded-wallet profile"
            );
            None
        }
    };
    ensure!(!wallet.exported, "exported wallets are not accepted");
    ensure!(!wallet.imported, "imported wallets are not accepted");

    let accounts = client
        .get_wallet_accounts(GetWalletAccountsRequest {
            organization_id: organization_id.clone(),
            wallet_id: Some(wallet_id.clone()),
            include_wallet_details: Some(false),
            pagination_options: None,
        })
        .await?
        .accounts;
    ensure!(accounts.len() == 1, "wallet must have exactly one account");
    let account = &accounts[0];
    ensure!(
        account.wallet_account_id == wallet_account_id,
        "Turnkey wallet account id mismatch"
    );
    ensure!(
        account.organization_id == organization_id,
        "Turnkey account organization mismatch"
    );
    ensure!(
        account.wallet_id == wallet_id,
        "Turnkey account wallet mismatch"
    );
    ensure!(
        account.curve == Curve::Ed25519,
        "account curve must be Ed25519"
    );
    ensure!(
        account.path_format == PathFormat::Bip32,
        "account path format must be BIP32"
    );
    ensure!(account.path == DERIVATION_PATH, "account path mismatch");
    ensure!(
        account.address_format == AddressFormat::Solana,
        "account address format must be Solana"
    );
    ensure!(account.address == solana_address, "Solana address mismatch");
    if let Some(wallet_name_suffix) = wallet_name_suffix {
        ensure!(
            account.name.as_deref() == Some(format!("solana-tvc-{wallet_name_suffix}").as_str()),
            "account name mismatch"
        );
    }

    let owner: solana_pubkey::Pubkey = solana_address.parse().context("invalid Solana address")?;
    let decoded_address = owner.to_bytes();
    let public_key = account
        .public_key
        .as_deref()
        .context("Turnkey account omitted its public key")?;
    let public_key = hex::decode(public_key.strip_prefix("0x").unwrap_or(public_key))
        .context("invalid Turnkey account public key")?;
    ensure!(
        public_key.as_slice() == decoded_address,
        "Turnkey public key does not match the Solana address"
    );

    println!(
        "{}",
        serde_json::to_string(&VerifiedWalletAccount {
            version: 1,
            organization_id,
            wallet_id,
            wallet_name,
            wallet_account_id,
            solana_address,
            derivation_path: DERIVATION_PATH.to_owned(),
            expected_ed25519_public_key: hex::encode(public_key),
            user_record: user_record_pda(&owner).0.to_string(),
            sol_interface: solana_pubkey::Pubkey::new_from_array(SOL_INTERFACE).to_string(),
            user_registry_program: user_registry_program_id().to_string(),
            shielded_program: solana_pubkey::Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID)
                .to_string(),
        })?
    );
    Ok(())
}
