//! Disposable Turnkey HD-wallet -> default-ring shielded self-transfer.
//!
//! This is an operator acceptance harness, not a public wallet API. It is
//! deliberately gated by an acknowledgement and environment-provided wallet
//! identifiers. The API private key is read from a local file and is never
//! printed or copied into the enclave image.

use std::{env, fs, sync::Arc, time::Duration};

use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;
use turnkey_client::generated::{
    immutable::{activity::v1::SignTransactionIntentV2, common::v1::TransactionType},
    services::coordinator::public::v1::{GetWalletAccountRequest, GetWalletRequest},
};
use turnkey_client::{TurnkeyClient, TurnkeyP256ApiKey};
use zolana_client::{AsyncRpc, AsyncSolanaRpc, ZolanaClient};
use zolana_keypair::ShieldedKeypairTrait;
use zolana_keypair_turnkey::{TurnkeyApiActivities, TurnkeyEd25519ShieldedKeypair, TurnkeyKeyRef};
use zolana_transaction::{AssetRegistry, Wallet, SOL_MINT};
use zolana_wallet::{
    build_private_transaction, build_registration_transaction, create_deposit, create_transfer,
    sync_wallet_async, DepositParams, KeypairWalletAuthority, TransferParams,
};

const ACK: &str = "I_UNDERSTAND_THIS_SPENDS_DEVNET_FUNDS";
const DEFAULT_RPC_URL: &str = "https://api.devnet.solana.com";
const DEFAULT_PHOTON_URL: &str = "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com";
const DEFAULT_PROVER_URL: &str =
    "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com:3001";
const DEFAULT_TREE: &str = "trEEbaNobcTESNmtsPBj3FX27q5sDCQePV2kb12FYho";
const DEPOSIT_LAMPORTS: u64 = 200_000_000;
const TRANSFER_LAMPORTS: u64 = 50_000_000;

#[derive(Deserialize)]
struct StoredApiKey {
    private_key: String,
    public_key: String,
}

struct Config {
    organization_id: String,
    wallet_id: String,
    address: String,
    api_key_path: String,
    rpc_url: String,
    photon_url: String,
    prover_url: String,
    tree: String,
    bootstrap_activity_id: Option<String>,
    build_only: bool,
}

impl Config {
    fn from_env() -> Result<Self> {
        ensure!(
            env::var("ZOLANA_TVC_E2E_ACK").as_deref() == Ok(ACK),
            "set ZOLANA_TVC_E2E_ACK={ACK}"
        );
        Ok(Self {
            organization_id: required("TURNKEY_E2E_ORGANIZATION_ID")?,
            wallet_id: required("TURNKEY_E2E_WALLET_ID")?,
            address: required("TURNKEY_E2E_SOLANA_ADDRESS")?,
            api_key_path: required("TURNKEY_E2E_API_KEY_PATH")?,
            rpc_url: optional("ZOLANA_E2E_RPC_URL", DEFAULT_RPC_URL),
            photon_url: optional("ZOLANA_E2E_PHOTON_URL", DEFAULT_PHOTON_URL),
            prover_url: optional("ZOLANA_E2E_PROVER_URL", DEFAULT_PROVER_URL),
            tree: optional("ZOLANA_E2E_TREE", DEFAULT_TREE),
            bootstrap_activity_id: env::var("ZOLANA_TVC_BOOTSTRAP_ACTIVITY_ID").ok(),
            build_only: env::var("ZOLANA_TVC_E2E_BUILD_ONLY").as_deref() == Ok("1"),
        })
    }
}

fn required(name: &'static str) -> Result<String> {
    env::var(name).with_context(|| format!("missing {name}"))
}

fn optional(name: &'static str, default: &'static str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

type TkClient = TurnkeyClient<TurnkeyP256ApiKey>;

fn load_turnkey_client(config: &Config) -> Result<Arc<TkClient>> {
    let stored: StoredApiKey = serde_json::from_str(&fs::read_to_string(&config.api_key_path)?)?;
    let api_key = TurnkeyP256ApiKey::from_strings(&stored.private_key, Some(&stored.public_key))?;
    Ok(Arc::new(
        TurnkeyClient::builder()
            .api_key(api_key)
            .build()?
            .with_app_proofs(),
    ))
}

async fn turnkey_sign_transaction(
    client: &TkClient,
    config: &Config,
    unsigned: Transaction,
) -> Result<(Transaction, String)> {
    ensure!(
        unsigned.signatures.len() == 1,
        "expected exactly one signature slot"
    );
    ensure!(
        unsigned.signatures[0] == Signature::default(),
        "unsigned slot was not zeroed"
    );
    let signed = client
        .sign_transaction(
            config.organization_id.clone(),
            client.current_timestamp(),
            SignTransactionIntentV2 {
                sign_with: config.address.clone(),
                unsigned_transaction: hex::encode(bincode1::serialize(&unsigned)?),
                r#type: TransactionType::Solana,
            },
        )
        .await?;
    ensure!(
        !signed.app_proofs.is_empty(),
        "Turnkey returned no App Proofs"
    );
    let transaction: Transaction =
        bincode1::deserialize(&hex::decode(&signed.result.signed_transaction)?)?;
    ensure!(
        transaction.message == unsigned.message,
        "Turnkey changed the Solana message"
    );
    ensure!(
        transaction.signatures.len() == 1,
        "Turnkey changed signature slots"
    );
    ensure!(
        transaction.signatures[0] != Signature::default(),
        "Turnkey returned a zero signature"
    );
    let owner = config.address.parse::<Pubkey>()?;
    ensure!(
        transaction.signatures[0].verify(owner.as_ref(), &transaction.message_data()),
        "Turnkey signature does not verify"
    );
    Ok((transaction, signed.activity_id))
}

async fn wait_for_slot(client: &ZolanaClient<AsyncSolanaRpc>, signature: Signature) -> Result<u64> {
    for _ in 0..120 {
        if let Some(status) = AsyncRpc::get_signature_statuses(client, vec![signature])
            .await?
            .into_iter()
            .next()
            .flatten()
        {
            if let Some(error) = status.err {
                bail!("transaction {signature} failed: {error:?}");
            }
            return Ok(status.slot);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    bail!("transaction {signature} did not confirm")
}

async fn sign_send(
    client: &ZolanaClient<AsyncSolanaRpc>,
    turnkey: &TkClient,
    config: &Config,
    unsigned: Transaction,
    label: &str,
) -> Result<(Signature, u64)> {
    let (signed, activity_id) = turnkey_sign_transaction(turnkey, config, unsigned).await?;
    let signature = AsyncRpc::send_transaction(client, &signed).await?;
    let slot = wait_for_slot(client, signature).await?;
    println!("{label}_activity_id={activity_id}");
    println!("{label}_signature={signature}");
    println!("{label}_slot={slot}");
    Ok((signature, slot))
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;
    let turnkey = load_turnkey_client(&config)?;
    let wallet = turnkey
        .get_wallet(GetWalletRequest {
            organization_id: config.organization_id.clone(),
            wallet_id: config.wallet_id.clone(),
        })
        .await?
        .wallet
        .context("wallet missing")?;
    let account = turnkey
        .get_wallet_account(GetWalletAccountRequest {
            organization_id: config.organization_id.clone(),
            wallet_id: config.wallet_id.clone(),
            address: Some(config.address.clone()),
            path: None,
        })
        .await?
        .account
        .context("wallet account missing")?;
    ensure!(wallet.wallet_id == config.wallet_id, "wrong wallet");
    ensure!(
        account.organization_id == config.organization_id,
        "wrong organization"
    );
    ensure!(account.address == config.address, "wrong wallet address");
    let public_key: [u8; 32] = hex::decode(account.public_key.context("missing public key")?)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong Ed25519 public key length"))?;
    ensure!(
        bs58::encode(public_key).into_string() == config.address,
        "public key/address mismatch"
    );

    let activities = Arc::new(TurnkeyApiActivities::new(Arc::clone(&turnkey)));
    let key_ref = TurnkeyKeyRef::new(&config.organization_id, &config.address);
    let keypair = if let Some(activity_id) = &config.bootstrap_activity_id {
        TurnkeyEd25519ShieldedKeypair::resume_bootstrap_with_pubkey(
            activities,
            key_ref,
            public_key,
            activity_id,
        )
        .await
        .context("resume Turnkey shielded bootstrap")?
    } else {
        TurnkeyEd25519ShieldedKeypair::bootstrap_with_pubkey(activities, key_ref, public_key)
            .await
            .context("Turnkey shielded bootstrap")?
    };
    let owner = config.address.parse::<Pubkey>()?;
    ensure!(
        keypair.solana_address().to_string() == config.address,
        "bootstrap owner mismatch"
    );
    let shielded_address = keypair.shielded_address()?;
    println!("turnkey_wallet_id={}", config.wallet_id);
    println!("turnkey_address={}", config.address);
    println!(
        "shielded_owner_hash={}",
        hex::encode(shielded_address.owner_hash()?)
    );

    let tree = config.tree.parse::<Pubkey>()?;
    let client = ZolanaClient::from_urls_allowing_insecure_http(
        AsyncSolanaRpc::new(config.rpc_url.clone()),
        &config.photon_url,
        config.prover_url.clone(),
        Address::new_from_array(tree.to_bytes()),
    );
    if let Some(registration) =
        build_registration_transaction(&client, owner, &shielded_address, None).await?
    {
        sign_send(&client, &turnkey, &config, registration, "registration").await?;
    } else {
        println!("registration=already_current");
    }

    let authority = KeypairWalletAuthority::with_viewing_keys(
        Address::new_from_array(owner.to_bytes()),
        &keypair,
        vec![keypair.viewing_key().clone()],
    )?;
    let mut private_wallet = Wallet::new(shielded_address, AssetRegistry::default())?;
    let initial_report = sync_wallet_async(&mut private_wallet, &authority, &client).await?;
    let mut before = private_wallet.balance(SOL_MINT, None)?.amount;
    if before < DEPOSIT_LAMPORTS {
        ensure!(
            !config.build_only,
            "build-only identity has insufficient shielded balance: {before}"
        );
        let public_balance =
            AsyncRpc::get_balance(&client, Address::new_from_array(owner.to_bytes())).await?;
        ensure!(
            public_balance > DEPOSIT_LAMPORTS + 20_000_000,
            "fund the disposable address on devnet first"
        );
        let deposit = create_deposit(DepositParams {
            recipient: &shielded_address,
            asset: SOL_MINT,
            amount: DEPOSIT_LAMPORTS,
            spl_token_account: None,
            spl_token_program: None,
            memo: Some(b"zolana-tvc-dev-e2e".to_vec()),
        })?;
        let deposit_tx = deposit
            .build_transaction(&client, owner, tree, owner)
            .await?;
        let (_, deposit_slot) =
            sign_send(&client, &turnkey, &config, deposit_tx, "deposit").await?;
        let deposit_report = sync_wallet_async(&mut private_wallet, &authority, &client).await?;
        before = private_wallet.balance(SOL_MINT, None)?.amount;
        ensure!(
            before >= DEPOSIT_LAMPORTS,
            "deposit not indexed: balance {before}, slot {deposit_slot}, report {deposit_report:?}"
        );
    } else {
        println!("deposit=already_indexed");
    }
    println!("initial_sync_report={initial_report:?}");
    println!("shielded_balance_before={before}");

    let created = create_transfer(TransferParams {
        rpc: &client,
        wallet: &private_wallet,
        payer: Address::new_from_array(owner.to_bytes()),
        recipient: owner,
        asset: SOL_MINT,
        amount: TRANSFER_LAMPORTS,
    })
    .await?;
    let unsigned = build_private_transaction(
        created.transaction,
        &private_wallet,
        &authority,
        &client,
        owner,
    )
    .await?;
    if config.build_only {
        println!(
            "unsigned_transaction_bytes={}",
            bincode1::serialized_size(&unsigned)?
        );
        println!("build_only=passed");
        return Ok(());
    }
    let (transfer_signature, _) =
        sign_send(&client, &turnkey, &config, unsigned, "shielded_transfer").await?;
    client
        .confirm_private_transaction(transfer_signature)
        .await?;

    let report = sync_wallet_async(&mut private_wallet, &authority, &client).await?;
    let after = private_wallet.balance(SOL_MINT, None)?.amount;
    ensure!(
        after == before,
        "self transfer changed shielded balance: before={before}, after={after}"
    );
    println!("shielded_balance_after={after}");
    println!("final_sync_report={report:?}");
    println!("e2e=passed");
    Ok(())
}
