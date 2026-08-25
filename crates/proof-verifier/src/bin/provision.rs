//! One-wallet development provisioning for the TVC Quorum API credential.

use std::{fs, path::PathBuf, str::FromStr};

use anyhow::{Context as _, Result, ensure};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use turnkey_client::generated::external::options::v1::Pagination;
use turnkey_client::generated::immutable::{
    activity::v1::{
        ActivityType, ApiKeyParamsV2, CreatePoliciesIntent, CreatePolicyIntentV3,
        CreateUsersIntentV4, UserParamsV4,
    },
    common::v1::{ApiKeyCurve, Effect, FeatureName},
};
use turnkey_client::generated::services::coordinator::public::v1::{
    GetActivitiesRequest, GetOrganizationConfigsRequest, GetPoliciesRequest,
    GetTvcAppDeploymentsRequest, GetUserRequest, GetUsersRequest,
};
use turnkey_client::{TurnkeyClient, TurnkeyP256ApiKey};

const CREATE_WALLET_POLICY_NAME: &str = "zolana-tvc-dev-create-wallet";
const CREATE_WALLET_POLICY_CONDITION: &str = "activity.type == 'ACTIVITY_TYPE_CREATE_WALLET'";
const BOOTSTRAP_POLICY_NAME: &str = "zolana-tvc-dev-bootstrap-0690e9e7";
const TRANSFER_POLICY_NAME: &str = "zolana-tvc-dev-default-ring-0690e9e7";
const REGISTRATION_POLICY_NAME: &str = "zolana-tvc-dev-registration-0690e9e7";
const DEPOSIT_POLICY_NAME: &str = "zolana-tvc-dev-deposit-0690e9e7";
const WALLET_AUTHORITY_USER_NAME: &str = "zolana-tvc-wallet-authority";
const WALLET_AUTHORITY_API_KEY_NAME: &str = "zolana-tvc-wallet-quorum-key";

#[derive(Debug, Parser)]
#[command(name = "zolana-tvc-provision")]
struct Cli {
    #[arg(long)]
    organization_id: String,
    #[arg(long)]
    api_key_path: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    InspectUser {
        #[arg(long)]
        user_id: String,
    },
    ListDeployments {
        #[arg(long)]
        app_id: String,
    },
    /// Print recent create-wallet activity status and public failure messages.
    RecentCreateWalletActivities {
        #[arg(long, default_value_t = 20)]
        limit: u16,
    },
    /// Print only whether Auth Proxy is enabled and its signer user ID.
    /// The Wallet Kit config ID is returned by the dashboard separately.
    InspectAuthProxy,
    CreateUser {
        #[arg(long)]
        compressed_public_key: String,
    },
    /// Idempotently bind the TVC Quorum signing key to one wallet organization.
    EnsureWalletAuthority {
        #[arg(long)]
        compressed_public_key: CompressedP256PublicKey,
    },
    CreatePolicies {
        #[arg(long)]
        user_id: String,
        #[arg(long)]
        wallet_address: String,
        #[arg(long)]
        default_tree: String,
        #[arg(long)]
        shielded_program: String,
    },
    CreateSetupPolicies {
        #[arg(long)]
        user_id: String,
        #[arg(long)]
        wallet_address: String,
        #[arg(long)]
        user_record: String,
        #[arg(long)]
        default_tree: String,
        #[arg(long)]
        sol_interface: String,
        #[arg(long)]
        user_registry_program: String,
        #[arg(long)]
        shielded_program: String,
    },
    /// Idempotently install the five exact signing policies for one newly
    /// verified wallet account before its descriptor is provisioned.
    EnsureWalletPolicies {
        #[arg(long)]
        user_id: String,
        #[arg(long)]
        wallet_address: String,
        #[arg(long)]
        user_record: String,
        #[arg(long)]
        default_tree: String,
        #[arg(long)]
        sol_interface: String,
        #[arg(long)]
        user_registry_program: String,
        #[arg(long)]
        shielded_program: String,
    },
    EnsureCreateWalletPolicy {
        #[arg(long)]
        user_id: String,
    },
}

#[derive(Deserialize)]
struct StoredApiKey {
    private_key: String,
    public_key: String,
}

#[derive(Clone, Debug)]
struct CompressedP256PublicKey(String);

impl FromStr for CompressedP256PublicKey {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() == 66
            && (value.starts_with("02") || value.starts_with("03"))
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            Ok(Self(value.to_owned()))
        } else {
            Err("compressed public key must be 33-byte lowercase SEC1 hex".to_owned())
        }
    }
}

#[derive(Serialize)]
struct WalletAuthority {
    user_id: String,
    api_key_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let stored: StoredApiKey = serde_json::from_slice(
        &fs::read(&cli.api_key_path)
            .with_context(|| format!("failed to read {}", cli.api_key_path.display()))?,
    )?;
    let api_key = TurnkeyP256ApiKey::from_strings(&stored.private_key, Some(&stored.public_key))?;
    let client = TurnkeyClient::builder()
        .api_key(api_key)
        .build()?
        .with_app_proofs();

    match cli.command {
        Command::InspectAuthProxy => {
            let configs = client
                .get_organization_configs(GetOrganizationConfigsRequest {
                    organization_id: cli.organization_id,
                })
                .await?
                .configs
                .context("Turnkey organization configs were not returned")?;
            let auth_proxy = configs
                .features
                .into_iter()
                .find(|feature| feature.name == FeatureName::AuthProxy);
            match auth_proxy {
                Some(feature) => println!(
                    "auth_proxy_enabled=true turnkey_signer_user_id={}",
                    feature.value.as_deref().unwrap_or("missing")
                ),
                None => println!("auth_proxy_enabled=false turnkey_signer_user_id=missing"),
            }
        }
        Command::RecentCreateWalletActivities { limit } => {
            ensure!(
                (1..=100).contains(&limit),
                "limit must be between 1 and 100"
            );
            let activities = client
                .get_activities(GetActivitiesRequest {
                    organization_id: cli.organization_id,
                    filter_by_status: Vec::new(),
                    pagination_options: Some(Pagination {
                        limit: limit.to_string(),
                        before: String::new(),
                        after: String::new(),
                    }),
                    filter_by_type: vec![ActivityType::CreateWallet],
                })
                .await?
                .activities;
            for activity in activities {
                let created_at = activity
                    .created_at
                    .as_ref()
                    .map(|timestamp| timestamp.seconds.as_str())
                    .unwrap_or("unknown");
                let (failure_code, failure_message) = activity
                    .failure
                    .as_ref()
                    .map(|failure| (failure.code, failure.message.as_str()))
                    .unwrap_or((0, ""));
                println!(
                    "activity_id={} status={:?} created_at_seconds={} failure_code={} failure_message={}",
                    activity.id,
                    activity.status,
                    created_at,
                    failure_code,
                    failure_message.replace(['\n', '\r'], " ")
                );
            }
        }
        Command::ListDeployments { app_id } => {
            let deployments = client
                .get_tvc_app_deployments(GetTvcAppDeploymentsRequest {
                    organization_id: cli.organization_id,
                    app_id,
                })
                .await?
                .tvc_deployments;
            for deployment in deployments {
                let release_id = deployment
                    .pivot_container
                    .as_ref()
                    .and_then(|container| {
                        container
                            .args
                            .windows(2)
                            .find(|pair| pair[0] == "--release-id")
                            .map(|pair| pair[1].as_str())
                    })
                    .unwrap_or("unknown");
                println!(
                    "deployment_id={} release_id={} marked_for_deletion={}",
                    deployment.id, release_id, deployment.delete
                );
            }
        }
        Command::InspectUser { user_id } => {
            let user = client
                .get_user(GetUserRequest {
                    organization_id: cli.organization_id,
                    user_id,
                })
                .await?
                .user
                .context("Turnkey user was not found")?;
            ensure!(user.api_keys.len() == 1, "expected one API key");
            println!("turnkey_service_user_id={}", user.user_id);
            println!("turnkey_api_key_id={}", user.api_keys[0].api_key_id);
        }
        Command::CreateUser {
            compressed_public_key,
        } => {
            ensure!(
                compressed_public_key.len() == 66
                    && (compressed_public_key.starts_with("02")
                        || compressed_public_key.starts_with("03"))
                    && compressed_public_key
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                "compressed public key must be 33-byte lowercase SEC1 hex"
            );
            let result = client
                .create_users(
                    cli.organization_id,
                    client.current_timestamp(),
                    CreateUsersIntentV4 {
                        users: vec![UserParamsV4 {
                            user_name: "zolana-tvc-wallet-dev-e2e".to_owned(),
                            user_email: None,
                            user_phone_number: None,
                            api_keys: vec![ApiKeyParamsV2 {
                                api_key_name: "wallet-dev-e2e-quorum-signing-key".to_owned(),
                                public_key: compressed_public_key,
                                curve_type: ApiKeyCurve::P256,
                                expiration_seconds: None,
                            }],
                            authenticators: Vec::new(),
                            oauth_providers: Vec::new(),
                            user_tags: Vec::new(),
                        }],
                    },
                )
                .await?;
            ensure!(result.result.user_ids.len() == 1, "expected one user ID");
            println!("create_user_activity_id={}", result.activity_id);
            println!("turnkey_service_user_id={}", result.result.user_ids[0]);
        }
        Command::EnsureWalletAuthority {
            compressed_public_key,
        } => {
            let users = client
                .get_users(GetUsersRequest {
                    organization_id: cli.organization_id.clone(),
                })
                .await?
                .users;
            let matching_users = users
                .iter()
                .filter(|user| user.user_name == WALLET_AUTHORITY_USER_NAME)
                .collect::<Vec<_>>();
            ensure!(
                matching_users.len() <= 1,
                "wallet authority user name is ambiguous"
            );
            let user_id = if let Some(user) = matching_users.first() {
                user.user_id.clone()
            } else {
                let result = client
                    .create_users(
                        cli.organization_id.clone(),
                        client.current_timestamp(),
                        CreateUsersIntentV4 {
                            users: vec![UserParamsV4 {
                                user_name: WALLET_AUTHORITY_USER_NAME.to_owned(),
                                user_email: None,
                                user_phone_number: None,
                                api_keys: vec![ApiKeyParamsV2 {
                                    api_key_name: WALLET_AUTHORITY_API_KEY_NAME.to_owned(),
                                    public_key: compressed_public_key.0.clone(),
                                    curve_type: ApiKeyCurve::P256,
                                    expiration_seconds: None,
                                }],
                                authenticators: Vec::new(),
                                oauth_providers: Vec::new(),
                                user_tags: Vec::new(),
                            }],
                        },
                    )
                    .await?;
                ensure!(result.result.user_ids.len() == 1, "expected one user ID");
                result.result.user_ids[0].clone()
            };
            let user = client
                .get_user(GetUserRequest {
                    organization_id: cli.organization_id,
                    user_id: user_id.clone(),
                })
                .await?
                .user
                .context("Turnkey wallet authority user was not found")?;
            ensure!(
                user.user_name == WALLET_AUTHORITY_USER_NAME,
                "wallet authority user name mismatch"
            );
            ensure!(
                user.api_keys.len() == 1,
                "wallet authority must have exactly one API key"
            );
            let api_key = &user.api_keys[0];
            ensure!(
                api_key.api_key_name == WALLET_AUTHORITY_API_KEY_NAME,
                "wallet authority API key name mismatch"
            );
            let credential = api_key
                .credential
                .as_ref()
                .context("wallet authority API key omitted its credential")?;
            let public_key = credential
                .public_key
                .strip_prefix("0x")
                .unwrap_or(credential.public_key.as_str())
                .to_ascii_lowercase();
            ensure!(
                public_key == compressed_public_key.0,
                "wallet authority API key does not match the TVC Quorum key"
            );
            println!(
                "{}",
                serde_json::to_string(&WalletAuthority {
                    user_id,
                    api_key_id: api_key.api_key_id.clone(),
                })?
            );
        }
        Command::CreatePolicies {
            user_id,
            wallet_address,
            default_tree,
            shielded_program,
        } => {
            for value in [&user_id, &wallet_address, &default_tree, &shielded_program] {
                ensure!(
                    !value.is_empty()
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
                    "policy identifier contains unsupported characters"
                );
            }
            let consensus = format!("approvers.any(user, user.id == '{user_id}')");
            let raw_condition = format!(
                "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && wallet_account.address == '{wallet_address}'"
            );
            let transaction_condition = format!(
                "activity.type == 'ACTIVITY_TYPE_SIGN_TRANSACTION_V2' && wallet_account.address == '{wallet_address}' && solana.tx.instructions.count() == 2 && solana.tx.instructions[0].program_key == 'ComputeBudget111111111111111111111111111111' && solana.tx.instructions[1].program_key == '{shielded_program}' && solana.tx.address_table_lookups.count() == 0 && solana.tx.account_keys.count() == 5 && solana.tx.account_keys.all(key, key in ['{wallet_address}', '{default_tree}', '11111111111111111111111111111111', 'ComputeBudget111111111111111111111111111111', '{shielded_program}'])"
            );
            let result = client
                .create_policies(
                    cli.organization_id,
                    client.current_timestamp(),
                    CreatePoliciesIntent {
                        policies: vec![
                            CreatePolicyIntentV3 {
                                policy_name: BOOTSTRAP_POLICY_NAME.to_owned(),
                                effect: Effect::Allow,
                                condition: Some(raw_condition),
                                consensus: Some(consensus.clone()),
                                notes: "Disposable development TVC bootstrap only; revoke raw-sign after enrollment."
                                    .to_owned(),
                                time: None,
                            },
                            CreatePolicyIntentV3 {
                                policy_name: TRANSFER_POLICY_NAME.to_owned(),
                                effect: Effect::Allow,
                                condition: Some(transaction_condition),
                                consensus: Some(consensus),
                                notes: "Disposable devnet default-ring TVC transfer with an exact wallet, tree, and program set."
                                    .to_owned(),
                                time: None,
                            },
                        ],
                    },
                )
                .await?;
            ensure!(
                result.result.policy_ids.len() == 2,
                "expected two policy IDs"
            );
            println!("create_policies_activity_id={}", result.activity_id);
            println!("bootstrap_policy_id={}", result.result.policy_ids[0]);
            println!("transfer_policy_id={}", result.result.policy_ids[1]);
        }
        Command::CreateSetupPolicies {
            user_id,
            wallet_address,
            user_record,
            default_tree,
            sol_interface,
            user_registry_program,
            shielded_program,
        } => {
            for value in [
                &user_id,
                &wallet_address,
                &user_record,
                &default_tree,
                &sol_interface,
                &user_registry_program,
                &shielded_program,
            ] {
                ensure!(
                    !value.is_empty()
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
                    "policy identifier contains unsupported characters"
                );
            }
            let consensus = format!("approvers.any(user, user.id == '{user_id}')");
            let registration_condition = format!(
                "activity.type == 'ACTIVITY_TYPE_SIGN_TRANSACTION_V2' && wallet_account.address == '{wallet_address}' && solana.tx.instructions.count() == 1 && solana.tx.instructions[0].program_key == '{user_registry_program}' && solana.tx.address_table_lookups.count() == 0 && solana.tx.account_keys.count() == 4 && solana.tx.account_keys.all(key, key in ['{wallet_address}', '{user_record}', '11111111111111111111111111111111', '{user_registry_program}'])"
            );
            let deposit_condition = format!(
                "activity.type == 'ACTIVITY_TYPE_SIGN_TRANSACTION_V2' && wallet_account.address == '{wallet_address}' && solana.tx.instructions.count() == 1 && solana.tx.instructions[0].program_key == '{shielded_program}' && solana.tx.address_table_lookups.count() == 0 && solana.tx.account_keys.count() == 5 && solana.tx.account_keys.all(key, key in ['{wallet_address}', '{default_tree}', '11111111111111111111111111111111', '{sol_interface}', '{shielded_program}'])"
            );
            let result = client
                .create_policies(
                    cli.organization_id,
                    client.current_timestamp(),
                    CreatePoliciesIntent {
                        policies: vec![
                            CreatePolicyIntentV3 {
                                policy_name: REGISTRATION_POLICY_NAME.to_owned(),
                                effect: Effect::Allow,
                                condition: Some(registration_condition),
                                consensus: Some(consensus.clone()),
                                notes: "Disposable development TVC registration for one exact Ed25519 wallet and registry PDA."
                                    .to_owned(),
                                time: None,
                            },
                            CreatePolicyIntentV3 {
                                policy_name: DEPOSIT_POLICY_NAME.to_owned(),
                                effect: Effect::Allow,
                                condition: Some(deposit_condition),
                                consensus: Some(consensus),
                                notes: "Disposable development TVC fixed SOL deposit for one exact wallet, tree, and vault."
                                    .to_owned(),
                                time: None,
                            },
                        ],
                    },
                )
                .await?;
            ensure!(
                result.result.policy_ids.len() == 2,
                "expected two setup policy IDs"
            );
            println!("create_setup_policies_activity_id={}", result.activity_id);
            println!("registration_policy_id={}", result.result.policy_ids[0]);
            println!("deposit_policy_id={}", result.result.policy_ids[1]);
        }
        Command::EnsureWalletPolicies {
            user_id,
            wallet_address,
            user_record,
            default_tree,
            sol_interface,
            user_registry_program,
            shielded_program,
        } => {
            for value in [
                &user_id,
                &wallet_address,
                &user_record,
                &default_tree,
                &sol_interface,
                &user_registry_program,
                &shielded_program,
            ] {
                ensure!(
                    !value.is_empty()
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
                    "policy identifier contains unsupported characters"
                );
            }
            let suffix = &wallet_address[..wallet_address.len().min(12)];
            let consensus = format!("approvers.any(user, user.id == '{user_id}')");
            let expected = vec![
                CreatePolicyIntentV3 {
                    policy_name: format!("zolana-tvc-bootstrap-{suffix}"),
                    effect: Effect::Allow,
                    condition: Some(format!(
                        "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && wallet_account.address == '{wallet_address}'"
                    )),
                    consensus: Some(consensus.clone()),
                    notes: "TVC deterministic bootstrap and recovery for one provisioned wallet account."
                        .to_owned(),
                    time: None,
                },
                CreatePolicyIntentV3 {
                    policy_name: format!("zolana-tvc-registration-{suffix}"),
                    effect: Effect::Allow,
                    condition: Some(format!(
                        "activity.type == 'ACTIVITY_TYPE_SIGN_TRANSACTION_V2' && wallet_account.address == '{wallet_address}' && solana.tx.instructions.count() == 1 && solana.tx.instructions[0].program_key == '{user_registry_program}' && solana.tx.address_table_lookups.count() == 0 && solana.tx.account_keys.count() == 4 && solana.tx.account_keys.all(key, key in ['{wallet_address}', '{user_record}', '11111111111111111111111111111111', '{user_registry_program}'])"
                    )),
                    consensus: Some(consensus.clone()),
                    notes: "TVC registration for one provisioned wallet account and canonical registry PDA."
                        .to_owned(),
                    time: None,
                },
                CreatePolicyIntentV3 {
                    policy_name: format!("zolana-tvc-deposit-{suffix}"),
                    effect: Effect::Allow,
                    condition: Some(format!(
                        "activity.type == 'ACTIVITY_TYPE_SIGN_TRANSACTION_V2' && wallet_account.address == '{wallet_address}' && solana.tx.instructions.count() == 1 && solana.tx.instructions[0].program_key == '{shielded_program}' && solana.tx.address_table_lookups.count() == 0 && solana.tx.account_keys.count() == 5 && solana.tx.account_keys.all(key, key in ['{wallet_address}', '{default_tree}', '11111111111111111111111111111111', '{sol_interface}', '{shielded_program}'])"
                    )),
                    consensus: Some(consensus.clone()),
                    notes: "TVC fixed development deposit for one provisioned wallet account and tree."
                        .to_owned(),
                    time: None,
                },
                CreatePolicyIntentV3 {
                    policy_name: format!("zolana-tvc-transfer-{suffix}"),
                    effect: Effect::Allow,
                    condition: Some(format!(
                        "activity.type == 'ACTIVITY_TYPE_SIGN_TRANSACTION_V2' && wallet_account.address == '{wallet_address}' && solana.tx.instructions.count() == 2 && solana.tx.instructions[0].program_key == 'ComputeBudget111111111111111111111111111111' && solana.tx.instructions[1].program_key == '{shielded_program}' && solana.tx.address_table_lookups.count() == 0 && solana.tx.account_keys.count() == 5 && solana.tx.account_keys.all(key, key in ['{wallet_address}', '{default_tree}', '11111111111111111111111111111111', 'ComputeBudget111111111111111111111111111111', '{shielded_program}'])"
                    )),
                    consensus: Some(consensus.clone()),
                    notes: "TVC default-ring development transfer for one provisioned wallet account and tree."
                        .to_owned(),
                    time: None,
                },
                CreatePolicyIntentV3 {
                    policy_name: format!("zolana-tvc-sol-withdrawal-{suffix}"),
                    effect: Effect::Allow,
                    condition: Some(format!(
                        "activity.type == 'ACTIVITY_TYPE_SIGN_TRANSACTION_V2' && wallet_account.address == '{wallet_address}' && solana.tx.instructions.count() == 2 && solana.tx.instructions[0].program_key == 'ComputeBudget111111111111111111111111111111' && solana.tx.instructions[1].program_key == '{shielded_program}' && solana.tx.address_table_lookups.count() == 0 && solana.tx.account_keys.count() == 6 && solana.tx.account_keys.all(key, key in ['{wallet_address}', '{default_tree}', '11111111111111111111111111111111', 'ComputeBudget111111111111111111111111111111', '{sol_interface}', '{shielded_program}'])"
                    )),
                    consensus: Some(consensus),
                    notes: "TVC default-ring development SOL withdrawal to the same provisioned public wallet."
                        .to_owned(),
                    time: None,
                },
            ];
            let policies = client
                .get_policies(GetPoliciesRequest {
                    organization_id: cli.organization_id.clone(),
                })
                .await?
                .policies;
            let mut missing = Vec::new();
            for policy in expected {
                if let Some(existing) = policies
                    .iter()
                    .find(|candidate| candidate.policy_name == policy.policy_name)
                {
                    ensure!(
                        existing.effect == policy.effect
                            && existing.condition == policy.condition
                            && existing.consensus == policy.consensus,
                        "existing wallet policy does not match the expected profile: {}",
                        policy.policy_name
                    );
                    println!("wallet_policy_current={}", policy.policy_name);
                } else {
                    missing.push(policy);
                }
            }
            if !missing.is_empty() {
                let result = client
                    .create_policies(
                        cli.organization_id,
                        client.current_timestamp(),
                        CreatePoliciesIntent { policies: missing },
                    )
                    .await?;
                println!("wallet_policy_activity_id={}", result.activity_id);
                println!("wallet_policies_created={}", result.result.policy_ids.len());
            } else {
                println!("wallet_policies_created=0");
            }
        }
        Command::EnsureCreateWalletPolicy { user_id } => {
            ensure!(
                !user_id.is_empty()
                    && user_id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
                "policy user ID contains unsupported characters"
            );
            let consensus = format!("approvers.any(user, user.id == '{user_id}')");
            let policies = client
                .get_policies(GetPoliciesRequest {
                    organization_id: cli.organization_id.clone(),
                })
                .await?
                .policies;
            if let Some(policy) = policies
                .iter()
                .find(|policy| policy.policy_name == CREATE_WALLET_POLICY_NAME)
            {
                ensure!(
                    policy.effect == Effect::Allow
                        && policy.condition.as_deref() == Some(CREATE_WALLET_POLICY_CONDITION)
                        && policy.consensus.as_deref() == Some(consensus.as_str()),
                    "existing create-wallet policy does not match the expected profile"
                );
                println!("create_wallet_policy=already_current");
                println!("create_wallet_policy_id={}", policy.policy_id);
            } else {
                let result = client
                    .create_policies(
                        cli.organization_id,
                        client.current_timestamp(),
                        CreatePoliciesIntent {
                            policies: vec![CreatePolicyIntentV3 {
                                policy_name: CREATE_WALLET_POLICY_NAME.to_owned(),
                                effect: Effect::Allow,
                                condition: Some(CREATE_WALLET_POLICY_CONDITION.to_owned()),
                                consensus: Some(consensus),
                                notes: "Disposable development TVC may create fixed-shape, unfunded Solana HD wallets; approved enclave code constrains all wallet parameters."
                                    .to_owned(),
                                time: None,
                            }],
                        },
                    )
                    .await?;
                ensure!(
                    result.result.policy_ids.len() == 1,
                    "expected one create-wallet policy ID"
                );
                println!("create_wallet_policy=created");
                println!("create_wallet_policy_activity_id={}", result.activity_id);
                println!("create_wallet_policy_id={}", result.result.policy_ids[0]);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_public_key_parser_is_strict() {
        let valid = format!("03{}", "ab".repeat(32));
        assert!(CompressedP256PublicKey::from_str(&valid).is_ok());
        assert!(CompressedP256PublicKey::from_str(&valid.to_ascii_uppercase()).is_err());
        assert!(CompressedP256PublicKey::from_str(&format!("04{}", "ab".repeat(32))).is_err());
        assert!(CompressedP256PublicKey::from_str("03ab").is_err());
    }
}
