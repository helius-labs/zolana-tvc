//! Read-only operator diagnostic for recent Turnkey activity metadata.

use std::{env, fs};

use anyhow::{Context as _, Result};
use serde::Deserialize;
use turnkey_client::generated::services::coordinator::public::v1::GetActivitiesRequest;
use turnkey_client::{TurnkeyClient, TurnkeyP256ApiKey};

#[derive(Deserialize)]
struct StoredApiKey {
    private_key: String,
    public_key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let path = env::args().nth(1).context("missing API key path")?;
    let organization_id = env::args().nth(2).context("missing organization id")?;
    let stored: StoredApiKey = serde_json::from_slice(&fs::read(path)?)?;
    let key = TurnkeyP256ApiKey::from_strings(&stored.private_key, Some(&stored.public_key))?;
    let client = TurnkeyClient::builder().api_key(key).build()?;
    let mut activities = client
        .get_activities(GetActivitiesRequest {
            organization_id,
            filter_by_status: Vec::new(),
            pagination_options: None,
            filter_by_type: Vec::new(),
        })
        .await?
        .activities;
    activities.sort_by_key(|activity| {
        std::cmp::Reverse(
            activity
                .created_at
                .as_ref()
                .and_then(|timestamp| timestamp.seconds.parse::<u128>().ok())
                .unwrap_or_default(),
        )
    });
    for activity in activities.into_iter().take(15) {
        println!(
            "id={} type={} status={} created_at={:?} failure={:?}",
            activity.id,
            activity.r#type.as_str_name(),
            activity.status.as_str_name(),
            activity.created_at,
            activity.failure
        );
    }
    Ok(())
}
