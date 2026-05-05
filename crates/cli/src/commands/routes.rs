use super::model_mount_http::{daemon_request, print_value};
use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::Method;
use serde_json::json;

#[derive(Parser, Debug)]
pub struct RoutesArgs {
    /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
    #[clap(long)]
    pub endpoint: Option<String>,

    /// Capability token. Defaults to IOI_DAEMON_TOKEN.
    #[clap(long)]
    pub token: Option<String>,

    /// Emit machine-readable JSON.
    #[clap(long)]
    pub json: bool,

    #[clap(subcommand)]
    pub command: RoutesCommands,
}

#[derive(Subcommand, Debug)]
pub enum RoutesCommands {
    /// List model routes.
    Ls,
    /// Test a model route selection.
    Test {
        id: String,
        #[clap(long, default_value = "chat")]
        capability: String,
        #[clap(long)]
        model: Option<String>,
        #[clap(long)]
        privacy: Option<String>,
    },
}

pub async fn run(args: RoutesArgs) -> Result<()> {
    let endpoint = args.endpoint.as_deref();
    let token = args.token.as_deref();
    let value = match args.command {
        RoutesCommands::Ls => {
            daemon_request(endpoint, token, Method::GET, "/api/v1/routes", None).await?
        }
        RoutesCommands::Test {
            id,
            capability,
            model,
            privacy,
        } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                &format!("/api/v1/routes/{id}/test"),
                Some(json!({
                    "capability": capability,
                    "model": model,
                    "model_policy": {
                        "privacy": privacy.unwrap_or_else(|| "local_or_enterprise".to_string())
                    }
                })),
            )
            .await?
        }
    };
    print_value(&value, args.json)
}
