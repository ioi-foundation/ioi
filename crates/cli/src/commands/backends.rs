use super::model_mount_http::{daemon_request, print_value};
use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::Method;

#[derive(Parser, Debug)]
pub struct BackendsArgs {
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
    pub command: BackendsCommands,
}

#[derive(Subcommand, Debug)]
pub enum BackendsCommands {
    /// List model backend drivers and runtime state.
    Ls,
    /// Probe backend health and record a lifecycle receipt.
    Health { id: String },
    /// Request backend start through the daemon control path.
    Start { id: String },
    /// Request backend stop through the daemon control path.
    Stop { id: String },
    /// Show recent backend logs.
    Logs { id: String },
    /// Capture a runtime engine and hardware survey through the daemon.
    Survey,
}

pub async fn run(args: BackendsArgs) -> Result<()> {
    let endpoint = args.endpoint.as_deref();
    let token = args.token.as_deref();
    let value = match args.command {
        BackendsCommands::Ls => {
            daemon_request(endpoint, token, Method::GET, "/api/v1/backends", None).await?
        }
        BackendsCommands::Health { id } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                &format!("/api/v1/backends/{id}/health"),
                None,
            )
            .await?
        }
        BackendsCommands::Start { id } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                &format!("/api/v1/backends/{id}/start"),
                None,
            )
            .await?
        }
        BackendsCommands::Stop { id } => {
            daemon_request(
                endpoint,
                token,
                Method::POST,
                &format!("/api/v1/backends/{id}/stop"),
                None,
            )
            .await?
        }
        BackendsCommands::Logs { id } => {
            daemon_request(
                endpoint,
                token,
                Method::GET,
                &format!("/api/v1/backends/{id}/logs"),
                None,
            )
            .await?
        }
        BackendsCommands::Survey => {
            daemon_request(endpoint, token, Method::POST, "/api/v1/runtime/survey", None).await?
        }
    };
    print_value(&value, args.json)
}
