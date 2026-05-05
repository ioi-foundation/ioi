use super::model_mount_http::{daemon_request, print_value};
use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::Method;

#[derive(Parser, Debug)]
pub struct ReceiptsArgs {
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
    pub command: ReceiptsCommands,
}

#[derive(Subcommand, Debug)]
pub enum ReceiptsCommands {
    /// List model mounting receipts.
    Ls,
    /// Inspect one receipt by id.
    Get { id: String },
    /// Replay canonical projection context for one receipt.
    Replay { id: String },
}

pub async fn run(args: ReceiptsArgs) -> Result<()> {
    let endpoint = args.endpoint.as_deref();
    let token = args.token.as_deref();
    let value = match args.command {
        ReceiptsCommands::Ls => {
            daemon_request(endpoint, token, Method::GET, "/api/v1/receipts", None).await?
        }
        ReceiptsCommands::Get { id } => {
            daemon_request(
                endpoint,
                token,
                Method::GET,
                &format!("/api/v1/receipts/{id}"),
                None,
            )
            .await?
        }
        ReceiptsCommands::Replay { id } => {
            daemon_request(
                endpoint,
                token,
                Method::GET,
                &format!("/api/v1/receipts/{id}/replay"),
                None,
            )
            .await?
        }
    };
    print_value(&value, args.json)
}
