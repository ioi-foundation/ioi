use super::model_mount_http::{daemon_request, print_value};
use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::Method;

#[derive(Parser, Debug)]
pub struct ServerArgs {
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
    pub command: ServerCommands,
}

#[derive(Subcommand, Debug)]
pub enum ServerCommands {
    /// Probe local model server status.
    Status,
    /// Request local model server start.
    Start,
    /// Request local model server stop.
    Stop,
}

pub async fn run(args: ServerArgs) -> Result<()> {
    let endpoint = args.endpoint.as_deref();
    let token = args.token.as_deref();
    let (method, route) = match args.command {
        ServerCommands::Status => (Method::GET, "/api/v1/server/status"),
        ServerCommands::Start => (Method::POST, "/api/v1/server/start"),
        ServerCommands::Stop => (Method::POST, "/api/v1/server/stop"),
    };
    let value = daemon_request(endpoint, token, method, route, None).await?;
    print_value(&value, args.json)
}
