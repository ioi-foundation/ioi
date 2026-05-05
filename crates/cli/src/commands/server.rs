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
    /// Request local model server restart.
    Restart,
    /// Read redacted local model server logs.
    Logs {
        /// Maximum records to return.
        #[clap(long, default_value_t = 80)]
        limit: usize,
    },
    /// Read redacted local model server event tail.
    Events {
        /// Maximum events to return.
        #[clap(long, default_value_t = 80)]
        limit: usize,
    },
}

pub async fn run(args: ServerArgs) -> Result<()> {
    let endpoint = args.endpoint.as_deref();
    let token = args.token.as_deref();
    let (method, route) = match args.command {
        ServerCommands::Status => (Method::GET, "/api/v1/server/status".to_string()),
        ServerCommands::Start => (Method::POST, "/api/v1/server/start".to_string()),
        ServerCommands::Stop => (Method::POST, "/api/v1/server/stop".to_string()),
        ServerCommands::Restart => (Method::POST, "/api/v1/server/restart".to_string()),
        ServerCommands::Logs { limit } => (
            Method::GET,
            format!("/api/v1/server/logs?limit={}", limit.min(200)),
        ),
        ServerCommands::Events { limit } => (
            Method::GET,
            format!("/api/v1/server/events?limit={}", limit.min(200)),
        ),
    };
    let value = daemon_request(endpoint, token, method, &route, None).await?;
    print_value(&value, args.json)
}
