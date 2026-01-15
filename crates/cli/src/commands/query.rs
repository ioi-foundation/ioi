// Path: crates/cli/src/commands/query.rs

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ioi_ipc::public::public_api_client::PublicApiClient;

#[derive(Parser, Debug)]
pub struct QueryArgs {
    /// The RPC address of the node.
    #[clap(long, default_value = "127.0.0.1:8555")]
    pub ipc_addr: String,

    #[clap(subcommand)]
    pub command: QueryCommands,
}

#[derive(Subcommand, Debug)]
pub enum QueryCommands {
    /// Get the current chain status.
    Status,
    /// Query a raw state key (hex).
    State { key: String },
}

pub async fn run(args: QueryArgs) -> Result<()> {
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", args.ipc_addr))?
        .connect()
        .await
        .context("Failed to connect to node RPC")?;

    let mut client = PublicApiClient::new(channel);

    match args.command {
        QueryCommands::Status => {
            let req = ioi_ipc::blockchain::GetStatusRequest {};
            let status = client.get_status(req).await?.into_inner();
            println!("Chain Status:");
            println!("  Height: {}", status.height);
            println!("  Timestamp: {}", status.latest_timestamp);
            println!("  Tx Count: {}", status.total_transactions);
            println!("  Running: {}", status.is_running);
        }
        QueryCommands::State { key } => {
            let key_bytes = hex::decode(key).context("Invalid hex key")?;
            let req = ioi_ipc::blockchain::QueryRawStateRequest { key: key_bytes };
            let resp = client.query_raw_state(req).await?.into_inner();

            if resp.found {
                println!("Value (Hex): {}", hex::encode(&resp.value));
                if let Ok(s) = String::from_utf8(resp.value) {
                    println!("Value (UTF8): {}", s);
                }
            } else {
                println!("Key not found.");
            }
        }
    }

    Ok(())
}