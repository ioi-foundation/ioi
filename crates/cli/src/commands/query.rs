// Path: crates/cli/src/commands/query.rs

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{GetTransactionStatusRequest, TxStatus};

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
    /// Query transaction status by hash.
    TxStatus { tx_hash: String },
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
        QueryCommands::TxStatus { tx_hash } => {
            let req = GetTransactionStatusRequest {
                tx_hash: tx_hash.clone(),
            };
            let resp = client.get_transaction_status(req).await?.into_inner();
            let status = TxStatus::try_from(resp.status).unwrap_or(TxStatus::Unknown);
            println!("Tx Status:");
            println!("  Hash: {}", tx_hash);
            println!("  Status: {:?}", status);
            println!("  Block Height: {}", resp.block_height);
            if !resp.error_message.trim().is_empty() {
                println!("  Error: {}", resp.error_message);
            }
        }
    }

    Ok(())
}
