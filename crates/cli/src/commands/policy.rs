// Path: crates/cli/src/commands/policy.rs

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_types::app::agentic::StepTrace;
use ioi_types::codec;
use ioi_validator::firewall::synthesizer::PolicySynthesizer;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct PolicyArgs {
    #[clap(subcommand)]
    pub command: PolicyCommands,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCommands {
    /// Generate a security policy from a session's execution trace.
    Generate {
        /// The session ID to analyze.
        session_id: String,
        /// The ID to assign to the new policy.
        #[clap(long, default_value = "auto-policy-v1")]
        policy_id: String,
        /// Output file path (defaults to stdout).
        #[clap(long)]
        output: Option<PathBuf>,
        /// RPC address of the local node.
        #[clap(long, default_value = "127.0.0.1:8555")]
        rpc: String,
    },
}

pub async fn run(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommands::Generate {
            session_id,
            policy_id,
            output,
            rpc,
        } => {
            println!("🔍 Fetching trace for session: {}", session_id);
            let session_bytes = hex::decode(&session_id).context("Invalid session ID hex")?;
            if session_bytes.len() != 32 {
                return Err(anyhow!("Session ID must be 32 bytes"));
            }

            let channel = tonic::transport::Channel::from_shared(format!("http://{}", rpc))?
                .connect()
                .await
                .context("Failed to connect to node RPC")?;
            let mut client = PublicApiClient::new(channel);

            // Fetch Traces
            let mut traces = Vec::new();
            let mut step = 0;
            loop {
                let prefix = b"agent::trace::";
                let mut key = Vec::new();
                key.extend_from_slice(prefix);
                key.extend_from_slice(&session_bytes);
                key.extend_from_slice(&(step as u32).to_le_bytes());

                let req = ioi_ipc::blockchain::QueryRawStateRequest { key };
                let resp = client.query_raw_state(req).await?.into_inner();

                if !resp.found || resp.value.is_empty() {
                    break;
                }
                let trace: StepTrace = codec::from_bytes_canonical(&resp.value)
                    .map_err(|e| anyhow!("Failed to decode trace step {}: {}", step, e))?;
                traces.push(trace);
                step += 1;
            }

            if traces.is_empty() {
                return Err(anyhow!("No traces found for session {}", session_id));
            }

            // Synthesize
            println!("⚙️ Synthesizing policy from {} traces...", traces.len());
            let policy = PolicySynthesizer::synthesize(&policy_id, &traces);
            let policy_json = serde_json::to_string_pretty(&policy)?;

            if let Some(path) = output {
                fs::write(&path, policy_json)?;
                println!("✅ Policy saved to {}", path.display());
            } else {
                println!("{}", policy_json);
            }
        }
    }
    Ok(())
}