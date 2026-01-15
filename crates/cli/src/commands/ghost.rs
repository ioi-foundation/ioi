// Path: crates/cli/src/commands/ghost.rs

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_types::app::agentic::StepTrace;
use ioi_types::codec;
use ioi_validator::firewall::synthesizer::PolicySynthesizer;
use std::fs;
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum GhostCommands {
    /// Synthesize a policy from a recorded session trace.
    Distill {
        /// The session ID to analyze.
        session_id: String,
        /// Output path for policy.json.
        #[clap(long, default_value = "policy.json")]
        output: PathBuf,
        /// RPC address of the local node.
        #[clap(long, default_value = "127.0.0.1:8555")]
        rpc: String,
    },
}

pub async fn run(command: GhostCommands) -> Result<()> {
    match command {
        GhostCommands::Distill {
            session_id,
            output,
            rpc,
        } => {
            println!(
                "👻 Ghost Mode: Distilling policy from session {}...",
                session_id
            );
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
            let policy =
                PolicySynthesizer::synthesize(&format!("auto-generated-{}", session_id), &traces);

            // Save
            let json = serde_json::to_string_pretty(&policy)?;
            fs::write(output.clone(), json)?;
            println!(
                "✅ Policy distilled. Review '{}' before signing.",
                output.display()
            );
        }
    }
    Ok(())
}