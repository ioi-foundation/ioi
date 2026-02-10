// Path: crates/cli/src/commands/trace.rs

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_types::app::agentic::StepTrace;
use ioi_types::codec;

#[derive(Parser, Debug)]
pub struct TraceArgs {
    /// The session ID to trace (hex).
    pub session_id: String,

    /// RPC address of the local node.
    #[clap(long, default_value = "127.0.0.1:8555")]
    pub rpc: String,
}

pub async fn run(args: TraceArgs) -> Result<()> {
    println!("🔍 Inspecting trace for session: {}", args.session_id);
    let session_bytes = hex::decode(&args.session_id).context("Invalid session ID hex")?;
    if session_bytes.len() != 32 {
        return Err(anyhow!("Session ID must be 32 bytes"));
    }

    // Connect to Node (Using Public API which proxies to Workload)
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", args.rpc))?
        .connect()
        .await
        .context("Failed to connect to node RPC")?;
    let mut client = PublicApiClient::new(channel);

    // Iterate through steps 0..N
    let mut step = 0;
    println!("\n--- Trace Log ---");

    loop {
        // Construct trace key: `agent::trace::{session_id}::{step}`
        // Defined in desktop.rs as TRACE_PREFIX + session + step_le_bytes
        let prefix = b"agent::trace::";
        let mut key = Vec::new();
        key.extend_from_slice(prefix);
        key.extend_from_slice(&session_bytes);
        key.extend_from_slice(&(step as u32).to_le_bytes());

        let req = ioi_ipc::blockchain::QueryRawStateRequest { key };
        let resp = client.query_raw_state(req).await?.into_inner();

        if !resp.found || resp.value.is_empty() {
            if step == 0 {
                println!("No trace found for this session.");
            } else {
                println!("--- End of Trace ({} steps) ---", step);
            }
            break;
        }

        // Deserialize
        let trace: StepTrace = codec::from_bytes_canonical(&resp.value)
            .map_err(|e| anyhow!("Failed to decode trace step {}: {}", step, e))?;

        // Print Step details
        println!("\n[Step {}]", trace.step_index);
        println!("  Timestamp:   {}", trace.timestamp);
        println!("  Success:     {}", trace.success);
        if let Some(err) = &trace.error {
            println!("  Error:       {}", err);
        }

        // Print Prompt (Truncated for readability)
        let prompt_preview = if trace.full_prompt.len() > 200 {
            format!("{}...", &trace.full_prompt[..200].replace('\n', " "))
        } else {
            trace.full_prompt.replace('\n', " ")
        };
        println!("  Prompt:      \"{}\"", prompt_preview);

        // Print Output
        println!("  Output:      {}", trace.raw_output.trim());
        println!("  Visual Hash: 0x{}", hex::encode(trace.visual_hash));

        step += 1;
    }

    Ok(())
}
