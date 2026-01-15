// Path: crates/cli/src/commands/agent.rs

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ioi_services::agentic::desktop::{StartAgentParams, StepAgentParams};
use ioi_types::app::{SystemPayload, ChainTransaction};
use crate::util::create_cli_tx;

#[derive(Parser, Debug)]
pub struct AgentArgs {
    /// The natural language goal (e.g. "Buy a red t-shirt").
    #[clap(index = 1)]
    pub goal: String,

    /// RPC address of the local node.
    #[clap(long, default_value = "127.0.0.1:9000")]
    pub rpc: String,

    /// Max steps to execute.
    #[clap(long, default_value = "10")]
    pub steps: u32,
}

pub async fn run(args: AgentArgs) -> Result<()> {
    println!("🤖 IOI Desktop Agent Client");
    println!("   Target Node: http://{}", args.rpc);
    println!("   Goal: \"{}\"", args.goal);

    // 1. Generate a Session ID
    let session_id: [u8; 32] = rand::random();
    println!("   Session ID: 0x{}", hex::encode(session_id));

    // 2. Load Local Identity (Client-side)
    let keypair = ioi_crypto::sign::eddsa::Ed25519KeyPair::generate().unwrap();

    // 3. Construct "Start Agent" Transaction
    let params = StartAgentParams {
        session_id,
        goal: args.goal,
        max_steps: args.steps,
        parent_session_id: None,
        initial_budget: 1000, // Default budget
    };

    let payload = SystemPayload::CallService {
        service_id: "desktop_agent".to_string(),
        method: "start@v1".to_string(),
        params: ioi_types::codec::to_bytes_canonical(&params).unwrap(),
    };

    // Helper to wrap in SystemTransaction and sign
    let tx = create_cli_tx(&keypair, payload, 0);

    // 4. Submit
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", args.rpc))?
        .connect()
        .await
        .context("Failed to connect to node RPC")?;
    let mut client = ioi_ipc::public::public_api_client::PublicApiClient::new(channel);

    let req = ioi_ipc::public::SubmitTransactionRequest {
        transaction_bytes: ioi_types::codec::to_bytes_canonical(&tx).unwrap(),
    };

    match client.submit_transaction(req).await {
        Ok(resp) => {
            println!("✅ Agent Started! TxHash: {}", resp.into_inner().tx_hash);
        }
        Err(e) => {
            return Err(anyhow!("Failed to start agent: {}", e.message()));
        }
    }

    // 5. Trigger the Loop (The Heartbeat)
    println!("   Triggering execution loop...");

    for i in 1..=args.steps {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        print!("   Step {}/{}... ", i, args.steps);

        let step_params = StepAgentParams { session_id };
        let step_payload = SystemPayload::CallService {
            service_id: "desktop_agent".to_string(),
            method: "step@v1".to_string(),
            params: ioi_types::codec::to_bytes_canonical(&step_params).unwrap(),
        };
        let step_tx = create_cli_tx(&keypair, step_payload, i as u64);

        let step_req = ioi_ipc::public::SubmitTransactionRequest {
            transaction_bytes: ioi_types::codec::to_bytes_canonical(&step_tx).unwrap(),
        };

        match client.submit_transaction(step_req).await {
            Ok(_) => println!("OK"),
            Err(e) => println!("Error: {}", e.message()),
        }
    }

    Ok(())
}