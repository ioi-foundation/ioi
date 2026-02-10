// Path: crates/cli/src/commands/dev.rs

use crate::util::create_cli_tx;
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use ioi_types::app::agentic::{AgentMacro, LlmToolDefinition};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, ChainTransaction, SystemPayload};
use ioi_types::codec;
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct DevArgs {
    #[clap(subcommand)]
    pub command: DevCommands,

    #[clap(long, default_value = "127.0.0.1:9000")]
    pub rpc: String,
}

#[derive(Subcommand, Debug)]
pub enum DevCommands {
    /// Inject a raw skill JSON into the node's SCS.
    InjectSkill { file: PathBuf },
}

#[derive(serde::Deserialize)]
struct HumanSkill {
    name: String,
    description: String,
    steps: Vec<HumanStep>,
}

#[derive(serde::Deserialize)]
struct HumanStep {
    tool: String,
    params: serde_json::Value,
}

pub async fn run(args: DevArgs) -> Result<()> {
    match args.command {
        DevCommands::InjectSkill { file } => {
            let json = std::fs::read_to_string(&file)?;
            let human: HumanSkill = serde_json::from_str(&json)?;

            // Convert to AgentMacro
            let mut steps = Vec::new();
            for step in human.steps {
                let target = match step.tool.as_str() {
                    "sys__exec" => ActionTarget::SysExec,
                    "agent__complete" => ActionTarget::Custom("agent__complete".into()),
                    // Add others as needed
                    other => ActionTarget::Custom(other.to_string()),
                };

                let params = serde_json::to_vec(&step.params)?;

                steps.push(ActionRequest {
                    target,
                    params,
                    context: ActionContext {
                        agent_id: "macro".into(),
                        session_id: None,
                        window_id: None,
                    },
                    nonce: 0,
                });
            }

            let skill = AgentMacro {
                definition: LlmToolDefinition {
                    name: human.name,
                    description: human.description,
                    parameters: r#"{"type":"object"}"#.into(),
                },
                steps,
                source_trace_hash: [0; 32],
                fitness: 1.0,
            };

            let params_bytes = codec::to_bytes_canonical(&skill).unwrap();

            let payload = SystemPayload::CallService {
                service_id: "optimizer".to_string(),
                method: "import_skill@v1".to_string(),
                params: params_bytes,
            };

            let keypair = ioi_crypto::sign::eddsa::Ed25519KeyPair::generate().unwrap();
            let tx = create_cli_tx(&keypair, payload, 0);

            let channel = tonic::transport::Channel::from_shared(format!("http://{}", args.rpc))?
                .connect()
                .await?;
            let mut client = ioi_ipc::public::public_api_client::PublicApiClient::new(channel);

            let req = ioi_ipc::public::SubmitTransactionRequest {
                transaction_bytes: codec::to_bytes_canonical(&tx).unwrap(),
            };

            let resp = client.submit_transaction(req).await?.into_inner();
            println!(
                "✅ Skill '{}' Injected! Tx: {}",
                skill.definition.name, resp.tx_hash
            );
        }
    }
    Ok(())
}
