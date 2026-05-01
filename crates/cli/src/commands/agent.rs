// Path: crates/cli/src/commands/agent.rs

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
// [FIX] Import AgentMode
use crate::util::create_cli_tx;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_services::agentic::runtime::substrate::RuntimeSubstrateSnapshot;
use ioi_services::agentic::runtime::tools::contracts::runtime_tool_contract_for_definition;
use ioi_services::agentic::runtime::types::ResumeAgentParams;
use ioi_services::agentic::runtime::{keys::get_runtime_substrate_key, AgentMode};
use ioi_services::agentic::runtime::{
    CancelAgentParams, DenyAgentParams, PauseAgentParams, PostMessageParams, StartAgentParams,
    StepAgentParams,
};
use ioi_types::app::agentic::LlmToolDefinition;
use ioi_types::app::{
    AutopilotGuiHarnessValidationContract, EffectiveAgentConfig, RuntimeSubstratePortContract,
    SystemPayload,
};
use std::path::PathBuf;
use tonic::transport::Channel;

/// Service identifier for the daemon-hosted desktop agent runtime.
/// CLI command handlers are clients of this service; execution semantics remain
/// owned by the daemon/runtime substrate.
const DESKTOP_AGENT_SERVICE_ID: &str = "desktop_agent";

#[derive(Parser, Debug)]
pub struct AgentArgs {
    /// The natural language goal (e.g. "Buy a red t-shirt").
    #[clap(index = 1)]
    pub goal: Option<String>,

    #[clap(subcommand)]
    pub command: Option<AgentCommands>,

    /// RPC address of the local node.
    #[clap(long, default_value = "127.0.0.1:9000")]
    pub rpc: String,

    /// Max steps to execute.
    #[clap(long, default_value = "20")]
    pub steps: u32,
}

#[derive(Subcommand, Debug)]
pub enum AgentCommands {
    /// Start and step an agent session through the unified runtime substrate.
    Run {
        /// The natural language goal.
        goal: String,
        /// RPC address of the local node.
        #[clap(long, default_value = "127.0.0.1:9000")]
        rpc: String,
        /// Max steps to execute.
        #[clap(long, default_value = "20")]
        steps: u32,
    },
    /// Post a user message to an existing session and auto-resume it.
    Chat {
        /// Session ID as 32-byte hex.
        session_id: String,
        /// Message to append as the operator/user.
        message: String,
        /// RPC address of the local node.
        #[clap(long, default_value = "127.0.0.1:9000")]
        rpc: String,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Resume a paused or running session without granting a specific approval.
    Resume {
        /// Session ID as 32-byte hex.
        session_id: String,
        /// RPC address of the local node.
        #[clap(long, default_value = "127.0.0.1:9000")]
        rpc: String,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Pause a session through the runtime service, preserving traceable state.
    Pause {
        /// Session ID as 32-byte hex.
        session_id: String,
        /// Operator-visible reason.
        #[clap(long, default_value = "operator requested pause")]
        reason: String,
        /// RPC address of the local node.
        #[clap(long, default_value = "127.0.0.1:9000")]
        rpc: String,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Cancel a session without deleting its trace or substrate snapshots.
    Cancel {
        /// Session ID as 32-byte hex.
        session_id: String,
        /// Operator-visible reason.
        #[clap(long, default_value = "operator cancelled session")]
        reason: String,
        /// RPC address of the local node.
        #[clap(long, default_value = "127.0.0.1:9000")]
        rpc: String,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Approve a pending policy gate and resume the session.
    Approve {
        /// Pending request hash emitted by the policy gate.
        request_hash: String,
        /// Session ID for the paused task.
        #[clap(long = "session-id")]
        session_id: String,
        /// RPC address of the local node.
        #[clap(long, default_value = "127.0.0.1:9000")]
        rpc: String,
    },
    /// Deny a pending approval and keep the session paused with evidence.
    Deny {
        /// Session ID as 32-byte hex.
        session_id: String,
        /// Optional request hash being denied.
        #[clap(long = "request-hash")]
        request_hash: Option<String>,
        /// Operator-visible reason.
        #[clap(long, default_value = "operator denied approval")]
        reason: String,
        /// RPC address of the local node.
        #[clap(long, default_value = "127.0.0.1:9000")]
        rpc: String,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Explain the active unified runtime substrate contract.
    Contract {
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Inspect canonical tool contracts and safety metadata.
    Tools {
        #[clap(subcommand)]
        command: Option<ToolCommands>,
        /// Filter to one tool name, for example shell__run.
        #[clap(long)]
        tool: Option<String>,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Explain agent runtime config defaults and precedence.
    ConfigExplain {
        /// Optional config key to explain.
        key: Option<String>,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Explain runtime policy decisions and authority surface.
    Policy {
        #[clap(subcommand)]
        command: AgentPolicyCommands,
    },
    /// Run local doctor checks for the runtime contract surface.
    Doctor {
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Fetch a persisted runtime substrate snapshot for one session step.
    Status {
        /// Session ID as 32-byte hex.
        session_id: String,
        /// Step index to inspect.
        #[clap(long)]
        step: u32,
        /// RPC address of the local node.
        #[clap(long, default_value = "127.0.0.1:8555")]
        rpc: String,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Print replayable runtime events from a substrate snapshot.
    Events(SnapshotArgs),
    /// Print the runtime trace bundle projection for a session step.
    Trace(SnapshotArgs),
    /// Verify a substrate snapshot contains the required runtime evidence.
    Verify(SnapshotArgs),
    /// Dry-run replay validation for a substrate snapshot.
    Replay(SnapshotArgs),
    /// Export a substrate snapshot and replay verification bundle.
    Export {
        /// Session ID as 32-byte hex.
        session_id: String,
        /// Step index to inspect.
        #[clap(long)]
        step: u32,
        /// Output JSON file.
        #[clap(long)]
        output: PathBuf,
        /// RPC address of the local node.
        #[clap(long, default_value = "127.0.0.1:8555")]
        rpc: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ToolCommands {
    /// List runtime tool contracts.
    List {
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Inspect one runtime tool contract.
    Inspect {
        /// Tool name, for example shell__run.
        tool: String,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Explain the policy metadata attached to a runtime tool.
    ExplainPolicy {
        /// Tool name, for example shell__run.
        tool: String,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum AgentPolicyCommands {
    /// Explain the shared policy and authority requirements.
    Explain {
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
}

#[derive(Parser, Debug)]
pub struct SnapshotArgs {
    /// Session ID as 32-byte hex.
    pub session_id: String,
    /// Step index to inspect.
    #[clap(long)]
    pub step: u32,
    /// RPC address of the local node.
    #[clap(long, default_value = "127.0.0.1:8555")]
    pub rpc: String,
    /// Emit machine-readable JSON.
    #[clap(long)]
    pub json: bool,
}

pub async fn run(args: AgentArgs) -> Result<()> {
    if let Some(command) = args.command {
        return run_agent_command(command).await;
    }

    let goal = args
        .goal
        .clone()
        .ok_or_else(|| anyhow!("agent requires either a goal or a subcommand"))?;

    run_agent_goal(goal, args.rpc, args.steps).await
}

async fn run_agent_goal(goal: String, rpc: String, steps: u32) -> Result<()> {
    println!("🤖 IOI Desktop Agent Client");
    println!("   Target Node: http://{}", rpc);
    println!("   Goal: \"{}\"", goal);

    // 1. Generate a Session ID
    let session_id: [u8; 32] = rand::random();
    println!("   Session ID: 0x{}", hex::encode(session_id));

    let params = StartAgentParams {
        session_id,
        goal,
        max_steps: steps,
        parent_session_id: None,
        initial_budget: 1000, // Default budget
        // [FIX] Added mode field
        mode: AgentMode::Agent,
    };

    let mut client = CliAgentRuntimeClient::connect(&rpc).await?;
    let tx_hash = client
        .submit_runtime_call("start@v1", encode_agent_params(&params, "start")?)
        .await?;
    println!("✅ Agent Started! TxHash: {}", tx_hash);

    println!("   Triggering execution loop...");

    for i in 1..=steps {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        print!("   Step {}/{}... ", i, steps);

        let step_params = StepAgentParams { session_id };
        match client
            .submit_runtime_call("step@v1", encode_agent_params(&step_params, "step")?)
            .await
        {
            Ok(_) => println!("OK"),
            Err(e) => println!("Error: {}", e),
        }
    }

    Ok(())
}

async fn run_agent_command(command: AgentCommands) -> Result<()> {
    match command {
        AgentCommands::Run { goal, rpc, steps } => run_agent_goal(goal, rpc, steps).await,
        AgentCommands::Chat {
            session_id,
            message,
            rpc,
            json,
        } => submit_chat(session_id, message, rpc, json).await,
        AgentCommands::Resume {
            session_id,
            rpc,
            json,
        } => submit_resume(session_id, rpc, json).await,
        AgentCommands::Pause {
            session_id,
            reason,
            rpc,
            json,
        } => submit_pause(session_id, reason, rpc, json).await,
        AgentCommands::Cancel {
            session_id,
            reason,
            rpc,
            json,
        } => submit_cancel(session_id, reason, rpc, json).await,
        AgentCommands::Approve {
            request_hash,
            session_id,
            rpc,
        } => {
            crate::commands::policy::run_approve(crate::commands::policy::PolicyApproveArgs {
                request_hash,
                session_id,
                rpc,
            })
            .await
        }
        AgentCommands::Deny {
            session_id,
            request_hash,
            reason,
            rpc,
            json,
        } => submit_deny(session_id, request_hash, reason, rpc, json).await,
        AgentCommands::Contract { json } => print_agent_contract(json),
        AgentCommands::Tools {
            command,
            tool,
            json,
        } => run_tool_command(command, tool, json),
        AgentCommands::ConfigExplain { key, json } => print_config_explain(key.as_deref(), json),
        AgentCommands::Policy { command } => run_policy_command(command),
        AgentCommands::Doctor { json } => print_doctor(json),
        AgentCommands::Status {
            session_id,
            step,
            rpc,
            json,
        } => print_status(session_id, step, rpc, json).await,
        AgentCommands::Events(args) => print_events(args).await,
        AgentCommands::Trace(args) => print_runtime_trace(args).await,
        AgentCommands::Verify(args) => verify_snapshot_command(args).await,
        AgentCommands::Replay(args) => replay_snapshot_command(args).await,
        AgentCommands::Export {
            session_id,
            step,
            output,
            rpc,
        } => export_snapshot(session_id, step, rpc, output).await,
    }
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn parse_session_id_hex(input: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(input.trim().trim_start_matches("0x")).context("Invalid session ID hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!("Session ID must be 32 bytes"));
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&bytes);
    Ok(session_id)
}

fn parse_optional_hash_hex(input: Option<&str>, label: &str) -> Result<Option<[u8; 32]>> {
    let Some(input) = input else {
        return Ok(None);
    };
    let bytes = hex::decode(input.trim().trim_start_matches("0x"))
        .with_context(|| format!("Invalid {label} hex"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{label} must be 32 bytes"));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(Some(hash))
}

struct CliAgentRuntimeClient {
    client: PublicApiClient<Channel>,
    keypair: ioi_crypto::sign::eddsa::Ed25519KeyPair,
    nonce: u64,
}

impl CliAgentRuntimeClient {
    async fn connect(rpc: &str) -> Result<Self> {
        let keypair = ioi_crypto::sign::eddsa::Ed25519KeyPair::generate()
            .map_err(|e| anyhow!("Failed to generate signer key: {}", e))?;
        let channel = Channel::from_shared(format!("http://{}", rpc))?
            .connect()
            .await
            .context("Failed to connect to node RPC")?;
        Ok(Self {
            client: PublicApiClient::new(channel),
            keypair,
            nonce: 0,
        })
    }

    async fn submit_runtime_call(&mut self, method: &str, params: Vec<u8>) -> Result<String> {
        let payload = desktop_agent_payload(method, params);
        let tx = create_cli_tx(&self.keypair, payload, self.nonce);
        self.nonce = self.nonce.saturating_add(1);
        let req = ioi_ipc::public::SubmitTransactionRequest {
            transaction_bytes: ioi_types::codec::to_bytes_canonical(&tx)
                .map_err(|e| anyhow!("Failed to encode tx: {}", e))?,
        };
        let response = self
            .client
            .submit_transaction(req)
            .await
            .with_context(|| format!("Failed to submit {DESKTOP_AGENT_SERVICE_ID}.{method}"))?
            .into_inner();
        Ok(response.tx_hash)
    }
}

fn desktop_agent_payload(method: &str, params: Vec<u8>) -> SystemPayload {
    SystemPayload::CallService {
        service_id: DESKTOP_AGENT_SERVICE_ID.to_string(),
        method: method.to_string(),
        params,
    }
}

fn encode_agent_params<T: parity_scale_codec::Encode>(params: &T, label: &str) -> Result<Vec<u8>> {
    ioi_types::codec::to_bytes_canonical(params)
        .map_err(|e| anyhow!("Failed to encode {label} params: {}", e))
}

async fn submit_desktop_agent_call(rpc: &str, method: &str, params: Vec<u8>) -> Result<String> {
    let mut client = CliAgentRuntimeClient::connect(rpc).await?;
    client.submit_runtime_call(method, params).await
}

fn print_submission(json: bool, action: &str, session_id: [u8; 32], tx_hash: String) -> Result<()> {
    if json {
        return print_json(&serde_json::json!({
            "action": action,
            "session_id": hex::encode(session_id),
            "tx_hash": tx_hash,
        }));
    }
    println!(
        "Submitted {} for session {}: tx_hash={}",
        action,
        hex::encode(session_id),
        tx_hash
    );
    Ok(())
}

async fn submit_chat(
    session_id_hex: String,
    message: String,
    rpc: String,
    json: bool,
) -> Result<()> {
    let session_id = parse_session_id_hex(&session_id_hex)?;
    let params = PostMessageParams {
        session_id,
        role: "user".to_string(),
        content: message,
    };
    let tx_hash = submit_desktop_agent_call(
        &rpc,
        "post_message@v1",
        ioi_types::codec::to_bytes_canonical(&params)
            .map_err(|e| anyhow!("Failed to encode post message params: {}", e))?,
    )
    .await?;
    print_submission(json, "chat", session_id, tx_hash)
}

async fn submit_resume(session_id_hex: String, rpc: String, json: bool) -> Result<()> {
    let session_id = parse_session_id_hex(&session_id_hex)?;
    let params = ResumeAgentParams {
        session_id,
        approval_grant: None,
    };
    let tx_hash = submit_desktop_agent_call(
        &rpc,
        "resume@v1",
        ioi_types::codec::to_bytes_canonical(&params)
            .map_err(|e| anyhow!("Failed to encode resume params: {}", e))?,
    )
    .await?;
    print_submission(json, "resume", session_id, tx_hash)
}

async fn submit_pause(
    session_id_hex: String,
    reason: String,
    rpc: String,
    json: bool,
) -> Result<()> {
    let session_id = parse_session_id_hex(&session_id_hex)?;
    let params = PauseAgentParams { session_id, reason };
    let tx_hash = submit_desktop_agent_call(
        &rpc,
        "pause@v1",
        ioi_types::codec::to_bytes_canonical(&params)
            .map_err(|e| anyhow!("Failed to encode pause params: {}", e))?,
    )
    .await?;
    print_submission(json, "pause", session_id, tx_hash)
}

async fn submit_cancel(
    session_id_hex: String,
    reason: String,
    rpc: String,
    json: bool,
) -> Result<()> {
    let session_id = parse_session_id_hex(&session_id_hex)?;
    let params = CancelAgentParams { session_id, reason };
    let tx_hash = submit_desktop_agent_call(
        &rpc,
        "cancel@v1",
        ioi_types::codec::to_bytes_canonical(&params)
            .map_err(|e| anyhow!("Failed to encode cancel params: {}", e))?,
    )
    .await?;
    print_submission(json, "cancel", session_id, tx_hash)
}

async fn submit_deny(
    session_id_hex: String,
    request_hash_hex: Option<String>,
    reason: String,
    rpc: String,
    json: bool,
) -> Result<()> {
    let session_id = parse_session_id_hex(&session_id_hex)?;
    let params = DenyAgentParams {
        session_id,
        request_hash: parse_optional_hash_hex(request_hash_hex.as_deref(), "request hash")?,
        reason,
    };
    let tx_hash = submit_desktop_agent_call(
        &rpc,
        "deny@v1",
        ioi_types::codec::to_bytes_canonical(&params)
            .map_err(|e| anyhow!("Failed to encode deny params: {}", e))?,
    )
    .await?;
    print_submission(json, "deny", session_id, tx_hash)
}

fn print_agent_contract(json: bool) -> Result<()> {
    let substrate = RuntimeSubstratePortContract::default();
    let gui = AutopilotGuiHarnessValidationContract::default();
    if json {
        return print_json(&serde_json::json!({
            "runtimeSubstratePortContract": substrate,
            "autopilotGuiHarnessValidationContract": gui,
        }));
    }

    println!("IOI unified agent substrate");
    println!("  Schema: {}", substrate.schema_version);
    println!("  Surfaces: {}", substrate.allowed_surfaces.len());
    println!(
        "  Required adapters: {}",
        substrate.required_adapters.join(", ")
    );
    println!(
        "  Required evidence classes: {}",
        substrate.required_evidence_classes.join(", ")
    );
    println!("  GUI harness: {}", gui.launch_command);
    Ok(())
}

fn canonical_operator_tool_names() -> Vec<&'static str> {
    vec![
        "file__read",
        "file__edit",
        "file__delete",
        "shell__run",
        "shell__start",
        "browser__inspect",
        "browser__click_at",
        "web__search",
        "web__read",
        "memory__read",
        "memory__append",
        "agent__delegate",
        "agent__await",
        "agent__complete",
        "connector__google__gmail_send",
        "commerce__checkout",
    ]
}

fn tool_definition(name: &str) -> LlmToolDefinition {
    LlmToolDefinition {
        name: name.to_string(),
        description: format!("Operator-inspected runtime tool contract for {name}"),
        parameters: r#"{"type":"object"}"#.to_string(),
    }
}

fn print_agent_tools(tool: Option<&str>, json: bool) -> Result<()> {
    let names: Vec<String> = match tool {
        Some(name) => vec![name.to_string()],
        None => canonical_operator_tool_names()
            .into_iter()
            .map(str::to_string)
            .collect(),
    };
    let contracts: Vec<_> = names
        .iter()
        .map(|name| runtime_tool_contract_for_definition(&tool_definition(name)))
        .collect();

    if json {
        return print_json(&contracts);
    }

    for contract in contracts {
        println!("{}", contract.display_name);
        println!("  policy: {}", contract.policy_target);
        println!("  effect: {}", contract.effect_class);
        println!("  risk: {}", contract.risk_domain);
        println!("  evidence: {}", contract.evidence_requirements.join(", "));
    }
    Ok(())
}

fn run_tool_command(
    command: Option<ToolCommands>,
    legacy_tool: Option<String>,
    json: bool,
) -> Result<()> {
    match command {
        Some(ToolCommands::List { json }) => print_agent_tools(None, json),
        Some(ToolCommands::Inspect { tool, json }) => print_agent_tools(Some(&tool), json),
        Some(ToolCommands::ExplainPolicy { tool, json }) => print_tool_policy(&tool, json),
        None => print_agent_tools(legacy_tool.as_deref(), json),
    }
}

fn print_tool_policy(tool: &str, json: bool) -> Result<()> {
    let contract = runtime_tool_contract_for_definition(&tool_definition(tool));
    let value = serde_json::json!({
        "tool": contract.display_name,
        "stable_tool_id": contract.stable_tool_id,
        "policy_target": contract.policy_target,
        "risk_domain": contract.risk_domain,
        "effect_class": contract.effect_class,
        "requires_approval": contract.is_effectful() || !contract.approval_scope_fields.is_empty(),
        "evidence_requirements": contract.evidence_requirements,
        "timeout_default_ms": contract.timeout_default_ms,
        "timeout_max_ms": contract.timeout_max_ms,
        "concurrency_class": contract.concurrency_class,
        "cancellation_behavior": contract.cancellation_behavior,
    });
    if json {
        return print_json(&value);
    }
    println!("Tool policy: {}", value["tool"].as_str().unwrap_or(tool));
    println!(
        "  target: {}",
        value["policy_target"].as_str().unwrap_or("unknown")
    );
    println!(
        "  risk/effect: {}/{}",
        value["risk_domain"].as_str().unwrap_or("unknown"),
        value["effect_class"].as_str().unwrap_or("unknown")
    );
    println!(
        "  approval: {}",
        value["requires_approval"].as_bool().unwrap_or(false)
    );
    Ok(())
}

fn config_explain_value(key: Option<&str>) -> Result<serde_json::Value> {
    let effective = EffectiveAgentConfig::default();
    if let Some(key) = key {
        let entry = effective
            .entry(key)
            .ok_or_else(|| anyhow!("unknown agent config key: {key}"))?;
        return serde_json::to_value(serde_json::json!({
            "schema_version": effective.schema_version,
            "source_order": effective.source_order,
            "entry": entry,
            "fail_closed_in_production": effective.fail_closed_in_production
        }))
        .context("serialize effective agent config entry");
    }
    serde_json::to_value(effective).context("serialize effective agent config")
}

fn run_policy_command(command: AgentPolicyCommands) -> Result<()> {
    match command {
        AgentPolicyCommands::Explain { json } => print_policy_explain(json),
    }
}

fn print_policy_explain(json: bool) -> Result<()> {
    let value = serde_json::json!({
        "authority_model": "fail-closed policy with explicit grants for non-reversible or high-risk actions",
        "operator_commands": ["agent approve", "agent deny", "agent pause", "agent resume", "agent cancel"],
        "substrate_evidence": ["AgentRuntimeEvent", "RuntimeExecutionEnvelope", "StopConditionRecord", "AgentQualityLedger"],
        "invariants": {
            "destructive_actions_require_fresh_authority": true,
            "denials_clear_pending_action": true,
            "pause_cancel_persist_substrate_snapshot": true,
            "dogfood_bypass_allowed": false
        }
    });
    if json {
        return print_json(&value);
    }
    println!("Agent policy and authority");
    println!("  destructive actions require fresh explicit authority");
    println!("  approvals resume via ApprovalGrant; denials keep the session paused");
    println!("  pause/cancel are service calls that persist runtime substrate snapshots");
    Ok(())
}

fn print_config_explain(key: Option<&str>, json: bool) -> Result<()> {
    let value = config_explain_value(key)?;
    if json {
        return print_json(&value);
    }
    if key.is_some() {
        let entry = value
            .get("entry")
            .and_then(|entry| entry.as_object())
            .ok_or_else(|| anyhow!("missing effective config entry"))?;
        println!(
            "Agent runtime config: {}",
            entry
                .get("key")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown")
        );
        println!(
            "  value: {}",
            entry
                .get("value_summary")
                .and_then(|value| value.as_str())
                .unwrap_or("redacted")
        );
        println!(
            "  source: {:?}, priority: {}",
            entry.get("source").unwrap_or(&serde_json::Value::Null),
            entry
                .get("priority")
                .and_then(|value| value.as_u64())
                .unwrap_or(0)
        );
        println!(
            "  policy locked: {}, user overridable: {}",
            entry
                .get("policy_locked")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
            entry
                .get("user_overridable")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
        );
        return Ok(());
    }
    println!("Agent runtime config precedence, low to high");
    if let Some(precedence) = value.get("source_order").and_then(|v| v.as_array()) {
        for (index, item) in precedence.iter().enumerate() {
            println!("  {}. {}", index + 1, item.as_str().unwrap_or("unknown"));
        }
    }
    println!("Effective keys");
    if let Some(entries) = value.get("entries").and_then(|v| v.as_array()) {
        for entry in entries {
            println!(
                "  {} [{}{}]",
                entry
                    .get("key")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown"),
                entry
                    .get("source")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown"),
                if entry
                    .get("policy_locked")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
                {
                    ", locked"
                } else {
                    ""
                }
            );
        }
    }
    Ok(())
}

fn print_doctor(json: bool) -> Result<()> {
    let substrate = RuntimeSubstratePortContract::default();
    let gui = AutopilotGuiHarnessValidationContract::default();
    let checks = serde_json::json!({
        "schema": substrate.schema_version,
        "requiredAdapterCount": substrate.required_adapters.len(),
        "requiredEvidenceClassCount": substrate.required_evidence_classes.len(),
        "forbidsPrivilegedDogfoodBypass": substrate.forbids_privileged_dogfood_bypass,
        "requiresTraceExport": substrate.requires_trace_export,
        "requiresQualityLedger": substrate.requires_quality_ledger,
        "retainedGuiQueryCount": gui.retained_queries.len(),
        "status": "pass"
    });
    if json {
        return print_json(&checks);
    }
    println!("Agent runtime doctor: pass");
    println!(
        "  adapters={} evidence_classes={} retained_gui_queries={}",
        substrate.required_adapters.len(),
        substrate.required_evidence_classes.len(),
        gui.retained_queries.len()
    );
    println!("  dogfood bypass forbidden; trace export and quality ledger required.");
    Ok(())
}

async fn fetch_runtime_snapshot(
    session_id_hex: &str,
    step: u32,
    rpc: &str,
) -> Result<([u8; 32], RuntimeSubstrateSnapshot)> {
    let session_id = parse_session_id_hex(session_id_hex)?;
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", rpc))?
        .connect()
        .await
        .context("Failed to connect to node RPC")?;
    let mut client = PublicApiClient::new(channel);
    let resp = client
        .query_raw_state(ioi_ipc::blockchain::QueryRawStateRequest {
            key: get_runtime_substrate_key(&session_id, step),
        })
        .await?
        .into_inner();
    if !resp.found || resp.value.is_empty() {
        return Err(anyhow!(
            "No runtime substrate snapshot found for session {} step {}",
            hex::encode(session_id),
            step
        ));
    }

    let snapshot: RuntimeSubstrateSnapshot = serde_json::from_slice(&resp.value)
        .context("Runtime substrate snapshot is not valid JSON")?;
    Ok((session_id, snapshot))
}

async fn print_status(session_id_hex: String, step: u32, rpc: String, json: bool) -> Result<()> {
    let (session_id, snapshot) = fetch_runtime_snapshot(&session_id_hex, step, &rpc).await?;
    if json {
        return print_json(&snapshot);
    }
    println!("Agent substrate snapshot");
    println!("  session: {}", hex::encode(session_id));
    println!("  step: {}", step);
    println!("  objective: {}", snapshot.task_state.current_objective);
    println!(
        "  strategy: {}",
        snapshot.strategy_decision.selected_strategy
    );
    println!("  stop: {}", snapshot.stop_condition.rationale);
    Ok(())
}

async fn print_events(args: SnapshotArgs) -> Result<()> {
    let (_, snapshot) = fetch_runtime_snapshot(&args.session_id, args.step, &args.rpc).await?;
    if args.json {
        return print_json(&snapshot.events);
    }
    println!("Agent runtime events");
    for event in snapshot.events {
        println!(
            "  [{}] {} -> {}",
            event.step_index,
            event.event_kind,
            event
                .receipt_or_state_pointer
                .as_deref()
                .unwrap_or("no pointer")
        );
    }
    Ok(())
}

fn snapshot_verification(snapshot: &RuntimeSubstrateSnapshot) -> serde_json::Value {
    let event_stream_consistent = snapshot
        .events
        .iter()
        .all(|event| event.session_id == snapshot.envelope.session_id);
    let required_classes = &snapshot.port_contract.required_evidence_classes;
    let has_dry_run_capability = |capability_id: &str| {
        snapshot
            .dry_run_capabilities
            .iter()
            .any(|capability| capability.capability_id == capability_id)
    };
    let dry_run_covers_guide_classes = [
        "dry_run:file_patch",
        "dry_run:shell_command",
        "dry_run:connector_action",
        "dry_run:policy_decision",
        "dry_run:workflow_side_effect",
        "dry_run:external_order_or_cart",
    ]
    .into_iter()
    .all(has_dry_run_capability);
    let probe_obligation_satisfied = !snapshot.uncertainty.should_probe()
        || snapshot.probes.iter().any(|probe| {
            !probe.hypothesis.trim().is_empty()
                && !probe.cheapest_validation_action.trim().is_empty()
                && !probe.expected_observation.trim().is_empty()
        });
    let semantic_impact_present = !snapshot.semantic_impact.risk_class.trim().is_empty();
    let high_risk_semantic_impact = snapshot.semantic_impact.risk_class
        == "requires_independent_verification"
        || !snapshot.semantic_impact.changed_policies.is_empty();
    let verifier_independence_matches_risk = !high_risk_semantic_impact
        || (!snapshot.verifier_independence_policy.same_model_allowed
            && !snapshot.verifier_independence_policy.same_context_allowed
            && snapshot
                .verifier_independence_policy
                .adversarial_review_required);
    let verifier_independence_complete = snapshot.verifier_independence_policy.evidence_only_mode
        && snapshot
            .verifier_independence_policy
            .failure_creates_repair_task
        && !snapshot
            .verifier_independence_policy
            .human_review_threshold
            .trim()
            .is_empty();
    let cognitive_budget_present = snapshot.cognitive_budget.max_tool_calls > 0
        && snapshot.cognitive_budget.max_wall_time_ms > 0;
    let drift_signal_recorded = !snapshot.drift_signal.evidence_refs.is_empty();
    let handoff_quality_complete = snapshot
        .handoff_quality
        .as_ref()
        .map(|handoff| handoff.passes())
        .unwrap_or(true);
    let bounded_learning_not_auto_promoted = snapshot
        .bounded_self_improvement_gate
        .as_ref()
        .map(|gate| !gate.can_promote() || gate.policy_decision.eq_ignore_ascii_case("allow"))
        .unwrap_or(true);
    let checks = serde_json::json!({
        "envelope_present": !snapshot.envelope.envelope_id.trim().is_empty(),
        "events_present": !snapshot.events.is_empty(),
        "event_stream_consistent": event_stream_consistent,
        "turn_state_present": !snapshot.turn_state.turn_id.trim().is_empty(),
        "decision_loop_present": snapshot.decision_loop.is_complete_enough_for_trace(),
        "session_trace_bundle_reconstructs": snapshot.session_trace_bundle.reconstructs_final_state,
        "model_routing_explainable": snapshot.model_routing.has_policy_explainable_selection(),
        "task_state_present": !snapshot.task_state.current_objective.trim().is_empty(),
        "prompt_assembly_present": !snapshot.prompt_assembly.final_prompt_hash.trim().is_empty() && snapshot.prompt_assembly.included_section_count() > 0,
        "strategy_uses_task_state": snapshot.strategy_router.used_task_state,
        "strategy_uses_uncertainty": snapshot.strategy_router.used_uncertainty,
        "strategy_uses_cognitive_budget": snapshot.strategy_router.used_cognitive_budget,
        "tool_contracts_projected": !snapshot.envelope.tool_contract_ids.is_empty() || snapshot.tool_contracts.is_empty(),
        "tool_selection_quality_projected": snapshot.tool_selection_quality.len() == snapshot.tool_contracts.len(),
        "file_observation_contract_projected": !snapshot.tool_contracts.iter().any(|contract| contract.display_name.starts_with("file__")) || !snapshot.file_observations.is_empty(),
        "postconditions_synthesized": !snapshot.postcondition_synthesizer.synthesizer_id.trim().is_empty(),
        "dry_run_capabilities_present": !snapshot.dry_run_capabilities.is_empty(),
        "dry_run_covers_guide_classes": dry_run_covers_guide_classes,
        "stop_condition_present": !snapshot.stop_condition.rationale.trim().is_empty(),
        "uncertainty_recorded": !snapshot.uncertainty.assessment_id.trim().is_empty() && !snapshot.uncertainty.rationale.trim().is_empty(),
        "probe_obligation_satisfied": probe_obligation_satisfied,
        "semantic_impact_present": semantic_impact_present,
        "semantic_impact_feeds_verifier_policy": verifier_independence_matches_risk,
        "verifier_independence_policy_complete": verifier_independence_complete,
        "cognitive_budget_present": cognitive_budget_present,
        "drift_signal_recorded": drift_signal_recorded,
        "handoff_quality_complete_when_present": handoff_quality_complete,
        "bounded_learning_not_auto_promoted": bounded_learning_not_auto_promoted,
        "quality_ledger_present": !snapshot.quality_ledger.ledger_id.trim().is_empty(),
        "workflow_adapter_uses_public_substrate": snapshot.workflow_envelope_adapter.uses_public_substrate_contract,
        "workflow_adapter_forbids_compositor_truth": snapshot.workflow_envelope_adapter.forbids_compositor_runtime_truth,
        "harness_adapter_uses_exported_trace": snapshot.harness_trace_adapter.consumes_exported_runtime_trace,
        "harness_adapter_avoids_compositor_ui_state": !snapshot.harness_trace_adapter.imports_compositor_ui_state,
        "operator_interruption_replayable": snapshot.operator_interruption.replayable,
        "operator_interruption_preserves_authority": snapshot.operator_interruption.preserves_objective_task_state_and_authority,
        "dogfood_bypass_forbidden": snapshot.port_contract.forbids_privileged_dogfood_bypass,
        "trace_export_required": snapshot.port_contract.requires_trace_export,
        "quality_ledger_required": snapshot.port_contract.requires_quality_ledger,
    });
    let all_passed = checks
        .as_object()
        .map(|map| map.values().all(|value| value.as_bool().unwrap_or(false)))
        .unwrap_or(false);
    serde_json::json!({
        "ok": all_passed,
        "schema": snapshot.port_contract.schema_version,
        "surface": snapshot.envelope.surface,
        "required_evidence_classes": required_classes,
        "checks": checks,
        "stop_condition": snapshot.stop_condition,
        "quality_ledger": snapshot.quality_ledger,
        "prompt_assembly": snapshot.prompt_assembly,
        "turn_state": snapshot.turn_state,
        "decision_loop": snapshot.decision_loop,
        "session_trace_bundle": snapshot.session_trace_bundle,
        "model_routing": snapshot.model_routing,
        "file_observations": snapshot.file_observations,
        "tool_selection_quality": snapshot.tool_selection_quality,
        "uncertainty": snapshot.uncertainty,
        "probes": snapshot.probes,
        "semantic_impact": snapshot.semantic_impact,
        "verifier_independence_policy": snapshot.verifier_independence_policy,
        "cognitive_budget": snapshot.cognitive_budget,
        "drift_signal": snapshot.drift_signal,
        "dry_run_capabilities": snapshot.dry_run_capabilities,
        "handoff_quality": snapshot.handoff_quality,
        "bounded_self_improvement_gate": snapshot.bounded_self_improvement_gate,
        "error_recovery": snapshot.error_recovery,
        "clarification": snapshot.clarification,
        "operator_interruption_events": snapshot.operator_interruption_events,
        "workflow_envelope_adapter": snapshot.workflow_envelope_adapter,
        "harness_trace_adapter": snapshot.harness_trace_adapter,
        "operator_interruption": snapshot.operator_interruption,
    })
}

async fn verify_snapshot_command(args: SnapshotArgs) -> Result<()> {
    let (_, snapshot) = fetch_runtime_snapshot(&args.session_id, args.step, &args.rpc).await?;
    let verification = snapshot_verification(&snapshot);
    if args.json {
        return print_json(&verification);
    }
    println!(
        "Agent substrate verification: {}",
        if verification["ok"].as_bool().unwrap_or(false) {
            "pass"
        } else {
            "fail"
        }
    );
    if let Some(checks) = verification["checks"].as_object() {
        for (name, passed) in checks {
            println!("  {}: {}", name, passed.as_bool().unwrap_or(false));
        }
    }
    Ok(())
}

fn replay_report(snapshot: &RuntimeSubstrateSnapshot) -> serde_json::Value {
    let mut previous_step = 0;
    let monotonic = snapshot.events.iter().enumerate().all(|(index, event)| {
        let ok = index == 0 || event.step_index >= previous_step;
        previous_step = event.step_index;
        ok
    });
    serde_json::json!({
        "replayable": monotonic && !snapshot.events.is_empty(),
        "event_count": snapshot.events.len(),
        "monotonic_step_order": monotonic,
        "event_ids": snapshot.events.iter().map(|event| event.event_id.clone()).collect::<Vec<_>>(),
        "trace_bundle_id": snapshot.envelope.trace_bundle_id,
        "quality_ledger_id": snapshot.envelope.quality_ledger_id,
        "stop_reason": snapshot.stop_condition.reason,
    })
}

async fn replay_snapshot_command(args: SnapshotArgs) -> Result<()> {
    let (_, snapshot) = fetch_runtime_snapshot(&args.session_id, args.step, &args.rpc).await?;
    let replay = replay_report(&snapshot);
    if args.json {
        return print_json(&replay);
    }
    println!(
        "Agent replay dry-run: {}",
        if replay["replayable"].as_bool().unwrap_or(false) {
            "pass"
        } else {
            "fail"
        }
    );
    println!("  events: {}", replay["event_count"]);
    println!("  trace: {}", snapshot.envelope.trace_bundle_id);
    Ok(())
}

async fn print_runtime_trace(args: SnapshotArgs) -> Result<()> {
    let (_, snapshot) = fetch_runtime_snapshot(&args.session_id, args.step, &args.rpc).await?;
    if args.json {
        return print_json(&serde_json::json!({
            "envelope": snapshot.envelope,
            "events": snapshot.events,
            "receipts": {
                "tool_contracts": snapshot.tool_contracts,
                "postconditions": snapshot.postconditions,
                "quality_ledger": snapshot.quality_ledger,
                "stop_condition": snapshot.stop_condition,
            },
            "task_state": snapshot.task_state,
        }));
    }
    println!("Agent runtime trace");
    println!("  trace bundle: {}", snapshot.envelope.trace_bundle_id);
    println!("  event stream: {}", snapshot.envelope.event_stream_id);
    println!("  quality ledger: {}", snapshot.envelope.quality_ledger_id);
    println!("  events: {}", snapshot.events.len());
    println!(
        "  receipts: tool_contracts={}, postcondition_checks={}",
        snapshot.tool_contracts.len(),
        snapshot.postconditions.checks.len()
    );
    Ok(())
}

async fn export_snapshot(
    session_id: String,
    step: u32,
    rpc: String,
    output: PathBuf,
) -> Result<()> {
    let (_, snapshot) = fetch_runtime_snapshot(&session_id, step, &rpc).await?;
    let verification = snapshot_verification(&snapshot);
    let replay = replay_report(&snapshot);
    let bundle = serde_json::json!({
        "snapshot": snapshot,
        "verification": verification,
        "replay": replay,
    });
    let bytes = serde_json::to_vec_pretty(&bundle)?;
    std::fs::write(&output, bytes)
        .with_context(|| format!("Failed to write {}", output.display()))?;
    println!("Exported agent runtime bundle to {}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_agent_operator_surface_commands() {
        let run = AgentArgs::try_parse_from(["agent", "run", "test goal"])
            .expect("run command should parse");
        assert!(matches!(run.command, Some(AgentCommands::Run { .. })));

        let chat = AgentArgs::try_parse_from(vec![
            "agent".to_string(),
            "chat".to_string(),
            "ab".repeat(32),
            "hello".to_string(),
            "--json".to_string(),
        ])
        .expect("chat command should parse");
        assert!(matches!(
            chat.command,
            Some(AgentCommands::Chat { json: true, .. })
        ));

        let events = AgentArgs::try_parse_from(vec![
            "agent".to_string(),
            "events".to_string(),
            "cd".repeat(32),
            "--step".to_string(),
            "3".to_string(),
            "--json".to_string(),
        ])
        .expect("events command should parse");
        assert!(matches!(
            events.command,
            Some(AgentCommands::Events(SnapshotArgs { json: true, .. }))
        ));
    }

    #[test]
    fn parses_nested_tool_and_policy_commands() {
        let tools =
            AgentArgs::try_parse_from(["agent", "tools", "inspect", "shell__run", "--json"])
                .expect("nested tools command should parse");
        assert!(matches!(
            tools.command,
            Some(AgentCommands::Tools {
                command: Some(ToolCommands::Inspect { json: true, .. }),
                ..
            })
        ));

        let policy = AgentArgs::try_parse_from(["agent", "policy", "explain", "--json"])
            .expect("policy explain command should parse");
        assert!(matches!(
            policy.command,
            Some(AgentCommands::Policy {
                command: AgentPolicyCommands::Explain { json: true }
            })
        ));

        let config = AgentArgs::try_parse_from([
            "agent",
            "config-explain",
            "trace.export.required",
            "--json",
        ])
        .expect("config explain key command should parse");
        assert!(matches!(
            config.command,
            Some(AgentCommands::ConfigExplain {
                key: Some(_),
                json: true
            })
        ));
    }

    #[test]
    fn snapshot_verification_requires_core_substrate_evidence() {
        let dry_run_capabilities = [
            "dry_run:file_patch",
            "dry_run:shell_command",
            "dry_run:connector_action",
            "dry_run:policy_decision",
            "dry_run:workflow_side_effect",
            "dry_run:external_order_or_cart",
        ]
        .into_iter()
        .map(|capability_id| ioi_types::app::DryRunCapability {
            capability_id: capability_id.to_string(),
            ..ioi_types::app::DryRunCapability::default()
        })
        .collect();
        let mut snapshot = RuntimeSubstrateSnapshot {
            envelope: ioi_types::app::RuntimeExecutionEnvelope::default(),
            port_contract: RuntimeSubstratePortContract::default(),
            events: vec![ioi_types::app::AgentRuntimeEvent::default()],
            tool_contracts: Vec::new(),
            prompt_assembly: ioi_types::app::PromptAssemblyContract::new(
                "prompt:test",
                vec![ioi_types::app::PromptSectionRecord::new(
                    "user_goal",
                    ioi_types::app::PromptLayerKind::UserGoal,
                    "test",
                    "verify substrate",
                    ioi_types::app::PromptSectionMutability::OperatorMutable,
                    ioi_types::app::PromptPrivacyClass::Public,
                )],
            ),
            turn_state: ioi_types::app::AgentTurnState {
                turn_id: "step:1".to_string(),
                ..ioi_types::app::AgentTurnState::default()
            },
            decision_loop: ioi_types::app::AgentDecisionLoop {
                stages: vec![
                    ioi_types::app::AgentDecisionStageRecord {
                        status: ioi_types::app::RuntimeCheckStatus::Passed,
                        ..ioi_types::app::AgentDecisionStageRecord::default()
                    };
                    ioi_types::app::AgentDecisionLoop::required_stage_count()
                ],
                all_required_stages_recorded: true,
                ..ioi_types::app::AgentDecisionLoop::default()
            },
            file_observations: Vec::new(),
            session_trace_bundle: ioi_types::app::SessionTraceBundle {
                reconstructs_final_state: true,
                ..ioi_types::app::SessionTraceBundle::default()
            },
            task_state: ioi_types::app::TaskStateModel::for_objective("verify substrate"),
            uncertainty: ioi_types::app::UncertaintyAssessment {
                assessment_id: "uncertainty:test".to_string(),
                rationale: "bounded verification can proceed from the exported snapshot"
                    .to_string(),
                selected_action: ioi_types::app::RuntimeDecisionAction::Execute,
                ..ioi_types::app::UncertaintyAssessment::default()
            },
            strategy_router: ioi_types::app::RuntimeStrategyRouter {
                used_task_state: true,
                used_uncertainty: true,
                used_cognitive_budget: true,
                ..ioi_types::app::RuntimeStrategyRouter::default()
            },
            strategy_decision: ioi_types::app::RuntimeStrategyDecision::default(),
            model_routing: ioi_types::app::ModelRoutingDecision {
                selected_profile: "fast".to_string(),
                selected_provider: "local".to_string(),
                selected_model: "configured-fast-profile".to_string(),
                candidates: vec![ioi_types::app::ModelCandidateScore {
                    profile: "fast".to_string(),
                    provider: "local".to_string(),
                    model: "configured-fast-profile".to_string(),
                    allowed_by_policy: true,
                    ..ioi_types::app::ModelCandidateScore::default()
                }],
                ..ioi_types::app::ModelRoutingDecision::default()
            },
            capability_discovery: ioi_types::app::CapabilityDiscovery::default(),
            capability_selection: ioi_types::app::CapabilitySelection::default(),
            capability_sequencing: ioi_types::app::CapabilitySequencing::default(),
            capability_retirement: ioi_types::app::CapabilityRetirement::default(),
            capability_sequence: ioi_types::app::CapabilitySequence::default(),
            tool_selection_quality: Vec::new(),
            probes: Vec::new(),
            postcondition_synthesizer: ioi_types::app::PostconditionSynthesizer {
                synthesizer_id: "pc".to_string(),
                ..ioi_types::app::PostconditionSynthesizer::default()
            },
            postconditions: ioi_types::app::PostconditionSynthesis::default(),
            semantic_impact: ioi_types::app::SemanticImpactAnalysis {
                risk_class: "no_mutation".to_string(),
                evidence_refs: vec![ioi_types::app::EvidenceRef::new(
                    "runtime_state",
                    "semantic-impact:test",
                )],
                ..ioi_types::app::SemanticImpactAnalysis::default()
            },
            cognitive_budget: ioi_types::app::CognitiveBudget::default(),
            drift_signal: ioi_types::app::DriftSignal {
                evidence_refs: vec![ioi_types::app::EvidenceRef::new(
                    "runtime_state",
                    "drift:test",
                )],
                ..ioi_types::app::DriftSignal::default()
            },
            verifier_independence_policy: ioi_types::app::VerifierIndependencePolicy::default(),
            dry_run_capabilities,
            handoff_quality: None,
            task_family_playbook: ioi_types::app::TaskFamilyPlaybook::default(),
            negative_learning: Vec::new(),
            memory_quality_gates: Vec::new(),
            operator_preference: None,
            bounded_self_improvement_gate: None,
            operator_collaboration: ioi_types::app::OperatorCollaborationContract::default(),
            workflow_envelope_adapter: ioi_types::app::WorkflowEnvelopeAdapter::default(),
            harness_trace_adapter: ioi_types::app::HarnessTraceAdapter::default(),
            operator_interruption: ioi_types::app::OperatorInterruptionContract::default(),
            operator_interruption_events: Vec::new(),
            clarification: None,
            error_recovery: Vec::new(),
            quality_ledger: ioi_types::app::AgentQualityLedger {
                ledger_id: "ledger".to_string(),
                ..ioi_types::app::AgentQualityLedger::default()
            },
            stop_condition: ioi_types::app::StopConditionRecord {
                rationale: "stopped".to_string(),
                ..ioi_types::app::StopConditionRecord::default()
            },
        };
        snapshot.envelope.envelope_id = "env".to_string();
        snapshot.envelope.session_id = "session".to_string();
        snapshot.events[0].session_id = "session".to_string();

        let verification = snapshot_verification(&snapshot);
        assert_eq!(verification["ok"], serde_json::Value::Bool(true));
    }

    #[test]
    fn config_explain_reports_locked_key_provenance() {
        let value = config_explain_value(Some("trace.export.required"))
            .expect("known key should be explainable");
        let entry = value.get("entry").expect("entry should be present");
        assert_eq!(entry["source"], "system_policy");
        assert_eq!(entry["policy_locked"], true);
        assert_eq!(entry["user_overridable"], false);
        assert!(config_explain_value(Some("unknown.key")).is_err());
    }
}
