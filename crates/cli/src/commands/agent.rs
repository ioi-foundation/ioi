// Path: crates/cli/src/commands/agent.rs

use super::agent_event_stream::{
    resolve_daemon_endpoint, resolve_daemon_token, stream_agent_events, AgentEventStreamArgs,
};
use super::agent_tui::{run_agent_tui, AgentTuiArgs};
use super::model_mount_http::daemon_request;
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
use reqwest::Method;
use std::path::PathBuf;
use tonic::transport::Channel;

/// Service identifier for the daemon-hosted desktop agent runtime.
/// CLI command handlers are clients of this service; execution semantics remain
/// owned by the daemon/runtime substrate.
const DESKTOP_AGENT_SERVICE_ID: &str = "desktop_agent";
const CODING_TOOLS_ROUTE: &str = "/v1/tools?pack=coding";
const CODING_TOOL_INVOKE_ROUTE_TEMPLATE: &str = "/v1/threads/{thread_id}/tools/{tool_id}/invoke";
const COMPUTER_USE_BROWSER_DISCOVERY_ROUTE: &str = "/v1/computer-use/browser-discovery";

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
    /// Explain model route controls and ModelRouteDecision projection.
    Model {
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Explain thinking/reasoning effort controls for routed models.
    Thinking {
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Explain memory controls and remember/list runtime projection.
    Memory {
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Inspect daemon-discovered governed runtime skills.
    Skills {
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Inspect daemon-discovered governed runtime hooks.
    Hooks {
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Inspect daemon-owned durable runtime tasks.
    Tasks {
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
    /// Stream canonical thread/run events for CLI and TUI inspectors.
    Stream(AgentEventStreamArgs),
    /// Open the thin daemon-backed terminal agent UI over canonical thread events.
    Tui(AgentTuiArgs),
    /// Fork a canonical runtime thread through the daemon control endpoint.
    Fork {
        /// Runtime thread id to fork.
        #[clap(long = "thread-id")]
        thread_id: String,
        /// Operator-visible fork reason.
        #[clap(long, default_value = "operator requested thread fork")]
        reason: String,
        /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
        #[clap(long)]
        endpoint: Option<String>,
        /// Capability token. Defaults to IOI_DAEMON_TOKEN.
        #[clap(long)]
        token: Option<String>,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Interrupt a canonical runtime turn through the daemon control endpoint.
    Interrupt {
        /// Runtime thread id that owns the turn.
        #[clap(long = "thread-id")]
        thread_id: String,
        /// Runtime turn id to interrupt.
        #[clap(long = "turn-id")]
        turn_id: String,
        /// Operator-visible reason.
        #[clap(long, default_value = "operator requested interrupt")]
        reason: String,
        /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
        #[clap(long)]
        endpoint: Option<String>,
        /// Capability token. Defaults to IOI_DAEMON_TOKEN.
        #[clap(long)]
        token: Option<String>,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Add operator steering guidance to a canonical runtime turn.
    Steer {
        /// Runtime thread id that owns the turn.
        #[clap(long = "thread-id")]
        thread_id: String,
        /// Runtime turn id to steer.
        #[clap(long = "turn-id")]
        turn_id: String,
        /// Operator-visible steering guidance.
        #[clap(long, default_value = "operator provided steering guidance")]
        guidance: String,
        /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
        #[clap(long)]
        endpoint: Option<String>,
        /// Capability token. Defaults to IOI_DAEMON_TOKEN.
        #[clap(long)]
        token: Option<String>,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Compact canonical runtime thread context through the daemon control endpoint.
    Compact {
        /// Runtime thread id to compact.
        #[clap(long = "thread-id")]
        thread_id: String,
        /// Operator-visible compaction reason.
        #[clap(long, default_value = "operator requested context compaction")]
        reason: String,
        /// Compaction scope.
        #[clap(long, default_value = "thread")]
        scope: String,
        /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
        #[clap(long)]
        endpoint: Option<String>,
        /// Capability token. Defaults to IOI_DAEMON_TOKEN.
        #[clap(long)]
        token: Option<String>,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
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
    /// List daemon-discovered coding tool-pack contracts.
    Coding {
        /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
        #[clap(long)]
        endpoint: Option<String>,
        /// Capability token. Defaults to IOI_DAEMON_TOKEN.
        #[clap(long)]
        token: Option<String>,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Discover local browser sessions without attaching, relaunching, or copying profiles.
    BrowserDiscovery {
        /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
        #[clap(long)]
        endpoint: Option<String>,
        /// Capability token. Defaults to IOI_DAEMON_TOKEN.
        #[clap(long)]
        token: Option<String>,
        /// Probe declared CDP endpoints for read-only metadata.
        #[clap(long)]
        probe: bool,
        /// Include tab metadata when a declared CDP endpoint is probed.
        #[clap(long = "include-tabs")]
        include_tabs: bool,
        /// Reveal tab titles in discovery output. Defaults to redacted titles.
        #[clap(long = "reveal-tab-titles")]
        reveal_tab_titles: bool,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Run a read-only native-browser computer-use prompt through the daemon thread-tool spine.
    NativeBrowser {
        /// Runtime thread id that owns the computer-use event stream.
        #[clap(long = "thread-id")]
        thread_id: String,
        /// Prompt/goal to run through the native-browser harness.
        #[clap(long)]
        prompt: Option<String>,
        /// URL hint for the native-browser observation.
        #[clap(long)]
        url: Option<String>,
        /// Requested browser action kind. Mutating actions are proposal/commit-gate only until approved.
        #[clap(long = "action-kind", default_value = "inspect")]
        action_kind: String,
        /// Approval receipt/ref that allows a mutating browser action to execute.
        #[clap(long = "approval-ref")]
        approval_ref: Option<String>,
        /// Grounded target ref for the requested browser action, for example a selector-shaped #id.
        #[clap(long = "target-ref")]
        target_ref: Option<String>,
        /// CSS selector for approved click actions.
        #[clap(long)]
        selector: Option<String>,
        /// Text payload for approved type_text actions.
        #[clap(long)]
        text: Option<String>,
        /// Key payload for approved key_press actions, for example Enter or Escape.
        #[clap(long)]
        key: Option<String>,
        /// Horizontal scroll delta for explicit scroll actions.
        #[clap(long = "scroll-x")]
        scroll_x: Option<i64>,
        /// Vertical scroll delta for explicit scroll actions.
        #[clap(long = "scroll-y")]
        scroll_y: Option<i64>,
        /// File path for approved upload actions.
        #[clap(long = "file-path")]
        file_path: Option<String>,
        /// HTTP CDP endpoint, for example http://127.0.0.1:9222.
        #[clap(long = "cdp-endpoint-url")]
        cdp_endpoint_url: Option<String>,
        /// CDP websocket debugger URL.
        #[clap(long = "cdp-websocket-url")]
        cdp_websocket_url: Option<String>,
        /// CDP executor timeout in milliseconds.
        #[clap(long = "cdp-timeout-ms")]
        cdp_timeout_ms: Option<u64>,
        /// Observation retention mode.
        #[clap(
            long = "observation-retention-mode",
            default_value = "prompt_visible_summary_only"
        )]
        observation_retention_mode: String,
        /// Runtime turn id to associate with the tool result.
        #[clap(long = "turn-id")]
        turn_id: Option<String>,
        /// Workflow graph id for React Flow-originated invocations.
        #[clap(long = "workflow-graph-id")]
        workflow_graph_id: Option<String>,
        /// Workflow node id for React Flow-originated invocations.
        #[clap(long = "workflow-node-id")]
        workflow_node_id: Option<String>,
        /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
        #[clap(long)]
        endpoint: Option<String>,
        /// Capability token. Defaults to IOI_DAEMON_TOKEN.
        #[clap(long)]
        token: Option<String>,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Emit governed computer-use pause/resume/abort/cleanup control receipts.
    ComputerUseControl {
        /// Runtime thread id that owns the computer-use event stream.
        #[clap(long = "thread-id")]
        thread_id: String,
        /// Control action: pause, resume, abort, or cleanup.
        #[clap(long = "action")]
        action: String,
        /// Computer-use lease id to control.
        #[clap(long = "lease-id")]
        lease_id: String,
        /// Human handoff ref to pause/resume.
        #[clap(long = "handoff-ref")]
        handoff_ref: Option<String>,
        /// Operator-visible reason.
        #[clap(long)]
        reason: Option<String>,
        /// Observation ref supplied after a resume handoff.
        #[clap(long = "resume-observation-ref")]
        resume_observation_ref: Option<String>,
        /// CDP endpoint supplied after a controlled relaunch resume.
        #[clap(long = "cdp-endpoint-url")]
        cdp_endpoint_url: Option<String>,
        /// Runtime turn id to associate with the control receipt.
        #[clap(long = "turn-id")]
        turn_id: Option<String>,
        /// Workflow graph id for React Flow-originated controls.
        #[clap(long = "workflow-graph-id")]
        workflow_graph_id: Option<String>,
        /// Workflow node id for React Flow-originated controls.
        #[clap(long = "workflow-node-id")]
        workflow_node_id: Option<String>,
        /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
        #[clap(long)]
        endpoint: Option<String>,
        /// Capability token. Defaults to IOI_DAEMON_TOKEN.
        #[clap(long)]
        token: Option<String>,
        /// Emit machine-readable JSON.
        #[clap(long)]
        json: bool,
    },
    /// Invoke a daemon-backed coding tool for a runtime thread.
    Run {
        /// Coding tool id, for example workspace.status, git.diff, file.inspect, file.apply_patch, test.run, lsp.diagnostics, artifact.read, or tool.retrieve_result.
        tool: String,
        /// Runtime thread id that owns the tool event stream.
        #[clap(long = "thread-id")]
        thread_id: String,
        /// Workspace-relative path for file.inspect, git.diff, file.apply_patch, test.run, or lsp.diagnostics.
        #[clap(long)]
        path: Option<String>,
        /// Structured command id for test.run or lsp.diagnostics, for example node.test, auto, node.check, or typescript.check.
        #[clap(long = "command-id")]
        command_id: Option<String>,
        /// Workspace-relative cwd for test.run or lsp.diagnostics.
        #[clap(long)]
        cwd: Option<String>,
        /// Extra structured argument for test.run or lsp.diagnostics. Repeat for multiple args.
        #[clap(long = "test-arg")]
        test_args: Vec<String>,
        /// Timeout in milliseconds for test.run or lsp.diagnostics.
        #[clap(long = "timeout-ms")]
        timeout_ms: Option<u64>,
        /// Maximum stdout/stderr preview bytes for test.run or lsp.diagnostics.
        #[clap(long = "max-output-bytes")]
        max_output_bytes: Option<u64>,
        /// Artifact id/ref for artifact.read or tool.retrieve_result.
        #[clap(long = "artifact-id")]
        artifact_id: Option<String>,
        /// Tool call id for tool.retrieve_result.
        #[clap(long = "tool-call-id")]
        tool_call_id: Option<String>,
        /// Byte offset for artifact.read or tool.retrieve_result.
        #[clap(long = "offset-bytes")]
        offset_bytes: Option<u64>,
        /// Byte length for artifact.read or tool.retrieve_result.
        #[clap(long = "length-bytes")]
        length_bytes: Option<u64>,
        /// Exact text to replace for file.apply_patch.
        #[clap(long = "old-text")]
        old_text: Option<String>,
        /// Replacement text for file.apply_patch.
        #[clap(long = "new-text")]
        new_text: Option<String>,
        /// Text to append for file.apply_patch.
        #[clap(long = "append-text")]
        append_text: Option<String>,
        /// Text to prepend for file.apply_patch.
        #[clap(long = "prepend-text")]
        prepend_text: Option<String>,
        /// Preview a file.apply_patch result without writing.
        #[clap(long = "dry-run")]
        dry_run: bool,
        /// Allow file.apply_patch to create a missing file when the parent directory exists.
        #[clap(long)]
        create: bool,
        /// Runtime turn id to associate with the tool result.
        #[clap(long = "turn-id")]
        turn_id: Option<String>,
        /// Workflow graph id for React Flow-originated invocations.
        #[clap(long = "workflow-graph-id")]
        workflow_graph_id: Option<String>,
        /// Workflow node id for React Flow-originated invocations.
        #[clap(long = "workflow-node-id")]
        workflow_node_id: Option<String>,
        /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
        #[clap(long)]
        endpoint: Option<String>,
        /// Capability token. Defaults to IOI_DAEMON_TOKEN.
        #[clap(long)]
        token: Option<String>,
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
        runtime_route_frame: None,
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
        AgentCommands::Model { json } => print_model_route_controls(json),
        AgentCommands::Thinking { json } => print_thinking_controls(json),
        AgentCommands::Memory { json } => print_memory_controls(json),
        AgentCommands::Skills { json } => {
            print_runtime_catalog(json, "/v1/skills", "skills", "skillCount").await
        }
        AgentCommands::Hooks { json } => {
            print_runtime_catalog(json, "/v1/hooks", "hooks", "hookCount").await
        }
        AgentCommands::Tasks { json } => print_runtime_list(json, "/v1/tasks", "tasks").await,
        AgentCommands::Tools {
            command,
            tool,
            json,
        } => run_tool_command(command, tool, json).await,
        AgentCommands::ConfigExplain { key, json } => print_config_explain(key.as_deref(), json),
        AgentCommands::Policy { command } => run_policy_command(command),
        AgentCommands::Doctor { json } => print_doctor(json).await,
        AgentCommands::Status {
            session_id,
            step,
            rpc,
            json,
        } => print_status(session_id, step, rpc, json).await,
        AgentCommands::Events(args) => print_events(args).await,
        AgentCommands::Stream(args) => stream_agent_events(args).await,
        AgentCommands::Tui(args) => run_agent_tui(args).await,
        AgentCommands::Fork {
            thread_id,
            reason,
            endpoint,
            token,
            json,
        } => fork_thread(thread_id, reason, endpoint, token, json).await,
        AgentCommands::Interrupt {
            thread_id,
            turn_id,
            reason,
            endpoint,
            token,
            json,
        } => interrupt_turn(thread_id, turn_id, reason, endpoint, token, json).await,
        AgentCommands::Steer {
            thread_id,
            turn_id,
            guidance,
            endpoint,
            token,
            json,
        } => steer_turn(thread_id, turn_id, guidance, endpoint, token, json).await,
        AgentCommands::Compact {
            thread_id,
            reason,
            scope,
            endpoint,
            token,
            json,
        } => compact_thread(thread_id, reason, scope, endpoint, token, json).await,
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

async fn fork_thread(
    thread_id: String,
    reason: String,
    endpoint: Option<String>,
    token: Option<String>,
    json: bool,
) -> Result<()> {
    let route = format!("/v1/threads/{thread_id}/fork");
    let response = daemon_request(
        endpoint.as_deref(),
        token.as_deref(),
        Method::POST,
        &route,
        Some(serde_json::json!({
            "reason": reason,
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.Fork",
            "component_kind": "thread_fork",
            "workflow_node_id": "runtime.thread-fork",
        })),
    )
    .await?;
    if json {
        return print_json(&response);
    }
    println!(
        "Forked thread {} into {}",
        thread_id,
        response
            .get("thread_id")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown")
    );
    Ok(())
}

async fn interrupt_turn(
    thread_id: String,
    turn_id: String,
    reason: String,
    endpoint: Option<String>,
    token: Option<String>,
    json: bool,
) -> Result<()> {
    let route = format!("/v1/threads/{thread_id}/turns/{turn_id}/interrupt");
    let response = daemon_request(
        endpoint.as_deref(),
        token.as_deref(),
        Method::POST,
        &route,
        Some(serde_json::json!({
            "reason": reason,
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.Interrupt",
            "component_kind": "operator_control",
            "workflow_node_id": "runtime.operator-interrupt",
        })),
    )
    .await?;
    if json {
        return print_json(&response);
    }
    println!(
        "Interrupted turn {} on thread {}: status={}",
        turn_id,
        thread_id,
        response
            .get("status")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown")
    );
    Ok(())
}

async fn steer_turn(
    thread_id: String,
    turn_id: String,
    guidance: String,
    endpoint: Option<String>,
    token: Option<String>,
    json: bool,
) -> Result<()> {
    let route = format!("/v1/threads/{thread_id}/turns/{turn_id}/steer");
    let response = daemon_request(
        endpoint.as_deref(),
        token.as_deref(),
        Method::POST,
        &route,
        Some(serde_json::json!({
            "guidance": guidance,
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.Steer",
            "component_kind": "operator_control",
            "workflow_node_id": "runtime.operator-steer",
        })),
    )
    .await?;
    if json {
        return print_json(&response);
    }
    println!(
        "Steered turn {} on thread {}: status={}",
        turn_id,
        thread_id,
        response
            .get("status")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown")
    );
    Ok(())
}

async fn compact_thread(
    thread_id: String,
    reason: String,
    scope: String,
    endpoint: Option<String>,
    token: Option<String>,
    json: bool,
) -> Result<()> {
    let route = format!("/v1/threads/{thread_id}/compact");
    let response = daemon_request(
        endpoint.as_deref(),
        token.as_deref(),
        Method::POST,
        &route,
        Some(serde_json::json!({
            "reason": reason,
            "scope": scope,
            "source": "cli_tui",
            "actor": "operator",
            "event_kind": "OperatorControl.Compact",
            "component_kind": "context_compaction",
            "workflow_node_id": "runtime.context-compact",
        })),
    )
    .await?;
    if json {
        return print_json(&response);
    }
    println!(
        "Compacted thread {}: latest_seq={}",
        thread_id,
        response
            .get("latest_seq")
            .and_then(|value| value.as_u64())
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string())
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

fn model_route_controls_contract() -> serde_json::Value {
    serde_json::json!({
        "schema_version": "ioi.agent-runtime.route-controls.v1",
        "commands": ["/model", "/thinking"],
        "surfaces": ["chat", "tui", "cli", "reactflow_workflow_node"],
        "event": "ModelRouteDecision",
        "event_type": "model_route_decision",
        "receipt_kind": "model_route_selection",
        "daemon_fields": [
            "model_route_decision",
            "model_route_receipt_id",
            "requested_model",
            "model_route_id"
        ],
        "workflow_config": {
            "node_type": "Model Router",
            "reactflow_fields": [
                "model.id",
                "model.routeId",
                "model.reasoningEffort",
                "model.privacy",
                "model.maxCostUsd",
                "model.allowHostedFallback",
                "model.workflowGraphId",
                "model.workflowNodeId"
            ]
        },
        "invariants": {
            "never_send_auto_upstream": true,
            "emit_decision_before_delta": true,
            "fallback_requires_receipt": true
        }
    })
}

fn print_model_route_controls(json: bool) -> Result<()> {
    let value = model_route_controls_contract();
    if json {
        return print_json(&value);
    }
    println!("Agent model controls");
    println!("  slash command: /model");
    println!("  event: ModelRouteDecision");
    println!("  receipt: model_route_selection");
    println!("  workflow node: Model Router");
    Ok(())
}

fn print_thinking_controls(json: bool) -> Result<()> {
    let value = serde_json::json!({
        "schema_version": "ioi.agent-runtime.thinking-controls.v1",
        "command": "/thinking",
        "field": "model.reasoningEffort",
        "accepted_values": ["low", "medium", "high", "xhigh"],
        "projection": "ModelRouteDecision.reasoningEffort",
        "surfaces": ["chat", "tui", "cli", "reactflow_workflow_node"],
        "fallback_behavior": "preserve requested thinking level in the fallback route decision"
    });
    if json {
        return print_json(&value);
    }
    println!("Agent thinking controls");
    println!("  slash command: /thinking");
    println!("  field: model.reasoningEffort");
    println!("  projection: ModelRouteDecision.reasoningEffort");
    Ok(())
}

fn print_memory_controls(json: bool) -> Result<()> {
    let value = serde_json::json!({
        "schema_version": "ioi.agent-runtime.memory-controls.v1",
        "commands": [
            "# remember",
            "/memory",
            "/memory show",
            "/memory disable",
            "/memory enable",
            "/memory path",
            "/memory edit <id> <text>",
            "/memory delete <id>"
        ],
        "events": ["memory_update"],
        "event_kinds": ["MemoryWrite", "MemoryEdit", "MemoryDelete", "MemoryPolicy"],
        "receipt_kinds": ["memory_write", "memory_edit", "memory_delete", "memory_policy"],
        "daemon_endpoints": [
            "/v1/agents/{id}/memory",
            "/v1/agents/{id}/memory/{memory_id}",
            "/v1/agents/{id}/memory/policy",
            "/v1/agents/{id}/memory/path",
            "/v1/threads/{id}/memory",
            "/v1/threads/{id}/memory/{memory_id}",
            "/v1/threads/{id}/memory/policy",
            "/v1/threads/{id}/memory/path"
        ],
        "workflow_config": {
            "node_types": ["MemoryScopeNode", "RememberNode", "MemoryInjectionNode", "MemoryPolicyNode", "MemoryEditNode"],
            "reactflow_fields": [
                "memory.scope",
                "memory.injectionEnabled",
                "memory.readOnly",
                "memory.writeRequiresApproval",
                "memory.retention",
                "memory.redaction",
                "memory.subagentInheritance"
            ]
        },
        "invariants": {
            "writes_emit_receipts": true,
            "thread_memory_is_explicit": true,
            "workflow_memory_can_be_disabled": true,
            "read_only_blocks_writes": true,
            "write_requires_approval_fails_closed": true,
            "subagent_memory_inheritance_is_explicit": true
        }
    });
    if json {
        return print_json(&value);
    }
    println!("Agent memory controls");
    println!("  remember: # remember <fact>");
    println!("  show: /memory show");
    println!("  disable: /memory disable");
    println!("  path: /memory path");
    println!("  edit: /memory edit <id> <text>");
    println!("  event: memory_update");
    println!("  receipts: memory_write, memory_edit, memory_delete, memory_policy");
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

async fn run_tool_command(
    command: Option<ToolCommands>,
    legacy_tool: Option<String>,
    json: bool,
) -> Result<()> {
    match command {
        Some(ToolCommands::List { json }) => print_agent_tools(None, json),
        Some(ToolCommands::Inspect { tool, json }) => print_agent_tools(Some(&tool), json),
        Some(ToolCommands::ExplainPolicy { tool, json }) => print_tool_policy(&tool, json),
        Some(ToolCommands::Coding {
            endpoint,
            token,
            json,
        }) => print_coding_tool_catalog(endpoint, token, json).await,
        Some(ToolCommands::BrowserDiscovery {
            endpoint,
            token,
            probe,
            include_tabs,
            reveal_tab_titles,
            json,
        }) => {
            print_browser_discovery(
                endpoint,
                token,
                probe,
                include_tabs,
                reveal_tab_titles,
                json,
            )
            .await
        }
        Some(ToolCommands::NativeBrowser {
            thread_id,
            prompt,
            url,
            action_kind,
            approval_ref,
            target_ref,
            selector,
            text,
            key,
            scroll_x,
            scroll_y,
            file_path,
            cdp_endpoint_url,
            cdp_websocket_url,
            cdp_timeout_ms,
            observation_retention_mode,
            turn_id,
            workflow_graph_id,
            workflow_node_id,
            endpoint,
            token,
            json,
        }) => {
            invoke_native_browser_tool(
                thread_id,
                prompt,
                url,
                action_kind,
                approval_ref,
                target_ref,
                selector,
                text,
                key,
                scroll_x,
                scroll_y,
                file_path,
                cdp_endpoint_url,
                cdp_websocket_url,
                cdp_timeout_ms,
                observation_retention_mode,
                turn_id,
                workflow_graph_id,
                workflow_node_id,
                endpoint,
                token,
                json,
            )
            .await
        }
        Some(ToolCommands::ComputerUseControl {
            thread_id,
            action,
            lease_id,
            handoff_ref,
            reason,
            resume_observation_ref,
            cdp_endpoint_url,
            turn_id,
            workflow_graph_id,
            workflow_node_id,
            endpoint,
            token,
            json,
        }) => {
            invoke_computer_use_control_tool(
                thread_id,
                action,
                lease_id,
                handoff_ref,
                reason,
                resume_observation_ref,
                cdp_endpoint_url,
                turn_id,
                workflow_graph_id,
                workflow_node_id,
                endpoint,
                token,
                json,
            )
            .await
        }
        Some(ToolCommands::Run {
            tool,
            thread_id,
            path,
            command_id,
            cwd,
            test_args,
            timeout_ms,
            max_output_bytes,
            artifact_id,
            tool_call_id,
            offset_bytes,
            length_bytes,
            old_text,
            new_text,
            append_text,
            prepend_text,
            dry_run,
            create,
            turn_id,
            workflow_graph_id,
            workflow_node_id,
            endpoint,
            token,
            json,
        }) => {
            invoke_coding_tool(
                tool,
                thread_id,
                path,
                command_id,
                cwd,
                test_args,
                timeout_ms,
                max_output_bytes,
                artifact_id,
                tool_call_id,
                offset_bytes,
                length_bytes,
                old_text,
                new_text,
                append_text,
                prepend_text,
                dry_run,
                create,
                turn_id,
                workflow_graph_id,
                workflow_node_id,
                endpoint,
                token,
                json,
            )
            .await
        }
        None => print_agent_tools(legacy_tool.as_deref(), json),
    }
}

async fn print_browser_discovery(
    endpoint: Option<String>,
    token: Option<String>,
    probe: bool,
    include_tabs: bool,
    reveal_tab_titles: bool,
    json: bool,
) -> Result<()> {
    let endpoint = resolve_daemon_endpoint(endpoint.as_deref());
    let token = resolve_daemon_token(token.as_deref());
    let route = format!(
        "{}?probe={}&include_tabs={}&reveal_tab_titles={}",
        COMPUTER_USE_BROWSER_DISCOVERY_ROUTE, probe, include_tabs, reveal_tab_titles
    );
    let value =
        daemon_request(Some(&endpoint), token.as_deref(), Method::GET, &route, None).await?;
    if json {
        return print_json(&serde_json::json!({
            "schema_version": "ioi.agent-cli.browser-discovery.v1",
            "tool_ref": "ioi.computer_use.browser_discovery",
            "endpoint": endpoint,
            "route": route,
            "browser_discovery_report": value,
        }));
    }
    let browser_process_count = value
        .get("browser_process_count")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let cdp_endpoint_count = value
        .get("cdp_endpoint_count")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let blocker_count = value
        .get("default_profile_remote_debugging_blockers")
        .and_then(|value| value.as_array())
        .map(Vec::len)
        .unwrap_or(0);
    let read_only = value
        .pointer("/safety/read_only")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
    let receipt = value
        .get("receipt_ref")
        .and_then(|value| value.as_str())
        .unwrap_or("none");
    println!(
        "Agent browser discovery: browsers={browser_process_count} cdp={cdp_endpoint_count} default_profile_blockers={blocker_count} read_only={read_only}"
    );
    println!("  receipt: {receipt}");
    if let Some(next_steps) = value
        .get("recommended_next_steps")
        .and_then(|value| value.as_array())
    {
        for step in next_steps.iter().filter_map(|value| value.as_str()).take(3) {
            println!("  next: {step}");
        }
    }
    Ok(())
}

async fn print_coding_tool_catalog(
    endpoint: Option<String>,
    token: Option<String>,
    json: bool,
) -> Result<()> {
    let endpoint = resolve_daemon_endpoint(endpoint.as_deref());
    let token = resolve_daemon_token(token.as_deref());
    let value = daemon_request(
        Some(&endpoint),
        token.as_deref(),
        Method::GET,
        CODING_TOOLS_ROUTE,
        None,
    )
    .await?;
    if json {
        return print_json(&serde_json::json!({
            "schema_version": "ioi.agent-cli.coding-tool-pack.v1",
            "tool_pack": "coding",
            "endpoint": endpoint,
            "route": CODING_TOOLS_ROUTE,
            "tools": value,
        }));
    }
    let count = value.as_array().map(Vec::len).unwrap_or(0);
    println!("Agent coding tools: {count}");
    if let Some(tools) = value.as_array() {
        for tool in tools {
            let id = tool
                .get("stableToolId")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let display = tool
                .get("displayName")
                .and_then(|value| value.as_str())
                .unwrap_or(id);
            let node = tool
                .get("workflowNodeType")
                .and_then(|value| value.as_str())
                .unwrap_or("CodingToolNode");
            println!("  {id}: {display} node={node}");
        }
    }
    Ok(())
}

async fn invoke_native_browser_tool(
    thread_id: String,
    prompt: Option<String>,
    url: Option<String>,
    action_kind: String,
    approval_ref: Option<String>,
    target_ref: Option<String>,
    selector: Option<String>,
    text: Option<String>,
    key: Option<String>,
    scroll_x: Option<i64>,
    scroll_y: Option<i64>,
    file_path: Option<String>,
    cdp_endpoint_url: Option<String>,
    cdp_websocket_url: Option<String>,
    cdp_timeout_ms: Option<u64>,
    observation_retention_mode: String,
    turn_id: Option<String>,
    workflow_graph_id: Option<String>,
    workflow_node_id: Option<String>,
    endpoint: Option<String>,
    token: Option<String>,
    json: bool,
) -> Result<()> {
    let endpoint = resolve_daemon_endpoint(endpoint.as_deref());
    let token = resolve_daemon_token(token.as_deref());
    let mut body = serde_json::Map::new();
    body.insert(
        "source".to_string(),
        serde_json::Value::String("sdk_client".to_string()),
    );
    let mut input = serde_json::Map::new();
    if let Some(prompt) = prompt.as_deref().filter(|value| !value.trim().is_empty()) {
        input.insert(
            "prompt".to_string(),
            serde_json::Value::String(prompt.trim().to_string()),
        );
    }
    if let Some(url) = url.as_deref().filter(|value| !value.trim().is_empty()) {
        input.insert(
            "url".to_string(),
            serde_json::Value::String(url.trim().to_string()),
        );
    }
    if !action_kind.trim().is_empty() {
        input.insert(
            "actionKind".to_string(),
            serde_json::Value::String(action_kind.trim().to_string()),
        );
    }
    if let Some(approval_ref) = approval_ref
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "approvalRef".to_string(),
            serde_json::Value::String(approval_ref.trim().to_string()),
        );
    }
    if let Some(target_ref) = target_ref
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "targetRef".to_string(),
            serde_json::Value::String(target_ref.trim().to_string()),
        );
    }
    if let Some(selector) = selector.as_deref().filter(|value| !value.trim().is_empty()) {
        input.insert(
            "selector".to_string(),
            serde_json::Value::String(selector.trim().to_string()),
        );
    }
    if let Some(text) = text.as_deref().filter(|value| !value.trim().is_empty()) {
        input.insert(
            "text".to_string(),
            serde_json::Value::String(text.trim().to_string()),
        );
    }
    if let Some(key) = key.as_deref().filter(|value| !value.trim().is_empty()) {
        input.insert(
            "key".to_string(),
            serde_json::Value::String(key.trim().to_string()),
        );
    }
    if let Some(scroll_x) = scroll_x {
        input.insert(
            "scrollX".to_string(),
            serde_json::Value::Number(scroll_x.into()),
        );
    }
    if let Some(scroll_y) = scroll_y {
        input.insert(
            "scrollY".to_string(),
            serde_json::Value::Number(scroll_y.into()),
        );
    }
    if let Some(file_path) = file_path
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "filePath".to_string(),
            serde_json::Value::String(file_path.trim().to_string()),
        );
    }
    if let Some(cdp_endpoint_url) = cdp_endpoint_url
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "cdpEndpointUrl".to_string(),
            serde_json::Value::String(cdp_endpoint_url.trim().to_string()),
        );
    }
    if let Some(cdp_websocket_url) = cdp_websocket_url
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "cdpWebSocketUrl".to_string(),
            serde_json::Value::String(cdp_websocket_url.trim().to_string()),
        );
    }
    if let Some(cdp_timeout_ms) = cdp_timeout_ms {
        input.insert(
            "cdpTimeoutMs".to_string(),
            serde_json::Value::Number(cdp_timeout_ms.into()),
        );
    }
    input.insert(
        "observationRetentionMode".to_string(),
        serde_json::Value::String(observation_retention_mode),
    );
    body.insert("input".to_string(), serde_json::Value::Object(input));
    if let Some(turn_id) = turn_id.as_deref().filter(|value| !value.trim().is_empty()) {
        body.insert(
            "turn_id".to_string(),
            serde_json::Value::String(turn_id.to_string()),
        );
    }
    if let Some(workflow_graph_id) = workflow_graph_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        body.insert(
            "workflow_graph_id".to_string(),
            serde_json::Value::String(workflow_graph_id.to_string()),
        );
    }
    body.insert(
        "workflow_node_id".to_string(),
        serde_json::Value::String(
            workflow_node_id
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("computer-use.native-browser.cli")
                .to_string(),
        ),
    );
    let route = coding_tool_invoke_route(&thread_id, "ioi.computer_use.native_browser");
    let value = daemon_request(
        Some(&endpoint),
        token.as_deref(),
        Method::POST,
        &route,
        Some(serde_json::Value::Object(body)),
    )
    .await?;
    if json {
        return print_json(&value);
    }
    let status = value
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let event_count = value
        .get("event_count")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let workflow_node = value
        .get("workflow_node_id")
        .and_then(|value| value.as_str())
        .unwrap_or("computer-use.native-browser.cli");
    let action_status = value
        .pointer("/result/actionReceipt/status")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let commit_gate_status = value
        .pointer("/result/commitGate/status")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    println!(
        "Native browser computer-use: thread={thread_id} status={status} node={workflow_node} events={event_count} action={action_status} commit_gate={commit_gate_status}"
    );
    Ok(())
}

async fn invoke_computer_use_control_tool(
    thread_id: String,
    action: String,
    lease_id: String,
    handoff_ref: Option<String>,
    reason: Option<String>,
    resume_observation_ref: Option<String>,
    cdp_endpoint_url: Option<String>,
    turn_id: Option<String>,
    workflow_graph_id: Option<String>,
    workflow_node_id: Option<String>,
    endpoint: Option<String>,
    token: Option<String>,
    json: bool,
) -> Result<()> {
    let endpoint = resolve_daemon_endpoint(endpoint.as_deref());
    let token = resolve_daemon_token(token.as_deref());
    let mut body = serde_json::Map::new();
    body.insert(
        "source".to_string(),
        serde_json::Value::String("cli".to_string()),
    );
    let mut input = serde_json::Map::new();
    input.insert(
        "controlAction".to_string(),
        serde_json::Value::String(action.trim().to_string()),
    );
    input.insert(
        "leaseId".to_string(),
        serde_json::Value::String(lease_id.trim().to_string()),
    );
    if let Some(handoff_ref) = handoff_ref
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "handoffRef".to_string(),
            serde_json::Value::String(handoff_ref.trim().to_string()),
        );
    }
    if let Some(reason) = reason.as_deref().filter(|value| !value.trim().is_empty()) {
        input.insert(
            "reason".to_string(),
            serde_json::Value::String(reason.trim().to_string()),
        );
    }
    if let Some(resume_observation_ref) = resume_observation_ref
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "resumeObservationRef".to_string(),
            serde_json::Value::String(resume_observation_ref.trim().to_string()),
        );
    }
    if let Some(cdp_endpoint_url) = cdp_endpoint_url
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        input.insert(
            "cdpEndpointUrl".to_string(),
            serde_json::Value::String(cdp_endpoint_url.trim().to_string()),
        );
    }
    body.insert("input".to_string(), serde_json::Value::Object(input));
    if let Some(turn_id) = turn_id.as_deref().filter(|value| !value.trim().is_empty()) {
        body.insert(
            "turn_id".to_string(),
            serde_json::Value::String(turn_id.to_string()),
        );
    }
    if let Some(workflow_graph_id) = workflow_graph_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        body.insert(
            "workflow_graph_id".to_string(),
            serde_json::Value::String(workflow_graph_id.to_string()),
        );
    }
    body.insert(
        "workflow_node_id".to_string(),
        serde_json::Value::String(
            workflow_node_id
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("computer-use.control.cli")
                .to_string(),
        ),
    );
    let route = coding_tool_invoke_route(&thread_id, "ioi.computer_use.control");
    let value = daemon_request(
        Some(&endpoint),
        token.as_deref(),
        Method::POST,
        &route,
        Some(serde_json::Value::Object(body)),
    )
    .await?;
    if json {
        return print_json(&value);
    }
    let status = value
        .pointer("/result/controlReceipt/status")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| value.get("status").and_then(|value| value.as_str()).unwrap_or("unknown"));
    let receipt = value
        .pointer("/result/controlReceipt/receipt_ref")
        .and_then(|value| value.as_str())
        .unwrap_or("none");
    println!(
        "Computer-use control: thread={thread_id} lease={lease_id} action={} status={status} receipt={receipt}",
        action.trim()
    );
    Ok(())
}

async fn invoke_coding_tool(
    tool: String,
    thread_id: String,
    path: Option<String>,
    command_id: Option<String>,
    cwd: Option<String>,
    test_args: Vec<String>,
    timeout_ms: Option<u64>,
    max_output_bytes: Option<u64>,
    artifact_id: Option<String>,
    tool_call_id: Option<String>,
    offset_bytes: Option<u64>,
    length_bytes: Option<u64>,
    old_text: Option<String>,
    new_text: Option<String>,
    append_text: Option<String>,
    prepend_text: Option<String>,
    dry_run: bool,
    create: bool,
    turn_id: Option<String>,
    workflow_graph_id: Option<String>,
    workflow_node_id: Option<String>,
    endpoint: Option<String>,
    token: Option<String>,
    json: bool,
) -> Result<()> {
    if tool == "file.inspect" && path.as_deref().map(str::trim).unwrap_or("").is_empty() {
        return Err(anyhow!(
            "agent tools run file.inspect requires --path <workspace-relative-path>"
        ));
    }
    if tool == "file.apply_patch" && path.as_deref().map(str::trim).unwrap_or("").is_empty() {
        return Err(anyhow!(
            "agent tools run file.apply_patch requires --path <workspace-relative-path>"
        ));
    }
    if tool == "lsp.diagnostics" && path.as_deref().map(str::trim).unwrap_or("").is_empty() {
        return Err(anyhow!(
            "agent tools run lsp.diagnostics requires --path <workspace-relative-path>"
        ));
    }
    let endpoint = resolve_daemon_endpoint(endpoint.as_deref());
    let token = resolve_daemon_token(token.as_deref());
    let mut body = serde_json::Map::new();
    body.insert(
        "source".to_string(),
        serde_json::Value::String("sdk_client".to_string()),
    );
    let mut input = serde_json::Map::new();
    if let Some(path) = path.as_deref().filter(|value| !value.trim().is_empty()) {
        input.insert(
            "path".to_string(),
            serde_json::Value::String(path.to_string()),
        );
    }
    if tool == "test.run" || tool == "lsp.diagnostics" {
        if let Some(command_id) = command_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            input.insert(
                "commandId".to_string(),
                serde_json::Value::String(command_id.to_string()),
            );
        }
        if let Some(cwd) = cwd.as_deref().filter(|value| !value.trim().is_empty()) {
            input.insert(
                "cwd".to_string(),
                serde_json::Value::String(cwd.to_string()),
            );
        }
        if !test_args.is_empty() {
            input.insert(
                "args".to_string(),
                serde_json::Value::Array(
                    test_args
                        .iter()
                        .map(|value| serde_json::Value::String(value.to_string()))
                        .collect(),
                ),
            );
        }
        if let Some(timeout_ms) = timeout_ms {
            input.insert(
                "timeoutMs".to_string(),
                serde_json::Value::Number(timeout_ms.into()),
            );
        }
        if let Some(max_output_bytes) = max_output_bytes {
            input.insert(
                "maxOutputBytes".to_string(),
                serde_json::Value::Number(max_output_bytes.into()),
            );
        }
    }
    if tool == "artifact.read" || tool == "tool.retrieve_result" {
        if let Some(artifact_id) = artifact_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            input.insert(
                "artifactId".to_string(),
                serde_json::Value::String(artifact_id.to_string()),
            );
        }
        if let Some(tool_call_id) = tool_call_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            input.insert(
                "toolCallId".to_string(),
                serde_json::Value::String(tool_call_id.to_string()),
            );
        }
        if let Some(offset_bytes) = offset_bytes {
            input.insert(
                "offsetBytes".to_string(),
                serde_json::Value::Number(offset_bytes.into()),
            );
        }
        if let Some(length_bytes) = length_bytes.or(max_output_bytes) {
            input.insert(
                "lengthBytes".to_string(),
                serde_json::Value::Number(length_bytes.into()),
            );
        }
        if tool == "artifact.read" && !input.contains_key("artifactId") {
            return Err(anyhow!(
                "agent tools run artifact.read requires --artifact-id <artifact-ref>"
            ));
        }
        if tool == "tool.retrieve_result"
            && !input.contains_key("artifactId")
            && !input.contains_key("toolCallId")
        {
            return Err(anyhow!(
                "agent tools run tool.retrieve_result requires --artifact-id or --tool-call-id"
            ));
        }
    }
    if let Some(old_text) = old_text
        .as_deref()
        .filter(|value| tool == "file.apply_patch" && !value.is_empty())
    {
        input.insert(
            "oldText".to_string(),
            serde_json::Value::String(old_text.to_string()),
        );
    }
    if let Some(new_text) = new_text.as_deref().filter(|_| tool == "file.apply_patch") {
        input.insert(
            "newText".to_string(),
            serde_json::Value::String(new_text.to_string()),
        );
    }
    if let Some(append_text) = append_text
        .as_deref()
        .filter(|_| tool == "file.apply_patch")
    {
        input.insert(
            "appendText".to_string(),
            serde_json::Value::String(append_text.to_string()),
        );
    }
    if let Some(prepend_text) = prepend_text
        .as_deref()
        .filter(|_| tool == "file.apply_patch")
    {
        input.insert(
            "prependText".to_string(),
            serde_json::Value::String(prepend_text.to_string()),
        );
    }
    if tool == "file.apply_patch" {
        if dry_run {
            input.insert("dryRun".to_string(), serde_json::Value::Bool(true));
        }
        if create {
            input.insert("create".to_string(), serde_json::Value::Bool(true));
        }
        let has_edit = input.contains_key("oldText")
            || input.contains_key("appendText")
            || input.contains_key("prependText");
        if !has_edit {
            return Err(anyhow!(
                "agent tools run file.apply_patch requires --old-text/--new-text, --append-text, or --prepend-text"
            ));
        }
    }
    if !input.is_empty() {
        body.insert("input".to_string(), serde_json::Value::Object(input));
    }
    if let Some(turn_id) = turn_id.as_deref().filter(|value| !value.trim().is_empty()) {
        body.insert(
            "turn_id".to_string(),
            serde_json::Value::String(turn_id.to_string()),
        );
    }
    if let Some(workflow_graph_id) = workflow_graph_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        body.insert(
            "workflow_graph_id".to_string(),
            serde_json::Value::String(workflow_graph_id.to_string()),
        );
    }
    if let Some(workflow_node_id) = workflow_node_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        body.insert(
            "workflow_node_id".to_string(),
            serde_json::Value::String(workflow_node_id.to_string()),
        );
    }
    let route = coding_tool_invoke_route(&thread_id, &tool);
    let value = daemon_request(
        Some(&endpoint),
        token.as_deref(),
        Method::POST,
        &route,
        Some(serde_json::Value::Object(body)),
    )
    .await?;
    if json {
        return print_json(&value);
    }
    let status = value
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let receipts = value
        .get("receipt_refs")
        .and_then(|value| value.as_array())
        .map(Vec::len)
        .unwrap_or(0);
    let workflow_node = value
        .get("workflow_node_id")
        .and_then(|value| value.as_str())
        .unwrap_or("none");
    println!(
        "Agent coding tool: tool={tool} thread={thread_id} status={status} node={workflow_node} receipts={receipts}"
    );
    Ok(())
}

fn coding_tool_invoke_route(thread_id: &str, tool_id: &str) -> String {
    CODING_TOOL_INVOKE_ROUTE_TEMPLATE
        .replace("{thread_id}", thread_id)
        .replace("{tool_id}", tool_id)
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

async fn print_doctor(json: bool) -> Result<()> {
    let value = match daemon_request(None, None, Method::GET, "/v1/doctor", None).await {
        Ok(value) => value,
        Err(error) => local_doctor_fallback(Some(error.to_string())),
    };
    if json {
        return print_json(&value);
    }
    let status = value
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let readiness = value
        .get("readiness")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let blockers = value
        .get("blockers")
        .and_then(|value| value.as_array())
        .map(|items| items.len())
        .unwrap_or(0);
    let warnings = value
        .get("optionalWarnings")
        .and_then(|value| value.as_array())
        .map(|items| items.len())
        .unwrap_or(0);
    println!("Agent runtime doctor: {status}");
    println!("  readiness={readiness} blockers={blockers} optional_warnings={warnings}");
    println!("  report: /v1/doctor (secrets redacted)");
    Ok(())
}

async fn print_runtime_catalog(
    json: bool,
    route: &str,
    label: &str,
    count_field: &str,
) -> Result<()> {
    let value = match daemon_request(None, None, Method::GET, route, None).await {
        Ok(value) => value,
        Err(error) => {
            let mut fallback = serde_json::json!({
                "schemaVersion": if route == "/v1/skills" {
                    "ioi.agent-runtime.skills.v1"
                } else {
                    "ioi.agent-runtime.hooks.v1"
                },
                "object": if route == "/v1/skills" {
                    "ioi.agent_skill_registry_projection"
                } else {
                    "ioi.agent_hook_registry_projection"
                },
                "status": "degraded",
                "source": "cli_local_fallback",
                "daemon": {
                    "endpoint": std::env::var("IOI_DAEMON_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:8765".to_string()),
                    "route": route,
                    "reachable": false,
                    "error": error.to_string(),
                },
                "redaction": {
                    "secretValuesIncluded": false,
                    "hookCommandsIncluded": false
                }
            });
            if let Some(object) = fallback.as_object_mut() {
                object.insert(count_field.to_string(), serde_json::json!(0));
            }
            fallback
        }
    };
    if json {
        return print_json(&value);
    }
    let status = value
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let count = value
        .get(count_field)
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    println!("Agent runtime {label}: {status}");
    println!("  discovered={count} report: {route} (secrets redacted)");
    Ok(())
}

async fn print_runtime_list(json: bool, route: &str, label: &str) -> Result<()> {
    let value = match daemon_request(None, None, Method::GET, route, None).await {
        Ok(value) => value,
        Err(error) => serde_json::json!({
            "schemaVersion": "ioi.agent-runtime.list-fallback.v1",
            "object": "ioi.agent_runtime_list_fallback",
            "status": "degraded",
            "label": label,
            "daemon": {
                "endpoint": std::env::var("IOI_DAEMON_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:8765".to_string()),
                "route": route,
                "reachable": false,
                "error": error.to_string(),
            },
            "items": [],
            "count": 0,
            "redaction": {
                "secretValuesIncluded": false
            }
        }),
    };
    if json {
        return print_json(&value);
    }
    let count = value
        .as_array()
        .map(|items| items.len())
        .or_else(|| {
            value
                .get("count")
                .and_then(|value| value.as_u64())
                .map(|count| count as usize)
        })
        .unwrap_or(0);
    println!("Agent runtime {label}: count={count}");
    println!("  report: {route} (secrets redacted)");
    Ok(())
}

fn local_doctor_fallback(error: Option<String>) -> serde_json::Value {
    let substrate = RuntimeSubstratePortContract::default();
    let gui = AutopilotGuiHarnessValidationContract::default();
    let provider_keys = [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "DEEPSEEK_API_KEY",
        "OPENROUTER_API_KEY",
        "IOI_AGENT_SDK_HOSTED_ENDPOINT",
        "IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT",
    ]
    .iter()
    .map(|name| {
        serde_json::json!({
            "name": name,
            "source": "env",
            "configured": std::env::var(name).is_ok(),
            "valueRedacted": true,
        })
    })
    .collect::<Vec<_>>();
    serde_json::json!({
        "schemaVersion": "ioi.agent-runtime.doctor.v1",
        "object": "ioi.agent_runtime_doctor_report",
        "status": "degraded",
        "readiness": "ready",
        "source": "cli_local_fallback",
        "daemon": {
            "endpoint": std::env::var("IOI_DAEMON_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:8765".to_string()),
            "reachable": false,
            "error": error,
        },
        "runtimeContract": {
            "schema": substrate.schema_version,
            "requiredAdapterCount": substrate.required_adapters.len(),
            "requiredEvidenceClassCount": substrate.required_evidence_classes.len(),
            "forbidsPrivilegedDogfoodBypass": substrate.forbids_privileged_dogfood_bypass,
            "requiresTraceExport": substrate.requires_trace_export,
            "requiresQualityLedger": substrate.requires_quality_ledger,
            "retainedGuiQueryCount": gui.retained_queries.len(),
        },
        "providerKeys": provider_keys,
        "checks": [
            {
                "id": "daemon.public_api",
                "status": "degraded",
                "required": false,
                "summary": "The daemon doctor endpoint could not be reached; local static contract checks were used."
            },
            {
                "id": "runtime.substrate_contract",
                "status": "pass",
                "required": true,
                "summary": "Static runtime substrate contract is present."
            }
        ],
        "blockers": [],
        "optionalWarnings": ["daemon.public_api"],
        "redaction": {
            "profile": "doctor_safe",
            "secretValuesIncluded": false
        }
    })
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

        let stream = AgentArgs::try_parse_from([
            "agent",
            "stream",
            "--thread-id",
            "thread_runtime_cli",
            "--since-seq",
            "0",
            "--last-event-id",
            "thread_runtime_cli:events:1",
            "--follow",
            "--json",
        ])
        .expect("stream command should parse");
        match stream.command {
            Some(AgentCommands::Stream(args)) => {
                assert_eq!(args.thread_id.as_deref(), Some("thread_runtime_cli"));
                assert_eq!(args.run_id, None);
                assert_eq!(args.since_seq, Some(0));
                assert_eq!(
                    args.last_event_id.as_deref(),
                    Some("thread_runtime_cli:events:1")
                );
                assert!(args.follow);
                assert!(args.json);
            }
            other => panic!("expected stream command, got {other:?}"),
        }

        let run_stream =
            AgentArgs::try_parse_from(["agent", "stream", "--run-id", "run_runtime_cli", "--json"])
                .expect("run stream command should parse");
        assert!(matches!(
            run_stream.command,
            Some(AgentCommands::Stream(AgentEventStreamArgs {
                run_id: Some(_),
                json: true,
                ..
            }))
        ));

        let tui = AgentArgs::try_parse_from([
            "agent",
            "tui",
            "--goal",
            "Validate the thin terminal UI",
            "--message",
            "stream canonical thread events",
            "--runtime-profile",
            "runtime_service",
            "--model",
            "auto",
            "--route-id",
            "route.native-local",
            "--cwd",
            "/tmp/ioi-workspace",
            "--interrupt",
            "--reason",
            "operator validation",
            "--since-seq",
            "0",
            "--endpoint",
            "http://127.0.0.1:8765",
            "--interactive",
            "--json",
        ])
        .expect("tui command should parse");
        match tui.command {
            Some(AgentCommands::Tui(args)) => {
                assert_eq!(args.goal.as_deref(), Some("Validate the thin terminal UI"));
                assert_eq!(
                    args.message.as_deref(),
                    Some("stream canonical thread events")
                );
                assert_eq!(args.runtime_profile.as_deref(), Some("runtime_service"));
                assert_eq!(args.model.as_deref(), Some("auto"));
                assert_eq!(args.route_id.as_deref(), Some("route.native-local"));
                assert_eq!(args.cwd.as_deref(), Some("/tmp/ioi-workspace"));
                assert!(args.interrupt);
                assert_eq!(args.since_seq, Some(0));
                assert!(args.interactive);
                assert!(args.json);
            }
            other => panic!("expected tui command, got {other:?}"),
        }

        let fork = AgentArgs::try_parse_from([
            "agent",
            "fork",
            "--thread-id",
            "thread_runtime_cli",
            "--reason",
            "branch live context",
            "--endpoint",
            "http://127.0.0.1:8765",
            "--json",
        ])
        .expect("fork command should parse");
        assert!(matches!(
            fork.command,
            Some(AgentCommands::Fork {
                thread_id,
                json: true,
                ..
            }) if thread_id == "thread_runtime_cli"
        ));

        let interrupt = AgentArgs::try_parse_from([
            "agent",
            "interrupt",
            "--thread-id",
            "thread_runtime_cli",
            "--turn-id",
            "turn_runtime_cli",
            "--reason",
            "operator validation",
            "--endpoint",
            "http://127.0.0.1:8765",
            "--json",
        ])
        .expect("interrupt command should parse");
        assert!(matches!(
            interrupt.command,
            Some(AgentCommands::Interrupt {
                thread_id,
                turn_id,
                json: true,
                ..
            }) if thread_id == "thread_runtime_cli" && turn_id == "turn_runtime_cli"
        ));

        let steer = AgentArgs::try_parse_from([
            "agent",
            "steer",
            "--thread-id",
            "thread_runtime_cli",
            "--turn-id",
            "turn_runtime_cli",
            "--guidance",
            "focus on the current failing assertion",
            "--endpoint",
            "http://127.0.0.1:8765",
            "--json",
        ])
        .expect("steer command should parse");
        assert!(matches!(
            steer.command,
            Some(AgentCommands::Steer {
                thread_id,
                turn_id,
                json: true,
                ..
            }) if thread_id == "thread_runtime_cli" && turn_id == "turn_runtime_cli"
        ));

        let compact = AgentArgs::try_parse_from([
            "agent",
            "compact",
            "--thread-id",
            "thread_runtime_cli",
            "--reason",
            "reduce stale context",
            "--scope",
            "thread",
            "--endpoint",
            "http://127.0.0.1:8765",
            "--json",
        ])
        .expect("compact command should parse");
        assert!(matches!(
            compact.command,
            Some(AgentCommands::Compact {
                thread_id,
                json: true,
                ..
            }) if thread_id == "thread_runtime_cli"
        ));

        let model = AgentArgs::try_parse_from(["agent", "model", "--json"])
            .expect("model command should parse");
        assert!(matches!(
            model.command,
            Some(AgentCommands::Model { json: true })
        ));

        let thinking = AgentArgs::try_parse_from(["agent", "thinking", "--json"])
            .expect("thinking command should parse");
        assert!(matches!(
            thinking.command,
            Some(AgentCommands::Thinking { json: true })
        ));

        let memory = AgentArgs::try_parse_from(["agent", "memory", "--json"])
            .expect("memory command should parse");
        assert!(matches!(
            memory.command,
            Some(AgentCommands::Memory { json: true })
        ));

        let doctor = AgentArgs::try_parse_from(["agent", "doctor", "--json"])
            .expect("doctor command should parse");
        assert!(matches!(
            doctor.command,
            Some(AgentCommands::Doctor { json: true })
        ));

        let skills = AgentArgs::try_parse_from(["agent", "skills", "--json"])
            .expect("skills command should parse");
        assert!(matches!(
            skills.command,
            Some(AgentCommands::Skills { json: true })
        ));

        let hooks = AgentArgs::try_parse_from(["agent", "hooks", "--json"])
            .expect("hooks command should parse");
        assert!(matches!(
            hooks.command,
            Some(AgentCommands::Hooks { json: true })
        ));

        let tasks = AgentArgs::try_parse_from(["agent", "tasks", "--json"])
            .expect("tasks command should parse");
        assert!(matches!(
            tasks.command,
            Some(AgentCommands::Tasks { json: true })
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
        let coding_tools = AgentArgs::try_parse_from([
            "agent",
            "tools",
            "coding",
            "--endpoint",
            "http://127.0.0.1:8765",
            "--json",
        ])
        .expect("coding tools command should parse");
        assert!(matches!(
            coding_tools.command,
            Some(AgentCommands::Tools {
                command: Some(ToolCommands::Coding { json: true, .. }),
                ..
            })
        ));
        let browser_discovery = AgentArgs::try_parse_from([
            "agent",
            "tools",
            "browser-discovery",
            "--endpoint",
            "http://127.0.0.1:8765",
            "--include-tabs",
            "--json",
        ])
        .expect("browser discovery command should parse");
        assert!(matches!(
            browser_discovery.command,
            Some(AgentCommands::Tools {
                command: Some(ToolCommands::BrowserDiscovery {
                    include_tabs: true,
                    json: true,
                    ..
                }),
                ..
            })
        ));
        let native_browser = AgentArgs::try_parse_from([
            "agent",
            "tools",
            "native-browser",
            "--endpoint",
            "http://127.0.0.1:8765",
            "--thread-id",
            "thread_runtime_cli",
            "--prompt",
            "inspect https://example.com",
            "--url",
            "https://example.com",
            "--action-kind",
            "click",
            "--approval-ref",
            "approval-browser-click",
            "--selector",
            "#submit",
            "--target-ref",
            "#submit",
            "--text",
            "hello",
            "--key",
            "Enter",
            "--scroll-y",
            "420",
            "--file-path",
            "/tmp/upload.txt",
            "--cdp-endpoint-url",
            "http://127.0.0.1:9222",
            "--cdp-timeout-ms",
            "5000",
            "--json",
        ])
        .expect("native browser command should parse");
        assert!(matches!(
            native_browser.command,
            Some(AgentCommands::Tools {
                command: Some(ToolCommands::NativeBrowser {
                    thread_id,
                    action_kind,
                    approval_ref: Some(approval_ref),
                    selector: Some(selector),
                    target_ref: Some(target_ref),
                    text: Some(text),
                    key: Some(key),
                    scroll_y: Some(scroll_y),
                    file_path: Some(file_path),
                    cdp_endpoint_url: Some(cdp_endpoint_url),
                    cdp_timeout_ms: Some(cdp_timeout_ms),
                    json: true,
                    ..
                }),
                ..
            }) if thread_id == "thread_runtime_cli"
                && action_kind == "click"
                && approval_ref == "approval-browser-click"
                && selector == "#submit"
                && target_ref == "#submit"
                && text == "hello"
                && key == "Enter"
                && scroll_y == 420
                && file_path == "/tmp/upload.txt"
                && cdp_endpoint_url == "http://127.0.0.1:9222"
                && cdp_timeout_ms == 5000
        ));
        let computer_use_control = AgentArgs::try_parse_from([
            "agent",
            "tools",
            "computer-use-control",
            "--endpoint",
            "http://127.0.0.1:8765",
            "--thread-id",
            "thread_runtime_cli",
            "--action",
            "resume",
            "--lease-id",
            "lease_controlled_relaunch",
            "--handoff-ref",
            "handoff_controlled_relaunch",
            "--resume-observation-ref",
            "observation_after_relaunch",
            "--cdp-endpoint-url",
            "http://127.0.0.1:9222",
            "--json",
        ])
        .expect("computer-use control command should parse");
        assert!(matches!(
            computer_use_control.command,
            Some(AgentCommands::Tools {
                command: Some(ToolCommands::ComputerUseControl {
                    thread_id,
                    action,
                    lease_id,
                    handoff_ref: Some(handoff_ref),
                    resume_observation_ref: Some(resume_observation_ref),
                    cdp_endpoint_url: Some(cdp_endpoint_url),
                    json: true,
                    ..
                }),
                ..
            }) if thread_id == "thread_runtime_cli"
                && action == "resume"
                && lease_id == "lease_controlled_relaunch"
                && handoff_ref == "handoff_controlled_relaunch"
                && resume_observation_ref == "observation_after_relaunch"
                && cdp_endpoint_url == "http://127.0.0.1:9222"
        ));
        let coding_tool_run = AgentArgs::try_parse_from([
            "agent",
            "tools",
            "run",
            "file.inspect",
            "--thread-id",
            "thread_runtime_cli",
            "--path",
            "README.md",
            "--json",
        ])
        .expect("coding tool run command should parse");
        assert!(matches!(
            coding_tool_run.command,
            Some(AgentCommands::Tools {
                command: Some(ToolCommands::Run { json: true, .. }),
                ..
            })
        ));
        let browser_discovery_tool_run = AgentArgs::try_parse_from([
            "agent",
            "tools",
            "run",
            "ioi.computer_use.browser_discovery",
            "--thread-id",
            "thread_runtime_cli",
            "--workflow-node-id",
            "computer-use.browser-discovery",
            "--json",
        ])
        .expect("computer-use browser discovery tool command should parse");
        assert!(matches!(
            browser_discovery_tool_run.command,
            Some(AgentCommands::Tools {
                command: Some(ToolCommands::Run {
                    workflow_node_id: Some(_),
                    json: true,
                    ..
                }),
                ..
            })
        ));
        let coding_patch_run = AgentArgs::try_parse_from([
            "agent",
            "tools",
            "run",
            "file.apply_patch",
            "--thread-id",
            "thread_runtime_cli",
            "--path",
            "README.md",
            "--old-text",
            "before",
            "--new-text",
            "after",
            "--dry-run",
            "--json",
        ])
        .expect("coding patch command should parse");
        assert!(matches!(
            coding_patch_run.command,
            Some(AgentCommands::Tools {
                command: Some(ToolCommands::Run {
                    dry_run: true,
                    json: true,
                    ..
                }),
                ..
            })
        ));
        let coding_test_run = AgentArgs::try_parse_from([
            "agent",
            "tools",
            "run",
            "test.run",
            "--thread-id",
            "thread_runtime_cli",
            "--command-id",
            "node.test",
            "--path",
            "sample.test.mjs",
            "--test-arg=--test-reporter=spec",
            "--timeout-ms",
            "30000",
            "--json",
        ])
        .expect("coding test command should parse");
        assert!(matches!(
            coding_test_run.command,
            Some(AgentCommands::Tools {
                command: Some(ToolCommands::Run {
                    command_id: Some(_),
                    timeout_ms: Some(30000),
                    json: true,
                    ..
                }),
                ..
            })
        ));
        let coding_diagnostics_run = AgentArgs::try_parse_from([
            "agent",
            "tools",
            "run",
            "lsp.diagnostics",
            "--thread-id",
            "thread_runtime_cli",
            "--command-id",
            "node.check",
            "--path",
            "src/main.mjs",
            "--timeout-ms",
            "30000",
            "--json",
        ])
        .expect("coding diagnostics command should parse");
        assert!(matches!(
            coding_diagnostics_run.command,
            Some(AgentCommands::Tools {
                command: Some(ToolCommands::Run {
                    command_id: Some(_),
                    timeout_ms: Some(30000),
                    json: true,
                    ..
                }),
                ..
            })
        ));
        let coding_artifact_read = AgentArgs::try_parse_from([
            "agent",
            "tools",
            "run",
            "artifact.read",
            "--thread-id",
            "thread_runtime_cli",
            "--artifact-id",
            "artifact_coding_tool_test_output",
            "--offset-bytes",
            "8",
            "--length-bytes",
            "128",
            "--json",
        ])
        .expect("coding artifact read command should parse");
        assert!(matches!(
            coding_artifact_read.command,
            Some(AgentCommands::Tools {
                command: Some(ToolCommands::Run {
                    artifact_id: Some(_),
                    offset_bytes: Some(8),
                    length_bytes: Some(128),
                    json: true,
                    ..
                }),
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
