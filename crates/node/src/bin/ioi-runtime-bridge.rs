#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::{StateAccess, StateManager};
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::inference::{InferenceRuntime, UnavailableInferenceRuntime};
use ioi_drivers::browser::computer_use::{
    action_proposal_from_affordance_graph, affordance_graph_from_target_index,
    commit_gate_for_action_proposal, observation_bundle_from_browser_artifacts,
    target_index_from_browser_artifacts,
};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::gui::IoiGuiDriver;
use ioi_drivers::os::NativeOsDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_memory::MemoryRuntime;
use ioi_services::agentic::runtime::keys::get_state_key;
use ioi_services::agentic::runtime::{
    AgentMode, AgentState, AgentStatus, PostMessageParams, RuntimeAgentService, StartAgentParams,
    StepAgentParams,
};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::flat::RedbFlatStore;
use ioi_types::app::runtime::computer_use::COMPUTER_USE_CONTRACT_SCHEMA_VERSION_V1;
use ioi_types::app::{AccountId, ChainId, KernelEvent, WorkloadReceipt};
use ioi_types::codec;
use parity_scale_codec::Encode;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[path = "../runtime_bridge_events.rs"]
mod runtime_bridge_events;

const COMMAND_SCHEMA_VERSION: &str = "ioi.runtime.bridge.command.v1";
const EVENT_SCHEMA_VERSION: &str = "ioi.runtime.event.v1";
const THREAD_SCHEMA_VERSION: &str = "ioi.runtime.thread.v1";

#[derive(Parser, Debug)]
#[clap(
    name = "ioi-runtime-bridge",
    about = "IOI RuntimeAgentService command bridge for the daemon RuntimeApiBridge"
)]
struct BridgeOpts {
    #[clap(long, env = "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_DATA_DIR")]
    data_dir: Option<PathBuf>,
    #[clap(long, env = "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_WORKSPACE")]
    workspace: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct BridgeRequest {
    #[serde(rename = "schema_version", alias = "schemaVersion")]
    schema_version: String,
    #[serde(rename = "bridge_id", alias = "bridgeId")]
    bridge_id: String,
    operation: String,
    #[serde(default)]
    input: Value,
}

#[derive(Debug, Deserialize)]
struct StartThreadInput {
    #[serde(default)]
    request: Value,
    #[serde(default)]
    options: Value,
    #[serde(rename = "runtimeProfile", alias = "runtime_profile")]
    runtime_profile: Option<String>,
    #[serde(rename = "agentId", alias = "agent_id")]
    agent_id: Option<String>,
    #[serde(rename = "threadId", alias = "thread_id")]
    thread_id: String,
    #[serde(rename = "workspaceRoot", alias = "workspace_root")]
    workspace_root: Option<String>,
    #[serde(rename = "createdAt", alias = "created_at")]
    created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SubmitTurnInput {
    #[serde(default)]
    request: Value,
    #[serde(rename = "agentId", alias = "agent_id")]
    agent_id: Option<String>,
    #[serde(rename = "threadId", alias = "thread_id")]
    thread_id: String,
    #[serde(rename = "sessionId", alias = "session_id")]
    session_id: String,
    #[serde(rename = "workspaceRoot", alias = "workspace_root")]
    workspace_root: Option<String>,
    #[serde(rename = "createdAt", alias = "created_at")]
    created_at: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let opts = BridgeOpts::parse();
    let result = async_main(opts).await;
    match result {
        Ok(value) => {
            println!(
                "{}",
                serde_json::to_string(&json!({ "ok": true, "result": value })).unwrap()
            );
        }
        Err(error) => {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "ok": false,
                    "error": {
                        "code": "runtime_agent_service_bridge",
                        "message": error.to_string(),
                    }
                }))
                .unwrap()
            );
        }
    }
}

async fn async_main(opts: BridgeOpts) -> Result<Value> {
    let request = read_bridge_request()?;
    if request.schema_version != COMMAND_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported bridge schema version '{}', expected '{}'",
            request.schema_version,
            COMMAND_SCHEMA_VERSION
        ));
    }
    match request.operation.as_str() {
        "start_thread" => {
            let input: StartThreadInput = serde_json::from_value(request.input)
                .context("failed to decode start_thread input")?;
            let workspace =
                workspace_root(opts.workspace.as_deref(), input.workspace_root.as_deref())?;
            let mut runtime = BridgeRuntime::open(opts.data_dir.as_deref(), &workspace)?;
            runtime.start_thread(&request.bridge_id, input).await
        }
        "submit_turn" => {
            let input: SubmitTurnInput = serde_json::from_value(request.input)
                .context("failed to decode submit_turn input")?;
            let workspace =
                workspace_root(opts.workspace.as_deref(), input.workspace_root.as_deref())?;
            let mut runtime = BridgeRuntime::open(opts.data_dir.as_deref(), &workspace)?;
            runtime.submit_turn(&request.bridge_id, input).await
        }
        other => Err(anyhow!("unsupported bridge operation '{other}'")),
    }
}

struct BridgeRuntime {
    state: RedbFlatStore<HashCommitmentScheme>,
    service: RuntimeAgentService,
    services: ServiceDirectory,
    browser_driver: Arc<BrowserDriver>,
    event_receiver: tokio::sync::broadcast::Receiver<KernelEvent>,
    height: u64,
}

impl BridgeRuntime {
    fn open(data_dir: Option<&Path>, workspace: &Path) -> Result<Self> {
        let data_dir = data_dir
            .map(Path::to_path_buf)
            .unwrap_or_else(|| workspace.join(".ioi").join("runtime-bridge"));
        fs::create_dir_all(&data_dir)
            .with_context(|| format!("failed to create bridge data dir {}", data_dir.display()))?;
        let memory_runtime = Arc::new(MemoryRuntime::open_sqlite(
            &data_dir.join("desktop-memory.db"),
        )?);
        let state = RedbFlatStore::new(
            &data_dir.join("runtime-state.redb"),
            HashCommitmentScheme::new(),
        )?;
        let inference: Arc<dyn InferenceRuntime> = Arc::new(UnavailableInferenceRuntime::new(
            "Runtime bridge inference is unavailable until a model route is configured.",
        ));
        let gui = Arc::new(IoiGuiDriver::new());
        let browser_driver = Arc::new(BrowserDriver::new());
        let (event_sender, event_receiver) = tokio::sync::broadcast::channel(1024);
        let service = RuntimeAgentService::new_hybrid(
            gui,
            Arc::new(TerminalDriver::new()),
            browser_driver.clone(),
            inference.clone(),
            inference,
        )
        .with_memory_runtime(memory_runtime)
        .with_workspace_path(workspace.to_string_lossy().to_string())
        .with_os_driver(Arc::new(NativeOsDriver::new()))
        .with_event_sender(event_sender)
        .with_som(true);
        Ok(Self {
            state,
            service,
            services: ServiceDirectory::new(vec![]),
            browser_driver,
            event_receiver,
            height: unix_millis(),
        })
    }

    async fn start_thread(&mut self, bridge_id: &str, input: StartThreadInput) -> Result<Value> {
        let session_id = start_session_id(&input.request)?;
        let goal = non_empty_string(&input.request, &["goal", "prompt", "message", "input"])
            .unwrap_or_else(|| "Runtime service thread started.".to_string());
        let max_steps = positive_u32(&input.request, &["max_steps", "maxSteps"])
            .or_else(|| positive_u32(&input.options, &["max_steps", "maxSteps"]))
            .unwrap_or(20);
        let params = StartAgentParams {
            session_id,
            goal,
            runtime_route_frame: None,
            max_steps,
            parent_session_id: None,
            initial_budget: positive_u64(&input.request, &["initial_budget", "initialBudget"])
                .unwrap_or(1000),
            mode: AgentMode::Agent,
        };
        self.call_service("start@v1", &params).await?;
        self.commit()?;
        let state = self.agent_state(session_id)?;
        let session_hex = hex::encode(session_id);
        let created_at = input.created_at.unwrap_or_else(now_rfc3339);
        let mut events = vec![tti_event(TtiEventInput {
            thread_id: &input.thread_id,
            turn_id: "",
            item_id: &format!("{}:item:runtime-agent-service-started", input.thread_id),
            idempotency_key: &format!("runtime-agent-service:{}:thread.started", session_hex),
            source_event_kind: "RuntimeAgentService.handle_service_call.start@v1",
            event_kind: "thread.started",
            status: "running",
            actor: "runtime",
            created_at: &created_at,
            workspace_root: input.workspace_root.as_deref(),
            component_kind: "runtime_thread",
            workflow_node_id: "runtime.runtime-thread",
            payload_schema_version: THREAD_SCHEMA_VERSION,
            payload: json!({
                "bridge_schema_version": COMMAND_SCHEMA_VERSION,
                "agent_id": input.agent_id,
                "session_id": session_hex,
                "runtime_profile": input.runtime_profile.unwrap_or_else(|| "runtime_service".to_string()),
                "goal": state.goal,
                "max_steps": state.max_steps,
            }),
        })];
        for (ordinal, event) in self.drain_kernel_events().iter().enumerate() {
            if let Some(mapped) = runtime_bridge_events::kernel_event_to_tti_event(
                event,
                &runtime_bridge_events::RuntimeBridgeEventContext {
                    thread_id: &input.thread_id,
                    turn_id: "",
                    workspace_root: input.workspace_root.as_deref(),
                    created_at: &created_at,
                    ordinal,
                },
            ) {
                events.push(mapped);
            }
        }
        Ok(json!({
            "bridge_id": bridge_id,
            "session_id": session_hex,
            "source": "runtime_service",
            "status": thread_status(&state.status),
            "updated_at": created_at,
            "events": events,
        }))
    }

    async fn submit_turn(&mut self, bridge_id: &str, input: SubmitTurnInput) -> Result<Value> {
        let session_id = parse_session_id(&input.session_id)?;
        let session_hex = hex::encode(session_id);
        let prompt =
            non_empty_string(&input.request, &["prompt", "message", "input"]).unwrap_or_default();
        if !prompt.trim().is_empty() {
            let params = PostMessageParams {
                session_id,
                role: "user".to_string(),
                content: prompt.clone(),
            };
            self.call_service("post_message@v1", &params).await?;
            self.commit()?;
        }
        let created_at = input.created_at.unwrap_or_else(now_rfc3339);
        let turn_suffix = format!("{}_{}", session_hex_short(&session_hex), unix_millis());
        let turn_id = format!("turn_runtime_service_{turn_suffix}");
        let run_id = format!("run_runtime_service_{turn_suffix}");
        let mut events = vec![tti_event(TtiEventInput {
            thread_id: &input.thread_id,
            turn_id: &turn_id,
            item_id: &format!("{}:item:user-message", turn_id),
            idempotency_key: &format!("runtime-agent-service:{}:{}:started", session_hex, turn_id),
            source_event_kind: "RuntimeAgentService.handle_service_call.post_message@v1",
            event_kind: "turn.started",
            status: "running",
            actor: "user",
            created_at: &created_at,
            workspace_root: input.workspace_root.as_deref(),
            component_kind: "runtime_turn",
            workflow_node_id: "runtime.runtime-turn",
            payload_schema_version: EVENT_SCHEMA_VERSION,
            payload: json!({
                "agent_id": input.agent_id,
                "session_id": session_hex,
                "prompt": prompt,
            }),
        })];

        let step_result = self
            .call_service("step@v1", &StepAgentParams { session_id })
            .await;
        if step_result.is_ok() {
            self.commit()?;
        }
        let kernel_events = self.drain_kernel_events();
        let state = self.agent_state(session_id)?;
        let completed_at = now_rfc3339();
        let (status, stop_reason, event_kind, event_status, summary) =
            match (&state.status, step_result) {
                (AgentStatus::Failed(reason), _) => (
                    "failed",
                    "runtime_bridge_failed",
                    "turn.failed",
                    "failed",
                    reason.clone(),
                ),
                (_, Err(error)) => (
                    "failed",
                    "runtime_bridge_failed",
                    "turn.failed",
                    "failed",
                    error.to_string(),
                ),
                (AgentStatus::Paused(reason), _) => (
                    "blocked",
                    "runtime_bridge_paused",
                    "turn.completed",
                    "blocked",
                    reason.clone(),
                ),
                (AgentStatus::Completed(summary), _) => (
                    "completed",
                    "runtime_bridge_completed",
                    "turn.completed",
                    "completed",
                    summary
                        .clone()
                        .unwrap_or_else(|| "Runtime turn completed.".to_string()),
                ),
                (_, _) => (
                    "completed",
                    "runtime_bridge_step_completed",
                    "turn.completed",
                    "completed",
                    "Runtime step completed.".to_string(),
                ),
            };
        for (ordinal, event) in kernel_events.iter().enumerate() {
            if let Some(mapped) = runtime_bridge_events::kernel_event_to_tti_event(
                event,
                &runtime_bridge_events::RuntimeBridgeEventContext {
                    thread_id: &input.thread_id,
                    turn_id: &turn_id,
                    workspace_root: input.workspace_root.as_deref(),
                    created_at: &completed_at,
                    ordinal,
                },
            ) {
                events.push(mapped);
            }
        }
        if request_indicates_computer_use(&input.request, &prompt)
            || kernel_events.iter().any(kernel_event_mentions_browser_tool)
        {
            let browser_tool_results = browser_tool_results(&kernel_events);
            if let Some((_, artifacts)) = self
                .browser_driver
                .recent_browser_observation_artifacts(Duration::from_secs(120))
                .await
            {
                let context = RuntimeBridgeComputerUseContext {
                    thread_id: &input.thread_id,
                    turn_id: &turn_id,
                    run_id: &run_id,
                    workspace_root: input.workspace_root.as_deref(),
                    created_at: &completed_at,
                };
                events.extend(browser_observation_artifacts_to_tti_events(
                    &context,
                    &artifacts,
                    &browser_tool_results,
                ));
            }
        }
        events.push(tti_event(TtiEventInput {
            thread_id: &input.thread_id,
            turn_id: &turn_id,
            item_id: &format!("{}:item:runtime-step", turn_id),
            idempotency_key: &format!(
                "runtime-agent-service:{}:{}:{}",
                session_hex, turn_id, event_kind
            ),
            source_event_kind: "RuntimeAgentService.handle_service_call.step@v1",
            event_kind,
            status: event_status,
            actor: "runtime",
            created_at: &completed_at,
            workspace_root: input.workspace_root.as_deref(),
            component_kind: "runtime_turn",
            workflow_node_id: "runtime.runtime-turn",
            payload_schema_version: EVENT_SCHEMA_VERSION,
            payload: json!({
                "session_id": session_hex,
                "agent_status": format!("{:?}", state.status),
                "step_count": state.step_count,
                "summary": summary,
            }),
        }));

        Ok(json!({
            "bridge_id": bridge_id,
            "run_id": run_id,
            "turn_id": turn_id,
            "source": "runtime_service",
            "status": status,
            "result": summary,
            "stop_reason": stop_reason,
            "created_at": created_at,
            "updated_at": completed_at,
            "events": events,
        }))
    }

    fn drain_kernel_events(&mut self) -> Vec<KernelEvent> {
        let mut events = Vec::new();
        loop {
            match self.event_receiver.try_recv() {
                Ok(event) => events.push(event),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
            }
        }
        events
    }

    async fn call_service<T: Encode>(&mut self, method: &str, params: &T) -> Result<()> {
        let encoded = codec::to_bytes_canonical(params)
            .map_err(|error| anyhow!("failed to encode {method} params: {error}"))?;
        let mut ctx = build_ctx(&self.services, self.height);
        self.service
            .handle_service_call(&mut self.state, method, &encoded, &mut ctx)
            .await
            .map_err(|error| anyhow!("{method} failed: {error}"))
    }

    fn commit(&mut self) -> Result<()> {
        self.height = self.height.saturating_add(1);
        self.state
            .commit_version(self.height)
            .map(|_| ())
            .map_err(|error| anyhow!("failed to commit runtime bridge state: {error}"))
    }

    fn agent_state(&self, session_id: [u8; 32]) -> Result<AgentState> {
        let key = get_state_key(&session_id);
        let Some(bytes) = self.state.get(&key)? else {
            return Err(anyhow!(
                "agent state missing for session {}",
                hex::encode(session_id)
            ));
        };
        codec::from_bytes_canonical(&bytes)
            .map_err(|error| anyhow!("failed to decode agent state: {error}"))
    }
}

struct TtiEventInput<'a> {
    thread_id: &'a str,
    turn_id: &'a str,
    item_id: &'a str,
    idempotency_key: &'a str,
    source_event_kind: &'a str,
    event_kind: &'a str,
    status: &'a str,
    actor: &'a str,
    created_at: &'a str,
    workspace_root: Option<&'a str>,
    component_kind: &'a str,
    workflow_node_id: &'a str,
    payload_schema_version: &'a str,
    payload: Value,
}

fn tti_event(input: TtiEventInput<'_>) -> Value {
    json!({
        "event_stream_id": format!("{}:events", input.thread_id),
        "thread_id": input.thread_id,
        "turn_id": input.turn_id,
        "item_id": input.item_id,
        "idempotency_key": input.idempotency_key,
        "source": "runtime_service",
        "source_event_kind": input.source_event_kind,
        "event_kind": input.event_kind,
        "status": input.status,
        "actor": input.actor,
        "created_at": input.created_at,
        "workspace_root": input.workspace_root,
        "component_kind": input.component_kind,
        "workflow_node_id": input.workflow_node_id,
        "payload_schema_version": input.payload_schema_version,
        "payload": input.payload,
        "fixture_profile": Value::Null,
    })
}

fn read_bridge_request() -> Result<BridgeRequest> {
    let mut raw = String::new();
    io::stdin()
        .read_to_string(&mut raw)
        .context("failed to read bridge request from stdin")?;
    serde_json::from_str(&raw).context("failed to parse bridge request JSON")
}

fn workspace_root(cli_workspace: Option<&Path>, input_workspace: Option<&str>) -> Result<PathBuf> {
    let workspace = cli_workspace
        .map(Path::to_path_buf)
        .or_else(|| input_workspace.map(PathBuf::from))
        .unwrap_or(std::env::current_dir()?);
    Ok(workspace)
}

fn start_session_id(request: &Value) -> Result<[u8; 32]> {
    if let Some(raw) = non_empty_string(request, &["session_id", "sessionId"]) {
        return parse_session_id(&raw);
    }
    let mut session_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut session_id);
    Ok(session_id)
}

fn parse_session_id(input: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(input.trim().trim_start_matches("0x"))
        .with_context(|| format!("invalid session id hex '{input}'"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("session id must be 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn non_empty_string(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        let Some(raw) = value.get(*key).and_then(Value::as_str) else {
            continue;
        };
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn positive_u32(value: &Value, keys: &[&str]) -> Option<u32> {
    for key in keys {
        let Some(parsed) = value.get(*key).and_then(Value::as_u64) else {
            continue;
        };
        if parsed > 0 && parsed <= u32::MAX as u64 {
            return Some(parsed as u32);
        }
    }
    None
}

fn positive_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    for key in keys {
        let Some(parsed) = value.get(*key).and_then(Value::as_u64) else {
            continue;
        };
        if parsed > 0 {
            return Some(parsed);
        }
    }
    None
}

struct RuntimeBridgeComputerUseContext<'a> {
    thread_id: &'a str,
    turn_id: &'a str,
    run_id: &'a str,
    workspace_root: Option<&'a str>,
    created_at: &'a str,
}

#[derive(Debug, Clone)]
struct BrowserToolResult {
    step_index: u32,
    tool_name: String,
    output: String,
    error_class: Option<String>,
}

fn browser_observation_artifacts_to_tti_events(
    context: &RuntimeBridgeComputerUseContext<'_>,
    artifacts: &ioi_drivers::browser::BrowserObservationArtifacts,
    browser_tool_results: &[BrowserToolResult],
) -> Vec<Value> {
    let lease_id = format!("lease_{}_browser", context.run_id);
    let observation_ref = format!("observation_{}_browser_live", context.run_id);
    let observation =
        observation_bundle_from_browser_artifacts(&lease_id, &observation_ref, artifacts);
    let target_index = target_index_from_browser_artifacts(&observation, artifacts);
    let affordance_graph = affordance_graph_from_target_index(&target_index);
    let action_proposal = action_proposal_from_affordance_graph(
        context.run_id,
        "runtime_service_bridge",
        &affordance_graph,
    );
    let commit_gate = action_proposal.as_ref().map(|proposal| {
        commit_gate_for_action_proposal(context.run_id, proposal, &affordance_graph)
    });
    let base_payload = json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION_V1,
        "computer_use_lane": "native_browser",
        "computer_use_session_mode": "owned_hermetic_browser",
        "computer_use_lease_id": lease_id,
        "computer_use_contract_ingest": "browser_observation_artifacts",
        "observation_retention_mode": "prompt_visible_summary_only",
        "run_id": context.run_id,
    });
    let observation_payload = extend_json_object(
        base_payload.clone(),
        json!({
            "computer_use_step": "observe",
            "computer_use_observation_ref": observation.observation_ref.clone(),
            "computer_use_target_index_ref": target_index.target_index_ref.clone(),
            "observation_bundle": observation.clone(),
            "target_index": target_index.clone(),
            "browser_observation_artifacts": {
                "url": artifacts.url.clone(),
                "page_title": artifacts.page_title.clone(),
                "browser_use_selector_map_present": artifacts.browser_use_selector_map_text.is_some(),
                "browsergym_dom_present": artifacts.browsergym_dom_text.is_some(),
                "browsergym_axtree_present": artifacts.browsergym_axtree_text.is_some(),
                "browsergym_focused_bid": artifacts.browsergym_focused_bid.clone(),
            },
        }),
    );
    let affordance_payload = extend_json_object(
        base_payload.clone(),
        json!({
            "computer_use_step": "build_affordance_graph",
            "computer_use_affordance_graph_ref": affordance_graph.graph_ref.clone(),
            "computer_use_target_index_ref": affordance_graph.target_index_ref.clone(),
            "affordance_graph": affordance_graph.clone(),
        }),
    );
    let mut events = vec![
        tti_event(TtiEventInput {
            thread_id: context.thread_id,
            turn_id: context.turn_id,
            item_id: &format!("{}:item:computer-use:observe", context.turn_id),
            idempotency_key: &format!(
                "runtime-agent-service:{}:computer-use:observation",
                context.run_id
            ),
            source_event_kind: "BrowserDriver.recent_browser_observation_artifacts",
            event_kind: "computer_use.observation",
            status: "completed",
            actor: "runtime",
            created_at: context.created_at,
            workspace_root: context.workspace_root,
            component_kind: "computer_use_harness",
            workflow_node_id: "computer-use.observe",
            payload_schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION_V1,
            payload: observation_payload,
        }),
        tti_event(TtiEventInput {
            thread_id: context.thread_id,
            turn_id: context.turn_id,
            item_id: &format!("{}:item:computer-use:affordance-graph", context.turn_id),
            idempotency_key: &format!(
                "runtime-agent-service:{}:computer-use:affordance-graph",
                context.run_id
            ),
            source_event_kind: "BrowserDriver.recent_browser_observation_artifacts",
            event_kind: "computer_use.affordance_graph",
            status: "completed",
            actor: "runtime",
            created_at: context.created_at,
            workspace_root: context.workspace_root,
            component_kind: "computer_use_harness",
            workflow_node_id: "computer-use.affordance-graph",
            payload_schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION_V1,
            payload: affordance_payload,
        }),
    ];
    if let (Some(action_proposal), Some(commit_gate)) = (&action_proposal, &commit_gate) {
        let proposal_payload = extend_json_object(
            base_payload.clone(),
            json!({
                "computer_use_step": "propose_action",
                "computer_use_proposal_ref": action_proposal.proposal_ref.clone(),
                "computer_use_target_ref": action_proposal.target_ref.clone(),
                "computer_use_policy_decision_ref": action_proposal.policy_decision_ref.clone(),
                "action_proposal": action_proposal_payload(&action_proposal, &commit_gate),
                "policy_gate": {
                    "policy_decision_ref": action_proposal.policy_decision_ref.clone(),
                    "outcome": if commit_gate.blocks_without_confirmation() {
                        "requires_confirmation_before_execution"
                    } else {
                        "approved_for_proposal_only"
                    },
                    "authority_scope": "computer_use.native_browser.read",
                },
            }),
        );
        let commit_payload = extend_json_object(
            base_payload.clone(),
            json!({
                "computer_use_step": "commit_or_handoff",
                "computer_use_commit_gate_ref": commit_gate.gate_ref.clone(),
                "commit_gate": commit_gate_payload(&commit_gate),
                "human_handoff_state": Value::Null,
            }),
        );
        events.push(tti_event(TtiEventInput {
            thread_id: context.thread_id,
            turn_id: context.turn_id,
            item_id: &format!("{}:item:computer-use:action-proposed", context.turn_id),
            idempotency_key: &format!(
                "runtime-agent-service:{}:computer-use:action-proposed",
                context.run_id
            ),
            source_event_kind: "BrowserDriver.recent_browser_observation_artifacts",
            event_kind: "computer_use.action_proposed",
            status: "running",
            actor: "runtime",
            created_at: context.created_at,
            workspace_root: context.workspace_root,
            component_kind: "computer_use_harness",
            workflow_node_id: "computer-use.action-proposal",
            payload_schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION_V1,
            payload: proposal_payload,
        }));
        events.push(tti_event(TtiEventInput {
            thread_id: context.thread_id,
            turn_id: context.turn_id,
            item_id: &format!("{}:item:computer-use:commit-gate", context.turn_id),
            idempotency_key: &format!(
                "runtime-agent-service:{}:computer-use:commit-gate",
                context.run_id
            ),
            source_event_kind: "BrowserDriver.recent_browser_observation_artifacts",
            event_kind: "computer_use.commit_gate",
            status: if commit_gate.blocks_without_confirmation() {
                "blocked"
            } else {
                "completed"
            },
            actor: "runtime",
            created_at: context.created_at,
            workspace_root: context.workspace_root,
            component_kind: "computer_use_harness",
            workflow_node_id: "computer-use.commit-gate",
            payload_schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION_V1,
            payload: commit_payload,
        }));
    }
    for result in browser_tool_results {
        let action_kind = browser_tool_action_kind(&result.tool_name);
        let failed = result.error_class.is_some();
        let action_ref = format!(
            "action_{}_runtime_bridge_{}_{}",
            stable_bridge_ref_fragment(context.run_id),
            result.step_index,
            stable_bridge_ref_fragment(&result.tool_name),
        );
        let verification_ref = format!(
            "verification_{}_runtime_bridge_{}_{}",
            stable_bridge_ref_fragment(context.run_id),
            result.step_index,
            stable_bridge_ref_fragment(&result.tool_name),
        );
        let target_ref = action_proposal
            .as_ref()
            .and_then(|proposal| proposal.target_ref.clone())
            .or_else(|| {
                target_index
                    .targets
                    .first()
                    .map(|target| target.target_ref.clone())
            });
        let proposal_ref = action_proposal
            .as_ref()
            .map(|proposal| proposal.proposal_ref.clone());
        let computer_action = json!({
            "action_ref": action_ref,
            "proposal_ref": proposal_ref.clone(),
            "action_kind": action_kind,
            "target_ref": target_ref,
            "observation_ref": observation.observation_ref,
            "coordinate_space_id": target_index.coordinate_space_id,
            "payload_summary": format!("RuntimeAgentService executed {}.", result.tool_name),
            "expected_postcondition": format!("{} result is reflected in the browser observation evidence.", result.tool_name),
            "approval_ref": Value::Null,
            "tool_name": result.tool_name,
            "step_index": result.step_index,
        });
        let action_receipt = json!({
            "receipt_ref": format!("receipt_{}_runtime_bridge_action_{}", stable_bridge_ref_fragment(context.run_id), result.step_index),
            "action_ref": action_ref,
            "adapter_id": "ioi.native_browser.runtime_service_bridge",
            "status": if failed { "failed" } else { "completed" },
            "grounding_ref": target_index.target_index_ref,
            "postcondition_summary": if failed {
                format!("Browser tool {} failed: {}.", result.tool_name, result.error_class.as_deref().unwrap_or("unknown_error"))
            } else {
                summarize_browser_tool_output(&result.output)
            },
            "verification_ref": verification_ref,
            "evidence_refs": [
                observation.observation_ref.clone(),
                target_index.target_index_ref.clone(),
                affordance_graph.graph_ref.clone(),
            ],
            "error_class": result.error_class.clone(),
        });
        let verification_receipt = json!({
            "verification_ref": verification_ref,
            "action_ref": action_ref,
            "status": if failed { "failed" } else { "passed" },
            "expected_postcondition": format!("{} produces a browser tool result bound to the active observation.", result.tool_name),
            "observed_postcondition": if failed {
                format!("Browser tool failed before postcondition verification: {}.", result.error_class.as_deref().unwrap_or("unknown_error"))
            } else {
                summarize_browser_tool_output(&result.output)
            },
            "verifier": "runtime_service_bridge_browser_tool_result",
            "evidence_refs": [
                observation.observation_ref.clone(),
                target_index.target_index_ref.clone(),
                format!("receipt_{}_runtime_bridge_action_{}", stable_bridge_ref_fragment(context.run_id), result.step_index),
            ],
        });
        let action_payload = extend_json_object(
            base_payload.clone(),
            json!({
                "computer_use_step": "execute_action",
                "computer_use_action_ref": computer_action["action_ref"].clone(),
                "computer_use_proposal_ref": proposal_ref,
                "computer_use_target_ref": computer_action["target_ref"].clone(),
                "computer_action": computer_action,
                "action_receipt": action_receipt,
            }),
        );
        let verification_payload = extend_json_object(
            base_payload.clone(),
            json!({
                "computer_use_step": "verify_postcondition",
                "computer_use_action_ref": verification_receipt["action_ref"].clone(),
                "computer_use_verification_ref": verification_receipt["verification_ref"].clone(),
                "verification_receipt": verification_receipt,
            }),
        );
        events.push(tti_event(TtiEventInput {
            thread_id: context.thread_id,
            turn_id: context.turn_id,
            item_id: &format!(
                "{}:item:computer-use:action-executed:{}",
                context.turn_id, result.step_index
            ),
            idempotency_key: &format!(
                "runtime-agent-service:{}:computer-use:action-executed:{}",
                context.run_id, result.step_index
            ),
            source_event_kind: "KernelEvent::AgentActionResult",
            event_kind: "computer_use.action_executed",
            status: if failed { "failed" } else { "completed" },
            actor: "runtime",
            created_at: context.created_at,
            workspace_root: context.workspace_root,
            component_kind: "computer_use_harness",
            workflow_node_id: "computer-use.action-executed",
            payload_schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION_V1,
            payload: action_payload,
        }));
        events.push(tti_event(TtiEventInput {
            thread_id: context.thread_id,
            turn_id: context.turn_id,
            item_id: &format!(
                "{}:item:computer-use:verification:{}",
                context.turn_id, result.step_index
            ),
            idempotency_key: &format!(
                "runtime-agent-service:{}:computer-use:verification:{}",
                context.run_id, result.step_index
            ),
            source_event_kind: "KernelEvent::AgentActionResult",
            event_kind: "computer_use.verification",
            status: if failed { "failed" } else { "completed" },
            actor: "runtime",
            created_at: context.created_at,
            workspace_root: context.workspace_root,
            component_kind: "computer_use_harness",
            workflow_node_id: "computer-use.verification",
            payload_schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION_V1,
            payload: verification_payload,
        }));
    }
    events
}

fn extend_json_object(mut base: Value, extension: Value) -> Value {
    let (Value::Object(base_map), Value::Object(extension_map)) = (&mut base, extension) else {
        return base;
    };
    for (key, value) in extension_map {
        base_map.insert(key, value);
    }
    base
}

fn action_proposal_payload(
    proposal: &ioi_types::app::runtime::computer_use::ActionProposal,
    commit_gate: &ioi_types::app::runtime::computer_use::CommitGate,
) -> Value {
    let mut payload = serde_json::to_value(proposal).unwrap_or_else(|_| json!({}));
    if let Value::Object(map) = &mut payload {
        map.insert(
            "confirmation_required".to_string(),
            Value::Bool(commit_gate.blocks_without_confirmation()),
        );
    }
    payload
}

fn commit_gate_payload(gate: &ioi_types::app::runtime::computer_use::CommitGate) -> Value {
    let mut payload = serde_json::to_value(gate).unwrap_or_else(|_| json!({}));
    if let Value::Object(map) = &mut payload {
        map.insert(
            "commit_gate_ref".to_string(),
            Value::String(gate.gate_ref.clone()),
        );
    }
    payload
}

fn browser_tool_results(events: &[KernelEvent]) -> Vec<BrowserToolResult> {
    events
        .iter()
        .filter_map(|event| match event {
            KernelEvent::AgentActionResult {
                step_index,
                tool_name,
                output,
                error_class,
                ..
            } if is_browser_tool(tool_name) => Some(BrowserToolResult {
                step_index: *step_index,
                tool_name: tool_name.clone(),
                output: output.clone(),
                error_class: error_class.clone(),
            }),
            _ => None,
        })
        .collect()
}

fn browser_tool_action_kind(tool_name: &str) -> &'static str {
    let normalized = tool_name.trim().to_ascii_lowercase();
    if normalized.contains("click") {
        "click"
    } else if normalized.contains("type") || normalized.contains("input") {
        "type_text"
    } else if normalized.contains("key") {
        "key_press"
    } else if normalized.contains("scroll") {
        "scroll"
    } else if normalized.contains("hover") {
        "hover"
    } else if normalized.contains("select") {
        "select"
    } else if normalized.contains("upload") {
        "upload"
    } else if normalized.contains("navigate")
        || normalized.contains("open")
        || normalized.contains("go_to")
    {
        "navigate"
    } else if normalized.contains("wait") {
        "wait"
    } else {
        "inspect"
    }
}

fn summarize_browser_tool_output(output: &str) -> String {
    let compact = output.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.is_empty() {
        "Browser tool completed without textual output.".to_string()
    } else if compact.len() > 240 {
        format!("{}...", &compact[..240])
    } else {
        compact
    }
}

fn stable_bridge_ref_fragment(value: &str) -> String {
    let mut fragment = String::with_capacity(value.len().min(64));
    let mut previous_was_separator = false;
    for ch in value.chars() {
        let normalized = if ch.is_ascii_alphanumeric() {
            previous_was_separator = false;
            Some(ch.to_ascii_lowercase())
        } else if !previous_was_separator {
            previous_was_separator = true;
            Some('_')
        } else {
            None
        };
        if let Some(normalized) = normalized {
            fragment.push(normalized);
        }
        if fragment.len() >= 64 {
            break;
        }
    }
    let trimmed = fragment.trim_matches('_');
    if trimmed.is_empty() {
        "runtime_bridge".to_string()
    } else {
        trimmed.to_string()
    }
}

fn request_indicates_computer_use(request: &Value, prompt: &str) -> bool {
    bool_value(request, &["computerUse", "computer_use"]).unwrap_or(false)
        || non_empty_string(request, &["computerUseLane", "computer_use_lane"]).is_some()
        || prompt_mentions_computer_use(prompt)
}

fn prompt_mentions_computer_use(prompt: &str) -> bool {
    let normalized = prompt.to_ascii_lowercase();
    [
        "browser",
        "chromium",
        "website",
        "web page",
        "url",
        "computer-use",
        "computer use",
        "cua",
        "gui",
        "desktop",
        "click",
        "selector",
        "playwright",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn bool_value(value: &Value, keys: &[&str]) -> Option<bool> {
    for key in keys {
        if let Some(parsed) = value.get(*key).and_then(Value::as_bool) {
            return Some(parsed);
        }
    }
    None
}

fn kernel_event_mentions_browser_tool(event: &KernelEvent) -> bool {
    match event {
        KernelEvent::AgentActionResult { tool_name, .. } => is_browser_tool(tool_name),
        KernelEvent::WorkloadReceipt(receipt) => {
            workload_receipt_tool_name(&receipt.receipt).is_some_and(is_browser_tool)
        }
        _ => false,
    }
}

fn workload_receipt_tool_name(receipt: &WorkloadReceipt) -> Option<&str> {
    match receipt {
        WorkloadReceipt::Exec(item) => Some(&item.tool_name),
        WorkloadReceipt::FsWrite(item) => Some(&item.tool_name),
        WorkloadReceipt::NetFetch(item) => Some(&item.tool_name),
        WorkloadReceipt::WebRetrieve(item) => Some(&item.tool_name),
        WorkloadReceipt::MemoryRetrieve(item) => Some(&item.tool_name),
        WorkloadReceipt::Inference(item) => Some(&item.tool_name),
        WorkloadReceipt::Media(item) => Some(&item.tool_name),
        WorkloadReceipt::ModelLifecycle(item) => Some(&item.tool_name),
        WorkloadReceipt::Worker(item) => Some(&item.tool_name),
        WorkloadReceipt::ParentPlaybook(item) => Some(&item.tool_name),
        WorkloadReceipt::Adapter(item) => Some(&item.tool_name),
    }
}

fn is_browser_tool(tool_name: &str) -> bool {
    tool_name
        .trim()
        .to_ascii_lowercase()
        .starts_with("browser__")
}

fn build_ctx<'a>(services: &'a ServiceDirectory, height: u64) -> TxContext<'a> {
    TxContext {
        block_height: height,
        block_timestamp: unix_millis().saturating_mul(1_000_000),
        chain_id: ChainId(0),
        signer_account_id: AccountId::default(),
        services,
        simulation: false,
        is_internal: false,
    }
}

fn thread_status(status: &AgentStatus) -> &'static str {
    match status {
        AgentStatus::Running | AgentStatus::Idle => "active",
        AgentStatus::Completed(_) => "completed",
        AgentStatus::Failed(_) => "failed",
        AgentStatus::Paused(_) => "blocked",
        AgentStatus::Terminated => "canceled",
    }
}

fn session_hex_short(session_hex: &str) -> &str {
    session_hex.get(..16).unwrap_or(session_hex)
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| format!("{}Z", unix_millis()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_drivers::browser::BrowserObservationArtifacts;
    use std::time::Instant;

    #[test]
    fn parses_bridge_request_aliases() {
        let request: BridgeRequest = serde_json::from_str(
            r#"{"schemaVersion":"ioi.runtime.bridge.command.v1","bridgeId":"bridge","operation":"start_thread","input":{}}"#,
        )
        .expect("decode bridge request");
        assert_eq!(request.schema_version, COMMAND_SCHEMA_VERSION);
        assert_eq!(request.bridge_id, "bridge");
    }

    #[test]
    fn tti_event_preserves_runtime_service_source() {
        let event = tti_event(TtiEventInput {
            thread_id: "thread_a",
            turn_id: "turn_a",
            item_id: "item_a",
            idempotency_key: "idem",
            source_event_kind: "RuntimeAgentService.handle_service_call.step@v1",
            event_kind: "turn.completed",
            status: "completed",
            actor: "runtime",
            created_at: "0Z",
            workspace_root: Some("/tmp/workspace"),
            component_kind: "runtime_turn",
            workflow_node_id: "runtime.runtime-turn",
            payload_schema_version: EVENT_SCHEMA_VERSION,
            payload: json!({"session_id":"abc"}),
        });
        assert_eq!(event["source"], "runtime_service");
        assert_eq!(event["fixture_profile"], Value::Null);
        assert_eq!(event["event_stream_id"], "thread_a:events");
    }

    #[test]
    fn browser_artifacts_project_to_computer_use_tti_events() {
        let artifacts = BrowserObservationArtifacts {
            captured_at: Instant::now(),
            url: Some("https://example.test/app".to_string()),
            page_title: Some("Example App".to_string()),
            browser_use_state_text: Some("state".to_string()),
            browser_use_selector_map_text: Some(
                "[42] <button name=Submit target_id=target-submit />\n\
                 [43] <input name=Search placeholder=Search target_id=target-search />"
                    .to_string(),
            ),
            browser_use_html_text: None,
            browser_use_eval_text: None,
            browser_use_markdown_text: None,
            browser_use_pagination_text: None,
            browser_use_tabs_text: None,
            browser_use_page_info_text: None,
            browser_use_pending_requests_text: None,
            browser_use_recent_events_text: None,
            browser_use_closed_popup_messages_text: None,
            browsergym_extra_properties_text: None,
            browsergym_focused_bid: Some("bid-submit".to_string()),
            browsergym_dom_text: Some("<button>Submit</button>".to_string()),
            browsergym_axtree_text: Some("button Submit".to_string()),
        };
        let context = RuntimeBridgeComputerUseContext {
            thread_id: "thread_browser",
            turn_id: "turn_browser",
            run_id: "run_browser",
            workspace_root: Some("/tmp/ioi"),
            created_at: "2026-05-14T00:00:00Z",
        };
        let events = browser_observation_artifacts_to_tti_events(&context, &artifacts, &[]);
        assert_eq!(events.len(), 4);
        assert_eq!(events[0]["event_kind"], "computer_use.observation");
        assert_eq!(events[0]["component_kind"], "computer_use_harness");
        assert_eq!(
            events[0]["payload"]["computer_use_contract_ingest"],
            "browser_observation_artifacts"
        );
        assert_eq!(
            events[0]["payload"]["observation_bundle"]["url"],
            "https://example.test/app"
        );
        assert_eq!(
            events[0]["payload"]["target_index"]["targets"][0]["label"],
            "Submit"
        );
        assert_eq!(events[1]["event_kind"], "computer_use.affordance_graph");
        assert!(events[1]["payload"]["affordance_graph"]["affordances"]
            .as_array()
            .unwrap()
            .iter()
            .any(|affordance| {
                affordance["possible_action"] == "click"
                    && affordance["confirmation_required"] == true
            }));
        assert_eq!(events[2]["event_kind"], "computer_use.action_proposed");
        assert_eq!(
            events[2]["payload"]["action_proposal"]["target_ref"],
            "target:observation_run_browser_browser_live:target-submit"
        );
        assert_eq!(
            events[2]["payload"]["action_proposal"]["confirmation_required"],
            false
        );
        assert_eq!(events[3]["event_kind"], "computer_use.commit_gate");
        assert_eq!(
            events[3]["payload"]["commit_gate"]["status"],
            "not_required"
        );
        assert_eq!(
            events[3]["payload"]["commit_gate"]["commit_gate_ref"],
            events[3]["payload"]["commit_gate"]["gate_ref"]
        );
    }

    #[test]
    fn browser_tool_results_project_to_action_and_verification_events() {
        let artifacts = BrowserObservationArtifacts {
            captured_at: Instant::now(),
            url: Some("https://example.test/app".to_string()),
            page_title: Some("Example App".to_string()),
            browser_use_state_text: Some("state".to_string()),
            browser_use_selector_map_text: Some(
                "[42] <button name=Submit target_id=target-submit />".to_string(),
            ),
            browser_use_html_text: None,
            browser_use_eval_text: None,
            browser_use_markdown_text: None,
            browser_use_pagination_text: None,
            browser_use_tabs_text: None,
            browser_use_page_info_text: None,
            browser_use_pending_requests_text: None,
            browser_use_recent_events_text: None,
            browser_use_closed_popup_messages_text: None,
            browsergym_extra_properties_text: None,
            browsergym_focused_bid: Some("bid-submit".to_string()),
            browsergym_dom_text: Some("<button>Submit</button>".to_string()),
            browsergym_axtree_text: Some("button Submit".to_string()),
        };
        let context = RuntimeBridgeComputerUseContext {
            thread_id: "thread_browser",
            turn_id: "turn_browser",
            run_id: "run_browser",
            workspace_root: Some("/tmp/ioi"),
            created_at: "2026-05-14T00:00:00Z",
        };
        let browser_results = vec![BrowserToolResult {
            step_index: 7,
            tool_name: "browser__inspect".to_string(),
            output: "Observed the Submit button.".to_string(),
            error_class: None,
        }];
        let events =
            browser_observation_artifacts_to_tti_events(&context, &artifacts, &browser_results);
        assert_eq!(events.len(), 6);
        assert_eq!(events[4]["event_kind"], "computer_use.action_executed");
        assert_eq!(
            events[4]["payload"]["computer_action"]["action_kind"],
            "inspect"
        );
        assert_eq!(
            events[4]["payload"]["action_receipt"]["status"],
            "completed"
        );
        assert_eq!(events[5]["event_kind"], "computer_use.verification");
        assert_eq!(
            events[5]["payload"]["verification_receipt"]["status"],
            "passed"
        );
    }

    #[test]
    fn computer_use_detection_accepts_metadata_prompt_and_browser_tools() {
        assert!(request_indicates_computer_use(
            &json!({"computerUse": true}),
            ""
        ));
        assert!(request_indicates_computer_use(
            &json!({}),
            "open the browser"
        ));
        assert!(kernel_event_mentions_browser_tool(
            &KernelEvent::AgentActionResult {
                session_id: [9u8; 32],
                step_index: 1,
                tool_name: "browser__inspect".to_string(),
                output: "ok".to_string(),
                error_class: None,
                agent_status: "Running".to_string(),
            }
        ));
    }
}
