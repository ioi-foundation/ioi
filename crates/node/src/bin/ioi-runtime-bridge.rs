#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ioi_api::chat::ChatIntentContext;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::{StateAccess, StateManager};
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime, UnavailableInferenceRuntime};
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
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy};
use ioi_services::agentic::runtime::keys::{
    get_agent_brain_key, get_agent_run_brain_artifact_index_key, get_agent_trajectory_step_key,
    get_runtime_substrate_key, get_state_key, AGENT_POLICY_PREFIX,
};
use ioi_services::agentic::runtime::policy_lease::policy_lease_snapshot_for_state;
use ioi_services::agentic::runtime::service::decision_loop::helpers::default_safe_policy;
use ioi_services::agentic::runtime::stop_hook::stop_hook_snapshot_for_state;
use ioi_services::agentic::runtime::trajectory::{
    AgentBrainRecord, AgentRunBrainArtifactIndexRecord, AgentTrajectoryStepRecord,
};
use ioi_services::agentic::runtime::workspace_change::hunk_proposal_review_state;
use ioi_services::agentic::runtime::{
    AgentMode, AgentState, AgentStatus, CancelAgentParams, DenyAgentParams, PauseAgentParams,
    PostMessageParams, ResumeAgentParams, RuntimeAgentService, StartAgentParams, StepAgentParams,
};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::flat::RedbFlatStore;
use ioi_types::app::agentic::{
    BrowserActionPlanRef, CommandExecutionPlanRef, RequiredCapability, RuntimeActionFrame,
    RuntimeIntentEvidence, RuntimeRouteFrame,
};
use ioi_types::app::runtime::computer_use::COMPUTER_USE_CONTRACT_SCHEMA_VERSION_V1;
use ioi_types::app::{AccountId, ChainId, KernelEvent, WorkloadReceipt};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[path = "../runtime_bridge_events.rs"]
mod runtime_bridge_events;

const COMMAND_SCHEMA_VERSION: &str = "ioi.runtime.bridge.command.v1";
const EVENT_SCHEMA_VERSION: &str = "ioi.runtime.event.v1";
const DEFAULT_RUNTIME_BRIDGE_SUBMIT_TURN_MAX_STEPS: u32 = 20;
const THREAD_SCHEMA_VERSION: &str = "ioi.runtime.thread.v1";
const DEFAULT_AGENT_STEP_TIMEOUT_MS: u64 = 75_000;
const DEFAULT_LOCAL_GPU_AGENT_STEP_TIMEOUT_MS: u64 = 180_000;
const DEFAULT_AGENT_TURN_IDLE_TIMEOUT_MS: u64 = 100_000;
const DEFAULT_BROWSER_OBSERVATION_TIMEOUT_MS: u64 = 5_000;

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
    #[serde(default)]
    options: Value,
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
    #[serde(
        default,
        rename = "streamedEventsOnly",
        alias = "streamed_events_only",
        alias = "streamEventsOnly",
        alias = "stream_events_only"
    )]
    streamed_events_only: bool,
}

#[derive(Debug, Deserialize)]
struct InspectThreadInput {
    #[serde(rename = "sessionId", alias = "session_id")]
    session_id: String,
    #[serde(rename = "threadId", alias = "thread_id")]
    thread_id: Option<String>,
    #[serde(rename = "workspaceRoot", alias = "workspace_root")]
    workspace_root: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ControlThreadInput {
    #[serde(rename = "sessionId", alias = "session_id")]
    session_id: String,
    #[serde(rename = "threadId", alias = "thread_id")]
    thread_id: Option<String>,
    #[serde(rename = "workspaceRoot", alias = "workspace_root")]
    workspace_root: Option<String>,
    action: String,
    #[serde(default)]
    reason: String,
    #[serde(rename = "requestHash", alias = "request_hash")]
    request_hash: Option<String>,
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
    std::env::set_var("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", &request.bridge_id);
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
        "inspect_thread" => {
            let input: InspectThreadInput = serde_json::from_value(request.input)
                .context("failed to decode inspect_thread input")?;
            let workspace =
                workspace_root(opts.workspace.as_deref(), input.workspace_root.as_deref())?;
            let runtime = BridgeRuntime::open(opts.data_dir.as_deref(), &workspace)?;
            runtime.inspect_thread(&request.bridge_id, input)
        }
        "control_thread" => {
            let input: ControlThreadInput = serde_json::from_value(request.input)
                .context("failed to decode control_thread input")?;
            let workspace =
                workspace_root(opts.workspace.as_deref(), input.workspace_root.as_deref())?;
            let mut runtime = BridgeRuntime::open(opts.data_dir.as_deref(), &workspace)?;
            runtime.control_thread(&request.bridge_id, input).await
        }
        other => Err(anyhow!("unsupported bridge operation '{other}'")),
    }
}

struct BridgeRuntime {
    state: RedbFlatStore<HashCommitmentScheme>,
    service: RuntimeAgentService,
    services: ServiceDirectory,
    browser_driver: Arc<BrowserDriver>,
    event_sender: tokio::sync::broadcast::Sender<KernelEvent>,
    event_receiver: tokio::sync::broadcast::Receiver<KernelEvent>,
    height: u64,
}

struct LiveKernelEventPump {
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl LiveKernelEventPump {
    async fn stop(mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        let _ = self.handle.await;
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn first_non_empty_env(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| non_empty_env(name))
}

fn bridge_inference_runtime() -> Arc<dyn InferenceRuntime> {
    let explicit_url = first_non_empty_env(&[
        "IOI_RUNTIME_AGENT_SERVICE_INFERENCE_URL",
        "IOI_RUNTIME_INFERENCE_URL",
    ]);
    let explicit_key = first_non_empty_env(&[
        "IOI_RUNTIME_AGENT_SERVICE_INFERENCE_API_KEY",
        "IOI_RUNTIME_INFERENCE_API_KEY",
    ])
    .unwrap_or_default();
    let explicit_model =
        first_non_empty_env(&["IOI_RUNTIME_AGENT_SERVICE_MODEL", "IOI_RUNTIME_MODEL"])
            .unwrap_or_else(|| "auto".to_string());

    if let Some(api_url) = explicit_url {
        return Arc::new(HttpInferenceRuntime::new(
            api_url,
            explicit_key,
            explicit_model,
        ));
    }

    Arc::new(UnavailableInferenceRuntime::new(
        "Runtime bridge inference is unavailable. Configure IOI_RUNTIME_AGENT_SERVICE_INFERENCE_URL/IOI_RUNTIME_AGENT_SERVICE_MODEL from a daemon-resolved model mounting route.",
    ))
}

fn runtime_policy_key(session_id: [u8; 32]) -> Vec<u8> {
    [AGENT_POLICY_PREFIX, session_id.as_slice()].concat()
}

fn normalize_runtime_control_value(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

fn runtime_control_string(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(control) = value
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|control| !control.is_empty())
        {
            return Some(control.to_string());
        }
    }
    value
        .get("options")
        .and_then(|options| runtime_control_string(options, keys))
}

fn runtime_controls_present(request: &Value, options: &Value) -> bool {
    runtime_control_string(
        request,
        &[
            "approvalMode",
            "approval_mode",
            "threadMode",
            "thread_mode",
            "mode",
        ],
    )
    .is_some()
        || runtime_control_string(
            options,
            &[
                "approvalMode",
                "approval_mode",
                "threadMode",
                "thread_mode",
                "mode",
            ],
        )
        .is_some()
}

fn runtime_controls_request_full_access(request: &Value, options: &Value) -> bool {
    let approval_mode = runtime_control_string(request, &["approvalMode", "approval_mode"])
        .or_else(|| runtime_control_string(options, &["approvalMode", "approval_mode"]))
        .map(|value| normalize_runtime_control_value(&value));
    let thread_mode = runtime_control_string(request, &["threadMode", "thread_mode", "mode"])
        .or_else(|| runtime_control_string(options, &["threadMode", "thread_mode", "mode"]))
        .map(|value| normalize_runtime_control_value(&value));
    matches!(approval_mode.as_deref(), Some("never_prompt"))
        || matches!(thread_mode.as_deref(), Some("yolo") | Some("never_prompt"))
}

fn runtime_controls_request_auto_review(request: &Value, options: &Value) -> bool {
    let approval_mode = runtime_control_string(request, &["approvalMode", "approval_mode"])
        .or_else(|| runtime_control_string(options, &["approvalMode", "approval_mode"]))
        .map(|value| normalize_runtime_control_value(&value));
    let thread_mode = runtime_control_string(request, &["threadMode", "thread_mode", "mode"])
        .or_else(|| runtime_control_string(options, &["threadMode", "thread_mode", "mode"]))
        .map(|value| normalize_runtime_control_value(&value));
    matches!(
        approval_mode.as_deref(),
        Some("suggest") | Some("auto_review") | Some("auto-review")
    ) || matches!(
        thread_mode.as_deref(),
        Some("suggest") | Some("auto_review") | Some("auto-review")
    )
}

fn runtime_control_policy(request: &Value, options: &Value) -> Option<ActionRules> {
    if !runtime_controls_present(request, options) {
        return None;
    }
    if runtime_controls_request_full_access(request, options) {
        return Some(ActionRules {
            policy_id: "runtime-bridge-full-access".to_string(),
            defaults: DefaultPolicy::AllowAll,
            ..ActionRules::default()
        });
    }
    let mut policy = default_safe_policy();
    policy.policy_id = if runtime_controls_request_auto_review(request, options) {
        "runtime-bridge-auto-review".to_string()
    } else {
        "runtime-bridge-default-permissions".to_string()
    };
    Some(policy)
}

fn bridge_object_field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| {
        let candidate = value.get(*key)?;
        candidate.as_object().map(|_| candidate)
    })
}

fn bridge_nested_object_field<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_object().map(|_| current)
}

fn bridge_string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn bridge_bool_field(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_bool))
}

fn bridge_string_array(value: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_array))
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn bridge_nested_string_field(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
}

fn command_line_has_shell_operators(command: &str) -> bool {
    command.contains("&&")
        || command.contains("||")
        || command
            .chars()
            .any(|ch| matches!(ch, ';' | '|' | '<' | '>'))
}

fn split_command_line_to_argv(command: &str) -> Option<Vec<String>> {
    let mut argv = Vec::new();
    let mut current = String::new();
    let mut chars = command.trim().chars().peekable();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active_quote) = quote {
            if ch == active_quote {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() {
            if !current.is_empty() {
                argv.push(std::mem::take(&mut current));
            }
            while chars.peek().is_some_and(|next| next.is_whitespace()) {
                chars.next();
            }
            continue;
        }
        current.push(ch);
    }

    if escaped || quote.is_some() {
        return None;
    }
    if !current.is_empty() {
        argv.push(current);
    }
    (!argv.is_empty()).then_some(argv)
}

fn runtime_command_argv_for_prompt(command: &str) -> Vec<String> {
    if !command_line_has_shell_operators(command) {
        if let Some(argv) = split_command_line_to_argv(command) {
            return argv;
        }
    }
    vec!["bash".to_string(), "-lc".to_string(), command.to_string()]
}

fn prompt_backtick_literals(prompt: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut rest = prompt;
    while let Some(start) = rest.find('`') {
        let after_start = &rest[start + 1..];
        let Some(end) = after_start.find('`') else {
            break;
        };
        let literal = after_start[..end].trim();
        if !literal.is_empty() {
            literals.push(literal.to_string());
        }
        rest = &after_start[end + 1..];
    }
    literals
}

fn literal_looks_like_file_path(literal: &str) -> bool {
    let trimmed = literal.trim();
    let relative_dotfile_path = trimmed
        .strip_prefix('.')
        .and_then(|rest| rest.chars().next())
        .is_some_and(|next| next.is_ascii_alphanumeric() || next == '_' || next == '-');
    !trimmed.is_empty()
        && (trimmed.starts_with('/')
            || trimmed.starts_with("./")
            || trimmed.starts_with("../")
            || trimmed.contains('/')
            || relative_dotfile_path)
        && !command_line_has_shell_operators(trimmed)
}

fn prompt_file_read_path(prompt: &str) -> Option<String> {
    let normalized = prompt.to_ascii_lowercase();
    if !(normalized.contains("read")
        || normalized.contains("view")
        || normalized.contains("open")
        || normalized.contains("inspect"))
    {
        return None;
    }
    prompt_backtick_literals(prompt)
        .into_iter()
        .find(|literal| literal_looks_like_file_path(literal))
}

fn workspace_target_evidence(value: &Value) -> Vec<RuntimeIntentEvidence> {
    let Some(workspace) = bridge_object_field(value, &["workspace"]) else {
        return Vec::new();
    };
    let Some(targets) = workspace.get("targets").and_then(Value::as_array) else {
        return Vec::new();
    };
    targets
        .iter()
        .filter_map(|target| {
            let kind = bridge_string_field(target, &["kind", "targetKind", "target_kind"])
                .unwrap_or_else(|| "search".to_string());
            let (evidence_kind, value) = if kind.eq_ignore_ascii_case("path") {
                (
                    "workspace_path",
                    bridge_string_field(target, &["path", "target", "value"])?,
                )
            } else {
                (
                    "workspace_search",
                    bridge_string_field(target, &["query", "regex", "target", "value"])?,
                )
            };
            Some(RuntimeIntentEvidence {
                evidence_kind: evidence_kind.to_string(),
                value,
                source: "autopilot_studio_workspace_target".to_string(),
                confidence: Some(92),
            })
        })
        .collect()
}

fn runtime_route_frame_candidates<'a>(
    request: &'a Value,
    options: Option<&'a Value>,
) -> Vec<&'a Value> {
    let mut candidates = Vec::new();
    if let Some(frame) = bridge_object_field(request, &["runtimeRouteFrame", "runtime_route_frame"])
    {
        candidates.push(frame);
    }
    if let Some(frame) = bridge_object_field(request, &["intentFrame", "intent_frame"]) {
        candidates.push(frame);
    }
    if let Some(frame) = bridge_nested_object_field(request, &["options", "runtimeRouteFrame"]) {
        candidates.push(frame);
    }
    if let Some(frame) = bridge_nested_object_field(request, &["options", "runtime_route_frame"]) {
        candidates.push(frame);
    }
    if let Some(frame) = bridge_nested_object_field(request, &["options", "intentFrame"]) {
        candidates.push(frame);
    }
    if let Some(frame) = bridge_nested_object_field(request, &["options", "intent_frame"]) {
        candidates.push(frame);
    }
    if let Some(frame) = bridge_nested_object_field(request, &["metadata", "intentFrame"]) {
        candidates.push(frame);
    }
    if let Some(frame) = bridge_nested_object_field(request, &["metadata", "intent_frame"]) {
        candidates.push(frame);
    }
    if let Some(options) = options {
        if let Some(frame) =
            bridge_object_field(options, &["runtimeRouteFrame", "runtime_route_frame"])
        {
            candidates.push(frame);
        }
        if let Some(frame) = bridge_object_field(options, &["intentFrame", "intent_frame"]) {
            candidates.push(frame);
        }
    }
    candidates
}

fn runtime_route_frame_for_bridge_input(
    request: &Value,
    options: Option<&Value>,
) -> Option<RuntimeRouteFrame> {
    runtime_route_frame_candidates(request, options)
        .into_iter()
        .find_map(runtime_route_frame_from_value)
}

fn runtime_route_frame_for_prompt(prompt: &str) -> Option<RuntimeRouteFrame> {
    let context = ChatIntentContext::new(prompt);
    if let Some(intent) = context.local_runtime_action_intent() {
        if intent.action_family.eq_ignore_ascii_case("shell") {
            let command = intent.target_command.as_deref()?.trim();
            if command.is_empty() {
                return None;
            }
            let required_capability = RequiredCapability {
                capability_id: "command.exec".to_string(),
                reason: Some(
                    "explicit command execution request must run through shell tools".to_string(),
                ),
            };
            return Some(RuntimeRouteFrame {
                intent_id: "command.exec".to_string(),
                route_family: "command_execution".to_string(),
                output_intent: "tool_execution".to_string(),
                direct_answer_allowed: false,
                target: prompt.replace(['\r', '\n'], " "),
                target_kind: Some("shell_command".to_string()),
                host_mutation: intent.requires_host_mutation,
                required_capabilities: vec!["command.exec".to_string()],
                typed_evidence: vec![RuntimeIntentEvidence {
                    evidence_kind: "normalized_request".to_string(),
                    value: "shell_command".to_string(),
                    source: "runtime_bridge_prompt_intent".to_string(),
                    confidence: Some(intent.confidence),
                }],
                typed_required_capabilities: vec![required_capability.clone()],
                host_mutation_scope: None,
                runtime_action: Some(RuntimeActionFrame {
                    intent_class: intent.intent_class.to_string(),
                    action_family: "shell".to_string(),
                    target_text: intent.target_text.replace(['\r', '\n'], " "),
                    target_kind: "shell_command".to_string(),
                    host_mutation: intent.requires_host_mutation,
                    required_capabilities: vec![required_capability],
                    browser_plan: None,
                    command_plan: Some(CommandExecutionPlanRef {
                        plan_ref: format!("command.exec:runtime-bridge-inline:{}", command.len()),
                        argv: runtime_command_argv_for_prompt(command),
                        shell_policy: "bounded".to_string(),
                        cwd: Some(".".to_string()),
                        env: Vec::new(),
                        approval_scope: None,
                        expected_receipt: Some("command_receipt".to_string()),
                    }),
                    file_plan: None,
                    provenance: Some("runtime_bridge_prompt_intent".to_string()),
                }),
                install_request: None,
                provenance: Some("runtime_bridge_prompt_intent".to_string()),
            });
        }
    }

    if let Some(frame) = runtime_browser_action_frame_for_prompt(prompt) {
        return Some(frame);
    }

    if let Some(frame) = runtime_source_backed_artifact_or_retrieval_frame_for_prompt(prompt) {
        return Some(frame);
    }

    let path = prompt_file_read_path(prompt)?;
    Some(RuntimeRouteFrame {
        intent_id: "workspace.context".to_string(),
        route_family: "workspace".to_string(),
        output_intent: "tool_execution".to_string(),
        direct_answer_allowed: false,
        target: path.clone(),
        target_kind: Some("workspace_path".to_string()),
        host_mutation: false,
        required_capabilities: vec!["workspace.read".to_string(), "file.read".to_string()],
        typed_evidence: vec![RuntimeIntentEvidence {
            evidence_kind: "workspace_path".to_string(),
            value: path,
            source: "runtime_bridge_prompt_intent".to_string(),
            confidence: Some(95),
        }],
        typed_required_capabilities: vec![RequiredCapability {
            capability_id: "file.read".to_string(),
            reason: Some(
                "explicit path read request must use the governed file reader".to_string(),
            ),
        }],
        host_mutation_scope: None,
        runtime_action: None,
        install_request: None,
        provenance: Some("runtime_bridge_prompt_intent".to_string()),
    })
}

fn runtime_browser_action_frame_for_prompt(prompt: &str) -> Option<RuntimeRouteFrame> {
    let text = prompt.trim();
    if text.is_empty() {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    if !prompt_requests_runtime_browser_action(&lower) {
        return None;
    }
    let url = runtime_first_url_literal(text)?;
    let required_capability = RequiredCapability {
        capability_id: "browser.interact".to_string(),
        reason: Some(
            "explicit browser session request must use governed browser tools".to_string(),
        ),
    };
    Some(RuntimeRouteFrame {
        intent_id: "browser.interact".to_string(),
        route_family: "browser".to_string(),
        output_intent: "tool_execution".to_string(),
        direct_answer_allowed: false,
        target: url.clone(),
        target_kind: Some("browser_action".to_string()),
        host_mutation: false,
        required_capabilities: vec![
            "conversation.reply".to_string(),
            "browser.interact".to_string(),
            "browser.inspect".to_string(),
            "ui.interact".to_string(),
        ],
        typed_evidence: vec![
            RuntimeIntentEvidence {
                evidence_kind: "browser_url".to_string(),
                value: url.clone(),
                source: "runtime_bridge_prompt_intent".to_string(),
                confidence: Some(94),
            },
            RuntimeIntentEvidence {
                evidence_kind: "normalized_request".to_string(),
                value: "browser_action".to_string(),
                source: "runtime_bridge_prompt_intent".to_string(),
                confidence: Some(90),
            },
        ],
        typed_required_capabilities: vec![required_capability.clone()],
        host_mutation_scope: None,
        runtime_action: Some(RuntimeActionFrame {
            intent_class: "browser.interact".to_string(),
            action_family: "browser".to_string(),
            target_text: url.clone(),
            target_kind: "browser_action".to_string(),
            host_mutation: false,
            required_capabilities: vec![required_capability],
            browser_plan: Some(BrowserActionPlanRef {
                plan_ref: format!("browser.navigate:runtime-bridge-inline:{}", url.len()),
                action: "navigate".to_string(),
                url,
                observation_required: true,
                observation_ref: None,
                coordinate_space_id: None,
                semantic_id: None,
            }),
            command_plan: None,
            file_plan: None,
            provenance: Some("runtime_bridge_prompt_intent".to_string()),
        }),
        install_request: None,
        provenance: Some("runtime_bridge_prompt_intent".to_string()),
    })
}

fn prompt_requests_runtime_browser_action(lower: &str) -> bool {
    let mentions_browser_surface = [
        " browser",
        " sandbox browser",
        " page",
        " webpage",
        " website",
        " fixture page",
        " tab",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    let requests_observation_or_navigation = [
        " open ",
        " navigate ",
        " inspect ",
        " browse ",
        " visit ",
        " summarize what changed",
        " summarize the page",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    mentions_browser_surface
        && requests_observation_or_navigation
        && (lower.contains("http://") || lower.contains("https://"))
}

fn runtime_first_url_literal(text: &str) -> Option<String> {
    let start = text.find("http://").or_else(|| text.find("https://"))?;
    let raw = text[start..]
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | '`' | '<' | '>' | ')' | ']' | '}' | ',' | ';'
            )
        })
        .trim_end_matches(|ch| matches!(ch, '.' | ':' | '!' | '?'));
    (!raw.is_empty()).then(|| raw.to_string())
}

fn runtime_source_backed_artifact_or_retrieval_frame_for_prompt(
    prompt: &str,
) -> Option<RuntimeRouteFrame> {
    let text = prompt.trim();
    if text.is_empty() {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    let artifact = prompt_requests_runtime_artifact(&lower);
    let source_required = prompt_requires_runtime_sources(&lower)
        || (artifact && prompt_artifact_benefits_from_runtime_sources(&lower));
    if !source_required {
        return None;
    }
    let query = runtime_research_query_for_prompt(text);
    let target_kind = if artifact {
        "source_backed_artifact"
    } else {
        "source_grounding"
    };
    let mut required_capabilities = vec![
        "conversation.reply".to_string(),
        "web.retrieve".to_string(),
        "sys.time.read".to_string(),
    ];
    if artifact {
        required_capabilities.extend([
            "filesystem.read".to_string(),
            "filesystem.write".to_string(),
        ]);
    }
    Some(RuntimeRouteFrame {
        intent_id: "retrieval.answer".to_string(),
        route_family: "web_research".to_string(),
        output_intent: "tool_execution".to_string(),
        direct_answer_allowed: false,
        target: query.clone(),
        target_kind: Some(target_kind.to_string()),
        host_mutation: artifact,
        required_capabilities,
        typed_evidence: vec![
            RuntimeIntentEvidence {
                evidence_kind: "retrieval_query".to_string(),
                value: query,
                source: "runtime_bridge_prompt_intent".to_string(),
                confidence: Some(88),
            },
            RuntimeIntentEvidence {
                evidence_kind: "normalized_request".to_string(),
                value: target_kind.to_string(),
                source: "runtime_bridge_prompt_intent".to_string(),
                confidence: Some(88),
            },
        ],
        typed_required_capabilities: Vec::new(),
        host_mutation_scope: None,
        runtime_action: None,
        install_request: None,
        provenance: Some("runtime_bridge_prompt_intent".to_string()),
    })
}

fn prompt_requires_runtime_sources(lower: &str) -> bool {
    [
        " source",
        " sources",
        "with source",
        "with sources",
        "use source",
        "use sources",
        "using source",
        "using sources",
        "cite",
        "citation",
        "citations",
        "reference",
        "references",
        "web search",
        "web read",
        "search the web",
        "search online",
        "research",
        "latest",
        "current",
        "right now",
        "price",
        "market cap",
        "investment",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn prompt_requests_runtime_artifact(lower: &str) -> bool {
    let has_action = [
        "create",
        "build",
        "make",
        "generate",
        "draft",
        "design",
        "prototype",
        "output",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    has_action
        && [
            "website",
            "web site",
            "webpage",
            "web page",
            "landing page",
            "microsite",
            "static site",
            "html file",
            "html page",
            "html document",
            "html website",
            "artifact",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn prompt_artifact_benefits_from_runtime_sources(lower: &str) -> bool {
    [
        "explain",
        "explains",
        "explaining",
        "about",
        "guide",
        "educational",
        "overview",
        "report",
        "compare",
        "versus",
        " vs ",
        "what is",
        "how does",
        "history",
        "timeline",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn runtime_research_query_for_prompt(prompt: &str) -> String {
    let normalized = prompt.replace(['\r', '\n'], " ");
    let lower = normalized.to_ascii_lowercase();
    if let Some(value) = runtime_query_after_label(&normalized, &lower, "research topic:") {
        return runtime_clean_research_query(&value);
    }
    for marker in [
        " about ",
        " explains ",
        " explain ",
        " on ",
        " for ",
        " comparing ",
        " compares ",
        " versus ",
        " vs ",
    ] {
        if let Some(index) = lower.find(marker) {
            let start = index + marker.len();
            if start < normalized.len() {
                let candidate = normalized[start..].to_string();
                let cleaned = runtime_clean_research_query(&candidate);
                if !cleaned.is_empty() {
                    return cleaned;
                }
            }
        }
    }
    runtime_clean_research_query(&normalized)
}

fn runtime_query_after_label(normalized: &str, lower: &str, label: &str) -> Option<String> {
    let index = lower.find(label)?;
    let start = index + label.len();
    if start >= normalized.len() {
        return None;
    }
    Some(normalized[start..].to_string())
}

fn runtime_clean_research_query(value: &str) -> String {
    let mut cleaned = value.trim().to_string();
    for marker in [
        " and use sources",
        " with sources",
        " using sources",
        " and cite sources",
        " with citations",
        " as an artifact",
        " as a website",
        " use the governed",
        " call web__",
        " then call",
    ] {
        if let Some(index) = cleaned.to_ascii_lowercase().find(marker) {
            cleaned.truncate(index);
        }
    }
    cleaned = cleaned
        .trim_matches(|ch: char| ch.is_ascii_punctuation() || ch.is_whitespace())
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if cleaned.len() > 180 {
        cleaned.truncate(180);
        cleaned = cleaned.trim().to_string();
    }
    cleaned
}

fn runtime_route_frame_for_prompt_or_bridge_input(
    request: &Value,
    options: Option<&Value>,
    prompt: &str,
) -> Option<RuntimeRouteFrame> {
    let bridge_frame = runtime_route_frame_for_bridge_input(request, options);
    if let Some(frame) = bridge_frame.as_ref() {
        if runtime_route_frame_from_bridge_should_own_prompt(frame) {
            return bridge_frame;
        }
    }
    runtime_route_frame_for_prompt(prompt).or(bridge_frame)
}

fn runtime_route_frame_from_bridge_should_own_prompt(frame: &RuntimeRouteFrame) -> bool {
    let generic_conversation_intent = frame.intent_id.eq_ignore_ascii_case("conversation.reply")
        && (frame.route_family.eq_ignore_ascii_case("conversation")
            || frame.route_family.eq_ignore_ascii_case("direct_model"));
    !generic_conversation_intent
}

fn runtime_route_frame_from_value(value: &Value) -> Option<RuntimeRouteFrame> {
    if let Ok(frame) = serde_json::from_value::<RuntimeRouteFrame>(value.clone()) {
        return Some(frame);
    }

    let intent_id = bridge_string_field(value, &["intentId", "intent_id"])?;
    let route_directive = bridge_string_field(value, &["routeDirective", "route_directive"])
        .unwrap_or_else(|| "agent".to_string());
    let execution_mode = bridge_string_field(value, &["executionMode", "execution_mode"])
        .unwrap_or_else(|| "agent".to_string());
    let artifact = bridge_object_field(value, &["artifact"]);
    let artifact_required = artifact
        .and_then(|artifact| bridge_bool_field(artifact, &["required"]))
        .unwrap_or(false);
    let artifact_class = artifact
        .and_then(|artifact| {
            bridge_string_field(
                artifact,
                &[
                    "artifactClass",
                    "artifact_class",
                    "class",
                    "outputModality",
                    "output_modality",
                ],
            )
        })
        .unwrap_or_default();
    let effect_contract = bridge_object_field(value, &["effectContract", "effect_contract"]);
    let host_mutation = effect_contract
        .and_then(|contract| bridge_bool_field(contract, &["hostMutation", "host_mutation"]))
        .unwrap_or(false);
    let retrieval_required = bridge_object_field(value, &["retrieval"])
        .and_then(|retrieval| bridge_bool_field(retrieval, &["required"]))
        .unwrap_or(false);
    let workspace_required = bridge_object_field(value, &["workspace"])
        .and_then(|workspace| bridge_bool_field(workspace, &["required"]))
        .unwrap_or(false);
    let mut required_capabilities =
        bridge_string_array(value, &["requiredCapabilities", "required_capabilities"]);
    if let Some(contract) = effect_contract {
        required_capabilities.extend(bridge_string_array(
            contract,
            &[
                "requiredCapabilities",
                "required_capabilities",
                "receiptsRequired",
                "receipts_required",
            ],
        ));
    }
    required_capabilities.sort();
    required_capabilities.dedup();
    let required_capability_text = required_capabilities
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    let requires_web_tools = retrieval_required
        || intent_id.eq_ignore_ascii_case("retrieval.answer")
        || required_capability_text.contains("web.")
        || required_capability_text.contains("retrieval_");
    let requires_workspace_tools = workspace_required
        || intent_id.eq_ignore_ascii_case("workspace.context")
        || required_capability_text.contains("file.")
        || required_capability_text.contains("file_")
        || required_capability_text.contains("workspace.");
    let direct_answer_allowed = route_directive == "ask"
        || (intent_id.eq_ignore_ascii_case("conversation.reply")
            && !artifact_required
            && !requires_web_tools
            && !requires_workspace_tools
            && !host_mutation);
    let output_intent = if artifact_required || route_directive == "artifact" {
        "artifact_generation"
    } else if requires_web_tools || requires_workspace_tools || host_mutation {
        "tool_execution"
    } else if direct_answer_allowed {
        "conversation_reply"
    } else {
        "tool_execution"
    };
    if required_capabilities.is_empty() {
        required_capabilities.push(if artifact_required {
            "artifact.create".to_string()
        } else if requires_web_tools {
            "web.research".to_string()
        } else if requires_workspace_tools {
            "workspace.read".to_string()
        } else {
            "conversation.reply".to_string()
        });
    }
    let mut typed_evidence = vec![RuntimeIntentEvidence {
        evidence_kind: "studio_intent_frame".to_string(),
        value: route_directive.clone(),
        source: "autopilot_studio".to_string(),
        confidence: value
            .get("confidence")
            .and_then(Value::as_f64)
            .map(|score| (score.clamp(0.0, 1.0) * 100.0).round() as u8),
    }];
    typed_evidence.extend(workspace_target_evidence(value));

    Some(RuntimeRouteFrame {
        intent_id,
        route_family: if artifact_required {
            "artifact".to_string()
        } else if route_directive == "ask" {
            "direct_model".to_string()
        } else if requires_web_tools {
            "web_research".to_string()
        } else if requires_workspace_tools {
            "workspace".to_string()
        } else {
            "conversation".to_string()
        },
        output_intent: output_intent.to_string(),
        direct_answer_allowed,
        target: artifact
            .and_then(|artifact| bridge_string_field(artifact, &["title", "summary"]))
            .or_else(|| {
                bridge_string_field(value, &["target", "query", "goal", "prompt", "message"])
            })
            .or_else(|| bridge_nested_string_field(value, &["decisionMaterial", "promptPreview"]))
            .or_else(|| bridge_nested_string_field(value, &["decision_material", "prompt_preview"]))
            .unwrap_or_else(|| route_directive.clone()),
        target_kind: if artifact_required {
            Some(if artifact_class.is_empty() {
                "artifact".to_string()
            } else {
                artifact_class
            })
        } else {
            Some(execution_mode)
        },
        host_mutation,
        required_capabilities,
        typed_evidence,
        typed_required_capabilities: vec![],
        host_mutation_scope: None,
        runtime_action: None,
        install_request: None,
        provenance: Some("autopilot_studio_intent_frame".to_string()),
    })
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
        let inference = bridge_inference_runtime();
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
        .with_event_sender(event_sender.clone())
        .with_som(true);
        Ok(Self {
            state,
            service,
            services: ServiceDirectory::new(vec![]),
            browser_driver,
            event_sender,
            event_receiver,
            height: unix_millis(),
        })
    }

    fn apply_runtime_control_policy(
        &mut self,
        session_id: [u8; 32],
        request: &Value,
        options: &Value,
    ) -> Result<()> {
        let Some(policy) = runtime_control_policy(request, options) else {
            return Ok(());
        };
        let encoded = codec::to_bytes_canonical(&policy)
            .map_err(|error| anyhow!("failed to encode runtime control policy: {error}"))?;
        self.state
            .insert(&runtime_policy_key(session_id), &encoded)
            .context("failed to persist runtime control policy")?;
        Ok(())
    }

    fn load_runtime_policy_for_session(&self, session_id: [u8; 32]) -> Result<ActionRules> {
        if let Some(bytes) = self
            .state
            .get(&runtime_policy_key(session_id))
            .context("failed to read session runtime policy")?
        {
            return codec::from_bytes_canonical::<ActionRules>(&bytes)
                .map_err(|error| anyhow!("failed to decode session runtime policy: {error}"));
        }

        if let Some(bytes) = self
            .state
            .get(&runtime_policy_key([0u8; 32]))
            .context("failed to read global runtime policy")?
        {
            return codec::from_bytes_canonical::<ActionRules>(&bytes)
                .map_err(|error| anyhow!("failed to decode global runtime policy: {error}"));
        }

        Ok(default_safe_policy())
    }

    async fn start_thread(&mut self, bridge_id: &str, input: StartThreadInput) -> Result<Value> {
        let session_id = start_session_id(&input.request)?;
        self.apply_runtime_control_policy(session_id, &input.request, &input.options)?;
        let goal = non_empty_string(&input.request, &["goal", "prompt", "message", "input"])
            .unwrap_or_else(|| "Runtime service thread started.".to_string());
        let runtime_route_frame = runtime_route_frame_for_prompt_or_bridge_input(
            &input.request,
            Some(&input.options),
            &goal,
        );
        let max_steps = positive_u32(&input.request, &["max_steps", "maxSteps"])
            .or_else(|| positive_u32(&input.options, &["max_steps", "maxSteps"]))
            .unwrap_or(20);
        let params = StartAgentParams {
            session_id,
            goal,
            runtime_route_frame,
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
        self.apply_runtime_control_policy(session_id, &input.request, &input.options)?;
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
        if let Some(runtime_route_frame) =
            runtime_route_frame_for_prompt_or_bridge_input(&input.request, None, &prompt)
        {
            self.apply_runtime_route_frame(session_id, runtime_route_frame)?;
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
        emit_runtime_bridge_event(&events[0]);

        let state_before_steps = self.agent_state(session_id)?;
        let mut last_progress_at = Instant::now();
        let turn_idle_timeout = runtime_bridge_turn_idle_timeout();
        let step_timeout_limit = runtime_bridge_step_timeout();
        let max_steps = runtime_bridge_submit_turn_max_steps(
            &input.request,
            &input.options,
            &state_before_steps,
        );
        let mut latest_state = state_before_steps.clone();
        if apply_submit_turn_step_budget(&mut latest_state, max_steps) {
            let key = get_state_key(&session_id);
            let encoded = codec::to_bytes_canonical(&latest_state)
                .map_err(|error| anyhow!("failed to encode updated agent step budget: {error}"))?;
            self.state
                .insert(&key, &encoded)
                .context("failed to persist submit_turn step budget")?;
            self.commit()?;
        }
        let mut step_count = 0;
        let mut step_result = Ok(());
        let mut completed_after_chat_reply = false;
        let mut kernel_events = Vec::new();
        let mut kernel_event_next_ordinal = 0usize;
        while step_count < max_steps {
            let idle_elapsed = last_progress_at.elapsed();
            if idle_elapsed >= turn_idle_timeout {
                step_result = Err(runtime_bridge_turn_idle_timeout_error(turn_idle_timeout));
                break;
            }
            let step_timeout = step_timeout_limit;
            let state_before_step = self.agent_state(session_id)?;
            let live_event_pump = if input.streamed_events_only {
                Some(self.spawn_live_kernel_event_pump(
                    input.thread_id.clone(),
                    turn_id.clone(),
                    input.workspace_root.clone(),
                    kernel_event_next_ordinal,
                ))
            } else {
                None
            };
            let res = self.call_step_service(session_id, step_timeout).await;
            if let Some(pump) = live_event_pump {
                pump.stop().await;
            }
            if res.is_ok() {
                self.commit()?;
            }
            let mut step_events = self.drain_kernel_events();
            if !input.streamed_events_only {
                emit_runtime_bridge_kernel_events(
                    &input.thread_id,
                    &turn_id,
                    input.workspace_root.as_deref(),
                    kernel_event_next_ordinal,
                    &step_events,
                );
            }
            kernel_event_next_ordinal += step_events.len();
            if let Err(error) = res {
                step_result = Err(error);
                kernel_events.append(&mut step_events);
                break;
            }
            let state = self.agent_state(session_id)?;
            latest_state = state.clone();
            let step_emitted_chat_reply = step_events
                .iter()
                .any(kernel_event_is_successful_chat_reply);
            if matches!(state.status, AgentStatus::Running)
                && !bridge_agent_step_made_progress(&state_before_step, &state, &step_events)
            {
                step_result = Err(runtime_bridge_no_progress_error(
                    &state_before_step,
                    &state,
                    step_events.len(),
                ));
                kernel_events.append(&mut step_events);
                break;
            }
            step_result = Ok(());
            last_progress_at = Instant::now();
            kernel_events.append(&mut step_events);
            let retry_blocked_pause = match &state.status {
                AgentStatus::Paused(reason) => runtime_bridge_retry_blocked_pause_reason(reason),
                _ => false,
            };
            if retry_blocked_pause {
                if step_count.saturating_add(1) >= max_steps {
                    step_result = Err(runtime_bridge_retry_recovery_exhausted_error(max_steps));
                    break;
                }
                step_count += 1;
                continue;
            }
            if matches!(
                state.status,
                AgentStatus::Completed(_) | AgentStatus::Failed(_) | AgentStatus::Paused(_)
            ) {
                break;
            }
            if step_emitted_chat_reply && bridge_agent_can_complete_after_chat_reply(&state) {
                completed_after_chat_reply = true;
                break;
            }
            step_count += 1;
        }
        let mut tail_events = self.drain_kernel_events();
        emit_runtime_bridge_kernel_events(
            &input.thread_id,
            &turn_id,
            input.workspace_root.as_deref(),
            kernel_event_next_ordinal,
            &tail_events,
        );
        kernel_events.append(&mut tail_events);
        let state = match self.agent_state(session_id) {
            Ok(state) => state,
            Err(error) => {
                if step_result.is_ok() {
                    step_result = Err(error);
                }
                latest_state
            }
        };
        let completed_at = now_rfc3339();
        let exhausted_step_budget = runtime_bridge_step_budget_exhausted(
            step_result.is_ok(),
            &state.status,
            step_count,
            max_steps,
        );
        let emitted_successful_chat_reply = completed_after_chat_reply
            || kernel_events
                .iter()
                .any(kernel_event_is_successful_chat_reply);
        let (status, stop_reason, event_kind, event_status, summary) =
            match (&state.status, step_result) {
                (AgentStatus::Failed(reason), _) => (
                    "failed",
                    "runtime_bridge_failed",
                    "turn.failed",
                    "failed",
                    reason.clone(),
                ),
                (_, Err(error)) => {
                    let stop_reason = runtime_bridge_stop_reason_for_error(&error);
                    (
                        "failed",
                        stop_reason,
                        "turn.failed",
                        "failed",
                        error.to_string(),
                    )
                }
                (AgentStatus::Paused(reason), _) => (
                    "blocked",
                    "runtime_bridge_paused",
                    "turn.completed",
                    "blocked",
                    reason.clone(),
                ),
                (AgentStatus::Completed(None), _)
                    if runtime_bridge_completed_without_final_reply(
                        &state.status,
                        emitted_successful_chat_reply,
                    ) =>
                {
                    (
                    "failed",
                    "runtime_bridge_missing_chat_reply",
                    "turn.failed",
                    "failed",
                    "Runtime Agent turn completed before producing a final chat reply.".to_string(),
                    )
                }
                (AgentStatus::Completed(summary), _) => (
                    "completed",
                    "runtime_bridge_completed",
                    "turn.completed",
                    "completed",
                    summary
                        .clone()
                        .unwrap_or_else(|| "Runtime turn completed.".to_string()),
                ),
                (_, _) if completed_after_chat_reply => (
                    "completed",
                    "runtime_bridge_chat_reply_completed",
                    "turn.completed",
                    "completed",
                    "Runtime turn completed after chat__reply.".to_string(),
                ),
                (_, _) if exhausted_step_budget => (
                    "failed",
                    "runtime_bridge_step_budget_exhausted",
                    "turn.failed",
                    "failed",
                    format!(
                        "Runtime Agent turn exhausted the step budget before producing a final answer (step_count={}, max_steps={}).",
                        state.step_count, max_steps
                    ),
                ),
                (_, _) => (
                    "running",
                    "runtime_bridge_step_pending",
                    "turn.step",
                    "running",
                    "Runtime step completed; Agent is still running.".to_string(),
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
                .recent_browser_observation_artifacts(runtime_bridge_browser_observation_timeout())
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

        let result_events = if input.streamed_events_only {
            compact_streamed_turn_result_events(&events)
        } else {
            events
        };

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
            "events": result_events,
        }))
    }

    fn inspect_thread(&self, bridge_id: &str, input: InspectThreadInput) -> Result<Value> {
        let session_id = parse_session_id(&input.session_id)?;
        let state = self.agent_state(session_id)?;
        let session_hex = hex::encode(session_id);
        let trajectory: Option<AgentTrajectoryStepRecord> = self.decode_optional_state_record(
            get_agent_trajectory_step_key(&session_id, state.step_count),
            "agent trajectory step",
        )?;
        let brain: Option<AgentBrainRecord> =
            self.decode_optional_state_record(get_agent_brain_key(&session_id), "agent brain")?;
        let run_brain_artifact_index: Option<AgentRunBrainArtifactIndexRecord> = self
            .decode_optional_state_record(
                get_agent_run_brain_artifact_index_key(&session_id),
                "agent run-brain artifact index",
            )?;
        let runtime_substrate = self
            .state
            .get(&get_runtime_substrate_key(&session_id, state.step_count))
            .context("failed to read runtime substrate state")?
            .map(|bytes| {
                serde_json::from_slice::<Value>(&bytes)
                    .context("failed to decode runtime substrate snapshot")
            })
            .transpose()?;
        let working_directory = state.working_directory.trim();
        let review_workspace_root = input
            .workspace_root
            .as_deref()
            .or_else(|| (!working_directory.is_empty()).then_some(working_directory));
        let workspace_change_reviews = review_workspace_root
            .and_then(|workspace_root| {
                let trajectory = trajectory.as_ref()?;
                Some(
                    trajectory
                        .workspace_changes
                        .iter()
                        .map(|change| hunk_proposal_review_state(workspace_root, change))
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap_or_default();
        let effective_policy = self.load_runtime_policy_for_session(session_id)?;
        let policy_leases = policy_lease_snapshot_for_state(
            &self.state,
            session_id,
            &effective_policy,
            &state.status,
            &state.working_directory,
            &state.pending_action_state(),
            unix_millis(),
        )
        .map_err(|error| anyhow!("failed to derive runtime policy lease snapshot: {error}"))?;
        let stop_hooks = stop_hook_snapshot_for_state(session_id, &state);

        Ok(json!({
            "bridge_id": bridge_id,
            "source": "runtime_service",
            "thread_id": input.thread_id,
            "session_id": session_hex,
            "status": thread_status(&state.status),
            "runtime_state": {
                "session_id": session_hex,
                "goal": state.goal,
                "status": thread_status(&state.status),
                "step_count": state.step_count,
                "max_steps": state.max_steps,
                "parent_session_id": state.parent_session_id.map(hex::encode),
                "child_session_ids": state.child_session_ids.iter().map(hex::encode).collect::<Vec<_>>(),
                "last_action_type": state.last_action_type,
                "pending_tool": state.pending_tool_call,
                "working_directory": state.working_directory,
            },
            "latest_trajectory": trajectory,
            "workspace_change_reviews": workspace_change_reviews,
            "policy_leases": policy_leases,
            "stop_hooks": stop_hooks,
            "brain": brain,
            "run_brain_artifact_index": run_brain_artifact_index,
            "runtime_substrate": runtime_substrate,
            "inspected_at": now_rfc3339(),
        }))
    }

    async fn control_thread(
        &mut self,
        bridge_id: &str,
        input: ControlThreadInput,
    ) -> Result<Value> {
        let session_id = parse_session_id(&input.session_id)?;
        let action = normalize_runtime_control_value(&input.action);
        match action.as_str() {
            "pause" | "stop" => {
                self.call_service(
                    "pause@v1",
                    &PauseAgentParams {
                        session_id,
                        reason: input.reason.clone(),
                    },
                )
                .await?;
            }
            "cancel" | "terminate" => {
                self.call_service(
                    "cancel@v1",
                    &CancelAgentParams {
                        session_id,
                        reason: input.reason.clone(),
                    },
                )
                .await?;
            }
            "resume" | "recover" => {
                self.call_service(
                    "resume@v1",
                    &ResumeAgentParams {
                        session_id,
                        approval_grant: None,
                    },
                )
                .await?;
            }
            "deny" => {
                let request_hash = input
                    .request_hash
                    .as_deref()
                    .map(|raw| parse_32_byte_hex(raw, "request hash"))
                    .transpose()?;
                self.call_service(
                    "deny@v1",
                    &DenyAgentParams {
                        session_id,
                        request_hash,
                        reason: input.reason.clone(),
                    },
                )
                .await?;
            }
            other => {
                return Err(anyhow!(
                    "unsupported control_thread action '{}'; expected pause, cancel, resume, or deny",
                    other
                ));
            }
        }
        self.commit()?;
        let inspection = self.inspect_thread(
            bridge_id,
            InspectThreadInput {
                session_id: input.session_id.clone(),
                thread_id: input.thread_id.clone(),
                workspace_root: input.workspace_root.clone(),
            },
        )?;
        let controlled_at = input.created_at.unwrap_or_else(now_rfc3339);
        Ok(json!({
            "bridge_id": bridge_id,
            "source": "runtime_service",
            "session_id": hex::encode(session_id),
            "action": action,
            "status": inspection.get("status").cloned().unwrap_or(Value::Null),
            "controlled_at": controlled_at,
            "inspection": inspection,
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

    fn spawn_live_kernel_event_pump(
        &self,
        thread_id: String,
        turn_id: String,
        workspace_root: Option<String>,
        start_ordinal: usize,
    ) -> LiveKernelEventPump {
        let mut receiver = self.event_sender.subscribe();
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let mut ordinal = start_ordinal;
            loop {
                tokio::select! {
                    _ = &mut stop_rx => {
                        loop {
                            match receiver.try_recv() {
                                Ok(event) => {
                                    if emit_runtime_bridge_kernel_event(
                                        &thread_id,
                                        &turn_id,
                                        workspace_root.as_deref(),
                                        ordinal,
                                        &event,
                                    ) {
                                        ordinal = ordinal.saturating_add(1);
                                    }
                                }
                                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
                                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
                                | Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
                            }
                        }
                        break;
                    }
                    received = receiver.recv() => {
                        match received {
                            Ok(event) => {
                                if emit_runtime_bridge_kernel_event(
                                    &thread_id,
                                    &turn_id,
                                    workspace_root.as_deref(),
                                    ordinal,
                                    &event,
                                ) {
                                    ordinal = ordinal.saturating_add(1);
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
        });
        LiveKernelEventPump {
            stop_tx: Some(stop_tx),
            handle,
        }
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

    async fn call_step_service(&mut self, session_id: [u8; 32], timeout: Duration) -> Result<()> {
        match tokio::time::timeout(
            timeout,
            self.call_service("step@v1", &StepAgentParams { session_id }),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(anyhow!(
                "runtime_bridge_step_timeout: step@v1 exceeded {}ms without returning an agent action",
                timeout.as_millis()
            )),
        }
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

    fn decode_optional_state_record<T: Decode>(
        &self,
        key: Vec<u8>,
        label: &str,
    ) -> Result<Option<T>> {
        self.state
            .get(&key)
            .with_context(|| format!("failed to read {label}"))?
            .map(|bytes| {
                codec::from_bytes_canonical::<T>(&bytes)
                    .map_err(|error| anyhow!("failed to decode {label}: {error}"))
            })
            .transpose()
    }

    fn apply_runtime_route_frame(
        &mut self,
        session_id: [u8; 32],
        runtime_route_frame: RuntimeRouteFrame,
    ) -> Result<()> {
        let key = get_state_key(&session_id);
        let Some(bytes) = self.state.get(&key)? else {
            return Err(anyhow!(
                "agent state missing for session {}",
                hex::encode(session_id)
            ));
        };
        let mut agent_state: AgentState = codec::from_bytes_canonical(&bytes)
            .map_err(|error| anyhow!("failed to decode agent state: {error}"))?;
        agent_state.runtime_route_frame = Some(runtime_route_frame);
        agent_state.resolved_intent = None;
        agent_state.awaiting_intent_clarification = false;
        let encoded = codec::to_bytes_canonical(&agent_state)
            .map_err(|error| anyhow!("failed to encode agent state: {error}"))?;
        self.state
            .insert(&key, &encoded)
            .context("failed to persist runtime route frame")?;
        Ok(())
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
    let payload_summary = runtime_bridge_events::product_projection_for_event(
        input.event_kind,
        input.status,
        input.actor,
        input.component_kind,
        &input.payload,
    );
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
        "product_projection_schema_version": runtime_bridge_events::PRODUCT_EVENT_PROJECTION_SCHEMA_VERSION,
        "payload_detail_visibility": "runs_tracing",
        "payload_summary": payload_summary,
        "payload": input.payload,
        "fixture_profile": Value::Null,
    })
}

fn emit_runtime_bridge_event(event: &Value) {
    println!(
        "{}",
        serde_json::to_string(&json!({
            "type": "runtime_event",
            "event": event,
        }))
        .unwrap()
    );
    let _ = io::stdout().flush();
}

fn emit_runtime_bridge_kernel_events(
    thread_id: &str,
    turn_id: &str,
    workspace_root: Option<&str>,
    start_ordinal: usize,
    events: &[KernelEvent],
) {
    for (offset, event) in events.iter().enumerate() {
        emit_runtime_bridge_kernel_event(
            thread_id,
            turn_id,
            workspace_root,
            start_ordinal + offset,
            event,
        );
    }
}

fn emit_runtime_bridge_kernel_event(
    thread_id: &str,
    turn_id: &str,
    workspace_root: Option<&str>,
    ordinal: usize,
    event: &KernelEvent,
) -> bool {
    let created_at = now_rfc3339();
    if let Some(mapped) = runtime_bridge_events::kernel_event_to_tti_event(
        event,
        &runtime_bridge_events::RuntimeBridgeEventContext {
            thread_id,
            turn_id,
            workspace_root,
            created_at: &created_at,
            ordinal,
        },
    ) {
        emit_runtime_bridge_event(&mapped);
        true
    } else {
        false
    }
}

fn compact_streamed_turn_result_events(events: &[Value]) -> Vec<Value> {
    let mut result = Vec::new();
    if let Some(started) = events
        .iter()
        .find(|event| {
            bridge_string_field(event, &["event_kind"]).as_deref() == Some("turn.started")
        })
        .cloned()
    {
        result.push(started);
    }
    for event in events {
        if !runtime_bridge_event_is_observable_work_lane(event) {
            continue;
        }
        let duplicate = result.iter().any(|existing| {
            bridge_string_field(existing, &["idempotency_key"])
                == bridge_string_field(event, &["idempotency_key"])
        });
        if !duplicate {
            result.push(event.clone());
        }
    }
    if let Some(last) = events.last().cloned() {
        let duplicate = result.iter().any(|event| {
            bridge_string_field(event, &["idempotency_key"])
                == bridge_string_field(&last, &["idempotency_key"])
        });
        if !duplicate {
            result.push(last);
        }
    }
    if result.is_empty() {
        events.first().cloned().into_iter().collect()
    } else {
        result
    }
}

fn runtime_bridge_event_is_observable_work_lane(event: &Value) -> bool {
    let kind = bridge_string_field(event, &["event_kind"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    if kind == "turn.started" || kind == "turn.completed" || kind == "turn.failed" {
        return false;
    }
    kind.starts_with("tool.")
        || kind.ends_with(".route_decision")
        || kind.starts_with("approval.")
        || kind.starts_with("policy.")
        || kind.starts_with("receipt.")
        || kind.starts_with("browser.")
        || kind.starts_with("computer.")
        || kind.starts_with("artifact.")
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
    parse_32_byte_hex(input, "session id")
}

fn parse_32_byte_hex(input: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(input.trim().trim_start_matches("0x"))
        .with_context(|| format!("invalid {label} hex '{input}'"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{label} must be 32 bytes, got {}", bytes.len()));
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

fn runtime_bridge_step_timeout() -> Duration {
    runtime_bridge_step_timeout_from_env(|name| std::env::var(name).ok())
}

fn runtime_bridge_step_timeout_from_env<F>(get_env: F) -> Duration
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(configured) = runtime_bridge_positive_duration_millis(get_env(
        "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_STEP_TIMEOUT_MS",
    )) {
        return configured;
    }
    let default_millis = if runtime_bridge_env_truthy(get_env("AUTOPILOT_LOCAL_GPU_DEV")) {
        DEFAULT_LOCAL_GPU_AGENT_STEP_TIMEOUT_MS
    } else {
        DEFAULT_AGENT_STEP_TIMEOUT_MS
    };
    let cognition_timeout =
        runtime_bridge_positive_duration_secs(get_env("IOI_COGNITION_INFERENCE_TIMEOUT_SECS"))
            .unwrap_or_else(|| {
                if runtime_bridge_env_truthy(get_env("AUTOPILOT_LOCAL_GPU_DEV")) {
                    Duration::from_secs(90)
                } else {
                    Duration::from_secs(30)
                }
            });
    Duration::from_millis(default_millis)
        .max(cognition_timeout.saturating_add(Duration::from_secs(30)))
}

fn runtime_bridge_turn_idle_timeout() -> Duration {
    std::env::var("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_TURN_IDLE_TIMEOUT_MS")
        .ok()
        .or_else(|| std::env::var("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_TURN_TIMEOUT_MS").ok())
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|millis| *millis > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_AGENT_TURN_IDLE_TIMEOUT_MS))
}

fn runtime_bridge_positive_duration_millis(raw: Option<String>) -> Option<Duration> {
    raw.and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|millis| *millis > 0)
        .map(Duration::from_millis)
}

fn runtime_bridge_positive_duration_secs(raw: Option<String>) -> Option<Duration> {
    raw.and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
}

fn runtime_bridge_env_truthy(raw: Option<String>) -> bool {
    raw.map(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
    .unwrap_or(false)
}

fn runtime_bridge_browser_observation_timeout() -> Duration {
    std::env::var("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_BROWSER_OBSERVATION_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|millis| *millis > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_BROWSER_OBSERVATION_TIMEOUT_MS))
}

fn kernel_event_is_agent_output(event: &KernelEvent) -> bool {
    match event {
        KernelEvent::AgentActionResult { .. } => true,
        KernelEvent::WorkloadReceipt(receipt) => {
            !matches!(receipt.receipt, WorkloadReceipt::Inference(_))
        }
        KernelEvent::FirewallInterception { .. }
        | KernelEvent::PiiDecisionReceipt(_)
        | KernelEvent::PiiReviewRequested { .. } => true,
        _ => false,
    }
}

fn kernel_event_is_successful_chat_reply(event: &KernelEvent) -> bool {
    matches!(
        event,
        KernelEvent::AgentActionResult {
            tool_name,
            output,
            error_class,
            agent_status,
            ..
        } if tool_name == "chat__reply"
            && error_class.is_none()
            && agent_status.eq_ignore_ascii_case("completed")
            && !output.trim().is_empty()
            && !runtime_bridge_chat_reply_is_deferred(output)
    )
}

fn runtime_bridge_chat_reply_is_deferred(output: &str) -> bool {
    output.trim().eq_ignore_ascii_case(
        "Deferred final reply while web research continues gathering evidence.",
    )
}

fn bridge_agent_can_complete_after_chat_reply(state: &AgentState) -> bool {
    matches!(state.status, AgentStatus::Running)
        && state.execution_queue.is_empty()
        && state.pending_approval.is_none()
        && state.pending_tool_call.is_none()
}

fn runtime_bridge_completed_without_final_reply(
    status: &AgentStatus,
    emitted_successful_chat_reply: bool,
) -> bool {
    matches!(status, AgentStatus::Completed(None)) && !emitted_successful_chat_reply
}

fn bridge_agent_step_made_progress(
    before: &AgentState,
    after: &AgentState,
    events: &[KernelEvent],
) -> bool {
    after.status != before.status
        || after.step_count > before.step_count
        || after.last_action_type != before.last_action_type
        || after.recent_actions.len() > before.recent_actions.len()
        || after.execution_queue.len() != before.execution_queue.len()
        || after.pending_approval.is_some()
        || after.pending_tool_call != before.pending_tool_call
        || after.pending_tool_jcs != before.pending_tool_jcs
        || events.iter().any(kernel_event_is_agent_output)
}

fn runtime_bridge_no_progress_error(
    before: &AgentState,
    after: &AgentState,
    event_count: usize,
) -> anyhow::Error {
    anyhow!(
        "runtime_bridge_no_progress: step@v1 returned while Agent Mode remained running without a tool action, queued action, status change, or step-count advance (step_count {} -> {}, queue_len {} -> {}, recent_actions {} -> {}, events={})",
        before.step_count,
        after.step_count,
        before.execution_queue.len(),
        after.execution_queue.len(),
        before.recent_actions.len(),
        after.recent_actions.len(),
        event_count
    )
}

fn runtime_bridge_turn_idle_timeout_error(timeout: Duration) -> anyhow::Error {
    anyhow!(
        "runtime_bridge_turn_idle_timeout: submit_turn exceeded {}ms without completed-step progress toward a terminal Agent Mode result",
        timeout.as_millis()
    )
}

fn runtime_bridge_retry_blocked_pause_reason(reason: &str) -> bool {
    reason.starts_with("Retry blocked: unchanged AttemptKey for")
        || reason.starts_with("Retry guard tripped after repeated")
}

fn runtime_bridge_retry_recovery_exhausted_error(max_steps: u32) -> anyhow::Error {
    anyhow!(
        "runtime_bridge_retry_recovery_exhausted: internal retry recovery exhausted the submit_turn step budget before a final verified answer (max_steps={})",
        max_steps
    )
}

fn runtime_bridge_stop_reason_for_error(error: &anyhow::Error) -> &'static str {
    let message = error.to_string();
    if message.contains("runtime_bridge_step_timeout") {
        "runtime_bridge_step_timeout"
    } else if message.contains("runtime_bridge_turn_idle_timeout")
        || message.contains("runtime_bridge_turn_timeout")
    {
        "runtime_bridge_turn_idle_timeout"
    } else if message.contains("runtime_bridge_no_progress") {
        "runtime_bridge_no_progress"
    } else if message.contains("runtime_bridge_retry_recovery_exhausted") {
        "runtime_bridge_retry_recovery_exhausted"
    } else {
        "runtime_bridge_failed"
    }
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
    let _ = prompt;
    bool_value(request, &["computerUse", "computer_use"]).unwrap_or(false)
        || non_empty_string(request, &["computerUseLane", "computer_use_lane"]).is_some()
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

fn runtime_bridge_step_budget_exhausted(
    step_result_ok: bool,
    status: &AgentStatus,
    completed_loop_steps: u32,
    requested_max_steps: u32,
) -> bool {
    step_result_ok
        && matches!(status, AgentStatus::Running)
        && completed_loop_steps >= requested_max_steps
}

fn runtime_bridge_submit_turn_max_steps(
    request: &Value,
    options: &Value,
    state_before_steps: &AgentState,
) -> u32 {
    let requested = [
        positive_u32(request, &["max_steps", "maxSteps"]),
        positive_u32(options, &["max_steps", "maxSteps"]),
        bridge_nested_object_field(request, &["options"])
            .and_then(|value| positive_u32(value, &["max_steps", "maxSteps"])),
    ]
    .into_iter()
    .flatten()
    .max();

    requested.unwrap_or_else(|| {
        state_before_steps
            .max_steps
            .saturating_sub(state_before_steps.step_count)
            .max(DEFAULT_RUNTIME_BRIDGE_SUBMIT_TURN_MAX_STEPS)
    })
}

fn apply_submit_turn_step_budget(state: &mut AgentState, max_steps: u32) -> bool {
    if max_steps == 0 || state.max_steps == max_steps {
        return false;
    }
    state.max_steps = max_steps;
    true
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
    fn runtime_control_policy_maps_yolo_to_allow_all() {
        let policy = runtime_control_policy(
            &json!({
                "approvalMode": "never_prompt",
                "threadMode": "yolo"
            }),
            &Value::Null,
        )
        .expect("policy override");
        assert_eq!(policy.policy_id, "runtime-bridge-full-access");
        assert_eq!(policy.defaults, DefaultPolicy::AllowAll);
    }

    #[test]
    fn runtime_control_policy_maps_default_permissions_to_safe_policy() {
        let policy = runtime_control_policy(
            &json!({
                "approval_mode": "suggest",
                "thread_mode": "agent"
            }),
            &Value::Null,
        )
        .expect("policy override");
        assert_eq!(policy.policy_id, "runtime-bridge-auto-review");
        assert_eq!(policy.defaults, DefaultPolicy::RequireApproval);
    }

    #[test]
    fn submit_turn_step_budget_reads_nested_runtime_options() {
        let state = test_agent_state();
        let request = json!({
            "prompt": "fix the failing test",
            "max_steps": 1,
            "options": {
                "maxSteps": 16
            }
        });
        let max_steps = runtime_bridge_submit_turn_max_steps(&request, &Value::Null, &state);
        assert_eq!(max_steps, 16);
    }

    #[test]
    fn submit_turn_step_budget_defaults_to_multi_step_model_tool_loop() {
        let mut state = test_agent_state();
        state.max_steps = 1;
        state.step_count = 0;

        let max_steps = runtime_bridge_submit_turn_max_steps(
            &json!({"prompt": "fix the failing test"}),
            &Value::Null,
            &state,
        );

        assert_eq!(max_steps, DEFAULT_RUNTIME_BRIDGE_SUBMIT_TURN_MAX_STEPS);
    }

    #[test]
    fn submit_turn_step_budget_updates_reused_agent_state() {
        let mut state = test_agent_state();
        state.max_steps = 8;
        assert!(apply_submit_turn_step_budget(&mut state, 16));
        assert_eq!(state.max_steps, 16);
        assert!(!apply_submit_turn_step_budget(&mut state, 16));
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
        assert_eq!(
            event["product_projection_schema_version"],
            runtime_bridge_events::PRODUCT_EVENT_PROJECTION_SCHEMA_VERSION
        );
        assert_eq!(event["payload_detail_visibility"], "runs_tracing");
        assert_eq!(event["payload_summary"]["visibility"], "work_lane");
        assert_eq!(
            event["payload_summary"]["schema_version"],
            runtime_bridge_events::PRODUCT_EVENT_PROJECTION_SCHEMA_VERSION
        );
    }

    #[test]
    fn compact_streamed_turn_result_events_keeps_observable_work_lane_events() {
        let started = json!({
            "event_kind": "turn.started",
            "idempotency_key": "started",
            "payload": { "prompt": "long prompt" }
        });
        let search = json!({
            "event_kind": "tool.completed",
            "idempotency_key": "tool-search",
            "payload": {
                "tool_name": "web__search",
                "output": "{\"sources\":[{\"title\":\"Photonic quantum computing\",\"url\":\"https://example.test/photonic\"}]}"
            }
        });
        let route = json!({
            "event_kind": "tool.route_decision",
            "idempotency_key": "route-search",
            "payload": { "tool_name": "web__search" }
        });
        let streamed_delta = json!({
            "event_kind": "answer.delta",
            "idempotency_key": "delta",
            "payload": { "delta": "<!DOCTYPE html>".repeat(2000) }
        });
        let terminal = json!({
            "event_kind": "turn.completed",
            "idempotency_key": "completed",
            "payload": { "summary": "done" }
        });

        let compacted = compact_streamed_turn_result_events(&[
            started.clone(),
            route.clone(),
            search.clone(),
            streamed_delta,
            terminal.clone(),
        ]);

        assert_eq!(compacted, vec![started, route, search, terminal]);
    }

    fn test_agent_state() -> AgentState {
        AgentState {
            session_id: [1u8; 32],
            goal: "test".to_string(),
            runtime_route_frame: None,
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: Vec::new(),
            budget: 0,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: Vec::new(),
            mode: AgentMode::Agent,
            current_tier: Default::default(),
            last_screen_phash: None,
            execution_queue: Vec::new(),
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: Default::default(),
            execution_ledger: Default::default(),
            visual_som_map: None,
            visual_semantic_map: None,
            work_graph_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: Default::default(),
            active_lens: None,
        }
    }

    #[test]
    fn bridge_agent_step_progress_requires_state_change_or_agent_output() {
        let before = test_agent_state();
        let after = before.clone();
        assert!(!bridge_agent_step_made_progress(&before, &after, &[]));

        let mut stepped = before.clone();
        stepped.step_count = 1;
        assert!(bridge_agent_step_made_progress(&before, &stepped, &[]));

        let mut completed = before.clone();
        completed.status = AgentStatus::Completed(Some("done".to_string()));
        assert!(bridge_agent_step_made_progress(&before, &completed, &[]));

        assert!(bridge_agent_step_made_progress(
            &before,
            &after,
            &[KernelEvent::AgentActionResult {
                session_id: [1u8; 32],
                step_index: 0,
                tool_name: "chat__reply".to_string(),
                output: "hello".to_string(),
                error_class: None,
                agent_status: "Completed".to_string(),
            }],
        ));
    }

    #[test]
    fn runtime_bridge_budget_exhaustion_does_not_mark_running_agent_completed() {
        assert!(runtime_bridge_step_budget_exhausted(
            true,
            &AgentStatus::Running,
            8,
            8,
        ));
        assert!(!runtime_bridge_step_budget_exhausted(
            true,
            &AgentStatus::Completed(Some("done".to_string())),
            8,
            8,
        ));
        assert!(!runtime_bridge_step_budget_exhausted(
            false,
            &AgentStatus::Running,
            8,
            8,
        ));
        assert!(!runtime_bridge_step_budget_exhausted(
            true,
            &AgentStatus::Running,
            7,
            8,
        ));
    }

    #[test]
    fn runtime_bridge_completed_none_still_requires_chat_reply() {
        assert!(runtime_bridge_completed_without_final_reply(
            &AgentStatus::Completed(None),
            false,
        ));
        assert!(!runtime_bridge_completed_without_final_reply(
            &AgentStatus::Completed(None),
            true,
        ));
        assert!(!runtime_bridge_completed_without_final_reply(
            &AgentStatus::Completed(Some("done".to_string())),
            false,
        ));
    }

    #[test]
    fn runtime_bridge_retry_blocked_pause_is_internal_recovery_signal() {
        assert!(runtime_bridge_retry_blocked_pause_reason(
            "Retry blocked: unchanged AttemptKey for NoEffectAfterAction"
        ));
        assert!(runtime_bridge_retry_blocked_pause_reason(
            "Retry guard tripped after repeated NoEffectAfterAction"
        ));
        assert!(!runtime_bridge_retry_blocked_pause_reason(
            "Waiting for human approval"
        ));

        let error = runtime_bridge_retry_recovery_exhausted_error(8);
        assert_eq!(
            runtime_bridge_stop_reason_for_error(&error),
            "runtime_bridge_retry_recovery_exhausted"
        );
    }

    #[test]
    fn runtime_bridge_step_timeout_does_not_undercut_local_model_inference() {
        let timeout = runtime_bridge_step_timeout_from_env(|name| match name {
            "AUTOPILOT_LOCAL_GPU_DEV" => Some("1".to_string()),
            "IOI_COGNITION_INFERENCE_TIMEOUT_SECS" => Some("140".to_string()),
            _ => None,
        });
        assert!(timeout >= Duration::from_secs(170));
    }

    #[test]
    fn runtime_bridge_step_timeout_honors_explicit_bridge_override() {
        let timeout = runtime_bridge_step_timeout_from_env(|name| match name {
            "AUTOPILOT_LOCAL_GPU_DEV" => Some("1".to_string()),
            "IOI_COGNITION_INFERENCE_TIMEOUT_SECS" => Some("140".to_string()),
            "IOI_RUNTIME_AGENT_SERVICE_BRIDGE_STEP_TIMEOUT_MS" => Some("45000".to_string()),
            _ => None,
        });
        assert_eq!(timeout, Duration::from_millis(45_000));
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
    fn computer_use_detection_uses_explicit_request_or_browser_tools() {
        assert!(request_indicates_computer_use(
            &json!({"computerUse": true}),
            ""
        ));
        assert!(!request_indicates_computer_use(
            &json!({}),
            "open the browser"
        ));
        assert!(!request_indicates_computer_use(
            &json!({}),
            "browser_fixture_url=http://127.0.0.1 computer_use_providers_url=http://127.0.0.1"
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

    #[test]
    fn deferred_web_research_chat_reply_is_not_terminal_bridge_reply() {
        let event = KernelEvent::AgentActionResult {
            session_id: [1u8; 32],
            step_index: 0,
            tool_name: "chat__reply".to_string(),
            output: "Deferred final reply while web research continues gathering evidence."
                .to_string(),
            error_class: None,
            agent_status: "Running".to_string(),
        };
        assert!(!kernel_event_is_successful_chat_reply(&event));

        let rejected_retry_feedback = KernelEvent::AgentActionResult {
            session_id: [1u8; 32],
            step_index: 1,
            tool_name: "chat__reply".to_string(),
            output: String::new(),
            error_class: None,
            agent_status: "Running".to_string(),
        };
        assert!(!kernel_event_is_successful_chat_reply(
            &rejected_retry_feedback
        ));

        let terminal = KernelEvent::AgentActionResult {
            session_id: [1u8; 32],
            step_index: 2,
            tool_name: "chat__reply".to_string(),
            output: "Here are the current sources I found.".to_string(),
            error_class: None,
            agent_status: "Completed".to_string(),
        };
        assert!(kernel_event_is_successful_chat_reply(&terminal));
    }

    #[test]
    fn bridge_prompt_intent_projects_inline_run_command_to_shell_route_frame() {
        let frame = runtime_route_frame_for_prompt(
            "Run `node --check scripts/lib/autopilot-agent-studio-chat-scenarios.mjs` and summarize the exit code.",
        )
        .expect("inline executable command should synthesize a shell route frame");

        assert_eq!(frame.intent_id, "command.exec");
        assert_eq!(frame.route_family, "command_execution");
        assert_eq!(frame.output_intent, "tool_execution");
        assert!(!frame.direct_answer_allowed);
        let action = frame.runtime_action.expect("runtime action");
        assert_eq!(action.action_family, "shell");
        let command_plan = action.command_plan.expect("command plan");
        assert_eq!(
            command_plan.argv,
            vec![
                "node".to_string(),
                "--check".to_string(),
                "scripts/lib/autopilot-agent-studio-chat-scenarios.mjs".to_string(),
            ]
        );
    }

    #[test]
    fn bridge_prompt_intent_keeps_shell_operator_commands_bounded() {
        let frame =
            runtime_route_frame_for_prompt("Run `echo ok | cat` and summarize the exit code.")
                .expect("inline shell pipeline should synthesize a shell route frame");
        let action = frame.runtime_action.expect("runtime action");
        let command_plan = action.command_plan.expect("command plan");
        assert_eq!(
            command_plan.argv,
            vec![
                "bash".to_string(),
                "-lc".to_string(),
                "echo ok | cat".to_string(),
            ]
        );
    }

    #[test]
    fn bridge_prompt_intent_does_not_project_inline_code_symbol_to_shell() {
        assert!(runtime_route_frame_for_prompt(
            "Explain how `formatOrderTotal` is used in this repo."
        )
        .is_none());
    }

    #[test]
    fn bridge_prompt_intent_projects_inline_path_read_to_file_route_frame() {
        let frame = runtime_route_frame_for_prompt(
            "Try to read `/etc/passwd` through the governed file tool and summarize whether the daemon blocks it.",
        )
        .expect("inline path read should synthesize a governed file route frame");

        assert_eq!(frame.intent_id, "workspace.context");
        assert_eq!(frame.route_family, "workspace");
        assert_eq!(frame.output_intent, "tool_execution");
        assert_eq!(frame.target, "/etc/passwd");
        assert_eq!(frame.target_kind.as_deref(), Some("workspace_path"));
        assert!(frame.runtime_action.is_none());
        assert!(frame
            .typed_evidence
            .iter()
            .any(|item| item.evidence_kind == "workspace_path" && item.value == "/etc/passwd"));
    }

    #[test]
    fn bridge_prompt_intent_projects_inline_dotfile_path_read_to_file_route_frame() {
        let frame = runtime_route_frame_for_prompt(
            "Try to read `.autopilot-stage73-outside-link` through the governed file tool and summarize whether the daemon blocks it.",
        )
        .expect("inline dotfile path read should synthesize a governed file route frame");

        assert_eq!(frame.intent_id, "workspace.context");
        assert_eq!(frame.route_family, "workspace");
        assert_eq!(frame.output_intent, "tool_execution");
        assert_eq!(frame.target, ".autopilot-stage73-outside-link");
        assert_eq!(frame.target_kind.as_deref(), Some("workspace_path"));
        assert!(frame.runtime_action.is_none());
        assert!(frame.typed_evidence.iter().any(|item| {
            item.evidence_kind == "workspace_path"
                && item.value == ".autopilot-stage73-outside-link"
        }));
    }

    #[test]
    fn bridge_prompt_runtime_action_beats_generic_studio_intent_frame() {
        let request = json!({
            "prompt": "Run `node --check scripts/lib/autopilot-agent-studio-chat-scenarios.mjs` and summarize the exit code.",
            "intentFrame": {
                "schemaVersion": "ioi.studio.intent-frame.v1",
                "intentId": "conversation.reply",
                "routeDirective": "agent",
                "executionMode": "agent",
                "artifact": { "required": false },
                "retrieval": { "required": false },
                "workspace": { "required": false },
                "requiredCapabilities": ["prim:conversation.reply"]
            }
        });
        let prompt = request
            .get("prompt")
            .and_then(Value::as_str)
            .expect("prompt");
        let frame = runtime_route_frame_for_prompt_or_bridge_input(&request, None, prompt)
            .expect("explicit shell prompt should override generic intent frame");

        assert_eq!(frame.intent_id, "command.exec");
        assert_eq!(frame.route_family, "command_execution");
        assert!(!frame.direct_answer_allowed);
        assert!(frame.runtime_action.is_some());
    }

    #[test]
    fn bridge_browser_prompt_projects_governed_browser_route_frame() {
        let request = json!({
            "prompt": "Open a sandbox browser, inspect this fixture page, and summarize what changed. Use http://127.0.0.1:40291/ as the disposable page.",
            "intentFrame": {
                "schemaVersion": "ioi.studio.intent-frame.v1",
                "intentId": "conversation.reply",
                "routeDirective": "agent",
                "executionMode": "agent",
                "artifact": { "required": false },
                "retrieval": { "required": false },
                "workspace": { "required": false },
                "requiredCapabilities": ["prim:conversation.reply"]
            }
        });
        let prompt = request
            .get("prompt")
            .and_then(Value::as_str)
            .expect("prompt");
        let frame = runtime_route_frame_for_prompt_or_bridge_input(&request, None, prompt)
            .expect("explicit browser prompt should override generic intent frame");

        assert_eq!(frame.intent_id, "browser.interact");
        assert_eq!(frame.route_family, "browser");
        assert_eq!(frame.output_intent, "tool_execution");
        assert!(!frame.direct_answer_allowed);
        assert_eq!(frame.target, "http://127.0.0.1:40291/");
        assert!(frame
            .required_capabilities
            .iter()
            .any(|capability| capability == "browser.inspect"));
        let action = frame.runtime_action.expect("runtime action");
        assert_eq!(action.action_family, "browser");
        let browser_plan = action.browser_plan.expect("browser plan");
        assert_eq!(browser_plan.action, "navigate");
        assert_eq!(browser_plan.url, "http://127.0.0.1:40291/");
        assert!(browser_plan.observation_required);
    }

    #[test]
    fn bridge_source_backed_html_prompt_beats_generic_studio_intent_frame() {
        let request = json!({
            "prompt": "Create an HTML file about photonic quantum computing and use sources.",
            "intentFrame": {
                "schemaVersion": "ioi.studio.intent-frame.v1",
                "intentId": "conversation.reply",
                "routeDirective": "agent",
                "executionMode": "agent",
                "artifact": { "required": false },
                "retrieval": { "required": false },
                "workspace": { "required": false },
                "requiredCapabilities": ["prim:conversation.reply"]
            }
        });
        let prompt = request
            .get("prompt")
            .and_then(Value::as_str)
            .expect("prompt");
        let frame = runtime_route_frame_for_prompt_or_bridge_input(&request, None, prompt)
            .expect("source-backed artifact prompt should override generic intent frame");

        assert_eq!(frame.intent_id, "retrieval.answer");
        assert_eq!(frame.route_family, "web_research");
        assert_eq!(frame.output_intent, "tool_execution");
        assert!(!frame.direct_answer_allowed);
        assert_eq!(frame.target, "photonic quantum computing");
        assert_eq!(frame.target_kind.as_deref(), Some("source_backed_artifact"));
        assert!(frame
            .required_capabilities
            .iter()
            .any(|capability| capability == "web.retrieve"));
        assert!(frame
            .required_capabilities
            .iter()
            .any(|capability| capability == "filesystem.write"));
    }

    #[test]
    fn bridge_internal_source_backed_artifact_prompt_uses_research_topic() {
        let prompt = concat!(
            "Create one complete self-contained HTML document for this request: Create an HTML file about photonic quantum computing and use sources.\n",
            "Research topic: photonic quantum computing\n\n",
            "Use the governed tool loop before writing the page.\n",
            "Call web__search with exactly the research topic above as the query.\n",
            "Then call chat__reply; the chat__reply message must contain the final HTML document only."
        );
        let request = json!({
            "prompt": prompt,
            "intentFrame": {
                "schemaVersion": "ioi.studio.intent-frame.v1",
                "intentId": "conversation.reply",
                "routeDirective": "agent",
                "executionMode": "agent",
                "artifact": { "required": false },
                "retrieval": { "required": false },
                "workspace": { "required": false },
                "requiredCapabilities": ["prim:conversation.reply"]
            }
        });
        let frame = runtime_route_frame_for_prompt_or_bridge_input(&request, None, prompt)
            .expect("internal source-backed artifact prompt should synthesize retrieval frame");

        assert_eq!(frame.intent_id, "retrieval.answer");
        assert_eq!(frame.route_family, "web_research");
        assert_eq!(frame.target, "photonic quantum computing");
        assert_eq!(frame.target_kind.as_deref(), Some("source_backed_artifact"));
    }

    #[test]
    fn bridge_studio_retrieval_frame_preserves_prompt_as_web_query_target() {
        let request = json!({
            "prompt": "Which is a better investment right now, Akash or Filecoin?",
            "intentFrame": {
                "schemaVersion": "ioi.studio.intent-frame.v1",
                "intentId": "retrieval.answer",
                "routeDirective": "agent",
                "executionMode": "agent",
                "target": "Which is a better investment right now, Akash or Filecoin?",
                "query": "Which is a better investment right now, Akash or Filecoin?",
                "artifact": { "required": false },
                "retrieval": { "required": true, "requirements": ["current_external_state", "source_grounding"] },
                "workspace": { "required": false },
                "requiredCapabilities": ["prim:conversation.reply", "prim:web.search", "prim:web.read"]
            }
        });
        let prompt = request
            .get("prompt")
            .and_then(Value::as_str)
            .expect("prompt");
        let frame = runtime_route_frame_for_prompt_or_bridge_input(&request, None, prompt)
            .expect("retrieval intent frame should become a typed web route");

        assert_eq!(frame.intent_id, "retrieval.answer");
        assert_eq!(frame.route_family, "web_research");
        assert_eq!(frame.output_intent, "tool_execution");
        assert!(!frame.direct_answer_allowed);
        assert_eq!(
            frame.target,
            "Which is a better investment right now, Akash or Filecoin?"
        );
    }

    #[test]
    fn bridge_studio_retrieval_frame_beats_internal_html_artifact_prompt() {
        let request = json!({
            "prompt": concat!(
                "Create one complete self-contained HTML document for this request: Create a website that explains post-quantum computers\n",
                "Research topic: post-quantum computers\n\n",
                "Call web__search with exactly the research topic above as the query.\n",
                "Then call chat__reply with the final HTML document only.\n",
                "The final answer must start with <!DOCTYPE html> and end immediately after </html>."
            ),
            "intentFrame": {
                "schemaVersion": "ioi.studio.intent-frame.v1",
                "intentId": "retrieval.answer",
                "routeDirective": "agent",
                "executionMode": "agent",
                "target": "post-quantum computers",
                "query": "post-quantum computers",
                "artifact": { "required": false },
                "retrieval": { "required": true, "requirements": ["source_grounding"] },
                "workspace": { "required": false },
                "requiredCapabilities": ["prim:conversation.reply", "prim:web.search", "prim:web.read"]
            }
        });
        let prompt = request
            .get("prompt")
            .and_then(Value::as_str)
            .expect("prompt");
        let frame = runtime_route_frame_for_prompt_or_bridge_input(&request, None, prompt)
            .expect("retrieval intent frame should own internal artifact prompts");

        assert_eq!(frame.intent_id, "retrieval.answer");
        assert_eq!(frame.route_family, "web_research");
        assert_eq!(frame.output_intent, "tool_execution");
        assert!(!frame.direct_answer_allowed);
        assert_eq!(frame.target, "post-quantum computers");
        assert!(frame.runtime_action.is_none());
    }
}
