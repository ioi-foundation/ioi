// Path: crates/services/src/agentic/desktop/service/step/incident.rs

use crate::agentic::desktop::keys::get_incident_key;
use crate::agentic::desktop::middleware;
use crate::agentic::desktop::service::step::anti_loop::FailureClass;
use crate::agentic::desktop::service::step::ontology::{
    classify_intent, default_strategy_for, GateState, IncidentStage, IntentClass,
    ResolutionAction, StrategyName, StrategyNode,
};
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::tools::discover_tools;
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use crate::agentic::rules::{ActionRules, ApprovalMode};
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{AgentTool, InferenceOptions, LlmToolDefinition};
use ioi_types::app::{ActionContext, ActionRequest};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

const FORBIDDEN_LIFECYCLE_TOOLS: &[&str] = &[
    "agent__complete",
    "chat__reply",
    "system__fail",
    "agent__delegate",
];

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct PendingGate {
    pub request_hash: String,
    pub action_fingerprint: String,
    pub prompted_count: u32,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct IncidentState {
    pub active: bool,
    pub incident_id: String,
    pub root_retry_hash: String,
    pub root_tool_jcs: Vec<u8>,
    pub root_tool_name: String,
    pub intent_class: String,
    pub root_failure_class: String,
    pub root_error: Option<String>,
    pub stage: String,
    pub strategy_name: String,
    pub strategy_cursor: String,
    pub visited_node_fingerprints: Vec<String>,
    pub pending_gate: Option<PendingGate>,
    pub gate_state: String,
    pub resolution_action: String,
    pub transitions_used: u32,
    pub max_transitions: u32,
    pub started_step: u32,
    pub pending_remedy_fingerprint: Option<String>,
    pub pending_remedy_tool_jcs: Option<Vec<u8>>,
    pub retry_enqueued: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
struct LegacyIncidentState {
    pub active: bool,
    pub incident_id: String,
    pub root_retry_hash: String,
    pub root_tool_jcs: Vec<u8>,
    pub root_tool_name: String,
    pub intent_class: String,
    pub root_failure_class: String,
    pub root_error: Option<String>,
    pub stage: String,
    pub strategy_name: String,
    pub strategy_cursor: String,
    pub visited_node_fingerprints: Vec<String>,
    pub pending_gate: Option<PendingGate>,
    pub gate_state: String,
    pub resolution_action: String,
    pub transitions_used: u32,
    pub max_transitions: u32,
    pub started_step: u32,
}

impl From<LegacyIncidentState> for IncidentState {
    fn from(value: LegacyIncidentState) -> Self {
        Self {
            active: value.active,
            incident_id: value.incident_id,
            root_retry_hash: value.root_retry_hash,
            root_tool_jcs: value.root_tool_jcs,
            root_tool_name: value.root_tool_name,
            intent_class: value.intent_class,
            root_failure_class: value.root_failure_class,
            root_error: value.root_error,
            stage: value.stage,
            strategy_name: value.strategy_name,
            strategy_cursor: value.strategy_cursor,
            visited_node_fingerprints: value.visited_node_fingerprints,
            pending_gate: value.pending_gate,
            gate_state: value.gate_state,
            resolution_action: value.resolution_action,
            transitions_used: value.transitions_used,
            max_transitions: value.max_transitions,
            started_step: value.started_step,
            pending_remedy_fingerprint: None,
            pending_remedy_tool_jcs: None,
            retry_enqueued: false,
        }
    }
}

impl IncidentState {
    fn new(
        root_retry_hash: &str,
        root_tool_jcs: &[u8],
        root_tool_name: &str,
        intent_class: IntentClass,
        root_failure_class: FailureClass,
        root_error: Option<&str>,
        strategy_name: StrategyName,
        strategy_node: StrategyNode,
        max_transitions: u32,
        started_step: u32,
    ) -> Self {
        let incident_id_seed = format!(
            "{}::{}::{}::{}",
            root_retry_hash,
            root_tool_name,
            started_step,
            now_millis()
        );
        let incident_id = sha256(incident_id_seed.as_bytes())
            .map(hex::encode)
            .unwrap_or_else(|_| hex::encode(root_retry_hash.as_bytes()));

        Self {
            active: true,
            incident_id,
            root_retry_hash: root_retry_hash.to_string(),
            root_tool_jcs: root_tool_jcs.to_vec(),
            root_tool_name: root_tool_name.to_string(),
            intent_class: intent_class.as_str().to_string(),
            root_failure_class: root_failure_class.as_str().to_string(),
            root_error: root_error.map(|v| v.to_string()),
            stage: IncidentStage::New.as_str().to_string(),
            strategy_name: strategy_name.as_str().to_string(),
            strategy_cursor: strategy_node.as_str().to_string(),
            visited_node_fingerprints: Vec::new(),
            pending_gate: None,
            gate_state: GateState::None.as_str().to_string(),
            resolution_action: ResolutionAction::None.as_str().to_string(),
            transitions_used: 0,
            max_transitions,
            started_step,
            pending_remedy_fingerprint: None,
            pending_remedy_tool_jcs: None,
            retry_enqueued: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentDirective {
    Noop,
    AwaitApproval,
    QueueActions,
    PauseForUser,
    Escalate,
    MarkResolved,
    MarkExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDirective {
    PromptUser,
    SuppressDuplicatePrompt,
    PauseLoop,
}

#[derive(Debug, Clone, Default)]
pub struct IncidentReceiptFields {
    pub intent_class: String,
    pub incident_id: String,
    pub incident_stage: String,
    pub strategy_name: String,
    pub strategy_node: String,
    pub gate_state: String,
    pub resolution_action: String,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn canonical_tool_name(tool: &AgentTool) -> String {
    serde_json::to_value(tool)
        .ok()
        .and_then(|value| {
            value
                .get("name")
                .and_then(|name| name.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("{:?}", tool.target()))
}

fn canonical_tool_args(tool: &AgentTool) -> serde_json::Value {
    serde_json::to_value(tool)
        .ok()
        .and_then(|value| value.get("arguments").cloned())
        .unwrap_or_else(|| json!({}))
}

fn tool_fingerprint(tool: &AgentTool) -> String {
    let payload = json!({
        "name": canonical_tool_name(tool),
        "arguments": canonical_tool_args(tool),
    });
    let canonical = serde_jcs::to_vec(&payload)
        .or_else(|_| serde_json::to_vec(&payload))
        .unwrap_or_default();
    sha256(&canonical)
        .map(hex::encode)
        .unwrap_or_else(|_| String::new())
}

pub fn action_fingerprint_from_tool_jcs(tool_jcs: &[u8]) -> String {
    sha256(tool_jcs)
        .map(hex::encode)
        .unwrap_or_else(|_| String::new())
}

fn policy_max_transitions(
    rules: &ActionRules,
    intent_class: IntentClass,
    failure_class: FailureClass,
) -> u32 {
    let mut max = rules.ontology_policy.max_incident_transitions.max(1);
    for ov in &rules.ontology_policy.intent_failure_overrides {
        if !ov
            .intent_class
            .eq_ignore_ascii_case(intent_class.as_str())
            || !ov
                .failure_class
                .eq_ignore_ascii_case(failure_class.as_str())
        {
            continue;
        }
        if let Some(override_max) = ov.max_transitions {
            max = override_max.max(1);
        }
    }
    max
}

fn policy_strategy_override(
    rules: &ActionRules,
    intent_class: IntentClass,
    failure_class: FailureClass,
) -> Option<StrategyName> {
    for ov in &rules.ontology_policy.intent_failure_overrides {
        if !ov
            .intent_class
            .eq_ignore_ascii_case(intent_class.as_str())
            || !ov
                .failure_class
                .eq_ignore_ascii_case(failure_class.as_str())
        {
            continue;
        }
        if let Some(name) = ov.strategy_name.as_deref() {
            return Some(StrategyName::from_str(name));
        }
    }
    None
}

fn effective_forbidden_tools(rules: &ActionRules) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for name in FORBIDDEN_LIFECYCLE_TOOLS {
        set.insert((*name).to_string());
    }
    for name in &rules.ontology_policy.tool_preferences.forbidden_remediation_tools {
        if !name.trim().is_empty() {
            set.insert(name.trim().to_string());
        }
    }
    set
}

fn is_recoverable_failure(class: FailureClass) -> bool {
    !matches!(
        class,
        FailureClass::PermissionOrApprovalRequired | FailureClass::UserInterventionNeeded
    )
}

fn parse_launch_app_name(root_tool_jcs: &[u8]) -> Option<String> {
    let tool: AgentTool = serde_json::from_slice(root_tool_jcs).ok()?;
    if let AgentTool::OsLaunchApp { app_name } = tool {
        let trimmed = app_name.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn normalize_app_name(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn app_install_candidates(app_name: &str) -> Vec<String> {
    let app = normalize_app_name(app_name);
    let mut candidates = Vec::<String>::new();

    let mut push_candidate = |value: &str| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return;
        }
        if !candidates.iter().any(|existing| existing == trimmed) {
            candidates.push(trimmed.to_string());
        }
    };

    #[cfg(target_os = "linux")]
    {
        if app.contains("calculator") {
            push_candidate("gnome-calculator");
            push_candidate("kcalc");
            push_candidate("qalculate-gtk");
        }
        if app.contains("code") || app.contains("vscode") {
            push_candidate("code");
            push_candidate("code-insiders");
        }
        if app.contains("chrome") {
            push_candidate("google-chrome-stable");
            push_candidate("chromium-browser");
        }
        if app.contains("firefox") {
            push_candidate("firefox");
        }
        if app.contains("terminal") {
            push_candidate("gnome-terminal");
            push_candidate("konsole");
            push_candidate("xterm");
        }
    }

    #[cfg(target_os = "macos")]
    {
        if app.contains("calculator") {
            push_candidate("apple-calculator");
        }
        if app.contains("code") || app.contains("vscode") {
            push_candidate("visual-studio-code");
        }
        if app.contains("chrome") {
            push_candidate("google-chrome");
        }
        if app.contains("firefox") {
            push_candidate("firefox");
        }
        if app.contains("terminal") {
            push_candidate("iterm2");
        }
    }

    #[cfg(target_os = "windows")]
    {
        if app.contains("calculator") {
            push_candidate("Microsoft.WindowsCalculator");
        }
        if app.contains("code") || app.contains("vscode") {
            push_candidate("Microsoft.VisualStudioCode");
        }
        if app.contains("chrome") {
            push_candidate("Google.Chrome");
        }
        if app.contains("firefox") {
            push_candidate("Mozilla.Firefox");
        }
        if app.contains("terminal") {
            push_candidate("Microsoft.WindowsTerminal");
        }
    }

    push_candidate(&app.replace(' ', "-"));
    push_candidate(&app);
    candidates
}

fn build_install_tool(package: &str, manager: Option<&str>) -> Result<AgentTool, TransactionError> {
    let mut args = json!({
        "package": package
    });
    if let Some(mgr) = manager.filter(|m| !m.trim().is_empty()) {
        args["manager"] = json!(mgr.trim());
    }
    let payload = json!({
        "name": "sys__install_package",
        "arguments": args
    });
    middleware::normalize_tool_call(&payload.to_string())
        .map_err(|e| TransactionError::Invalid(format!("Install tool normalization failed: {}", e)))
}

fn preferred_install_manager(rules: &ActionRules, attempt_idx: usize) -> Option<String> {
    let prefs = &rules.ontology_policy.tool_preferences.install_manager_priority;
    if prefs.is_empty() {
        return None;
    }
    let idx = attempt_idx.min(prefs.len().saturating_sub(1));
    let manager = prefs[idx].trim();
    if manager.is_empty() {
        None
    } else {
        Some(manager.to_string())
    }
}

fn deterministic_recovery_tool(
    available_tool_names: &BTreeSet<String>,
    incident_state: &IncidentState,
    agent_state: &AgentState,
    rules: &ActionRules,
) -> Result<Option<AgentTool>, TransactionError> {
    let failure = FailureClass::from_str(&incident_state.root_failure_class)
        .unwrap_or(FailureClass::UnexpectedState);
    let intent = IntentClass::from_str(&incident_state.intent_class);

    if intent == IntentClass::OpenApp
        && matches!(
            failure,
            FailureClass::ToolUnavailable
                | FailureClass::MissingDependency
                | FailureClass::TargetNotFound
        )
        && available_tool_names.contains("sys__install_package")
    {
        if let Some(app_name) = parse_launch_app_name(&incident_state.root_tool_jcs) {
            let candidates = app_install_candidates(&app_name);
            if !candidates.is_empty() {
                let idx = incident_state.transitions_used as usize;
                let pkg_idx = idx.min(candidates.len() - 1);
                let manager = preferred_install_manager(rules, idx);
                return Ok(Some(build_install_tool(
                    &candidates[pkg_idx],
                    manager.as_deref(),
                )?));
            }
        }
    }

    if available_tool_names.contains("ui__find") {
        let query = parse_launch_app_name(&incident_state.root_tool_jcs)
            .or_else(|| {
                agent_state
                    .target
                    .as_ref()
                    .and_then(|target| target.app_hint.clone())
            })
            .unwrap_or_else(|| agent_state.goal.clone());
        let payload = json!({
            "name": "ui__find",
            "arguments": { "query": query }
        });
        let tool = middleware::normalize_tool_call(&payload.to_string())
            .map_err(|e| TransactionError::Invalid(format!("ui__find fallback invalid: {}", e)))?;
        return Ok(Some(tool));
    }

    if available_tool_names.contains("os__focus_window") {
        if let Some(hint) = agent_state
            .target
            .as_ref()
            .and_then(|target| target.app_hint.clone())
        {
            let payload = json!({
                "name": "os__focus_window",
                "arguments": { "title": hint }
            });
            let tool = middleware::normalize_tool_call(&payload.to_string()).map_err(|e| {
                TransactionError::Invalid(format!("os__focus_window fallback invalid: {}", e))
            })?;
            return Ok(Some(tool));
        }
    }

    Ok(None)
}

fn validate_recovery_tool(
    tool: &AgentTool,
    available_tool_names: &BTreeSet<String>,
    forbidden: &BTreeSet<String>,
    visited_node_fingerprints: &[String],
) -> Result<(), TransactionError> {
    let name = canonical_tool_name(tool);
    if forbidden.contains(&name) {
        return Err(TransactionError::Invalid(format!(
            "Forbidden incident tool selected: {}",
            name
        )));
    }
    if !available_tool_names.contains(&name) {
        return Err(TransactionError::Invalid(format!(
            "Incident tool '{}' not in available tool set",
            name
        )));
    }
    let fp = tool_fingerprint(tool);
    if visited_node_fingerprints.iter().any(|known| known == &fp) {
        return Err(TransactionError::Invalid(
            "Duplicate incident remedy fingerprint".to_string(),
        ));
    }
    Ok(())
}

fn build_planner_prompt(
    incident_state: &IncidentState,
    forbidden_tools: &BTreeSet<String>,
) -> String {
    format!(
        "You are an ontology incident resolver. Choose EXACTLY ONE JSON tool call.\n\
         Rules:\n\
         1. Output exactly one JSON tool call.\n\
         2. Forbidden tools: {}.\n\
         3. Do not repeat previous remedy fingerprints.\n\
         4. For install semantics, prefer sys__install_package over raw sys__exec.\n\
         5. Keep action tightly scoped to recover the root action.\n\
         Context:\n\
         - Incident: {}\n\
         - Intent class: {}\n\
         - Failure class: {}\n\
         - Root tool: {}\n\
         - Stage: {}\n\
         - Strategy: {} / {}\n\
         - Transitions: {}/{}\n\
         - Last error: {}\n",
        forbidden_tools
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        incident_state.incident_id,
        incident_state.intent_class,
        incident_state.root_failure_class,
        incident_state.root_tool_name,
        incident_state.stage,
        incident_state.strategy_name,
        incident_state.strategy_cursor,
        incident_state.transitions_used,
        incident_state.max_transitions,
        incident_state.root_error.as_deref().unwrap_or("unknown"),
    )
}

fn tool_to_action_request(
    tool: &AgentTool,
    session_id: [u8; 32],
    nonce: u64,
) -> Result<ActionRequest, TransactionError> {
    let args = canonical_tool_args(tool);
    let params = serde_jcs::to_vec(&args)
        .or_else(|_| serde_json::to_vec(&args))
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    Ok(ActionRequest {
        target: tool.target(),
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce,
    })
}

fn queue_recovery_action(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    recovery_tool: &AgentTool,
) -> Result<(), TransactionError> {
    let base_nonce = agent_state.step_count as u64 + 1;
    let recovery_request = tool_to_action_request(recovery_tool, session_id, base_nonce)?;
    agent_state.execution_queue.insert(0, recovery_request);
    Ok(())
}

fn queue_root_retry(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    root_tool_jcs: &[u8],
) -> Result<bool, TransactionError> {
    let root_tool: AgentTool = serde_json::from_slice(root_tool_jcs).map_err(|e| {
        TransactionError::Serialization(format!(
            "Failed to deserialize root incident tool: {}",
            e
        ))
    })?;

    let nonce = agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1;
    let retry_request = tool_to_action_request(&root_tool, session_id, nonce)?;
    let duplicate = agent_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == retry_request.target && queued.params == retry_request.params);
    if duplicate {
        return Ok(false);
    }

    agent_state.execution_queue.insert(0, retry_request);
    Ok(true)
}

pub fn load_incident_state(
    state: &dyn StateAccess,
    session_id: &[u8; 32],
) -> Result<Option<IncidentState>, TransactionError> {
    let key = get_incident_key(session_id);
    let Some(bytes) = state.get(&key)? else {
        return Ok(None);
    };
    match codec::from_bytes_canonical::<IncidentState>(&bytes) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(_) => {
            let legacy = codec::from_bytes_canonical::<LegacyIncidentState>(&bytes)
                .map_err(TransactionError::Serialization)?;
            Ok(Some(legacy.into()))
        }
    }
}

pub fn clear_incident_state(
    state: &mut dyn StateAccess,
    session_id: &[u8; 32],
) -> Result<(), TransactionError> {
    let key = get_incident_key(session_id);
    state.delete(&key)?;
    Ok(())
}

fn persist_incident_state(
    state: &mut dyn StateAccess,
    session_id: &[u8; 32],
    incident_state: &IncidentState,
) -> Result<(), TransactionError> {
    let key = get_incident_key(session_id);
    let bytes = codec::to_bytes_canonical(incident_state).map_err(TransactionError::Serialization)?;
    state.insert(&key, &bytes)?;
    Ok(())
}

pub fn should_enter_incident_recovery(
    failure_class: Option<FailureClass>,
    policy_decision: &str,
    stop_condition_hit: bool,
    incident_state: Option<&IncidentState>,
) -> bool {
    if stop_condition_hit {
        return false;
    }
    if matches!(policy_decision, "require_approval" | "denied") {
        return false;
    }
    let Some(class) = failure_class else {
        return false;
    };
    if !is_recoverable_failure(class) {
        return false;
    }
    if let Some(incident) = incident_state {
        if incident.active && incident.transitions_used >= incident.max_transitions {
            return false;
        }
    }
    true
}

pub async fn emit_incident_chat_progress(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    block_height: u64,
    content: impl Into<String>,
) -> Result<(), TransactionError> {
    let msg = ioi_types::app::agentic::ChatMessage {
        role: "system".to_string(),
        content: content.into(),
        timestamp: now_millis(),
        trace_hash: None,
    };
    let _ = service
        .append_chat_to_scs(session_id, &msg, block_height)
        .await?;
    Ok(())
}

pub fn incident_receipt_fields(incident_state: Option<&IncidentState>) -> IncidentReceiptFields {
    let Some(incident) = incident_state else {
        return IncidentReceiptFields::default();
    };
    IncidentReceiptFields {
        intent_class: incident.intent_class.clone(),
        incident_id: incident.incident_id.clone(),
        incident_stage: incident.stage.clone(),
        strategy_name: incident.strategy_name.clone(),
        strategy_node: incident.strategy_cursor.clone(),
        gate_state: incident.gate_state.clone(),
        resolution_action: incident.resolution_action.clone(),
    }
}

pub async fn advance_incident_after_action_outcome(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    executed_retry_hash: &str,
    executed_tool_jcs: &[u8],
    success: bool,
    block_height: u64,
    error_msg: Option<&str>,
    verification_checks: &mut Vec<String>,
) -> Result<IncidentDirective, TransactionError> {
    let Some(mut incident_state) = load_incident_state(state, &session_id)? else {
        verification_checks.push("incident_active=false".to_string());
        return Ok(IncidentDirective::Noop);
    };

    if !incident_state.active {
        verification_checks.push("incident_active=false".to_string());
        return Ok(IncidentDirective::Noop);
    }

    let stage_before = incident_state.stage.clone();
    let executed_fingerprint = action_fingerprint_from_tool_jcs(executed_tool_jcs);
    let is_pending_remedy = incident_state
        .pending_remedy_fingerprint
        .as_deref()
        .map(|fp| fp == executed_fingerprint.as_str())
        .unwrap_or(false);

    if is_pending_remedy {
        if success {
            incident_state.pending_remedy_fingerprint = None;
            incident_state.pending_remedy_tool_jcs = None;
            incident_state.stage = IncidentStage::RetryRoot.as_str().to_string();
            incident_state.strategy_cursor = StrategyNode::RetryRootAction.as_str().to_string();
            incident_state.gate_state = GateState::Cleared.as_str().to_string();
            incident_state.resolution_action = ResolutionAction::RetryRoot.as_str().to_string();
            let queued_retry = if incident_state.retry_enqueued {
                false
            } else {
                queue_root_retry(agent_state, session_id, &incident_state.root_tool_jcs)?
            };
            incident_state.retry_enqueued = incident_state.retry_enqueued || queued_retry;
            let stage_after = incident_state.stage.clone();
            persist_incident_state(state, &session_id, &incident_state)?;
            emit_incident_chat_progress(
                service,
                session_id,
                block_height,
                if queued_retry {
                    format!(
                        "System: Remedy succeeded for incident '{}'; queued root retry.",
                        incident_state.incident_id
                    )
                } else {
                    format!(
                        "System: Remedy succeeded for incident '{}'; root retry already queued.",
                        incident_state.incident_id
                    )
                },
            )
            .await?;
            verification_checks.push("incident_active=true".to_string());
            verification_checks.push(format!("incident_id={}", incident_state.incident_id));
            verification_checks.push(format!("incident_stage_before={}", stage_before));
            verification_checks.push(format!("incident_stage_after={}", stage_after));
            verification_checks.push(format!(
                "incident_transitions_used={}",
                incident_state.transitions_used
            ));
            verification_checks.push(format!(
                "incident_budget_remaining={}",
                incident_state
                    .max_transitions
                    .saturating_sub(incident_state.transitions_used)
            ));
            verification_checks.push(format!(
                "queued_retry_after_remedy_success={}",
                queued_retry
            ));
            return Ok(if queued_retry {
                IncidentDirective::QueueActions
            } else {
                IncidentDirective::Noop
            });
        }

        incident_state.pending_remedy_fingerprint = None;
        incident_state.pending_remedy_tool_jcs = None;
        incident_state.retry_enqueued = false;
        incident_state.stage = IncidentStage::Diagnose.as_str().to_string();
        incident_state.strategy_cursor = StrategyNode::DiagnoseFailure.as_str().to_string();
        incident_state.gate_state = GateState::Cleared.as_str().to_string();
        incident_state.resolution_action = ResolutionAction::ExecuteRemedy.as_str().to_string();
        incident_state.root_error = error_msg.map(|v| v.to_string());
        let stage_after = incident_state.stage.clone();
        persist_incident_state(state, &session_id, &incident_state)?;
        emit_incident_chat_progress(
            service,
            session_id,
            block_height,
            format!(
                "System: Remedy failed for incident '{}'; selecting next strategy node.",
                incident_state.incident_id
            ),
        )
        .await?;
        verification_checks.push("incident_active=true".to_string());
        verification_checks.push(format!("incident_id={}", incident_state.incident_id));
        verification_checks.push(format!("incident_stage_before={}", stage_before));
        verification_checks.push(format!("incident_stage_after={}", stage_after));
        verification_checks.push("queued_retry_after_remedy_success=false".to_string());
        return Ok(IncidentDirective::Noop);
    }

    if success && incident_state.root_retry_hash == executed_retry_hash {
        incident_state.stage = IncidentStage::Resolved.as_str().to_string();
        incident_state.gate_state = GateState::Cleared.as_str().to_string();
        incident_state.resolution_action = ResolutionAction::MarkResolved.as_str().to_string();
        emit_incident_chat_progress(
            service,
            session_id,
            block_height,
            format!(
                "System: Incident '{}' resolved after {} transition(s).",
                incident_state.incident_id, incident_state.transitions_used
            ),
        )
        .await?;
        clear_incident_state(state, &session_id)?;
        verification_checks.push("incident_active=false".to_string());
        verification_checks.push("incident_resolved=true".to_string());
        verification_checks.push(format!("incident_stage_before={}", stage_before));
        verification_checks.push(format!(
            "incident_stage_after={}",
            IncidentStage::Resolved.as_str()
        ));
        return Ok(IncidentDirective::MarkResolved);
    }

    let stage_after = incident_state.stage.clone();
    persist_incident_state(state, &session_id, &incident_state)?;
    verification_checks.push("incident_active=true".to_string());
    verification_checks.push(format!("incident_id={}", incident_state.incident_id));
    verification_checks.push(format!("incident_stage_before={}", stage_before));
    verification_checks.push(format!("incident_stage_after={}", stage_after));
    verification_checks.push(format!(
        "incident_transitions_used={}",
        incident_state.transitions_used
    ));
    verification_checks.push(format!(
        "incident_budget_remaining={}",
        incident_state
            .max_transitions
            .saturating_sub(incident_state.transitions_used)
    ));
    Ok(IncidentDirective::Noop)
}

pub fn register_pending_approval(
    state: &mut dyn StateAccess,
    rules: &ActionRules,
    agent_state: &AgentState,
    session_id: [u8; 32],
    root_retry_hash: &str,
    root_tool_name: &str,
    root_tool_jcs: &[u8],
    action_fingerprint: &str,
    request_hash: &str,
) -> Result<ApprovalDirective, TransactionError> {
    let intent = classify_intent(
        &agent_state.goal,
        root_tool_name,
        agent_state
            .target
            .as_ref()
            .and_then(|target| target.app_hint.as_deref()),
    );
    let failure = FailureClass::PermissionOrApprovalRequired;
    let (mut strategy_name, strategy_node) = default_strategy_for(intent, failure);
    if let Some(ov) = policy_strategy_override(rules, intent, failure) {
        strategy_name = ov;
    }
    let max_transitions = policy_max_transitions(rules, intent, failure);
    let loaded_incident = load_incident_state(state, &session_id)?;
    let mut incident = match loaded_incident {
        Some(current) if current.active => current,
        _ => IncidentState::new(
            root_retry_hash,
            root_tool_jcs,
            root_tool_name,
            intent,
            failure,
            None,
            strategy_name,
            strategy_node,
            max_transitions,
            agent_state.step_count,
        ),
    };

    // Preserve root incident identity across queued remedy/retry approval interceptions.
    incident.max_transitions = max_transitions;
    if incident.root_retry_hash.is_empty() {
        incident.root_retry_hash = root_retry_hash.to_string();
    }
    if incident.root_tool_name.is_empty() {
        incident.root_tool_name = root_tool_name.to_string();
    }
    if incident.root_tool_jcs.is_empty() {
        incident.root_tool_jcs = root_tool_jcs.to_vec();
    }
    if incident.intent_class.is_empty() {
        incident.intent_class = intent.as_str().to_string();
    }
    if incident.root_failure_class.is_empty() {
        incident.root_failure_class = failure.as_str().to_string();
    }

    let mut prompted_count = incident
        .pending_gate
        .as_ref()
        .filter(|pending| {
            pending.request_hash == request_hash && pending.action_fingerprint == action_fingerprint
        })
        .map(|pending| pending.prompted_count)
        .unwrap_or(0);

    let approval_mode = rules.ontology_policy.approval_mode;
    let bounded_limit = rules
        .ontology_policy
        .tool_preferences
        .bounded_reprompt_limit
        .max(1);

    let directive = match approval_mode {
        ApprovalMode::SinglePending => {
            if prompted_count > 0 {
                ApprovalDirective::SuppressDuplicatePrompt
            } else {
                ApprovalDirective::PromptUser
            }
        }
        ApprovalMode::BoundedReprompt => {
            if prompted_count >= bounded_limit {
                ApprovalDirective::PauseLoop
            } else {
                ApprovalDirective::PromptUser
            }
        }
        ApprovalMode::AlwaysPrompt => ApprovalDirective::PromptUser,
    };

    if matches!(directive, ApprovalDirective::PromptUser) {
        prompted_count = prompted_count.saturating_add(1);
        incident.transitions_used = incident.transitions_used.saturating_add(1);
    }

    incident.stage = IncidentStage::AwaitApproval.as_str().to_string();
    if incident.strategy_name.is_empty() {
        incident.strategy_name = strategy_name.as_str().to_string();
    }
    if incident.strategy_cursor.is_empty() {
        incident.strategy_cursor = strategy_node.as_str().to_string();
    }
    incident.gate_state = GateState::Pending.as_str().to_string();
    incident.resolution_action = ResolutionAction::WaitForUser.as_str().to_string();
    incident.pending_gate = Some(PendingGate {
        request_hash: request_hash.to_string(),
        action_fingerprint: action_fingerprint.to_string(),
        prompted_count,
        updated_at_ms: now_millis(),
    });

    if matches!(directive, ApprovalDirective::PauseLoop) {
        incident.stage = IncidentStage::PausedForUser.as_str().to_string();
        incident.gate_state = GateState::Denied.as_str().to_string();
        incident.resolution_action = ResolutionAction::Pause.as_str().to_string();
    }

    persist_incident_state(state, &session_id, &incident)?;
    Ok(directive)
}

pub fn mark_gate_approved(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
) -> Result<(), TransactionError> {
    let Some(mut incident) = load_incident_state(state, &session_id)? else {
        return Ok(());
    };
    incident.gate_state = GateState::Approved.as_str().to_string();
    incident.pending_gate = None;
    incident.resolution_action = ResolutionAction::RetryRoot.as_str().to_string();
    incident.stage = IncidentStage::RetryRoot.as_str().to_string();
    persist_incident_state(state, &session_id, &incident)?;
    Ok(())
}

pub async fn start_or_continue_incident_recovery(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
    rules: &ActionRules,
    root_retry_hash: &str,
    root_tool_name: &str,
    root_tool_jcs: &[u8],
    root_failure_class: FailureClass,
    root_error: Option<&str>,
    verification_checks: &mut Vec<String>,
) -> Result<IncidentDirective, TransactionError> {
    let intent = classify_intent(
        &agent_state.goal,
        root_tool_name,
        agent_state
            .target
            .as_ref()
            .and_then(|target| target.app_hint.as_deref()),
    );
    let (mut strategy_name, mut strategy_node) = default_strategy_for(intent, root_failure_class);
    if let Some(ov) = policy_strategy_override(rules, intent, root_failure_class) {
        strategy_name = ov;
    }
    let max_transitions = policy_max_transitions(rules, intent, root_failure_class);

    let loaded_incident = load_incident_state(state, &session_id)?;
    let mut incident_state = match loaded_incident.as_ref() {
        Some(current)
            if current.active
                && (current.root_tool_jcs == root_tool_jcs
                    || current.root_retry_hash == root_retry_hash) =>
        {
            current.clone()
        }
        _ => IncidentState::new(
            root_retry_hash,
            root_tool_jcs,
            root_tool_name,
            intent,
            root_failure_class,
            root_error,
            strategy_name,
            strategy_node,
            max_transitions,
            agent_state.step_count,
        ),
    };

    let incident_id_stable = loaded_incident
        .as_ref()
        .map(|prior| prior.incident_id == incident_state.incident_id)
        .unwrap_or(true);
    let stage_before = incident_state.stage.clone();

    incident_state.root_error = root_error.map(|v| v.to_string());
    incident_state.intent_class = intent.as_str().to_string();
    incident_state.root_failure_class = root_failure_class.as_str().to_string();
    incident_state.max_transitions = max_transitions;
    incident_state.strategy_name = strategy_name.as_str().to_string();

    if incident_state.transitions_used >= incident_state.max_transitions {
        incident_state.active = false;
        incident_state.stage = IncidentStage::Exhausted.as_str().to_string();
        incident_state.gate_state = GateState::Cleared.as_str().to_string();
        incident_state.resolution_action = ResolutionAction::MarkExhausted.as_str().to_string();
        persist_incident_state(state, &session_id, &incident_state)?;
        emit_incident_chat_progress(
            service,
            session_id,
            block_height,
            format!(
                "System: Incident '{}' exhausted transition budget ({}/{}).",
                incident_state.incident_id,
                incident_state.transitions_used,
                incident_state.max_transitions
            ),
        )
        .await?;
        verification_checks.push("incident_active=false".to_string());
        verification_checks.push("incident_exhausted=true".to_string());
        verification_checks.push("incident_budget_remaining=0".to_string());
        return Ok(IncidentDirective::MarkExhausted);
    }

    let active_window_title = if let Some(os_driver) = service.os_driver.as_ref() {
        match os_driver.get_active_window_info().await {
            Ok(Some(win)) => format!("{} ({})", win.title, win.app_name),
            Ok(None) => "Unknown".to_string(),
            Err(_) => "Unknown".to_string(),
        }
    } else {
        "Unknown".to_string()
    };
    let tools = discover_tools(
        state,
        service.scs.as_deref(),
        &agent_state.goal,
        service.fast_inference.clone(),
        agent_state.current_tier,
        &active_window_title,
    )
    .await;

    let available_tool_names: BTreeSet<String> =
        tools.iter().map(|tool| tool.name.clone()).collect();
    let forbidden_tools = effective_forbidden_tools(rules);
    let planner_tools: Vec<LlmToolDefinition> = tools
        .into_iter()
        .filter(|tool| !forbidden_tools.contains(&tool.name))
        .collect();
    if planner_tools.is_empty() {
        return Err(TransactionError::Invalid(
            "No eligible incident recovery tools available".to_string(),
        ));
    }

    let mut chosen_tool = deterministic_recovery_tool(
        &available_tool_names,
        &incident_state,
        agent_state,
        rules,
    )?;

    if chosen_tool.is_none() {
        let prompt = build_planner_prompt(&incident_state, &forbidden_tools);
        let messages = json!([
            { "role": "system", "content": prompt },
            { "role": "user", "content": "Choose the next recovery action now." }
        ]);
        let input = serde_json::to_vec(&messages)
            .map_err(|e| TransactionError::Serialization(e.to_string()))?;
        let options = InferenceOptions {
            temperature: 0.0,
            json_mode: true,
            max_tokens: 384,
            tools: planner_tools,
        };
        let output = service
            .reasoning_inference
            .execute_inference([0u8; 32], &input, options)
            .await
            .map_err(|e| {
                TransactionError::Invalid(format!("Incident planner inference failed: {}", e))
            })?;
        let raw_output = String::from_utf8_lossy(&output).to_string();
        chosen_tool = Some(middleware::normalize_tool_call(&raw_output).map_err(|e| {
            TransactionError::Invalid(format!("Incident planner output invalid: {}", e))
        })?);
    }

    let recovery_tool = chosen_tool.ok_or_else(|| {
        TransactionError::Invalid("Incident planner could not choose a recovery tool".to_string())
    })?;

    validate_recovery_tool(
        &recovery_tool,
        &available_tool_names,
        &forbidden_tools,
        &incident_state.visited_node_fingerprints,
    )?;

    let recovery_tool_jcs = serde_jcs::to_vec(&recovery_tool)
        .or_else(|_| serde_json::to_vec(&recovery_tool))
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let recovery_fingerprint = action_fingerprint_from_tool_jcs(&recovery_tool_jcs);
    let fp = tool_fingerprint(&recovery_tool);
    incident_state.visited_node_fingerprints.push(fp);
    incident_state.transitions_used = incident_state.transitions_used.saturating_add(1);
    incident_state.stage = IncidentStage::ExecuteRemedy.as_str().to_string();
    strategy_node = match StrategyNode::from_str(&incident_state.strategy_cursor) {
        StrategyNode::DiagnoseFailure => StrategyNode::DiscoverRemedy,
        StrategyNode::DiscoverRemedy => StrategyNode::RetryRootAction,
        StrategyNode::InstallDependency => StrategyNode::RetryRootAction,
        StrategyNode::RefreshContext => StrategyNode::RetryRootAction,
        other => other,
    };
    incident_state.strategy_cursor = strategy_node.as_str().to_string();
    incident_state.gate_state = GateState::Cleared.as_str().to_string();
    incident_state.resolution_action = ResolutionAction::ExecuteRemedy.as_str().to_string();
    incident_state.pending_remedy_fingerprint = Some(recovery_fingerprint);
    incident_state.pending_remedy_tool_jcs = Some(recovery_tool_jcs);
    incident_state.retry_enqueued = false;
    persist_incident_state(state, &session_id, &incident_state)?;

    queue_recovery_action(agent_state, session_id, &recovery_tool)?;
    agent_state.status = AgentStatus::Running;

    emit_incident_chat_progress(
        service,
        session_id,
        block_height,
        format!(
            "System: Incident '{}' transition {}/{} using strategy {} node {}.",
            incident_state.incident_id,
            incident_state.transitions_used,
            incident_state.max_transitions,
            incident_state.strategy_name,
            incident_state.strategy_cursor
        ),
    )
    .await?;
    emit_incident_chat_progress(
        service,
        session_id,
        block_height,
        format!(
            "System: Selected recovery action `{}`. Root retry will be queued only after remedy success.",
            canonical_tool_name(&recovery_tool)
        ),
    )
    .await?;

    verification_checks.push("incident_active=true".to_string());
    verification_checks.push(format!("incident_id_stable={}", incident_id_stable));
    verification_checks.push(format!("incident_id={}", incident_state.incident_id));
    verification_checks.push(format!("incident_stage_before={}", stage_before));
    verification_checks.push(format!("incident_stage_after={}", incident_state.stage));
    verification_checks.push(format!(
        "incident_transitions_used={}",
        incident_state.transitions_used
    ));
    verification_checks.push(format!(
        "incident_budget_remaining={}",
        incident_state
            .max_transitions
            .saturating_sub(incident_state.transitions_used)
    ));
    verification_checks.push(format!("incident_intent={}", incident_state.intent_class));
    verification_checks.push(format!(
        "incident_strategy={}",
        incident_state.strategy_name
    ));
    verification_checks.push(format!(
        "incident_strategy_node={}",
        incident_state.strategy_cursor
    ));
    verification_checks.push("queued_retry_after_remedy_success=false".to_string());

    Ok(IncidentDirective::QueueActions)
}

#[cfg(test)]
mod tests {
    use super::{
        app_install_candidates, effective_forbidden_tools, policy_max_transitions,
        should_enter_incident_recovery, ApprovalDirective,
    };
    use crate::agentic::desktop::service::step::anti_loop::FailureClass;
    use crate::agentic::rules::{ActionRules, ApprovalMode, OntologyPolicy, ToolPreferences};

    #[test]
    fn incident_gate_blocks_non_recoverable_classes() {
        assert!(!should_enter_incident_recovery(
            Some(FailureClass::PermissionOrApprovalRequired),
            "allowed",
            false,
            None
        ));
        assert!(!should_enter_incident_recovery(
            Some(FailureClass::UserInterventionNeeded),
            "allowed",
            false,
            None
        ));
        assert!(should_enter_incident_recovery(
            Some(FailureClass::ToolUnavailable),
            "allowed",
            false,
            None
        ));
    }

    #[test]
    fn install_candidates_include_normalized_name() {
        let candidates = app_install_candidates("Calculator");
        assert!(candidates.iter().any(|candidate| candidate == "calculator"));
    }

    #[test]
    fn policy_max_transitions_defaults_to_ontology_policy() {
        let rules = ActionRules {
            ontology_policy: OntologyPolicy {
                approval_mode: ApprovalMode::SinglePending,
                max_incident_transitions: 19,
                intent_failure_overrides: Vec::new(),
                tool_preferences: ToolPreferences::default(),
            },
            ..Default::default()
        };
        assert_eq!(
            policy_max_transitions(&rules, super::IntentClass::Unknown, FailureClass::UnexpectedState),
            19
        );
    }

    #[test]
    fn forbidden_tools_include_policy_entries() {
        let rules = ActionRules {
            ontology_policy: OntologyPolicy {
                tool_preferences: ToolPreferences {
                    forbidden_remediation_tools: vec!["sys__exec".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let set = effective_forbidden_tools(&rules);
        assert!(set.contains("agent__complete"));
        assert!(set.contains("sys__exec"));
    }

    #[test]
    fn approval_directive_type_is_exhaustive() {
        let value = ApprovalDirective::PromptUser;
        assert!(matches!(
            value,
            ApprovalDirective::PromptUser
                | ApprovalDirective::SuppressDuplicatePrompt
                | ApprovalDirective::PauseLoop
        ));
    }
}
