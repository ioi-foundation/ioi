use crate::agentic::runtime::service::recovery::anti_loop::tier_as_str;
use crate::agentic::runtime::types::{AgentState, AgentStatus, ExecutionTier, ToolCallStatus};
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{determinism_step_contract_state_key, DeterminismStepContractEvidence};
use ioi_types::error::TransactionError;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

const ACTION_FINGERPRINT_LOG_PREFIX: &str = "action_fingerprint::";
const EXECUTION_EVIDENCE_PREFIX: &str = "evidence::";
const SUCCESS_CONDITION_PREFIX: &str = "success_condition::";

pub(super) fn get_status_str(status: &AgentStatus) -> String {
    format!("{:?}", status)
        .split('(')
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

pub(super) fn mark_system_fail_status(status: &mut AgentStatus, reason: impl Into<String>) {
    *status = AgentStatus::Failed(reason.into());
}

pub(super) fn enforce_system_fail_terminal_status(
    current_tool_name: &str,
    status: &mut AgentStatus,
    error_msg: Option<&str>,
) -> bool {
    if current_tool_name != "agent__escalate" {
        return false;
    }

    if !matches!(status, AgentStatus::Failed(_)) {
        let degradation_reason = error_msg.unwrap_or("Agent requested explicit failure");
        mark_system_fail_status(status, degradation_reason.to_string());
    }

    true
}

// Helper to determine if an action relies on precise screen coordinates.
#[allow(dead_code)]
pub(super) fn requires_visual_integrity(tool: &AgentTool) -> bool {
    match tool {
        AgentTool::Screen(action) => matches!(
            action,
            ioi_types::app::agentic::ScreenAction::LeftClickId { .. }
                | ioi_types::app::agentic::ScreenAction::LeftClick {
                    coordinate: Some(_),
                    ..
                }
                | ioi_types::app::agentic::ScreenAction::LeftClickDrag { .. }
                | ioi_types::app::agentic::ScreenAction::DragDrop { .. }
                | ioi_types::app::agentic::ScreenAction::DragDropId { .. }
                | ioi_types::app::agentic::ScreenAction::DragDropElement { .. }
                | ioi_types::app::agentic::ScreenAction::MouseMove { .. }
                | ioi_types::app::agentic::ScreenAction::Scroll {
                    coordinate: Some(_),
                    ..
                }
        ),
        AgentTool::GuiClick { .. } => true,
        AgentTool::GuiScroll { .. } => true,
        AgentTool::BrowserSyntheticClick { .. } => true,
        AgentTool::BrowserClick { .. } => true,
        _ => false,
    }
}

pub fn canonical_tool_identity(tool: &AgentTool) -> (String, serde_json::Value) {
    let serialized = serde_json::to_value(tool).unwrap_or_else(|_| json!({}));
    let dynamic = match tool {
        AgentTool::Dynamic(value) => Some(value),
        _ => None,
    };

    let tool_name = serialized
        .get("name")
        .and_then(|value| value.as_str())
        .or_else(|| dynamic.and_then(|value| value.get("name").and_then(|n| n.as_str())))
        .map(str::to_string)
        .unwrap_or_else(|| format!("{:?}", tool.target()));

    let args = serialized
        .get("arguments")
        .cloned()
        .or_else(|| dynamic.and_then(|value| value.get("arguments").cloned()))
        .unwrap_or_else(|| json!({}));

    (tool_name, args)
}

pub(crate) fn latest_retained_shell_command_id(text: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(text).ok();
    if let Some(command_id) = value
        .as_ref()
        .and_then(|value| value.get("command_id").or_else(|| value.get("commandId")))
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
    {
        return Some(command_id.trim().to_string());
    }

    let re = regex::Regex::new(r#"(?i)\\?"command_?id\\?"\s*:\s*\\?"([^"\\\s]+)\\?""#).ok()?;
    re.captures_iter(text)
        .filter_map(|captures| {
            captures
                .get(1)
                .map(|value| value.as_str().trim().to_string())
        })
        .filter(|value| !value.is_empty())
        .last()
}

pub(crate) fn retained_shell_lifecycle_followup(
    goal: &str,
    current_tool_name: &str,
    executed_tool: Option<&AgentTool>,
    output: Option<&str>,
) -> Option<AgentTool> {
    if !is_retained_shell_lifecycle_goal(goal) {
        return None;
    }

    match current_tool_name {
        "shell__start" => {
            let command_id = latest_retained_shell_command_id(output?)?;
            if retained_shell_goal_requests_status(goal) {
                return Some(AgentTool::SysExecStatus { command_id });
            }
            if let Some(stdin) = retained_shell_stdin_payload(goal) {
                return Some(AgentTool::SysExecInput { command_id, stdin });
            }
            if retained_shell_goal_requests_terminate(goal)
                || retained_shell_goal_requests_reset(goal)
            {
                return Some(AgentTool::SysExecTerminate { command_id });
            }
            None
        }
        "shell__status" => {
            let command_id = command_id_from_executed_tool(executed_tool)?;
            if retained_shell_output_indicates_cleanup_ready(output)
                && retained_shell_goal_requests_terminate(goal)
            {
                return Some(AgentTool::SysExecTerminate { command_id });
            }
            if retained_shell_output_indicates_cleanup_ready(output)
                && retained_shell_goal_requests_reset(goal)
            {
                return Some(AgentTool::SysExecSessionReset {});
            }
            if let Some(stdin) = retained_shell_stdin_payload(goal) {
                return Some(AgentTool::SysExecInput { command_id, stdin });
            }
            retained_shell_goal_requests_reset(goal)
                .then_some(AgentTool::SysExecTerminate { command_id })
        }
        "shell__input" => {
            let command_id = command_id_from_executed_tool(executed_tool)?;
            if retained_shell_goal_requests_terminate(goal) {
                return Some(AgentTool::SysExecTerminate { command_id });
            }
            if retained_shell_output_indicates_cleanup_ready(output)
                && retained_shell_goal_requests_reset(goal)
            {
                return Some(AgentTool::SysExecSessionReset {});
            }
            retained_shell_goal_requests_reset(goal)
                .then_some(AgentTool::SysExecTerminate { command_id })
        }
        "shell__terminate" => {
            retained_shell_goal_requests_reset(goal).then_some(AgentTool::SysExecSessionReset {})
        }
        "shell__reset" => {
            retained_shell_goal_requests_clean_reply(goal).then(|| AgentTool::ChatReply {
                message: retained_shell_completion_reply(goal),
            })
        }
        _ => None,
    }
}

pub(crate) fn retained_shell_obsolete_input_after_stop(goal: &str, error: Option<&str>) -> bool {
    if !is_retained_shell_lifecycle_goal(goal)
        || !(retained_shell_goal_requests_terminate(goal)
            || retained_shell_goal_requests_reset(goal))
    {
        return false;
    }
    let lower = error.unwrap_or_default().to_ascii_lowercase();
    [
        "is no longer running",
        "no longer running",
        "no longer accepts stdin",
        "stdin is no longer available",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

pub(crate) fn retained_shell_lifecycle_tool_name(tool: &AgentTool) -> Option<&'static str> {
    match tool {
        AgentTool::SysExecStatus { .. } => Some("shell__status"),
        AgentTool::SysExecInput { .. } => Some("shell__input"),
        AgentTool::SysExecTerminate { .. } => Some("shell__terminate"),
        AgentTool::SysExecSessionReset {} => Some("shell__reset"),
        _ => None,
    }
}

fn is_retained_shell_lifecycle_goal(goal: &str) -> bool {
    let lower = goal.to_ascii_lowercase();
    let retained_shell_context = [
        "retained",
        "persistent",
        "background",
        "long-running",
        "helper",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        && ["shell", "command", "stdin", "helper", "process"]
            .iter()
            .any(|needle| lower.contains(needle));
    let lifecycle_actions = ["status", "input", "stdin", "terminate", "reset", "stop"]
        .iter()
        .filter(|needle| lower.contains(**needle))
        .count();
    retained_shell_context && lifecycle_actions >= 2
}

fn retained_shell_goal_requests_status(goal: &str) -> bool {
    let lower = goal.to_ascii_lowercase();
    lower.contains("status") || lower.contains("check the helper") || lower.contains("check helper")
}

fn retained_shell_goal_requests_terminate(goal: &str) -> bool {
    let lower = goal.to_ascii_lowercase();
    lower.contains("terminate")
        || lower.contains("stop the helper")
        || lower.contains("stop helper")
        || lower.contains("kill the helper")
}

fn retained_shell_goal_requests_reset(goal: &str) -> bool {
    let lower = goal.to_ascii_lowercase();
    lower.contains("reset")
        || lower.contains("clear retained")
        || lower.contains("clear shell state")
        || lower.contains("clean up")
}

fn retained_shell_goal_requests_clean_reply(goal: &str) -> bool {
    let lower = goal.to_ascii_lowercase();
    lower.contains("answer")
        || lower.contains("reply")
        || lower.contains("clean sentence")
        || lower.contains("summarize")
        || lower.contains("tell me")
}

fn command_id_from_executed_tool(tool: Option<&AgentTool>) -> Option<String> {
    match tool? {
        AgentTool::SysExecStatus { command_id }
        | AgentTool::SysExecInput { command_id, .. }
        | AgentTool::SysExecTerminate { command_id } => Some(command_id.clone()),
        _ => None,
    }
}

fn retained_shell_output_indicates_cleanup_ready(output: Option<&str>) -> bool {
    let lower = output.unwrap_or_default().to_ascii_lowercase();
    [
        "\"status\":\"completed\"",
        "\"status\": \"completed\"",
        "status: completed",
        "retained command terminated",
        "retained shell state reset",
        "already sent",
        "duplicate input",
        "already stopped",
        "already terminated",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn retained_shell_stdin_payload(goal: &str) -> Option<String> {
    let backtick_value = goal
        .split('`')
        .nth(1)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let quoted_value = || {
        regex::Regex::new(r#"(?i)(?:send|input|stdin)[^"']*["']([^"']+)["']"#)
            .ok()
            .and_then(|re| {
                re.captures(goal)
                    .and_then(|captures| captures.get(1))
                    .map(|m| m.as_str().trim().to_string())
            })
            .filter(|value| !value.is_empty())
    };
    let value = backtick_value.map(str::to_string).or_else(quoted_value)?;
    Some(if value.ends_with('\n') {
        value
    } else {
        format!("{value}\n")
    })
}

fn retained_shell_completion_reply(goal: &str) -> String {
    if let Some(stdin) = retained_shell_stdin_payload(goal) {
        let trimmed = stdin.trim();
        if !trimmed.is_empty() {
            return format!(
                "Retained shell helper checked, received `{}`, terminated, and reset.",
                trimmed
            );
        }
    }
    "Retained shell helper checked, input sent, terminated, and reset.".to_string()
}

pub fn canonical_intent_hash(
    tool_name: &str,
    args: &serde_json::Value,
    tier: ExecutionTier,
    step_index: u32,
    tool_version: &str,
) -> String {
    let payload = json!({
        "tool_name": tool_name,
        "args": args,
        "tier": tier_as_str(tier),
        "step_index": step_index,
        "tool_version": tool_version,
    });

    let canonical_bytes =
        serde_jcs::to_vec(&payload).expect("canonical_intent_hash: JCS canonicalization failed");
    let digest = sha256(&canonical_bytes).expect("canonical_intent_hash: sha256 failed");
    hex::encode(digest)
}

pub fn canonical_retry_intent_hash(
    tool_name: &str,
    args: &serde_json::Value,
    _tier: ExecutionTier,
    tool_version: &str,
) -> String {
    let payload = json!({
        "tool_name": tool_name,
        "args": args,
        "tool_version": tool_version,
        "retry_scope": "attempt_dedupe_v1",
    });

    let canonical_bytes = serde_jcs::to_vec(&payload)
        .expect("canonical_retry_intent_hash: JCS canonicalization failed");
    let digest = sha256(&canonical_bytes).expect("canonical_retry_intent_hash: sha256 failed");
    hex::encode(digest)
}

pub fn action_fingerprint_key(fingerprint_hash: &str) -> String {
    format!("{}{}", ACTION_FINGERPRINT_LOG_PREFIX, fingerprint_hash)
}

pub fn mark_action_fingerprint_executed_at_step(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    fingerprint_hash: &str,
    step_index: u32,
    label: impl AsRef<str>,
) {
    let value = format!("{};step={}", label.as_ref(), step_index);
    tool_execution_log.insert(
        action_fingerprint_key(fingerprint_hash),
        ToolCallStatus::Executed(value),
    );
}

pub fn action_fingerprint_execution_step(
    tool_execution_log: &BTreeMap<String, ToolCallStatus>,
    fingerprint_hash: &str,
) -> Option<u32> {
    let key = action_fingerprint_key(fingerprint_hash);
    match tool_execution_log.get(&key) {
        Some(ToolCallStatus::Executed(value)) => parse_action_fingerprint_step(value),
        _ => None,
    }
}

pub fn action_fingerprint_execution_label(
    tool_execution_log: &BTreeMap<String, ToolCallStatus>,
    fingerprint_hash: &str,
) -> Option<String> {
    let key = action_fingerprint_key(fingerprint_hash);
    match tool_execution_log.get(&key) {
        Some(ToolCallStatus::Executed(value)) => parse_action_fingerprint_label(value)
            .map(str::to_string)
            .filter(|label| !label.is_empty()),
        _ => None,
    }
}

fn parse_action_fingerprint_step(value: &str) -> Option<u32> {
    value
        .split(';')
        .find_map(|segment| segment.strip_prefix("step="))
        .and_then(|step| step.parse::<u32>().ok())
}

fn parse_action_fingerprint_label(value: &str) -> Option<&str> {
    value.split(';').next().map(str::trim)
}

pub fn drop_legacy_action_fingerprint_receipt(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    fingerprint_hash: &str,
) -> bool {
    let key = action_fingerprint_key(fingerprint_hash);
    let should_drop = matches!(
        tool_execution_log.get(&key),
        Some(ToolCallStatus::Executed(value)) if parse_action_fingerprint_step(value).is_none()
    );
    if should_drop {
        tool_execution_log.remove(&key);
    }
    should_drop
}

pub fn execution_evidence_key(name: &str) -> String {
    format!("{}{}=true", EXECUTION_EVIDENCE_PREFIX, name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEvidence {
    Execution,
    Verification,
    HostDiscovery,
    WorkspaceReadObserved,
    WorkspaceEditApplied,
}

impl RuntimeEvidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Verification => "verification",
            Self::HostDiscovery => "host_discovery",
            Self::WorkspaceReadObserved => "workspace_read_observed",
            Self::WorkspaceEditApplied => "workspace_edit_applied",
        }
    }
}

pub fn execution_evidence_key_for(receipt: RuntimeEvidence) -> String {
    execution_evidence_key(receipt.as_str())
}

pub fn success_condition_key(name: &str) -> String {
    format!("{}{}=true", SUCCESS_CONDITION_PREFIX, name)
}

pub fn tool_success_evidence_name(tool_name: &str) -> String {
    format!("tool::{}::executed", tool_name)
}

pub fn record_execution_evidence(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    name: &str,
) {
    record_execution_evidence_with_value(tool_execution_log, name, "true".to_string());
}

pub fn record_execution_evidence_for(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    receipt: RuntimeEvidence,
) {
    record_execution_evidence(tool_execution_log, receipt.as_str());
}

pub fn record_execution_evidence_with_value(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    name: &str,
    value: String,
) {
    tool_execution_log.insert(
        execution_evidence_key(name),
        ToolCallStatus::Executed(value),
    );
}

pub fn record_execution_evidence_for_value(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    receipt: RuntimeEvidence,
    value: String,
) {
    record_execution_evidence_with_value(tool_execution_log, receipt.as_str(), value);
}

pub fn record_success_condition(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    name: &str,
) {
    tool_execution_log.insert(
        success_condition_key(name),
        ToolCallStatus::Executed("true".to_string()),
    );
}

pub fn has_execution_evidence(
    tool_execution_log: &BTreeMap<String, ToolCallStatus>,
    name: &str,
) -> bool {
    matches!(
        tool_execution_log.get(&execution_evidence_key(name)),
        Some(ToolCallStatus::Executed(_))
    )
}

pub fn missing_runtime_action_completion_evidence(agent_state: &AgentState) -> Vec<String> {
    let mut missing = Vec::new();
    if goal_requests_browser_coordinate_click(&agent_state.goal) {
        let evidence_name = tool_success_evidence_name("browser__click_at");
        if !has_execution_evidence(&agent_state.tool_execution_log, &evidence_name) {
            missing.push(evidence_name);
        }
    }
    missing
}

fn goal_requests_browser_coordinate_click(goal: &str) -> bool {
    let normalized = goal.to_ascii_lowercase();
    let browser_context =
        normalized.contains("browser") || normalized.contains("local browser fixture");
    let click_request = normalized.contains("click");
    let grounded_coordinate_request = normalized.contains("coordinate")
        || normalized.contains("click_at")
        || normalized.contains("canvas")
        || normalized.contains("target action")
        || normalized.contains("target");
    browser_context && click_request && grounded_coordinate_request
}

pub fn execution_evidence_value<'a>(
    tool_execution_log: &'a BTreeMap<String, ToolCallStatus>,
    name: &str,
) -> Option<&'a str> {
    match tool_execution_log.get(&execution_evidence_key(name)) {
        Some(ToolCallStatus::Executed(value)) => Some(value.as_str()),
        _ => None,
    }
}

pub fn has_success_condition(
    tool_execution_log: &BTreeMap<String, ToolCallStatus>,
    name: &str,
) -> bool {
    matches!(
        tool_execution_log.get(&success_condition_key(name)),
        Some(ToolCallStatus::Executed(_))
    )
}

pub fn extract_completion_evidence_keys(
    verification_checks: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut evidence = BTreeSet::<String>::new();
    let mut success_conditions = BTreeSet::<String>::new();
    for check in verification_checks {
        let token = check.trim();
        if let Some(rest) = token.strip_prefix("evidence::") {
            let marker = rest.trim_end_matches("=true").trim();
            if !marker.is_empty() {
                evidence.insert(marker.to_string());
            }
        } else if let Some(rest) = token.strip_prefix("success_condition::") {
            let marker = rest.trim_end_matches("=true").trim();
            if !marker.is_empty() {
                success_conditions.insert(marker.to_string());
            }
        }
    }
    (
        evidence.into_iter().collect::<Vec<_>>(),
        success_conditions.into_iter().collect::<Vec<_>>(),
    )
}

pub fn persist_step_evidence_to_ledger(
    agent_state: &mut AgentState,
    intent_id: &str,
    verification_checks: &[String],
) {
    let intent_id = (!intent_id.trim().is_empty()).then(|| intent_id.to_string());
    let mut evidence = BTreeMap::<String, String>::new();
    let mut success_conditions = BTreeMap::<String, String>::new();
    let has_typed_log_evidence = agent_state.tool_execution_log.iter().any(|(key, status)| {
        key.trim().starts_with(EXECUTION_EVIDENCE_PREFIX)
            && matches!(
                status,
                ToolCallStatus::Executed(value)
                    if {
                        let value = value.trim();
                        !value.is_empty() && value != "true"
                    }
            )
    });
    if has_typed_log_evidence {
        for (key, status) in &agent_state.tool_execution_log {
            let Some(rest) = key.trim().strip_prefix(EXECUTION_EVIDENCE_PREFIX) else {
                continue;
            };
            let (name, _) = rest
                .split_once('=')
                .map(|(name, value)| (name.trim(), value.trim()))
                .unwrap_or((rest.trim(), "true"));
            if name.is_empty() || evidence.contains_key(name) {
                continue;
            }
            if let ToolCallStatus::Executed(value) = status {
                if !value.trim().is_empty() {
                    evidence.insert(name.to_string(), value.to_string());
                }
            }
        }
        for (key, status) in &agent_state.tool_execution_log {
            let Some(rest) = key.trim().strip_prefix(SUCCESS_CONDITION_PREFIX) else {
                continue;
            };
            let (name, _) = rest
                .split_once('=')
                .map(|(name, value)| (name.trim(), value.trim()))
                .unwrap_or((rest.trim(), "true"));
            if name.is_empty() || success_conditions.contains_key(name) {
                continue;
            }
            if let ToolCallStatus::Executed(value) = status {
                if !value.trim().is_empty() {
                    success_conditions.insert(name.to_string(), value.to_string());
                }
            }
        }
    }
    for check in verification_checks {
        let token = check.trim();
        if let Some(rest) = token.strip_prefix(EXECUTION_EVIDENCE_PREFIX) {
            let (name, marker_value) = rest
                .split_once('=')
                .map(|(name, value)| (name.trim(), value.trim()))
                .unwrap_or((rest.trim(), "true"));
            if !name.is_empty() {
                let value = execution_evidence_value(&agent_state.tool_execution_log, name)
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or(marker_value);
                evidence.insert(name.to_string(), value.to_string());
            }
        } else if let Some(rest) = token.strip_prefix(SUCCESS_CONDITION_PREFIX) {
            let (name, marker_value) = rest
                .split_once('=')
                .map(|(name, value)| (name.trim(), value.trim()))
                .unwrap_or((rest.trim(), "true"));
            if !name.is_empty() {
                success_conditions.insert(name.to_string(), marker_value.to_string());
            }
        }
    }
    for (receipt, value) in evidence {
        agent_state
            .execution_ledger
            .record_evidence(intent_id.clone(), receipt, value);
    }
    for (postcondition, value) in success_conditions {
        agent_state.execution_ledger.record_success_condition(
            intent_id.clone(),
            postcondition,
            value,
        );
    }
    if let Some(value) = agent_state
        .execution_ledger
        .evidence_value("verification")
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "true")
        .map(str::to_string)
    {
        agent_state.execution_ledger.record_verification_evidence(
            intent_id.clone(),
            "verification",
            value,
        );
    }
    for check in verification_checks {
        let token = check.trim();
        if token.is_empty()
            || token.starts_with("evidence::")
            || token.starts_with("success_condition::")
        {
            continue;
        }
        let (key, value) = token
            .split_once('=')
            .map(|(key, value)| (key.trim(), value.trim()))
            .unwrap_or((token, "true"));
        if key.is_empty() {
            continue;
        }
        agent_state
            .execution_ledger
            .record_verification_evidence(intent_id.clone(), key, value);
    }
}

pub fn recovery_retry_from_checks(
    verification_checks: &[String],
    prior_consecutive_failures: u8,
) -> (bool, Option<String>) {
    let mut explicit_retry = false;
    let mut explicit_reason: Option<String> = None;
    for check in verification_checks {
        let token = check.trim();
        if token == "determinism_recovery_retry=true" {
            explicit_retry = true;
            continue;
        }
        if let Some(rest) = token.strip_prefix("determinism_recovery_reason=") {
            let reason = rest.trim();
            if !reason.is_empty() {
                explicit_reason = Some(reason.to_string());
                explicit_retry = true;
            }
            continue;
        }
        if let Some(rest) = token.strip_prefix("attempt_repeat_count=") {
            if let Ok(count) = rest.trim().parse::<u32>() {
                if count > 0 {
                    explicit_retry = true;
                    if explicit_reason.is_none() {
                        explicit_reason = Some(format!("attempt_repeat_count={}", count));
                    }
                }
            }
        }
    }

    let recovery_retry = explicit_retry || prior_consecutive_failures > 0;
    let recovery_reason = if let Some(reason) = explicit_reason {
        Some(reason)
    } else if prior_consecutive_failures > 0 {
        Some(format!(
            "consecutive_failures={}",
            prior_consecutive_failures
        ))
    } else {
        None
    };
    (recovery_retry, recovery_reason)
}

pub fn persist_step_evidence(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    verification_checks: &[String],
    prior_consecutive_failures: u8,
) -> Result<(), TransactionError> {
    let (evidence, success_conditions) = extract_completion_evidence_keys(verification_checks);
    let (recovery_retry, recovery_reason) =
        recovery_retry_from_checks(verification_checks, prior_consecutive_failures);
    let evidence = DeterminismStepContractEvidence {
        schema_version: DeterminismStepContractEvidence::schema_version(),
        intent_id: intent_id.to_string(),
        receipts: evidence,
        postconditions: success_conditions,
        recovery_retry,
        recovery_reason,
    };
    let key = determinism_step_contract_state_key(session_id, step_index);
    let bytes = ioi_types::codec::to_bytes_canonical(&evidence)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    state.insert(&key, &bytes)?;
    Ok(())
}

#[cfg(test)]
#[path = "support/tests.rs"]
mod tests;
