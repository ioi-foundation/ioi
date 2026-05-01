use crate::agentic::runtime::service::step::anti_loop::tier_as_str;
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
