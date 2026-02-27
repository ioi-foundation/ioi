use crate::agentic::desktop::service::step::anti_loop::tier_as_str;
use crate::agentic::desktop::types::{AgentStatus, ExecutionTier, ToolCallStatus};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;
use serde_json::json;
use std::collections::BTreeMap;

const ACTION_FINGERPRINT_LOG_PREFIX: &str = "action_fingerprint::";
const EXECUTION_RECEIPT_PREFIX: &str = "receipt::";
const EXECUTION_POSTCONDITION_PREFIX: &str = "postcondition::";

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
    if current_tool_name != "system__fail" {
        return false;
    }

    if !matches!(status, AgentStatus::Failed(_)) {
        let fallback_reason = error_msg.unwrap_or("Agent requested explicit failure");
        mark_system_fail_status(status, fallback_reason.to_string());
    }

    true
}

// Helper to determine if an action relies on precise screen coordinates.
pub(super) fn requires_visual_integrity(tool: &AgentTool) -> bool {
    match tool {
        AgentTool::Computer(action) => matches!(
            action,
            ioi_types::app::agentic::ComputerAction::LeftClickId { .. }
                | ioi_types::app::agentic::ComputerAction::LeftClick {
                    coordinate: Some(_),
                    ..
                }
                | ioi_types::app::agentic::ComputerAction::LeftClickDrag { .. }
                | ioi_types::app::agentic::ComputerAction::DragDrop { .. }
                | ioi_types::app::agentic::ComputerAction::DragDropId { .. }
                | ioi_types::app::agentic::ComputerAction::DragDropElement { .. }
                | ioi_types::app::agentic::ComputerAction::MouseMove { .. }
                | ioi_types::app::agentic::ComputerAction::Scroll {
                    coordinate: Some(_),
                    ..
                }
        ),
        AgentTool::GuiClick { .. } => true,
        AgentTool::GuiScroll { .. } => true,
        AgentTool::BrowserSyntheticClick { .. } => true,
        AgentTool::BrowserClick { .. } => true,
        AgentTool::BrowserClickElement { .. } => true,
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

    let canonical_bytes = serde_jcs::to_vec(&payload)
        .or_else(|_| serde_json::to_vec(&payload))
        .unwrap_or_default();

    sha256(&canonical_bytes)
        .map(hex::encode)
        .unwrap_or_else(|_| "unknown".to_string())
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
        .or_else(|_| serde_json::to_vec(&payload))
        .unwrap_or_default();

    sha256(&canonical_bytes)
        .map(hex::encode)
        .unwrap_or_else(|_| "unknown".to_string())
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

fn parse_action_fingerprint_step(value: &str) -> Option<u32> {
    value
        .split(';')
        .find_map(|segment| segment.strip_prefix("step="))
        .and_then(|step| step.parse::<u32>().ok())
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

pub fn receipt_marker(name: &str) -> String {
    format!("{}{}=true", EXECUTION_RECEIPT_PREFIX, name)
}

pub fn postcondition_marker(name: &str) -> String {
    format!("{}{}=true", EXECUTION_POSTCONDITION_PREFIX, name)
}

pub fn mark_execution_receipt(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    name: &str,
) {
    mark_execution_receipt_with_value(tool_execution_log, name, "true".to_string());
}

pub fn mark_execution_receipt_with_value(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    name: &str,
    value: String,
) {
    tool_execution_log.insert(receipt_marker(name), ToolCallStatus::Executed(value));
}

pub fn mark_execution_postcondition(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    name: &str,
) {
    tool_execution_log.insert(
        postcondition_marker(name),
        ToolCallStatus::Executed("true".to_string()),
    );
}

pub fn has_execution_receipt(
    tool_execution_log: &BTreeMap<String, ToolCallStatus>,
    name: &str,
) -> bool {
    matches!(
        tool_execution_log.get(&receipt_marker(name)),
        Some(ToolCallStatus::Executed(_))
    )
}

pub fn execution_receipt_value<'a>(
    tool_execution_log: &'a BTreeMap<String, ToolCallStatus>,
    name: &str,
) -> Option<&'a str> {
    match tool_execution_log.get(&receipt_marker(name)) {
        Some(ToolCallStatus::Executed(value)) => Some(value.as_str()),
        _ => None,
    }
}

pub fn has_execution_postcondition(
    tool_execution_log: &BTreeMap<String, ToolCallStatus>,
    name: &str,
) -> bool {
    matches!(
        tool_execution_log.get(&postcondition_marker(name)),
        Some(ToolCallStatus::Executed(_))
    )
}

#[cfg(test)]
mod tests {
    use super::{
        action_fingerprint_execution_step, drop_legacy_action_fingerprint_receipt,
        mark_action_fingerprint_executed_at_step,
    };
    use crate::agentic::desktop::types::ToolCallStatus;
    use std::collections::BTreeMap;

    #[test]
    fn action_fingerprint_step_roundtrips_when_recorded_with_step() {
        let mut log = BTreeMap::new();
        mark_action_fingerprint_executed_at_step(&mut log, "abc", 7, "success");
        assert_eq!(action_fingerprint_execution_step(&log, "abc"), Some(7));
    }

    #[test]
    fn legacy_action_fingerprint_marker_is_dropped() {
        let mut log = BTreeMap::new();
        log.insert(
            "action_fingerprint::legacy".to_string(),
            ToolCallStatus::Executed("success".to_string()),
        );
        assert!(drop_legacy_action_fingerprint_receipt(&mut log, "legacy"));
        assert_eq!(action_fingerprint_execution_step(&log, "legacy"), None);
        assert!(log.get("action_fingerprint::legacy").is_none());
    }
}
