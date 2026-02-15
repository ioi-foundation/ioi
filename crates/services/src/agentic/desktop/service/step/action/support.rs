use crate::agentic::desktop::service::step::anti_loop::tier_as_str;
use crate::agentic::desktop::types::{AgentStatus, ExecutionTier};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;
use serde_json::json;

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
