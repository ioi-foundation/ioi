use super::super::{no_visual, ActionExecutionOutcome};
use crate::agentic::runtime::service::RuntimeAgentService;

pub(crate) fn handle_system_fail_tool(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    reason: String,
    missing_capability: Option<String>,
) -> ActionExecutionOutcome {
    log::warn!(
        "Agent explicit failure: {} (Missing: {:?})",
        reason,
        missing_capability
    );

    let (error_msg, error_class) = if let Some(cap) = missing_capability {
        let reason_lc = reason.to_lowercase();
        let is_true_capability_gap = reason_lc.contains("missing tool")
            || reason_lc.contains("tool is missing")
            || reason_lc.contains("not listed in your available tools")
            || reason_lc.contains("capability missing")
            || reason_lc.contains("tier restricted")
            || reason_lc.contains("no typing-capable tool is available")
            || reason_lc.contains("no clipboard-capable tool is available")
            || reason_lc.contains("no click-capable tool is available")
            || (reason_lc.contains("no ")
                && reason_lc.contains("tool")
                && reason_lc.contains("available"));

        if is_true_capability_gap {
            (
                format!(
                    "ESCALATE_REQUEST: Missing capability '{}'. Reason: {}",
                    cap, reason
                ),
                Some("ToolUnavailable".to_string()),
            )
        } else {
            // Treat lookup/runtime failures as action failures, not tier/capability upgrades.
            (
                format!("Agent Failure: {} (claimed capability: '{}')", reason, cap),
                None,
            )
        }
    } else {
        (format!("Agent Failure: {}", reason), None)
    };

    if let Some(tx) = &service.event_sender {
        let _ = tx.send(ioi_types::app::KernelEvent::AgentActionResult {
            session_id,
            step_index,
            tool_name: "agent__escalate".to_string(),
            output: error_msg.clone(),
            error_class,
            // [FIX] Authoritative Status
            agent_status: "Failed".to_string(),
        });
    }

    no_visual(false, None, Some(error_msg))
}
