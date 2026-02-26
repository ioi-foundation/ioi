use super::super::{no_visual, ActionExecutionOutcome};
use crate::agentic::desktop::service::DesktopAgentService;

pub(crate) fn handle_system_fail_tool(
    service: &DesktopAgentService,
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

    let error_msg = if let Some(cap) = missing_capability {
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
            format!(
                "ESCALATE_REQUEST: Missing capability '{}'. Reason: {}",
                cap, reason
            )
        } else {
            // Treat lookup/runtime failures as action failures, not tier/capability upgrades.
            format!("Agent Failure: {} (claimed capability: '{}')", reason, cap)
        }
    } else {
        format!("Agent Failure: {}", reason)
    };

    if let Some(tx) = &service.event_sender {
        let _ = tx.send(ioi_types::app::KernelEvent::AgentActionResult {
            session_id,
            step_index,
            tool_name: "system__fail".to_string(),
            output: error_msg.clone(),
            // [FIX] Authoritative Status
            agent_status: "Failed".to_string(),
        });
    }

    no_visual(false, None, Some(error_msg))
}
