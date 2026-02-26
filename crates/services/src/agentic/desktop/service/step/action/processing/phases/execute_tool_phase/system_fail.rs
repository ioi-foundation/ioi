use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_system_fail_outcome(
    agent_state: &mut AgentState,
    reason: &str,
    block_timestamp_ns: u64,
    success: &mut bool,
    error_msg: &mut Option<String>,
    history_entry: &mut Option<String>,
    action_output: &mut Option<String>,
    terminal_chat_reply_output: &mut Option<String>,
    current_tool_name: &mut String,
    is_lifecycle_action: &mut bool,
    verification_checks: &mut Vec<String>,
) {
    let mailbox_intent = is_mailbox_connector_goal(&agent_state.goal);
    let mailbox_reason = reason.to_ascii_lowercase();
    if mailbox_intent
        && (mailbox_reason.contains("mailbox")
            || mailbox_reason.contains("email")
            || mailbox_reason.contains("mail "))
    {
        let run_timestamp_ms = block_timestamp_ns / 1_000_000;
        let summary = render_mailbox_access_limited_reply(&agent_state.goal, run_timestamp_ms);
        *success = true;
        *error_msg = None;
        *history_entry = Some(summary.clone());
        *action_output = Some(summary.clone());
        *terminal_chat_reply_output = Some(summary.clone());
        *current_tool_name = "chat__reply".to_string();
        *is_lifecycle_action = true;
        agent_state.status = AgentStatus::Completed(Some(summary));
        agent_state.pending_search_completion = None;
        agent_state.execution_queue.clear();
        agent_state.recent_actions.clear();
        verification_checks.push("mailbox_system_fail_degraded_to_reply=true".to_string());
        verification_checks.push("terminal_chat_reply_ready=true".to_string());
    } else {
        mark_system_fail_status(&mut agent_state.status, reason.to_string());
        *is_lifecycle_action = true;
        *action_output = Some(format!("Agent Failed: {}", reason));
    }
}
