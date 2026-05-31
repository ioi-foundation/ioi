use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_system_fail_outcome(
    agent_state: &mut AgentState,
    reason: &str,
    _block_timestamp_ns: u64,
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
        *success = true;
        *error_msg = None;
        let feedback = concat!(
            "Tool result: mailbox content requires a mailbox connector tool. ",
            "Return this typed limitation to the model loop so it can choose an allowed ",
            "mail connector action or produce a model-authored blocker."
        )
        .to_string();
        *history_entry = Some(feedback.clone());
        *action_output = Some(feedback);
        *terminal_chat_reply_output = None;
        *current_tool_name = "system__fail".to_string();
        *is_lifecycle_action = false;
        agent_state.status = AgentStatus::Running;
        agent_state.recent_actions.clear();
        verification_checks.push("mailbox_system_fail_returned_to_model_loop=true".to_string());
        verification_checks.push("terminal_chat_reply_ready=false".to_string());
    } else {
        mark_system_fail_status(&mut agent_state.status, reason.to_string());
        *is_lifecycle_action = true;
        *action_output = Some(format!("Agent Failed: {}", reason));
    }
}
