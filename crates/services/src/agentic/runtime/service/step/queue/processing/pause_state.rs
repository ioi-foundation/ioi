use crate::agentic::runtime::types::{AgentPauseReason, AgentState, PendingActionState};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::error::TransactionError;

pub(super) fn record_waiting_for_sudo_password(
    agent_state: &mut AgentState,
    action_json: &str,
    tool_jcs: &[u8],
) -> Result<(), TransactionError> {
    let tool_hash_bytes = sha256(tool_jcs).map_err(|error| {
        TransactionError::Invalid(format!("Failed to hash queued install tool JCS: {}", error))
    })?;
    let mut tool_hash = [0u8; 32];
    tool_hash.copy_from_slice(tool_hash_bytes.as_ref());

    agent_state.set_pause_reason(AgentPauseReason::WaitingForSudoPassword);
    agent_state.execution_queue.clear();
    agent_state.replace_pending_action_state(PendingActionState {
        approval: None,
        tool_call: Some(action_json.to_string()),
        tool_jcs: Some(tool_jcs.to_vec()),
        tool_hash: Some(tool_hash),
        request_nonce: Some(agent_state.step_count as u64),
        visual_hash: Some(agent_state.last_screen_phash.unwrap_or([0u8; 32])),
    });

    Ok(())
}

pub(super) fn record_waiting_for_target_clarification(agent_state: &mut AgentState) {
    agent_state.set_pause_reason(AgentPauseReason::WaitingForTargetClarification);
    agent_state.clear_pending_action_state();
    agent_state.execution_queue.clear();
}

pub(super) fn record_waiting_for_approval(
    agent_state: &mut AgentState,
    action_json: &str,
    tool_jcs: &[u8],
    tool_hash: [u8; 32],
    visual_hash: [u8; 32],
) {
    agent_state.replace_pending_action_state(PendingActionState {
        approval: None,
        tool_call: Some(action_json.to_string()),
        tool_jcs: Some(tool_jcs.to_vec()),
        tool_hash: Some(tool_hash),
        request_nonce: Some(agent_state.step_count as u64),
        visual_hash: Some(visual_hash),
    });
    agent_state.set_pause_reason(AgentPauseReason::WaitingForApproval);
}

pub(super) fn clear_pending_approval_pause(agent_state: &mut AgentState) {
    agent_state.clear_pending_action_state();
    agent_state.status = crate::agentic::runtime::types::AgentStatus::Running;
}

pub(super) fn record_approval_loop_pause(agent_state: &mut AgentState) {
    agent_state.set_pause_reason(AgentPauseReason::ApprovalLoopDetected);
}
