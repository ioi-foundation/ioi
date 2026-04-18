use super::pause_state::{
    record_approval_loop_pause, record_waiting_for_approval, record_waiting_for_sudo_password,
    record_waiting_for_target_clarification,
};
use crate::agentic::runtime::service::step::anti_loop::FailureClass;
use crate::agentic::runtime::service::step::incident::{
    mark_incident_wait_for_user, ApprovalDirective,
};
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::AgentState;
use crate::agentic::runtime::utils::timestamp_ms_now;
use ioi_api::state::StateAccess;
use ioi_types::error::TransactionError;

async fn append_chat_message(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    block_height: u64,
    role: &str,
    content: String,
) -> Result<(), TransactionError> {
    let msg = ioi_types::app::agentic::ChatMessage {
        role: role.to_string(),
        content,
        timestamp: timestamp_ms_now(),
        trace_hash: None,
    };
    let _ = service
        .append_chat_to_scs(session_id, &msg, block_height)
        .await?;
    Ok(())
}

pub(super) async fn resolve_approval_directive_outcome(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
    approval_hash: &str,
    approval_directive: ApprovalDirective,
    policy_decision: &mut String,
) -> Result<(bool, Option<String>, Option<String>, Option<[u8; 32]>), TransactionError> {
    match approval_directive {
        ApprovalDirective::PromptUser => {
            append_chat_message(
                service,
                session_id,
                block_height,
                "system",
                format!(
                    "System: Queued action halted by Agency Firewall (Hash: {}). Requesting authorization.",
                    approval_hash
                ),
            )
            .await?;
            Ok((true, None, None, None))
        }
        ApprovalDirective::SuppressDuplicatePrompt => {
            append_chat_message(
                service,
                session_id,
                block_height,
                "system",
                "System: Approval already pending for this incident/action. Waiting for your decision."
                    .to_string(),
            )
            .await?;
            Ok((true, None, None, None))
        }
        ApprovalDirective::PauseLoop => {
            *policy_decision = "denied".to_string();
            let loop_msg = format!(
                "ERROR_CLASS=PermissionOrApprovalRequired Approval loop policy paused this incident for request hash {}.",
                approval_hash
            );
            record_approval_loop_pause(agent_state);
            append_chat_message(
                service,
                session_id,
                block_height,
                "system",
                format!(
                    "System: {} Please approve, deny, or change policy settings.",
                    loop_msg
                ),
            )
            .await?;
            Ok((false, None, Some(loop_msg), None))
        }
    }
}

async fn append_tool_output_message_if_present(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    block_height: u64,
    tool_name: &str,
    err: Option<&str>,
) -> Result<(), TransactionError> {
    if let Some(err_text) = err {
        append_chat_message(
            service,
            session_id,
            block_height,
            "tool",
            format!("Tool Output ({}): {}", tool_name, err_text),
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn enter_wait_for_sudo_password(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
    tool_name: &str,
    err: Option<&str>,
    action_json: &str,
    tool_jcs: &[u8],
    verification_checks: &mut Vec<String>,
) -> Result<(), TransactionError> {
    mark_incident_wait_for_user(
        state,
        session_id,
        "wait_for_sudo_password",
        FailureClass::PermissionOrApprovalRequired,
        err,
    )?;
    record_waiting_for_sudo_password(agent_state, action_json, tool_jcs)?;

    append_tool_output_message_if_present(service, session_id, block_height, tool_name, err)
        .await?;
    append_chat_message(
        service,
        session_id,
        block_height,
        "system",
        "System: WAIT_FOR_SUDO_PASSWORD. Install requires sudo password. Enter password to retry once."
            .to_string(),
    )
    .await?;
    verification_checks.push("awaiting_sudo_password=true".to_string());
    Ok(())
}

pub(super) async fn enter_wait_for_clarification(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
    tool_name: &str,
    err: Option<&str>,
    verification_checks: &mut Vec<String>,
) -> Result<(), TransactionError> {
    mark_incident_wait_for_user(
        state,
        session_id,
        "wait_for_clarification",
        FailureClass::UserInterventionNeeded,
        err,
    )?;
    record_waiting_for_target_clarification(agent_state);

    append_tool_output_message_if_present(service, session_id, block_height, tool_name, err)
        .await?;
    append_chat_message(
        service,
        session_id,
        block_height,
        "system",
        "System: WAIT_FOR_CLARIFICATION. Target identity could not be resolved. Provide clarification input to continue."
            .to_string(),
    )
    .await?;
    verification_checks.push("awaiting_clarification=true".to_string());
    Ok(())
}

pub(super) fn record_pending_approval_wait(
    agent_state: &mut AgentState,
    action_json: &str,
    tool_jcs: &[u8],
    tool_hash: [u8; 32],
    pending_visual_hash: [u8; 32],
) {
    record_waiting_for_approval(
        agent_state,
        action_json,
        tool_jcs,
        tool_hash,
        pending_visual_hash,
    );
}
