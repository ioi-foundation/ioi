use super::super::sudo::{
    incident_waiting_for_sudo_password, maybe_restore_pending_install_from_incident,
    status_mentions_sudo_password, RUNTIME_SECRET_KIND_SUDO_PASSWORD,
};
use crate::agentic::runtime::keys::{get_approval_grant_key, get_state_key};
use crate::agentic::runtime::runtime_secret;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::{
    AgentPauseReason, AgentState, AgentStatus, ResumeAgentParams,
};
use crate::agentic::runtime::utils::{persist_agent_state, timestamp_ms_now};
use ioi_api::state::StateAccess;
use ioi_types::codec;
use ioi_types::error::TransactionError;

pub async fn handle_resume(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    p: ResumeAgentParams,
) -> Result<(), TransactionError> {
    let key = get_state_key(&p.session_id);
    let bytes = state
        .get(&key)?
        .ok_or(TransactionError::Invalid("Session not found".into()))?;
    let mut agent_state: AgentState = codec::from_bytes_canonical(&bytes)?;
    let session_id_hex = hex::encode(p.session_id);
    let waiting_for_sudo_password_before_resume = agent_state.is_waiting_for_sudo_password();
    let status_hints_sudo_wait = status_mentions_sudo_password(&agent_state.status);
    let incident_waiting_for_sudo = incident_waiting_for_sudo_password(state, p.session_id)?;
    let runtime_secret_ready =
        runtime_secret::has_secret(&session_id_hex, RUNTIME_SECRET_KIND_SUDO_PASSWORD);
    let sudo_retry_resume = p.approval_grant.is_none()
        && (waiting_for_sudo_password_before_resume
            || status_hints_sudo_wait
            || incident_waiting_for_sudo
            || runtime_secret_ready);

    if matches!(agent_state.status, AgentStatus::Paused(_))
        || agent_state.status == AgentStatus::Running
        || sudo_retry_resume
    {
        agent_state.set_running();
        if sudo_retry_resume {
            maybe_restore_pending_install_from_incident(state, p.session_id, &mut agent_state)?;
        }

        let resuming_pending_install = agent_state
            .pending_action_state()
            .tool_jcs
            .as_ref()
            .and_then(|raw| serde_json::from_slice::<ioi_types::app::agentic::AgentTool>(raw).ok())
            .map(|tool| {
                matches!(
                    tool,
                    ioi_types::app::agentic::AgentTool::SysInstallPackage { .. }
                )
            })
            .unwrap_or(false);
        if sudo_retry_resume {
            agent_state.execution_queue.clear();
            if !resuming_pending_install {
                log::warn!(
                    "Resume requested for sudo retry, but pending install tool is unavailable for session {}. Keeping session paused.",
                    hex::encode(&p.session_id[..4])
                );
                agent_state.set_pause_reason(AgentPauseReason::WaitingForSudoPassword);
                persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;
                return Ok(());
            }
        }

        if let Some(grant) = p.approval_grant {
            log::info!(
                "Resuming session {} with Approval Grant for hash {:?}",
                hex::encode(&p.session_id[0..4]),
                hex::encode(&grant.request_hash)
            );
            agent_state.pending_approval = Some(grant.clone());
            state.insert(
                &get_approval_grant_key(&p.session_id),
                &codec::to_bytes_canonical(&grant)?,
            )?;

            let msg = ioi_types::app::agentic::ChatMessage {
                role: "system".to_string(),
                content:
                    "Authorization GRANTED via ApprovalGrant. You may retry the action immediately."
                        .to_string(),
                timestamp: timestamp_ms_now(),
                trace_hash: None,
            };

            let new_root = service.append_chat_to_scs(p.session_id, &msg, 0).await?;
            agent_state.transcript_root = new_root;
        } else {
            agent_state.pending_approval = None;
            state.delete(&get_approval_grant_key(&p.session_id))?;
            let msg = ioi_types::app::agentic::ChatMessage {
                role: "system".to_string(),
                content: "Resumed by user/controller without specific approval.".to_string(),
                timestamp: timestamp_ms_now(),
                trace_hash: None,
            };
            let new_root = service.append_chat_to_scs(p.session_id, &msg, 0).await?;
            agent_state.transcript_root = new_root;
        }

        agent_state.consecutive_failures = 0;

        persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;
        Ok(())
    } else {
        Err(TransactionError::Invalid(format!(
            "Agent cannot resume from status: {:?}",
            agent_state.status
        )))
    }
}
