use super::super::runtime_locality::maybe_seed_runtime_locality_context;
use super::super::sudo::{
    incident_waiting_for_sudo_password, maybe_restore_pending_install_from_incident,
    RUNTIME_SECRET_KIND_SUDO_PASSWORD,
};
use super::reset_for_new_user_goal;
use crate::agentic::runtime::keys::{get_incident_key, get_remediation_key, get_state_key};
use crate::agentic::runtime::runtime_secret;
use crate::agentic::runtime::service::recovery::incident::mark_incident_retry_root;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::PostMessageParams;
use crate::agentic::runtime::utils::{persist_agent_state, timestamp_ms_now};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::codec;
use ioi_types::error::TransactionError;

pub async fn handle_post_message(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    p: PostMessageParams,
    ctx: &TxContext<'_>,
) -> Result<(), TransactionError> {
    let key = get_state_key(&p.session_id);
    if let Some(bytes) = state.get(&key)? {
        let mut agent_state: crate::agentic::runtime::types::AgentState =
            codec::from_bytes_canonical(&bytes)?;
        let timestamp_ms = timestamp_ms_now();
        let role = p.role.clone();
        let content = p.content.clone();
        let incident_waiting_for_sudo = incident_waiting_for_sudo_password(state, p.session_id)?;
        let waiting_for_sudo_password =
            agent_state.is_waiting_for_sudo_password() || incident_waiting_for_sudo;
        if role == "user" {
            if waiting_for_sudo_password {
                if content.trim().is_empty() {
                    return Err(TransactionError::Invalid(
                        "Sudo password input cannot be empty".into(),
                    ));
                }
                let session_id_hex = hex::encode(p.session_id);
                runtime_secret::set_secret(
                    &session_id_hex,
                    RUNTIME_SECRET_KIND_SUDO_PASSWORD,
                    content.clone(),
                    true,
                    120,
                )
                .map_err(TransactionError::Invalid)?;
                log::info!(
                    "Captured runtime sudo credential from user message for session {}",
                    hex::encode(&p.session_id[..4])
                );
                mark_incident_retry_root(state, p.session_id)?;
                maybe_restore_pending_install_from_incident(state, p.session_id, &mut agent_state)?;
            } else {
                reset_for_new_user_goal(&mut agent_state, &content);
                maybe_seed_runtime_locality_context(&content).await;
                let remediation_key = get_remediation_key(&p.session_id);
                let incident_key = get_incident_key(&p.session_id);
                state.delete(&remediation_key)?;
                state.delete(&incident_key)?;
            }
        }
        let transcript_msg = if role == "user" && waiting_for_sudo_password {
            ioi_types::app::agentic::ChatMessage {
                role: "system".to_string(),
                content: "System: Runtime sudo credential received. Retrying pending install."
                    .to_string(),
                timestamp: timestamp_ms,
                trace_hash: None,
            }
        } else {
            ioi_types::app::agentic::ChatMessage {
                role,
                content,
                timestamp: timestamp_ms,
                trace_hash: None,
            }
        };

        let new_root = service
            .append_chat_to_scs(p.session_id, &transcript_msg, ctx.block_height)
            .await?;
        agent_state.transcript_root = new_root;

        if agent_state.status != crate::agentic::runtime::types::AgentStatus::Running {
            log::info!(
                "Auto-resuming agent session {} due to new message",
                hex::encode(&p.session_id[..4])
            );
            agent_state.set_running();
            agent_state.consecutive_failures = 0;
        }

        persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;
    } else {
        return Err(TransactionError::Invalid("Session not found".into()));
    }

    Ok(())
}
