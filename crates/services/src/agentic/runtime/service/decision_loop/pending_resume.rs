use crate::agentic::runtime::runtime_secret;
use crate::agentic::runtime::service::actions;
use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::runtime::types::{AgentPauseReason, AgentState};
use crate::agentic::runtime::utils::persist_agent_state;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::AgentTool;
use ioi_types::error::TransactionError;

const RUNTIME_SECRET_KIND_SUDO_PASSWORD: &str = "sudo_password";

pub(super) fn should_clear_stale_canonical_pending(
    agent_state: &AgentState,
    allow_runtime_secret_retry: bool,
) -> bool {
    agent_state.has_canonical_pending_action()
        && agent_state.pending_approval.is_none()
        && !allow_runtime_secret_retry
}

fn pending_tool_is_browser_action(agent_state: &AgentState) -> bool {
    let Some(raw) = agent_state.pending_tool_jcs.as_ref() else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(raw) else {
        return false;
    };
    value
        .get("name")
        .and_then(|name| name.as_str())
        .map(|name| name.starts_with("browser__"))
        .unwrap_or(false)
}

pub(super) fn maybe_enable_browser_lease_for_pending_action(
    service: &RuntimeAgentService,
    agent_state: &AgentState,
) {
    if pending_tool_is_browser_action(agent_state) {
        service.browser.set_lease(true);
    }
}

pub(super) async fn maybe_resume_pending_action_or_clear_stale(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    key: &[u8],
    block_height: u64,
    block_timestamp: u64,
    call_context: ServiceCallContext<'_>,
) -> Result<bool, TransactionError> {
    let Some(raw_pending) = agent_state.pending_tool_jcs.as_ref() else {
        return Ok(false);
    };

    let allow_runtime_secret_retry = serde_json::from_slice::<AgentTool>(raw_pending)
        .ok()
        .map(|tool| matches!(tool, AgentTool::SysInstallPackage { .. }))
        .unwrap_or(false);
    if allow_runtime_secret_retry && agent_state.pending_approval.is_none() {
        let session_id_hex = hex::encode(session_id);
        if !runtime_secret::has_secret(&session_id_hex, RUNTIME_SECRET_KIND_SUDO_PASSWORD) {
            if !agent_state.is_waiting_for_sudo_password() {
                log::warn!(
                    "Pending install retry without runtime secret for session {}; forcing pause.",
                    hex::encode(&session_id[..4])
                );
                agent_state.set_pause_reason(AgentPauseReason::WaitingForSudoPassword);
                persist_agent_state(state, key, agent_state, service.memory_runtime.as_ref())?;
            }
            return Ok(true);
        }
    }
    if agent_state.pending_approval.is_some() || allow_runtime_secret_retry {
        log::info!("Resuming canonical pending action.");
        actions::resume_pending_action(
            service,
            state,
            agent_state,
            session_id,
            block_height,
            block_timestamp,
            call_context,
        )
        .await?;
        return Ok(true);
    }
    if should_clear_stale_canonical_pending(agent_state, allow_runtime_secret_retry) {
        log::warn!(
            "Clearing stale canonical pending tool metadata for session {} (missing approval/runtime-secret resume context).",
            hex::encode(&session_id[..4])
        );
        agent_state.clear_pending_action_state();
    }

    Ok(false)
}
