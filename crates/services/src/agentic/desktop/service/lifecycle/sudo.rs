use crate::agentic::desktop::keys::get_incident_key;
use crate::agentic::desktop::middleware;
use crate::agentic::desktop::service::step::incident::IncidentState;
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;
use ioi_types::codec;
use ioi_types::error::TransactionError;

pub(super) const RUNTIME_SECRET_KIND_SUDO_PASSWORD: &str = "sudo_password";

pub(super) fn is_waiting_for_sudo_password(status: &AgentStatus) -> bool {
    matches!(
        status,
        AgentStatus::Paused(reason) if reason.eq_ignore_ascii_case("Waiting for sudo password")
    )
}

pub(super) fn status_mentions_sudo_password(status: &AgentStatus) -> bool {
    match status {
        AgentStatus::Paused(reason) | AgentStatus::Failed(reason) => {
            let lower = reason.to_ascii_lowercase();
            lower.contains("sudo password") || lower.contains("administrative privileges")
        }
        _ => false,
    }
}

pub(super) fn incident_waiting_for_sudo_password(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
) -> Result<bool, TransactionError> {
    let incident_key = get_incident_key(&session_id);
    let Some(incident_bytes) = state.get(&incident_key)? else {
        return Ok(false);
    };
    let incident: IncidentState = codec::from_bytes_canonical(&incident_bytes)?;
    Ok(incident
        .resolution_action
        .eq_ignore_ascii_case("wait_for_sudo_password"))
}

fn restore_pending_install_from_tool_call(
    agent_state: &mut AgentState,
) -> Result<bool, TransactionError> {
    if agent_state.pending_tool_jcs.is_some() {
        return Ok(true);
    }
    let Some(raw) = agent_state.pending_tool_call.as_deref() else {
        return Ok(false);
    };
    let parsed = match middleware::normalize_tool_call(raw) {
        Ok(tool) => tool,
        Err(_) => return Ok(false),
    };
    if !matches!(parsed, AgentTool::SysInstallPackage { .. }) {
        return Ok(false);
    }

    let tool_jcs = serde_jcs::to_vec(&parsed).map_err(|e| {
        TransactionError::Serialization(format!("Failed to encode pending install tool: {}", e))
    })?;
    let hash_bytes = sha256(&tool_jcs).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(hash_bytes.as_ref());

    agent_state.pending_tool_jcs = Some(tool_jcs);
    agent_state.pending_tool_hash = Some(hash_arr);
    if agent_state.pending_visual_hash.is_none() {
        agent_state.pending_visual_hash = Some(agent_state.last_screen_phash.unwrap_or([0u8; 32]));
    }
    agent_state.pending_approval = None;
    Ok(true)
}

pub(super) fn maybe_restore_pending_install_from_incident(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    agent_state: &mut AgentState,
) -> Result<(), TransactionError> {
    if agent_state.pending_tool_jcs.is_some() {
        return Ok(());
    }

    if restore_pending_install_from_tool_call(agent_state)? {
        return Ok(());
    }

    let incident_key = get_incident_key(&session_id);
    let Some(incident_bytes) = state.get(&incident_key)? else {
        return Ok(());
    };
    let incident: IncidentState = codec::from_bytes_canonical(&incident_bytes)?;
    let waiting_for_sudo = incident
        .resolution_action
        .eq_ignore_ascii_case("wait_for_sudo_password");
    let is_install_root = incident
        .root_tool_name
        .eq_ignore_ascii_case("sys__install_package")
        || incident
            .root_tool_name
            .eq_ignore_ascii_case("sys::install_package")
        || incident.root_tool_name.ends_with("install_package");
    if !waiting_for_sudo || !is_install_root || incident.root_tool_jcs.is_empty() {
        return Ok(());
    }

    let hash_bytes =
        sha256(&incident.root_tool_jcs).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(hash_bytes.as_ref());
    agent_state.pending_tool_jcs = Some(incident.root_tool_jcs);
    agent_state.pending_tool_hash = Some(hash_arr);
    agent_state.pending_approval = None;
    agent_state.execution_queue.clear();
    Ok(())
}
