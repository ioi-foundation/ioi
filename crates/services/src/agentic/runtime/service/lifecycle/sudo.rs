use crate::agentic::runtime::keys::get_incident_key;
use crate::agentic::runtime::middleware;
use crate::agentic::runtime::service::recovery::incident::IncidentState;
use crate::agentic::runtime::types::{AgentPauseReason, AgentState, AgentStatus};
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;
use ioi_types::codec;
use ioi_types::error::TransactionError;

pub(super) const RUNTIME_SECRET_KIND_SUDO_PASSWORD: &str = "sudo_password";

fn pending_install_available(agent_state: &AgentState) -> bool {
    agent_state
        .pending_action_state()
        .tool_jcs
        .as_ref()
        .and_then(|raw| serde_json::from_slice::<AgentTool>(raw).ok())
        .map(|tool| matches!(tool, AgentTool::SysInstallPackage { .. }))
        .unwrap_or(false)
}

#[allow(dead_code)]
pub(super) fn is_waiting_for_sudo_password(status: &AgentStatus) -> bool {
    matches!(
        status,
        AgentStatus::Paused(reason)
            if matches!(
                AgentPauseReason::from_message(reason),
                AgentPauseReason::WaitingForSudoPassword
            )
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

    let mut pending = agent_state.pending_action_state();
    pending.tool_jcs = Some(tool_jcs);
    pending.tool_hash = Some(hash_arr);
    if pending.visual_hash.is_none() {
        pending.visual_hash = Some(agent_state.last_screen_phash.unwrap_or([0u8; 32]));
    }
    pending.approval = None;
    agent_state.replace_pending_action_state(pending);
    Ok(true)
}

pub(super) fn maybe_restore_pending_install_from_incident(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    agent_state: &mut AgentState,
) -> Result<(), TransactionError> {
    if pending_install_available(agent_state) {
        return Ok(());
    }

    // A prior approval or recovery pass can leave stale non-install pending metadata
    // behind. Drop it so sudo retry resume can reconstruct the canonical install tool.
    if agent_state.pending_tool_jcs.is_some() {
        let mut pending = agent_state.pending_action_state();
        pending.tool_jcs = None;
        pending.tool_hash = None;
        agent_state.replace_pending_action_state(pending);
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
        .eq_ignore_ascii_case("package__install")
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
    let mut pending = agent_state.pending_action_state();
    pending.tool_jcs = Some(incident.root_tool_jcs);
    pending.tool_hash = Some(hash_arr);
    pending.tool_call = pending
        .tool_jcs
        .as_ref()
        .and_then(|raw| String::from_utf8(raw.clone()).ok());
    if pending.visual_hash.is_none() {
        pending.visual_hash = Some(agent_state.last_screen_phash.unwrap_or([0u8; 32]));
    }
    pending.approval = None;
    agent_state.replace_pending_action_state(pending);
    agent_state.execution_queue.clear();
    Ok(())
}

#[cfg(test)]
#[path = "sudo/tests.rs"]
mod tests;
