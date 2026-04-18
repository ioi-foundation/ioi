use super::super::compaction::perform_cognitive_compaction;
use crate::agentic::runtime::keys::{get_incident_key, get_remediation_key, get_state_key};
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::SessionSummary;
use crate::agentic::runtime::utils::delete_agent_state_checkpoint;
use ioi_api::state::StateAccess;
use ioi_types::codec;
use ioi_types::error::TransactionError;

pub async fn handle_delete_session(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    session_id_bytes: &[u8],
) -> Result<(), TransactionError> {
    let session_id: [u8; 32] = session_id_bytes
        .try_into()
        .map_err(|_| TransactionError::Invalid("Invalid session ID".into()))?;

    let state_key = get_state_key(&session_id);
    state.delete(&state_key)?;
    if let Err(error) = delete_agent_state_checkpoint(service.memory_runtime.as_ref(), session_id) {
        log::warn!(
            "Failed to delete agent-state checkpoint for session {}: {}",
            hex::encode(&session_id[..4]),
            error
        );
    }
    let remediation_key = get_remediation_key(&session_id);
    state.delete(&remediation_key)?;
    let incident_key = get_incident_key(&session_id);
    state.delete(&incident_key)?;

    let history_key = b"agent::history".to_vec();
    if let Some(bytes) = state.get(&history_key)? {
        let mut history: Vec<SessionSummary> = codec::from_bytes_canonical(&bytes)?;

        let len_before = history.len();
        history.retain(|s| s.session_id != session_id);

        if history.len() < len_before {
            state.insert(&history_key, &codec::to_bytes_canonical(&history)?)?;
        }
    }

    if let Err(e) = perform_cognitive_compaction(service, session_id).await {
        log::warn!("Cognitive Compaction failed during session delete: {}", e);
    }

    log::info!("Deleted/Terminated session {}", hex::encode(session_id));
    Ok(())
}
