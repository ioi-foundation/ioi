use crate::agentic::desktop::keys::get_state_key;
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use ioi_api::state::StateAccess;
use ioi_types::codec;

pub(super) fn await_child_session_status(
    state: &mut dyn StateAccess,
    child_session_id_hex: &str,
) -> Result<String, String> {
    let child_session_id = parse_session_id_hex(child_session_id_hex)?;
    let key = get_state_key(&child_session_id);
    let bytes = state
        .get(&key)
        .map_err(|e| {
            format!(
                "ERROR_CLASS=UnexpectedState Child state lookup failed: {}",
                e
            )
        })?
        .ok_or_else(|| {
            format!(
                "ERROR_CLASS=UnexpectedState Child session '{}' not found.",
                child_session_id_hex
            )
        })?;

    let child_state: AgentState = codec::from_bytes_canonical(&bytes).map_err(|e| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to decode child session '{}': {}",
            child_session_id_hex, e
        )
    })?;

    match child_state.status {
        AgentStatus::Running | AgentStatus::Idle => Ok("Running".to_string()),
        AgentStatus::Paused(reason) => Ok(format!("Running (paused: {})", reason)),
        AgentStatus::Completed(Some(result)) => Ok(result),
        AgentStatus::Completed(None) => Ok("Completed".to_string()),
        AgentStatus::Failed(reason) => Err(format!(
            "ERROR_CLASS=UnexpectedState Child agent failed: {}",
            reason
        )),
        AgentStatus::Terminated => {
            Err("ERROR_CLASS=UnexpectedState Child agent terminated.".to_string())
        }
    }
}

fn parse_session_id_hex(input: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(input.trim()).map_err(|e| {
        format!(
            "ERROR_CLASS=ToolUnavailable Invalid child_session_id_hex '{}': {}",
            input, e
        )
    })?;
    if bytes.len() != 32 {
        return Err(format!(
            "ERROR_CLASS=ToolUnavailable child_session_id_hex '{}' must be 32 bytes (got {}).",
            input,
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
