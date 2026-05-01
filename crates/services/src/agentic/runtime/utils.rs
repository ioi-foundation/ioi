// Path: crates/services/src/agentic/runtime/utils.rs

use crate::agentic::runtime::keys::{
    get_parent_playbook_run_key, get_runtime_substrate_key, get_state_key, TRACE_PREFIX,
};
use crate::agentic::runtime::substrate::runtime_substrate_snapshot_for_state;
use crate::agentic::runtime::types::{AgentState, AgentStatus, ParentPlaybookRun};
use ioi_api::state::StateAccess;
use ioi_memory::MemoryRuntime;
use ioi_types::app::agentic::StepTrace;
use ioi_types::app::KernelEvent;
use ioi_types::codec;
use ioi_types::error::TransactionError;

use image::load_from_memory; // [FIX] Added missing import
use image_hasher::{HashAlg, HasherConfig};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const AGENT_STATE_CHECKPOINT_NAME: &str = "desktop.agent_state.v1";
pub const AGENT_RUNTIME_SUBSTRATE_CHECKPOINT_NAME: &str = "desktop.agent_runtime_substrate.v1";

pub fn timestamp_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

pub fn timestamp_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Helper to get a string representation of the agent status for event emission.
fn get_status_str(status: &AgentStatus) -> String {
    format!("{:?}", status)
        .split('(')
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

pub fn compute_phash(image_bytes: &[u8]) -> Result<[u8; 32], TransactionError> {
    let img = load_from_memory(image_bytes)
        .map_err(|e| TransactionError::Invalid(format!("Image decode failed: {}", e)))?;
    let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
    let hash = hasher.hash_image(&img);
    let hash_bytes = hash.as_bytes();

    let mut out = [0u8; 32];
    let len = hash_bytes.len().min(32);
    out[..len].copy_from_slice(&hash_bytes[..len]);
    Ok(out)
}

pub fn persist_agent_state(
    state: &mut dyn StateAccess,
    key: &[u8],
    agent_state: &AgentState,
    memory_runtime: Option<&Arc<MemoryRuntime>>,
) -> Result<(), TransactionError> {
    let bytes = codec::to_bytes_canonical(agent_state)?;
    state.insert(key, &bytes)?;

    let snapshot =
        runtime_substrate_snapshot_for_state(agent_state, ioi_types::app::RuntimeSurface::Api);
    let snapshot_bytes = serde_json::to_vec(&snapshot).map_err(|error| {
        TransactionError::Invalid(format!(
            "Failed to encode runtime substrate snapshot: {}",
            error
        ))
    })?;
    let snapshot_key = get_runtime_substrate_key(&agent_state.session_id, agent_state.step_count);
    state.insert(&snapshot_key, &snapshot_bytes)?;

    if let Some(memory_runtime) = memory_runtime {
        memory_runtime
            .upsert_checkpoint_blob(agent_state.session_id, AGENT_STATE_CHECKPOINT_NAME, &bytes)
            .map_err(|error| {
                TransactionError::Invalid(format!(
                    "Failed to persist agent-state checkpoint: {}",
                    error
                ))
            })?;
        memory_runtime
            .upsert_checkpoint_blob(
                agent_state.session_id,
                AGENT_RUNTIME_SUBSTRATE_CHECKPOINT_NAME,
                &snapshot_bytes,
            )
            .map_err(|error| {
                TransactionError::Invalid(format!(
                    "Failed to persist runtime substrate checkpoint: {}",
                    error
                ))
            })?;
    }

    Ok(())
}

pub fn delete_agent_state_checkpoint(
    memory_runtime: Option<&Arc<MemoryRuntime>>,
    session_id: [u8; 32],
) -> Result<(), TransactionError> {
    let Some(memory_runtime) = memory_runtime else {
        return Ok(());
    };

    memory_runtime
        .delete_checkpoint_blob(session_id, AGENT_STATE_CHECKPOINT_NAME)
        .map_err(|error| {
            TransactionError::Invalid(format!(
                "Failed to delete agent-state checkpoint: {}",
                error
            ))
        })?;
    memory_runtime
        .delete_checkpoint_blob(session_id, AGENT_RUNTIME_SUBSTRATE_CHECKPOINT_NAME)
        .map_err(|error| {
            TransactionError::Invalid(format!(
                "Failed to delete runtime substrate checkpoint: {}",
                error
            ))
        })?;
    Ok(())
}

pub fn load_agent_state_checkpoint(
    memory_runtime: &MemoryRuntime,
    session_id: [u8; 32],
) -> Result<Option<AgentState>, TransactionError> {
    let Some(bytes) = memory_runtime
        .load_checkpoint_blob(session_id, AGENT_STATE_CHECKPOINT_NAME)
        .map_err(|error| {
            TransactionError::Invalid(format!("Failed to load agent-state checkpoint: {}", error))
        })?
    else {
        return Ok(None);
    };

    let agent_state = codec::from_bytes_canonical::<AgentState>(&bytes).map_err(|error| {
        TransactionError::Invalid(format!(
            "Failed to decode agent-state checkpoint: {}",
            error
        ))
    })?;

    if agent_state.session_id != session_id {
        return Err(TransactionError::Invalid(
            "Agent-state checkpoint session mismatch".to_string(),
        ));
    }

    Ok(Some(agent_state))
}

fn agent_state_resolution_priority(status: &AgentStatus) -> u8 {
    match status {
        AgentStatus::Completed(_) | AgentStatus::Failed(_) | AgentStatus::Terminated => 3,
        AgentStatus::Paused(_) => 2,
        AgentStatus::Running | AgentStatus::Idle => 1,
    }
}

fn select_preferred_agent_state(raw_state: AgentState, checkpoint_state: AgentState) -> AgentState {
    let raw_priority = agent_state_resolution_priority(&raw_state.status);
    let checkpoint_priority = agent_state_resolution_priority(&checkpoint_state.status);
    if raw_priority != checkpoint_priority {
        return if raw_priority > checkpoint_priority {
            raw_state
        } else {
            checkpoint_state
        };
    }

    if raw_state.step_count != checkpoint_state.step_count {
        return if raw_state.step_count > checkpoint_state.step_count {
            raw_state
        } else {
            checkpoint_state
        };
    }

    raw_state
}

fn instruction_contract_slot_value<'a>(
    agent_state: &'a AgentState,
    slot_name: &str,
) -> Option<&'a str> {
    agent_state
        .resolved_intent
        .as_ref()?
        .instruction_contract
        .as_ref()?
        .slot_bindings
        .iter()
        .find(|binding| binding.slot.trim().eq_ignore_ascii_case(slot_name))
        .and_then(|binding| binding.value.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn active_parent_playbook_child_session_id(
    state: &dyn StateAccess,
    agent_state: &AgentState,
) -> Option<[u8; 32]> {
    let playbook_id = instruction_contract_slot_value(agent_state, "playbook_id")?;
    let key = get_parent_playbook_run_key(&agent_state.session_id, playbook_id);
    let bytes = state.get(&key).ok().flatten()?;
    let run = codec::from_bytes_canonical::<ParentPlaybookRun>(&bytes).ok()?;
    run.active_child_session_id
}

pub(crate) fn max_steps_completion_blocked_by_active_child(
    state: &dyn StateAccess,
    agent_state: &AgentState,
) -> bool {
    active_parent_playbook_child_session_id(state, agent_state).is_some()
}

pub(crate) fn should_terminalize_running_agent_after_max_steps(
    state: &dyn StateAccess,
    agent_state: &AgentState,
) -> bool {
    agent_state.step_count >= agent_state.max_steps
        && agent_state.status == AgentStatus::Running
        && agent_state.pending_search_completion.is_none()
        && !max_steps_completion_blocked_by_active_child(state, agent_state)
}

pub fn await_child_session_status_for_inspection(
    state: &dyn StateAccess,
    memory_runtime: Option<&Arc<MemoryRuntime>>,
    child_session_id_hex: &str,
) -> Result<String, String> {
    let child_session_id = parse_child_session_id_hex(child_session_id_hex)?;
    let child_state = load_agent_state_with_runtime_preference(
        state,
        memory_runtime,
        child_session_id,
        child_session_id_hex,
    )?;

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

fn load_agent_state_from_state(
    state: &dyn StateAccess,
    session_id: [u8; 32],
    child_session_id_hex: &str,
) -> Result<AgentState, String> {
    let key = get_state_key(&session_id);
    let bytes = state
        .get(&key)
        .map_err(|error| {
            format!(
                "ERROR_CLASS=UnexpectedState Child state lookup failed: {}",
                error
            )
        })?
        .ok_or_else(|| {
            format!(
                "ERROR_CLASS=UnexpectedState Child session '{}' not found.",
                child_session_id_hex
            )
        })?;

    codec::from_bytes_canonical::<AgentState>(&bytes).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to decode child session '{}': {}",
            child_session_id_hex, error
        )
    })
}

fn try_load_agent_state_from_state(
    state: &dyn StateAccess,
    session_id: [u8; 32],
    child_session_id_hex: &str,
) -> Result<Option<AgentState>, String> {
    let key = get_state_key(&session_id);
    if state
        .get(&key)
        .map_err(|error| {
            format!(
                "ERROR_CLASS=UnexpectedState Child state lookup failed: {}",
                error
            )
        })?
        .is_none()
    {
        return Ok(None);
    }

    load_agent_state_from_state(state, session_id, child_session_id_hex).map(Some)
}

pub fn load_agent_state_with_runtime_preference(
    state: &dyn StateAccess,
    memory_runtime: Option<&Arc<MemoryRuntime>>,
    session_id: [u8; 32],
    child_session_id_hex: &str,
) -> Result<AgentState, String> {
    let raw_state = try_load_agent_state_from_state(state, session_id, child_session_id_hex)?;
    let checkpoint_state = if let Some(memory_runtime) = memory_runtime {
        load_agent_state_checkpoint(memory_runtime.as_ref(), session_id).map_err(|error| {
            format!(
                "ERROR_CLASS=UnexpectedState Failed to load child session '{}' from runtime checkpoint: {}",
                child_session_id_hex, error
            )
        })?
    } else {
        None
    };

    match (raw_state, checkpoint_state) {
        (Some(raw_state), Some(checkpoint_state)) => {
            Ok(select_preferred_agent_state(raw_state, checkpoint_state))
        }
        (Some(raw_state), None) => Ok(raw_state),
        (None, Some(checkpoint_state)) => Ok(checkpoint_state),
        (None, None) => Err(format!(
            "ERROR_CLASS=UnexpectedState Child session '{}' not found.",
            child_session_id_hex
        )),
    }
}

fn parse_child_session_id_hex(input: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(input.trim()).map_err(|error| {
        format!(
            "ERROR_CLASS=ToolUnavailable Invalid child_session_id_hex '{}': {}",
            input, error
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

pub fn goto_trace_log(
    agent_state: &mut AgentState,
    state: &mut dyn StateAccess,
    key: &[u8],
    session_id: [u8; 32],
    visual_hash_arr: [u8; 32],
    user_prompt: String,
    output_str: String,
    action_success: bool,
    action_error: Option<String>,
    action_type: String,
    event_sender: Option<tokio::sync::broadcast::Sender<KernelEvent>>,
    skill_hash: Option<[u8; 32]>,
    memory_runtime: Option<&Arc<MemoryRuntime>>,
) -> Result<(), TransactionError> {
    let trace = StepTrace {
        session_id,
        step_index: agent_state.step_count,
        visual_hash: visual_hash_arr,
        full_prompt: user_prompt,
        raw_output: output_str,
        success: action_success,
        error: action_error.clone(),
        cost_incurred: 0,
        fitness_score: None,
        skill_hash,
        timestamp: timestamp_secs_now(),
    };

    let trace_key = [
        TRACE_PREFIX,
        session_id.as_slice(),
        &agent_state.step_count.to_le_bytes(),
    ]
    .concat();
    state.insert(&trace_key, &codec::to_bytes_canonical(&trace)?)?;

    if let Some(tx) = &event_sender {
        let event = KernelEvent::AgentStep(trace.clone());
        let _ = tx.send(event);
    }

    if let Some(_e) = action_error {
        agent_state.consecutive_failures += 1;
    } else {
        agent_state.consecutive_failures = 0;
    }

    agent_state.last_action_type = Some(action_type);

    if should_terminalize_running_agent_after_max_steps(state, agent_state) {
        agent_state.status = AgentStatus::Completed(None);

        if let Some(tx) = &event_sender {
            let _ = tx.send(KernelEvent::AgentActionResult {
                session_id,
                step_index: agent_state.step_count,
                tool_name: "system::max_steps_reached".to_string(),
                output: "Max steps reached. Task completed.".to_string(),
                error_class: None,
                agent_status: get_status_str(&agent_state.status),
            });
        }
    }

    persist_agent_state(state, key, agent_state, memory_runtime)?;
    Ok(())
}

#[cfg(test)]
#[path = "utils/tests.rs"]
mod tests;
