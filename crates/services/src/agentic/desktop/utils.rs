// Path: crates/services/src/agentic/desktop/utils.rs

use crate::agentic::desktop::keys::TRACE_PREFIX;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::StepTrace;
use ioi_types::app::KernelEvent;
use ioi_types::codec;
use ioi_types::error::TransactionError;

// [FIX] Removed unused import
use image::load_from_memory;
use image_hasher::{HashAlg, HasherConfig};
use std::time::{SystemTime, UNIX_EPOCH};
use dcrypt::algorithms::ByteSerializable;

use super::types::{AgentState, AgentStatus};

pub fn compute_phash(image_bytes: &[u8]) -> Result<[u8; 32], TransactionError> {
    let img = load_from_memory(image_bytes)
        .map_err(|e| TransactionError::Invalid(format!("Image decode failed: {}", e)))?;
    let hasher = HasherConfig::new()
        .hash_alg(HashAlg::Gradient)
        .to_hasher();
    let hash = hasher.hash_image(&img);
    let hash_bytes = hash.as_bytes();

    let mut out = [0u8; 32];
    let len = hash_bytes.len().min(32);
    out[..len].copy_from_slice(&hash_bytes[..len]);
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
) -> Result<(), TransactionError> {
    let trace = StepTrace {
        session_id,
        step_index: agent_state.step_count,
        visual_hash: visual_hash_arr,
        full_prompt: user_prompt,
        raw_output: output_str,
        success: action_success,
        error: action_error.clone(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    
    let trace_key = [TRACE_PREFIX, session_id.as_slice(), &agent_state.step_count.to_le_bytes()].concat();
    state.insert(&trace_key, &codec::to_bytes_canonical(&trace)?)?;

    if let Some(tx) = &event_sender {
        let event = KernelEvent::AgentStep(trace.clone());
        match tx.send(event) {
            Ok(count) => log::info!(target: "agent_driver", "Emitted AgentStep event to {} subscribers. Step: {}", count, trace.step_index),
            Err(_) => log::warn!(target: "agent_driver", "Failed to emit AgentStep event (no subscribers)"),
        }
    }

    if let Some(e) = action_error {
        agent_state.consecutive_failures += 1;
        agent_state.history.push(format!("System: Action Failed: {}", e));
    } else {
        agent_state.consecutive_failures = 0;
    }

    agent_state.step_count += 1;
    agent_state.last_action_type = Some(action_type);

    if agent_state.step_count >= agent_state.max_steps && agent_state.status == AgentStatus::Running {
        agent_state.status = AgentStatus::Completed(None);
        
        // [FIX] Emit completion event so UI knows to stop when max steps reached
        if let Some(tx) = &event_sender {
             let _ = tx.send(KernelEvent::AgentActionResult {
                 session_id,
                 step_index: agent_state.step_count,
                 tool_name: "system::max_steps_reached".to_string(),
                 output: "Max steps reached. Task completed.".to_string(),
             });
        }
    }

    state.insert(key, &codec::to_bytes_canonical(&agent_state)?)?;
    Ok(())
}