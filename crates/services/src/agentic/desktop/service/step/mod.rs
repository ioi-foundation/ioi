// Path: crates/services/src/agentic/desktop/service/step/mod.rs

pub mod helpers;
pub mod visual;
pub mod queue;
pub mod perception;
pub mod cognition;
pub mod action;

use super::DesktopAgentService;
use crate::agentic::desktop::keys::{get_state_key};
use crate::agentic::desktop::types::{AgentState, AgentStatus, StepAgentParams};
use crate::agentic::desktop::utils::{goto_trace_log};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::codec;
use ioi_types::error::TransactionError;
use ioi_types::app::KernelEvent;
use hex;

pub async fn handle_step(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    p: StepAgentParams,
    ctx: &mut TxContext<'_>,
) -> Result<(), TransactionError> {
    // 1. Hydrate State
    let key = get_state_key(&p.session_id);
    let bytes = state
        .get(&key)?
        .ok_or(TransactionError::Invalid("Session not found".into()))?;
    let mut agent_state: AgentState = codec::from_bytes_canonical(&bytes)?;

    // 2. Validate Status
    if agent_state.status != AgentStatus::Running {
        return Err(TransactionError::Invalid(format!("Agent not running: {:?}", agent_state.status)));
    }
    if agent_state.budget == 0 || agent_state.consecutive_failures >= 5 { 
        agent_state.status = AgentStatus::Failed("Resources/Retry limit exceeded".into());
        state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
        return Ok(());
    }

    // 3. Execution Queue (Deterministic Path)
    // If we have macro steps queued up, execute the next one immediately without inference.
    if !agent_state.execution_queue.is_empty() {
        return queue::process_queue_item(service, state, &mut agent_state, &p).await;
    }

    // 4. Resume Pending (Gated Path)
    // [FIX] Clone the pending string immediately to avoid holding an immutable borrow of agent_state
    // while we need a mutable borrow for process_tool_output.
    let pending_tool_call_opt = agent_state.pending_tool_call.clone();

    if let Some(pending) = pending_tool_call_opt {
        log::info!("Resuming pending tool call for session {}", hex::encode(&p.session_id[..4]));
        let phash = agent_state.last_screen_phash.unwrap_or([0u8; 32]);
        
        // Execute the pending action string
        return action::process_tool_output(
            service, 
            state, 
            &mut agent_state, 
            pending, // Already cloned and owned string
            phash,
            "Resumed".to_string(), 
            p.session_id, 
            ctx.block_height
        ).await;
    }

    // --- COGNITIVE LOOP (System 2) ---

    // 5. Perception (Gather Inputs)
    // Screenshots, SoM Overlay, RAG, Tool Discovery
    let perception = perception::gather_context(service, state, &mut agent_state).await?;

    // 6. Cognition (Reasoning & Decision)
    // Construct Prompt -> LLM -> Raw Output
    let cognition_result = cognition::think(service, &agent_state, &perception, p.session_id).await?;

    // 7. Action (Parse & Execute)
    // Normalize -> Policy Check -> Tool Execution -> Trace Logging
    action::process_tool_output(
        service, 
        state, 
        &mut agent_state, 
        cognition_result.raw_output, 
        perception.visual_phash, 
        cognition_result.strategy_used, 
        p.session_id, 
        ctx.block_height
    ).await?;

    // 8. Persist State
    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    Ok(())
}