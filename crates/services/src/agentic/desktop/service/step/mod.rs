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
use ioi_types::app::agentic::StepTrace; // [FIX] Added import
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
    
    // [NEW] Automated Failure Recovery Loop
    // If failures hit a threshold (3), attempt to synthesize a fix before giving up (at 5).
    if agent_state.consecutive_failures >= 3 && agent_state.consecutive_failures < 5 {
        if let Some(optimizer) = &service.optimizer {
            log::warn!("Agent stuck ({} failures). Triggering Optimizer intervention...", agent_state.consecutive_failures);
            
            // Fetch the trace of the LAST step (which presumably failed)
            let trace_key = crate::agentic::desktop::keys::get_trace_key(&p.session_id, agent_state.step_count.saturating_sub(1));
            
            if let Ok(Some(bytes)) = state.get(&trace_key) {
                if let Ok(last_trace) = codec::from_bytes_canonical::<StepTrace>(&bytes) {
                     match optimizer.synthesize_recovery_skill(p.session_id, &last_trace).await {
                         Ok(skill) => {
                             log::info!("Recovery successful. Injected skill: {}", skill.definition.name);
                             
                             // Reset failure counter to give the agent a fresh chance with the new skill
                             agent_state.consecutive_failures = 0;
                             
                             // Append system message informing the agent of the new capability
                             let msg = format!("SYSTEM: I noticed you are stuck. I have synthesized a new tool '{}' to help you. Try using it.", skill.definition.name);
                             let sys_msg = ioi_types::app::agentic::ChatMessage {
                                role: "system".to_string(),
                                content: msg,
                                timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
                                trace_hash: None,
                            };
                            service.append_chat_to_scs(p.session_id, &sys_msg, ctx.block_height).await?;
                            
                            // Save state and return early to let the agent re-plan in the next tick
                            state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                            return Ok(());
                         },
                         Err(e) => {
                             log::error!("Optimizer failed to synthesize recovery: {}", e);
                             // If recovery fails, fall through to the standard failure logic below.
                         }
                     }
                }
            }
        }
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