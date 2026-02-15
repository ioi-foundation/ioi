// Path: crates/services/src/agentic/desktop/service/step/mod.rs

pub mod action;
pub mod anti_loop;
pub mod cognition;
pub mod helpers;
pub mod incident;
pub mod ontology;
pub mod perception;
pub mod queue;
pub mod visual;

use super::DesktopAgentService;
// [FIX] Import actions module from parent service directory
use crate::agentic::desktop::keys::{get_mutation_receipt_ptr_key, get_state_key};
use crate::agentic::desktop::service::actions;
use crate::agentic::desktop::service::step::anti_loop::choose_routing_tier;
use crate::agentic::desktop::types::{AgentState, AgentStatus, StepAgentParams};
use hex;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_crypto::algorithms::hash::sha256;
use ioi_scs::{FrameType, RetentionClass};
use ioi_types::app::agentic::{AgentTool, StepTrace};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::json;

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
        return Err(TransactionError::Invalid(format!(
            "Agent not running: {:?}",
            agent_state.status
        )));
    }

    // Automated Failure Recovery Loop (Optimizer)
    if agent_state.consecutive_failures >= 3 && agent_state.consecutive_failures < 5 {
        if let Some(optimizer) = &service.optimizer {
            log::warn!(
                "Agent stuck ({} failures). Triggering Optimizer intervention...",
                agent_state.consecutive_failures
            );

            let trace_key = crate::agentic::desktop::keys::get_trace_key(
                &p.session_id,
                agent_state.step_count.saturating_sub(1),
            );

            if let Ok(Some(bytes)) = state.get(&trace_key) {
                if let Ok(last_trace) = codec::from_bytes_canonical::<StepTrace>(&bytes) {
                    match optimizer
                        .synthesize_recovery_skill(p.session_id, &last_trace)
                        .await
                    {
                        Ok(skill) => {
                            log::info!(
                                "Recovery successful. Injected skill: {}",
                                skill.definition.name
                            );

                            let parent_skill_hash = agent_state.active_skill_hash;
                            let skill_bytes = codec::to_bytes_canonical(&skill)?;
                            let skill_hash = sha256(&skill_bytes).map_err(|e| {
                                TransactionError::Invalid(format!("Skill hash failed: {}", e))
                            })?;
                            let mut child_skill_hash = [0u8; 32];
                            child_skill_hash.copy_from_slice(skill_hash.as_ref());
                            agent_state.active_skill_hash = Some(child_skill_hash);
                            agent_state.consecutive_failures = 0;

                            let msg = format!("SYSTEM: I noticed you are stuck. I have synthesized a new tool '{}' to help you. Try using it.", skill.definition.name);
                            let sys_msg = ioi_types::app::agentic::ChatMessage {
                                role: "system".to_string(),
                                content: msg,
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis() as u64,
                                trace_hash: None,
                            };
                            service
                                .append_chat_to_scs(p.session_id, &sys_msg, ctx.block_height)
                                .await?;

                            if let Some(scs_mutex) = &service.scs {
                                let trace_hash = sha256(&codec::to_bytes_canonical(&last_trace)?)
                                    .map_err(|e| {
                                    TransactionError::Invalid(format!("Trace hash failed: {}", e))
                                })?;
                                let mutation_payload = serde_json::to_vec(&json!({
                                    "kind": "MutationReceipt",
                                    "strategy": "Hotfix",
                                    "session_id": hex::encode(p.session_id),
                                    "step_index": agent_state.step_count,
                                    "block_height": ctx.block_height,
                                    "parent_skill_hash": parent_skill_hash.map(hex::encode),
                                    "child_skill_hash": hex::encode(child_skill_hash),
                                    "source_trace_hash": hex::encode(trace_hash),
                                    "rationale": format!(
                                        "Auto-synthesized recovery skill '{}'",
                                        skill.definition.name
                                    ),
                                }))
                                .map_err(|e| TransactionError::Serialization(e.to_string()))?;

                                let mutation_ptr = {
                                    let mut store = scs_mutex.lock().map_err(|_| {
                                        TransactionError::Invalid(
                                            "Internal: SCS lock poisoned".into(),
                                        )
                                    })?;
                                    let frame_id = store
                                        .append_frame(
                                            FrameType::System,
                                            &mutation_payload,
                                            ctx.block_height,
                                            [0u8; 32],
                                            p.session_id,
                                            RetentionClass::Archival,
                                        )
                                        .map_err(|e| {
                                            TransactionError::Invalid(format!(
                                                "Failed to append mutation receipt frame: {}",
                                                e
                                            ))
                                        })?;
                                    let checksum = store
                                        .toc
                                        .frames
                                        .get(frame_id as usize)
                                        .map(|f| f.checksum)
                                        .unwrap_or([0u8; 32]);
                                    format!("scs://mutation-receipt/{}", hex::encode(checksum))
                                };

                                let mutation_ptr_key = get_mutation_receipt_ptr_key(&p.session_id);
                                state.insert(&mutation_ptr_key, mutation_ptr.as_bytes())?;
                            }

                            state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                            return Ok(());
                        }
                        Err(e) => {
                            log::error!("Optimizer failed to synthesize recovery: {}", e);
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

    // [NEW] Browser Lease Management
    if let Some(pending) = &agent_state.pending_tool_call {
        if pending.contains("browser__") {
            service.browser.set_lease(true);
        }
    }

    // 3. Execution Queue
    if !agent_state.execution_queue.is_empty() {
        return queue::process_queue_item(service, state, &mut agent_state, &p, ctx.block_height)
            .await;
    }

    // 4. Resume Pending
    // [FIX] Prioritize canonical JCS resume if available.
    // This ensures we execute EXACTLY what was approved, using the exact visual context.
    if agent_state.pending_tool_jcs.is_some() {
        let allow_runtime_secret_retry = agent_state
            .pending_tool_jcs
            .as_ref()
            .and_then(|raw| serde_json::from_slice::<AgentTool>(raw).ok())
            .map(|tool| matches!(tool, AgentTool::SysInstallPackage { .. }))
            .unwrap_or(false);
        if agent_state.pending_approval.is_some() || allow_runtime_secret_retry {
            log::info!("Resuming canonical pending action.");
            // [FIX] Call resume_pending_action from service::actions module
            return actions::resume_pending_action(
                service,
                state,
                &mut agent_state,
                p.session_id,
                ctx.block_height,
            )
            .await;
        }
        // If JCS exists but no approval, we are still waiting. Stop.
        return Ok(());
    }

    // Legacy Resume (String-based) - Keep for backward compat
    if let Some(pending_json) = agent_state.pending_tool_call.clone() {
        log::info!("Resuming legacy pending tool call string.");
        let phash = agent_state.last_screen_phash.unwrap_or([0u8; 32]);
        return action::process_tool_output(
            service,
            state,
            &mut agent_state,
            pending_json,
            phash,
            "Resumed".to_string(),
            p.session_id,
            ctx.block_height,
        )
        .await;
    }

    // --- COGNITIVE LOOP (System 2) ---

    // 5. Perception
    // [PARITY] Deterministic modality router with failure-class memory.
    let routing_decision = choose_routing_tier(&agent_state);
    let target_tier = routing_decision.tier;
    log::info!(
        "Parity router selected tier={} reason={} source_failure={:?}",
        crate::agentic::desktop::service::step::anti_loop::tier_as_str(target_tier),
        routing_decision.reason_code,
        routing_decision.source_failure
    );

    // Force state update so tools.rs sees correct tier
    agent_state.current_tier = target_tier;

    let perception =
        perception::gather_context(service, state, &mut agent_state, Some(target_tier)).await?;

    // 6. Cognition
    let cognition_result =
        cognition::think(service, &agent_state, &perception, p.session_id).await?;

    // 7. Action
    match action::process_tool_output(
        service,
        state,
        &mut agent_state,
        cognition_result.raw_output,
        perception.visual_phash,
        cognition_result.strategy_used,
        p.session_id,
        ctx.block_height,
    )
    .await
    {
        Ok(_) => {
            // [FIX] Removed buggy trace inspection logic.
            // Tier escalation is now handled atomically inside process_tool_output via the SystemFail check.
        }
        Err(e) => return Err(e),
    }

    // 8. Persist State
    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    Ok(())
}
