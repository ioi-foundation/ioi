use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use crate::agentic::desktop::utils::{goto_trace_log, persist_agent_state};
use ioi_api::state::StateAccess;
use ioi_types::codec;
use ioi_types::error::TransactionError;

pub(super) async fn handle_refusal(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    key: &[u8],
    session_id: [u8; 32],
    visual_phash: [u8; 32],
    reason: &str,
) -> Result<(), TransactionError> {
    log::warn!("Agent Refusal Intercepted: {}", reason);
    goto_trace_log(
        agent_state,
        state,
        key,
        session_id,
        visual_phash,
        "[Refusal Intercepted]".to_string(),
        reason.to_string(),
        true,
        None,
        "system::refusal".to_string(),
        service.event_sender.clone(),
        None,
        service.memory_runtime.as_ref(),
    )?;
    agent_state.step_count += 1;
    agent_state.status = AgentStatus::Paused(format!("Model Refusal: {}", reason));
    agent_state.consecutive_failures = 0;
    persist_agent_state(state, key, agent_state, service.memory_runtime.as_ref())?;
    Ok(())
}

pub(super) async fn evaluate_and_crystallize(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
) {
    if let Some(eval) = &service.evaluator {
        let traces = match service.fetch_session_traces(state, session_id) {
            Ok(traces) if !traces.is_empty() => traces,
            _ => return,
        };

        let contract = ioi_types::app::IntentContract {
            max_price: agent_state.budget + agent_state.tokens_used,
            deadline_epoch: 0,
            min_confidence_score: 80,
            allowed_providers: vec![],
            outcome_type: ioi_types::app::OutcomeType::Result,
            optimize_for: ioi_types::app::OptimizationObjective::Reliability,
        };

        if let Ok(report) = eval.evaluate(&traces, &contract).await {
            if report.score >= 0.8 && report.passed_hard_constraints {
                if let Some(opt) = &service.optimizer {
                    let trace_bytes = match codec::to_bytes_canonical(&traces) {
                        Ok(bytes) => bytes,
                        Err(_) => return,
                    };
                    let trace_hash_bytes =
                        ioi_crypto::algorithms::hash::sha256(&trace_bytes).unwrap_or([0u8; 32]);
                    let mut trace_hash_arr = [0u8; 32];
                    trace_hash_arr.copy_from_slice(trace_hash_bytes.as_ref());
                    let _ = opt
                        .crystallize_skill_internal(
                            state,
                            session_id,
                            trace_hash_arr,
                            Some((&traces, &agent_state.goal)),
                        )
                        .await;
                }
            }
        }
    }
}
