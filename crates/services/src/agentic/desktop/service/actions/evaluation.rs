// Path: crates/services/src/agentic/desktop/service/actions/evaluation.rs

use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::AgentState;
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{IntentContract, OptimizationObjective, OutcomeType};
use ioi_types::codec;

pub async fn evaluate_and_crystallize(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
) {
    if let Some(eval) = &service.evaluator {
        log::info!("Agent Complete. Running fitness evaluation...");

        let traces = match service.fetch_session_traces(state, session_id) {
            Ok(traces) if !traces.is_empty() => traces,
            _ => return,
        };

        let contract = IntentContract {
            max_price: agent_state.budget + agent_state.tokens_used,
            deadline_epoch: 0,
            min_confidence_score: 80,
            allowed_providers: vec![],
            outcome_type: OutcomeType::Result,
            optimize_for: OptimizationObjective::Reliability,
        };

        if let Ok(report) = eval.evaluate(&traces, &contract).await {
            log::info!(
                "Evaluation Complete. Score: {:.2}. Rationale: {}",
                report.score,
                report.rationale
            );

            if report.score >= 0.8 && report.passed_hard_constraints {
                if let Some(opt) = &service.optimizer {
                    log::info!("High fitness detected! Crystallizing skill...");

                    let trace_bytes = match codec::to_bytes_canonical(&traces) {
                        Ok(bytes) => bytes,
                        Err(_) => return,
                    };
                    let trace_hash_bytes = sha256(&trace_bytes).unwrap_or([0u8; 32]);
                    let mut trace_hash_arr = [0u8; 32];
                    trace_hash_arr.copy_from_slice(trace_hash_bytes.as_ref());

                    if let Ok(skill) = opt
                        .crystallize_skill_internal(
                            state,
                            session_id,
                            trace_hash_arr,
                            Some((&traces, &agent_state.goal)),
                        )
                        .await
                    {
                        if let Some(tx) = &service.event_sender {
                            let _ = tx.send(ioi_types::app::KernelEvent::SystemUpdate {
                                component: "Optimizer".to_string(),
                                status: format!(
                                    "Crystallized skill '{}' (Fitness: {:.2})",
                                    skill.macro_body.definition.name, report.score
                                ),
                            });
                        }
                    }
                }
            }
        }
    }
}
