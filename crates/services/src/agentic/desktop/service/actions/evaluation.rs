// Path: crates/services/src/agentic/desktop/service/actions/evaluation.rs

use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::AgentState;
use crate::agentic::fitness::Evaluator;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::StepTrace;
use ioi_types::app::{IntentContract, OptimizationObjective, OutcomeType};
// [FIX] Change import to dcrypt
use dcrypt::algorithms::ByteSerializable;

pub async fn evaluate_and_crystallize(
    service: &DesktopAgentService,
    agent_state: &AgentState,
    session_id: [u8; 32],
    result: &str,
) {
    if let Some(eval) = &service.evaluator {
        log::info!("Agent Complete. Running fitness evaluation...");

        let history = service
            .hydrate_session_history(session_id)
            .unwrap_or_default();
        let reconstructed_trace: Vec<StepTrace> = history
            .iter()
            .enumerate()
            .map(|(i, msg)| StepTrace {
                session_id: session_id,
                step_index: i as u32,
                visual_hash: [0; 32],
                full_prompt: format!("{}: {}", msg.role, msg.content),
                raw_output: msg.content.clone(),
                success: true,
                error: None,
                cost_incurred: 0,
                fitness_score: None,
                skill_hash: None,
                timestamp: msg.timestamp / 1000,
            })
            .collect();

        let contract = IntentContract {
            max_price: agent_state.budget + agent_state.tokens_used,
            deadline_epoch: 0,
            min_confidence_score: 80,
            allowed_providers: vec![],
            outcome_type: OutcomeType::Result,
            optimize_for: OptimizationObjective::Reliability,
        };

        if let Ok(report) = eval.evaluate(&reconstructed_trace, &contract).await {
            log::info!(
                "Evaluation Complete. Score: {:.2}. Rationale: {}",
                report.score,
                report.rationale
            );

            if report.score >= 0.8 && report.passed_hard_constraints {
                if let Some(opt) = &service.optimizer {
                    log::info!("High fitness detected! Crystallizing skill...");

                    let trace_hash_bytes = sha256(result.as_bytes()).unwrap_or([0u8; 32]);
                    let mut trace_hash_arr = [0u8; 32];
                    trace_hash_arr.copy_from_slice(trace_hash_bytes.as_ref());

                    if let Ok(skill) = opt
                        .crystallize_skill_internal(session_id, trace_hash_arr, None)
                        .await
                    {
                        if let Some(tx) = &service.event_sender {
                            let _ = tx.send(ioi_types::app::KernelEvent::SystemUpdate {
                                component: "Optimizer".to_string(),
                                status: format!(
                                    "Crystallized skill '{}' (Fitness: {:.2})",
                                    skill.definition.name, report.score
                                ),
                            });
                        }
                    }
                }
            }
        }
    }
}
