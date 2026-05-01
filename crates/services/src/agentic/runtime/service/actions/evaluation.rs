// Path: crates/services/src/agentic/runtime/service/actions/evaluation.rs

use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::AgentState;
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{
    BoundedSelfImprovementGate, IntentContract, OptimizationObjective, OutcomeType,
};
use ioi_types::codec;

pub(crate) fn self_improvement_gate_key(session_id: [u8; 32], trace_hash: [u8; 32]) -> Vec<u8> {
    [
        b"agent::self_improvement_gate::".as_slice(),
        session_id.as_ref(),
        b"::",
        trace_hash.as_ref(),
    ]
    .concat()
}

pub(crate) fn skill_candidate_self_improvement_gate(
    trace_hash: [u8; 32],
    trace_steps: usize,
    score: f32,
    passed_hard_constraints: bool,
) -> BoundedSelfImprovementGate {
    let trace_hash_hex = hex::encode(trace_hash);
    BoundedSelfImprovementGate {
        source_trace_hash: trace_hash_hex.clone(),
        mutation_type: "skill_candidate_from_trace".to_string(),
        allowed_surface: "runtime_optimizer_candidate_only".to_string(),
        validation_slice: format!(
            "single_session_trace_score={score:.3};hard_constraints={passed_hard_constraints};trace_steps={trace_steps}"
        ),
        protected_holdout_summary:
            "not_run_candidate_only;not_prompt_eligible_until_validation_and_holdout".to_string(),
        cross_model_or_profile_regression_check:
            "not_run_candidate_only;required_before_validation_or_promotion".to_string(),
        complexity_budget: "candidate_only_no_authority_expansion_no_prompt_eligibility".to_string(),
        rollback_ref: format!("delete_skill_candidate_for_trace:{trace_hash_hex}"),
        policy_decision: "allow_candidate_only".to_string(),
    }
}

pub(crate) fn gate_allows_candidate_staging(gate: &BoundedSelfImprovementGate) -> bool {
    !gate.source_trace_hash.trim().is_empty()
        && gate.mutation_type == "skill_candidate_from_trace"
        && gate.allowed_surface == "runtime_optimizer_candidate_only"
        && !gate.validation_slice.trim().is_empty()
        && !gate.protected_holdout_summary.trim().is_empty()
        && !gate
            .cross_model_or_profile_regression_check
            .trim()
            .is_empty()
        && !gate.complexity_budget.trim().is_empty()
        && !gate.rollback_ref.trim().is_empty()
        && gate.policy_decision == "allow_candidate_only"
}

pub(crate) fn persist_self_improvement_gate(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    trace_hash: [u8; 32],
    gate: &BoundedSelfImprovementGate,
) -> bool {
    let Ok(bytes) = codec::to_bytes_canonical(gate) else {
        return false;
    };
    state
        .insert(&self_improvement_gate_key(session_id, trace_hash), &bytes)
        .is_ok()
}

pub async fn evaluate_and_crystallize(
    service: &RuntimeAgentService,
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
                    log::info!(
                        "High fitness detected; staging bounded skill candidate pending validation."
                    );

                    let trace_bytes = match codec::to_bytes_canonical(&traces) {
                        Ok(bytes) => bytes,
                        Err(_) => return,
                    };
                    let trace_hash_bytes = sha256(&trace_bytes).unwrap_or([0u8; 32]);
                    let mut trace_hash_arr = [0u8; 32];
                    trace_hash_arr.copy_from_slice(trace_hash_bytes.as_ref());

                    let gate = skill_candidate_self_improvement_gate(
                        trace_hash_arr,
                        traces.len(),
                        report.score,
                        report.passed_hard_constraints,
                    );
                    if !gate_allows_candidate_staging(&gate)
                        || !persist_self_improvement_gate(state, session_id, trace_hash_arr, &gate)
                    {
                        log::warn!(
                            "Self-improvement gate blocked skill candidate staging for session {}",
                            hex::encode(session_id)
                        );
                        return;
                    }

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
                                component: "BoundedSelfImprovementGate".to_string(),
                                status: format!(
                                    "Staged skill candidate '{}' behind validation/holdout gate (Fitness: {:.2}; Promotion: blocked until gate clears)",
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

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::error::StateError;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MemoryState {
        values: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl StateAccess for MemoryState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.values.get(key).cloned())
        }

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.values.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.values.remove(key);
            Ok(())
        }

        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            for (key, value) in updates {
                self.values.insert(key.clone(), value.clone());
            }
            Ok(())
        }

        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            Ok(keys
                .iter()
                .map(|key| self.values.get(key).cloned())
                .collect())
        }

        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            for key in deletes {
                self.values.remove(key);
            }
            for (key, value) in inserts {
                self.values.insert(key.clone(), value.clone());
            }
            Ok(())
        }

        fn prefix_scan(
            &self,
            _prefix: &[u8],
        ) -> Result<ioi_api::state::StateScanIter<'_>, StateError> {
            Ok(Box::new(std::iter::empty()))
        }
    }

    #[test]
    fn skill_candidate_gate_allows_staging_but_not_promotion() {
        let gate = skill_candidate_self_improvement_gate([7; 32], 3, 0.91, true);

        assert!(gate_allows_candidate_staging(&gate));
        assert!(!gate.can_promote());
        assert_eq!(gate.policy_decision, "allow_candidate_only");
        assert!(gate
            .protected_holdout_summary
            .contains("not_prompt_eligible_until_validation"));
    }

    #[test]
    fn skill_candidate_gate_persists_before_candidate_creation() {
        let session_id = [4; 32];
        let trace_hash = [8; 32];
        let gate = skill_candidate_self_improvement_gate(trace_hash, 2, 0.85, true);
        let mut state = MemoryState::default();

        assert!(persist_self_improvement_gate(
            &mut state, session_id, trace_hash, &gate
        ));
        let stored = state
            .get(&self_improvement_gate_key(session_id, trace_hash))
            .expect("state read should work")
            .expect("gate should be stored");
        let decoded: BoundedSelfImprovementGate =
            codec::from_bytes_canonical(&stored).expect("gate should decode");

        assert_eq!(decoded, gate);
    }
}
