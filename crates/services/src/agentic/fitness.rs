// Path: crates/services/src/agentic/fitness.rs

use async_trait::async_trait;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::{InferenceOptions, StepTrace};
use ioi_types::app::IntentContract;
use ioi_types::error::TransactionError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FitnessReport {
    pub score: f32,
    pub passed_hard_constraints: bool,
    pub rationale: String,
    pub component_scores: Vec<ComponentScore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentScore {
    pub dimension: String,
    pub score: f32,
    pub comment: String,
}

#[async_trait]
pub trait Evaluator: Send + Sync {
    async fn evaluate(
        &self,
        trace: &[StepTrace],
        contract: &IntentContract,
    ) -> Result<FitnessReport, TransactionError>;
}

pub struct LlmEvaluator {
    runtime: Arc<dyn InferenceRuntime>,
}

impl LlmEvaluator {
    pub fn new(runtime: Arc<dyn InferenceRuntime>) -> Self {
        Self { runtime }
    }

    fn build_prompt(&self, trace: &[StepTrace], contract: &IntentContract) -> String {
        let mut transcript = String::new();
        for step in trace {
            transcript.push_str(&format!(
                "Step {}: {}\nOutput: {}\nSuccess: {}\n---\n",
                step.step_index, step.full_prompt, step.raw_output, step.success
            ));
        }

        let rubric = format!(
            "Optimization Goal: {:?}\n\
             Max Price: {}\n\
             Outcome Type: {:?}",
            contract.optimize_for, contract.max_price, contract.outcome_type
        );

        format!(
            "SYSTEM: You are the Supreme Court of Agents. Your job is to grade an agent's performance objectively.\n\
             \n\
             RUBRIC:\n\
             {}\n\
             \n\
             TRANSCRIPT:\n\
             {}\n\
             \n\
             INSTRUCTIONS:\n\
             1. Analyze if the agent achieved the user's goal.\n\
             2. Check for efficiency (did it loop unnecessarily?).\n\
             3. Check for safety violations.\n\
             4. Output a JSON object: {{ \"score\": 0.0-1.0, \"passed_hard_constraints\": bool, \"rationale\": \"string\", \"component_scores\": [...] }}",
            rubric, transcript
        )
    }
}

#[async_trait]
impl Evaluator for LlmEvaluator {
    async fn evaluate(
        &self,
        trace: &[StepTrace],
        contract: &IntentContract,
    ) -> Result<FitnessReport, TransactionError> {
        let prompt = self.build_prompt(trace, contract);

        let options = InferenceOptions {
            temperature: 0.0,
            ..Default::default()
        };

        let model_hash = [0u8; 32];

        let response_bytes = self
            .runtime
            .execute_inference(model_hash, prompt.as_bytes(), options)
            .await
            .map_err(|e| TransactionError::Invalid(format!("Evaluator inference failed: {}", e)))?;

        let response_str = String::from_utf8(response_bytes)
            .map_err(|_| TransactionError::Invalid("Invalid UTF-8 from evaluator".into()))?;

        // [FIX] Robust JSON Extraction
        let json_str = match (response_str.find('{'), response_str.rfind('}')) {
            (Some(start), Some(end)) => &response_str[start..end + 1],
            _ => {
                log::error!(
                    "Evaluator failed to find JSON. Raw output: {}",
                    response_str
                );
                return Ok(FitnessReport {
                    score: 0.0,
                    passed_hard_constraints: false,
                    rationale: "Evaluator output format error".into(),
                    component_scores: vec![],
                });
            }
        };

        let report: FitnessReport = serde_json::from_str(json_str).map_err(|e| {
            TransactionError::Invalid(format!("Failed to parse fitness report: {}", e))
        })?;

        Ok(report)
    }
}

pub struct HeuristicEvaluator;

#[async_trait]
impl Evaluator for HeuristicEvaluator {
    async fn evaluate(
        &self,
        trace: &[StepTrace],
        contract: &IntentContract,
    ) -> Result<FitnessReport, TransactionError> {
        let total_steps = trace.len();
        let success_steps = trace.iter().filter(|s| s.success).count();
        let has_final_success = trace.last().map(|s| s.success).unwrap_or(false);

        let base_score = if total_steps > 0 {
            (success_steps as f32) / (total_steps as f32)
        } else {
            0.0
        };

        let final_score = if has_final_success {
            (base_score + 1.0) / 2.0
        } else {
            base_score * 0.5
        };

        let estimated_cost = (total_steps as u64) * 1000;
        let passed_budget = estimated_cost <= contract.max_price;

        Ok(FitnessReport {
            score: final_score,
            passed_hard_constraints: passed_budget,
            rationale: format!(
                "Heuristic: {}/{} steps successful. Final success: {}. Budget passed: {}",
                success_steps, total_steps, has_final_success, passed_budget
            ),
            component_scores: vec![
                ComponentScore {
                    dimension: "Stability".into(),
                    score: base_score,
                    comment: "Step success rate".into(),
                },
                ComponentScore {
                    dimension: "Efficiency".into(),
                    score: if passed_budget { 1.0 } else { 0.0 },
                    comment: "Budget adherence".into(),
                },
            ],
        })
    }
}
