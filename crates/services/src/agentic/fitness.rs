// Path: crates/services/src/agentic/fitness.rs

//! The Fitness Function (The Evaluator).
//!
//! This module defines the logic for scoring agent performance.
//! In the context of Recursive Self-Improvement (RSI), this is the "Reward Function"
//! that determines whether a mutation (new agent version) survives or is discarded.
//!
//! It implements the `Evaluator` trait, grading execution traces against
//! the deterministic `IntentContract` rubric.

use async_trait::async_trait;
use ioi_api::vm::inference::{InferenceRuntime, SafetyVerdict};
use ioi_types::app::agentic::{InferenceOptions, StepTrace};
use ioi_types::app::{IntentContract, OutcomeType};
use ioi_types::error::TransactionError;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

// --- Data Structures ---

/// The detailed score report produced by the Evaluator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FitnessReport {
    /// The overall score (0.0 to 1.0).
    pub score: f32,
    /// Whether the agent satisfied the "Must Have" criteria.
    pub passed_hard_constraints: bool,
    /// Detailed reasoning for the score (Chain of Thought).
    pub rationale: String,
    /// Breakdown of scores per rubric dimension.
    pub component_scores: Vec<ComponentScore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentScore {
    pub dimension: String,
    pub score: f32,
    pub comment: String,
}

/// A trait for grading agent execution.
#[async_trait]
pub trait Evaluator: Send + Sync {
    /// Grades a completed execution trace against a rubric.
    async fn evaluate(
        &self,
        trace: &[StepTrace],
        contract: &IntentContract,
    ) -> Result<FitnessReport, TransactionError>;
}

// --- Implementation ---

/// An AI-driven Evaluator that uses a strong reasoning model to grade agents.
pub struct LlmEvaluator {
    runtime: Arc<dyn InferenceRuntime>,
}

impl LlmEvaluator {
    pub fn new(runtime: Arc<dyn InferenceRuntime>) -> Self {
        Self { runtime }
    }

    /// Constructs the evaluation prompt.
    fn build_prompt(&self, trace: &[StepTrace], contract: &IntentContract) -> String {
        // Summarize the trace for the evaluator
        let mut transcript = String::new();
        for step in trace {
            transcript.push_str(&format!(
                "Step {}: {}\nOutput: {}\nSuccess: {}\n---\n",
                step.step_index, step.full_prompt, step.raw_output, step.success
            ));
        }

        // Format the rubric from the IntentContract
        // (Assuming IntentContract has a way to express specific rubrics, or we use a generic one)
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
        
        // Use a deterministic (temp=0) setting for evaluation to ensure fairness.
        let options = InferenceOptions {
            temperature: 0.0,
            ..Default::default()
        };

        // Use a zero-hash for model ID (default model)
        let model_hash = [0u8; 32];

        let response_bytes = self.runtime
            .execute_inference(model_hash, prompt.as_bytes(), options)
            .await
            .map_err(|e| TransactionError::Invalid(format!("Evaluator inference failed: {}", e)))?;

        let response_str = String::from_utf8(response_bytes)
             .map_err(|_| TransactionError::Invalid("Invalid UTF-8 from evaluator".into()))?;

        // Extract JSON
        let json_start = response_str.find('{').unwrap_or(0);
        let json_end = response_str.rfind('}').map(|i| i + 1).unwrap_or(response_str.len());
        let json_str = &response_str[json_start..json_end];

        let report: FitnessReport = serde_json::from_str(json_str)
            .map_err(|e| TransactionError::Invalid(format!("Failed to parse fitness report: {}", e)))?;

        Ok(report)
    }
}

// --- Hard Coded Heuristics (Fallback) ---

/// A simple evaluator that checks basic success/fail and cost metrics.
/// Useful for low-overhead checks or when an LLM is not available.
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

        // Basic Score: Ratio of successful steps + Bonus for finishing
        let base_score = if total_steps > 0 {
            (success_steps as f32) / (total_steps as f32)
        } else {
            0.0
        };
        
        let final_score = if has_final_success {
            (base_score + 1.0) / 2.0 // Boost score if goal achieved
        } else {
            base_score * 0.5 // Penalty if goal not reached
        };

        // Hard Constraint: Did we stay within budget? (Proxy via steps vs max_price)
        // Assuming 1 step ~= 1000 Gas for heuristic
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
                }
            ],
        })
    }
}