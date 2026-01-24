// Path: crates/types/src/app/evolution.rs

//! Core data structures for Recursive Self-Improvement (RSI) and Evolutionary Dynamics.
//!
//! This module defines the primitives required to track the "Biology" of software:
//! Lineage (Genealogy), Mutation (Changes), and Fitness (Scoring).
//! These types are used by the `OptimizerService`, `GovernanceModule`, and `Autopilot`
//! to visualize and enforce the evolutionary cycle.

use crate::app::AccountId;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Defines the strategy an agent uses to improve itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum OptimizationStrategy {
    /// Rewriting the System Prompt (Instruction Tuning).
    PromptRefinement,
    /// Adding/Removing Tools from the Manifest (Capability Search).
    ToolSelection,
    /// Adjusting scalar parameters like temperature, top_p, or budget (Hyperparameter Tuning).
    HyperparameterTuning,
    /// Rewriting the underlying Python/WASM logic (Code Mutation).
    CodeMutation,
    /// A combination or unspecified strategy.
    Hybrid,
}

/// A receipt proving that a mutation occurred and was verified.
/// This acts as the "Birth Certificate" for a new agent version.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct MutationReceipt {
    /// The unique ID of the parent agent (the version being improved).
    pub parent_hash: [u8; 32],
    
    /// The unique ID of the new agent (the child).
    pub child_hash: [u8; 32],
    
    /// The generation number (Parent Gen + 1).
    pub generation: u64,
    
    /// The specific strategy used for this mutation.
    pub strategy: OptimizationStrategy,
    
    /// A digest or diff of the change (e.g. "Prompt updated to handle CSV edge cases").
    /// This is the "Genotype" diff.
    pub diff_summary: String,
    
    /// The Chain of Thought (Rationale) from the Optimizer explaining *why* this change improves fitness.
    pub rationale: String,
    
    /// The fitness score achieved in the sandbox test before deployment (0.0 - 1.0).
    pub pre_deployment_fitness: f32,
    
    /// The block height where this mutation was committed.
    pub block_height: u64,
}

/// Represents a node in the agent's genealogical tree.
/// Used by the UI (Autopilot) to visualize the "DNA" tab.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct LineageNode {
    /// The hash of this agent version.
    pub manifest_hash: [u8; 32],
    
    /// The generation number.
    pub generation: u64,
    
    /// The parent's hash (None for Genesis/Root agents).
    pub parent_hash: Option<[u8; 32]>,
    
    /// Aggregate fitness score in production (moving average).
    pub live_fitness_score: f32,
    
    /// Total Labor Gas earned by this version (Economic Fitness).
    pub total_earnings: u128,
    
    /// Number of successful tasks completed.
    pub tasks_completed: u64,
    
    /// Status of this lineage branch.
    pub status: LineageStatus,
}

/// The lifecycle status of a specific agent version in the evolutionary tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum LineageStatus {
    /// Active and accepting new tasks.
    Active,
    /// Deprecated (replaced by a fitter child), but still readable.
    Deprecated,
    /// Extinct (failed to survive; bankrupt or buggy).
    Extinct,
    /// Candidate (in sandbox, not yet deployed).
    Candidate,
}

/// A request to the Optimizer to improve a specific agent.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct EvolutionRequest {
    /// The agent to improve.
    pub target_agent_id: AccountId,
    
    /// The specific failure trace to learn from (optional).
    /// If None, the Optimizer effectively "daydreams" or explores random mutations.
    pub feedback_trace_id: Option<[u8; 32]>,
    
    /// The maximum budget allowed for the mutation process (Evolution Fee).
    pub evolution_budget: u64,
}

// Implement default for LineageNode to simplify initialization
impl Default for LineageNode {
    fn default() -> Self {
        Self {
            manifest_hash: [0u8; 32],
            generation: 0,
            parent_hash: None,
            live_fitness_score: 0.0,
            total_earnings: 0,
            tasks_completed: 0,
            status: LineageStatus::Candidate,
        }
    }
}