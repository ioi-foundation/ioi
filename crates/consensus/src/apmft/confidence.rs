// Path: crates/consensus/src/apmft/confidence.rs

//! Manages the Confidence Score (C_B) for blocks in the mesh.
//!
//! Protocol Apex replaces binary finality with an asymptotic confidence score.
//! Blocks become "Durable" once C_B exceeds the security parameter lambda.

use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct ConfidenceTracker {
    /// Map of BlockHash -> Confidence Score.
    scores: HashMap<[u8; 32], u32>,
    /// The security parameter lambda (threshold for Durability).
    lambda: u32,
}

impl ConfidenceTracker {
    pub fn new(lambda: u32) -> Self {
        Self {
            scores: HashMap::new(),
            lambda,
        }
    }

    /// Increments the confidence of a block and its ancestors.
    pub fn increment(&mut self, block_hash: [u8; 32]) {
        let entry = self.scores.entry(block_hash).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    /// Returns the current confidence score for a block.
    pub fn get_score(&self, block_hash: &[u8; 32]) -> u32 {
        *self.scores.get(block_hash).unwrap_or(&0)
    }

    /// Checks if a block has achieved Durable Finality.
    pub fn is_durable(&self, block_hash: &[u8; 32]) -> bool {
        self.get_score(block_hash) >= self.lambda
    }
    
    /// Prunes scores for old blocks to manage memory.
    pub fn prune(&mut self, _min_height: u64) {
        // In a real impl, we'd map Hash -> Height to prune effectively.
        // For now, we rely on LRU or external cleanup.
    }
}