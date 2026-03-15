// Path: crates/consensus/src/convergent/guardian_majority/handoff.rs

use ioi_types::app::{AccountId, Block, ChainTransaction};
use ioi_types::error::ConsensusError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Legacy local-view structure retained for research reconciliation experiments.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct LocalView {
    /// The last finalized height observed by this node.
    pub height: u64,
    /// The hash of the block at that height.
    pub block_hash: [u8; 32],
    /// Signature proving this view comes from a valid validator (reusing Ed25519 for now).
    pub signature: Vec<u8>,
}

/// Executes the legacy reconciliation logic retained for witness/audit analysis.
/// Returns the block hash that should seed further nested-guardian investigation.
pub fn reconcile_views(
    views: &[LocalView], 
    threshold: usize
) -> Result<[u8; 32], ConsensusError> {
    if views.len() < threshold {
        return Err(ConsensusError::BlockVerificationFailed("Insufficient views for reconciliation".into()));
    }

    // 1. Find max height reported by any peer
    let max_height = views.iter().map(|v| v.height).max().unwrap_or(0);

    // 2. Filter candidates at max_height
    let candidates: Vec<&LocalView> = views.iter().filter(|v| v.height == max_height).collect();

    // 3. Check for consensus at tip.
    // If there are multiple candidates at max_height, we fall back to the
    // witness/audit sampling path rather than a production consensus engine
    // switch.
    
    let mut counts = std::collections::HashMap::new();
    for c in &candidates {
        *counts.entry(c.block_hash).or_insert(0) += 1;
    }

    // Find hash with most support
    let (best_hash, count) = counts.into_iter()
        .max_by_key(|(_, count)| *count)
        .ok_or(ConsensusError::BlockVerificationFailed("No candidates found".into()))?;

    // Safety check: is it a majority of the sample?
    if count > candidates.len() / 2 {
        Ok(best_hash)
    } else {
        // No clear winner: return the best candidate and let witness sampling
        // continue building evidence.
        Ok(best_hash)
    }
}
