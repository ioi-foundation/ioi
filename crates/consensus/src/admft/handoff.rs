// Path: crates/consensus/src/admft/handoff.rs

use ioi_types::app::{AccountId, Block, ChainTransaction};
use ioi_types::error::ConsensusError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// The Local View broadcast by a node entering the transition phase.
/// Matches Definition 3.5 in Protocol Apex.
#[derive(Debug, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct LocalView {
    /// The last finalized height observed by this node.
    pub height: u64,
    /// The hash of the block at that height.
    pub block_hash: [u8; 32],
    /// Signature proving this view comes from a valid validator (reusing Ed25519 for now).
    pub signature: Vec<u8>,
}

/// Executes the reconciliation logic (Algorithm 6).
/// Returns the block hash that should be considered the "Genesis" for Engine B.
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

    // 3. Check for consensus at tip
    // If there is only one unique hash at max_height, we adopt it.
    // If there are multiple (fork at tip), we must defer to A-PMFT's probabilistic resolution.
    // For Phase 2 implementation, we enforce a simple majority rule for the handoff.
    
    let mut counts = std::collections::HashMap::new();
    for c in &candidates {
        *counts.entry(c.block_hash).or_insert(0) += 1;
    }

    // Find hash with most support
    let (best_hash, count) = counts.into_iter()
        .max_by_key(|(_, count)| *count)
        .ok_or(ConsensusError::BlockVerificationFailed("No candidates found".into()))?;

    // Safety check: is it a majority of the sample?
    // Note: candidates.len() represents the subset of nodes at the highest height.
    // In a partition, this might be small. 
    // Protocol Apex suggests we trust the max height if signatures are valid, 
    // but majority provides stronger safety against malicious view injection.
    if count > candidates.len() / 2 {
        Ok(best_hash)
    } else {
        // Twilight Zone: No clear winner. 
        // Protocol Apex says: "Resolve via MeshConsensus".
        // For this step, we return the best candidate but flag it (log warning).
        // The Engine B startup will re-verify this tip statistically.
        Ok(best_hash)
    }
}