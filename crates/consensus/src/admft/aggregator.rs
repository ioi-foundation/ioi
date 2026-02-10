// Path: crates/consensus/src/admft/aggregator.rs

//! Aggregates individual consensus votes into a compact Quorum Certificate.
//! This module handles the BLS signature aggregation logic for Phase 2 scalability.

use ioi_types::app::{AccountId, ConsensusVote, QuorumCertificate};
// Use crypto crate for BLS operations (assumed available in Phase 2)
// For Phase 1 compatibility, we might fallback to vector collection.
// We'll prepare the structure for both.

use std::collections::HashMap; // [FIX] Removed HashSet

/// Aggregates votes for a specific block hash.
#[derive(Debug, Clone, Default)]
pub struct VoteAggregator {
    /// The height this aggregator is targeting.
    pub height: u64,
    /// The view this aggregator is targeting.
    pub view: u64,
    /// The block hash being voted on.
    pub block_hash: [u8; 32],

    /// Map of Voter ID -> Signature.
    pub votes: HashMap<AccountId, Vec<u8>>,

    /// Total weight accumulated so far.
    pub accumulated_weight: u128,
}

impl VoteAggregator {
    pub fn new(height: u64, view: u64, block_hash: [u8; 32]) -> Self {
        Self {
            height,
            view,
            block_hash,
            votes: HashMap::new(),
            accumulated_weight: 0,
        }
    }

    /// Adds a vote to the aggregation.
    /// Returns true if the vote was new (not a duplicate).
    pub fn add_vote(&mut self, vote: &ConsensusVote, weight: u128) -> bool {
        if vote.height != self.height
            || vote.view != self.view
            || vote.block_hash != self.block_hash
        {
            return false;
        }

        if self.votes.contains_key(&vote.voter) {
            return false;
        }

        self.votes.insert(vote.voter, vote.signature.clone());
        self.accumulated_weight += weight;
        true
    }

    /// Checks if the quorum threshold has been met.
    pub fn is_quorum_reached(&self, total_weight: u128) -> bool {
        // A-DMFT Quorum: > 1/2 for liveness with Guardian, or > 2/3 for BFT.
        // We use > 2/3 (67%) for standard BFT safety.
        let threshold = (total_weight * 2) / 3;
        self.accumulated_weight > threshold
    }

    /// Constructs the Quorum Certificate.
    ///
    /// In Phase 1 (Ed25519), this returns a list of individual signatures.
    /// In Phase 2 (BLS), this will perform signature aggregation.
    pub fn build_qc(&self) -> QuorumCertificate {
        // For now, we just collect the list.
        // BLS Aggregation logic would go here:
        // 1. Sort voters by ID (canonical bitfield order).
        // 2. Aggregate signatures using ioi_crypto::sign::bls::aggregate_signatures.
        // 3. Construct signers_bitfield.

        let signatures: Vec<(AccountId, Vec<u8>)> =
            self.votes.iter().map(|(k, v)| (*k, v.clone())).collect();

        QuorumCertificate {
            height: self.height,
            view: self.view,
            block_hash: self.block_hash,
            signatures,
            aggregated_signature: vec![], // Empty for Phase 1
            signers_bitfield: vec![],     // Empty for Phase 1
        }
    }
}
