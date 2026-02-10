// Path: crates/consensus/src/apmft/mod.rs

//! Engine B: Asymptotic Probabilistic Mesh Fault Tolerance (A-PMFT).
//!
//! This engine is activated when the hardware root of trust is shattered.
//! It relies on randomized gossip sampling and statistical finality rather than
//! leader-based deterministic voting.

use crate::{ConsensusDecision, ConsensusEngine, PenaltyEngine, PenaltyMechanism};
use async_trait::async_trait;
use ioi_api::chain::AnchoredStateView;
use ioi_api::commitment::CommitmentScheme;
// [NEW] Import ConsensusControl
use ioi_api::consensus::ConsensusControl;
use ioi_api::state::{StateAccess, StateManager};
use ioi_system::SystemState;
use ioi_types::app::{AccountId, Block, ConsensusVote, FailureReport}; // [FIX] Removed ConfidenceVote
use ioi_types::error::{ConsensusError, TransactionError};
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

mod confidence;
mod vrf;

use self::confidence::ConfidenceTracker;
use self::vrf::Sortition;

#[derive(Debug, Clone)]
pub struct ApmftEngine {
    /// Current sampling round.
    pub current_round: u64,
    /// Cryptographic sortition logic.
    sortition: Arc<Mutex<Sortition>>,
    /// Confidence score tracker.
    confidence: Arc<Mutex<ConfidenceTracker>>,
    /// The preferred tip of this node.
    preferred_tip: [u8; 32],
    /// Samples collected in the current round.
    samples: Vec<[u8; 32]>,
}

impl Default for ApmftEngine {
    fn default() -> Self {
        Self {
            current_round: 0,
            // [FIX] Initialize with dummy key; real key injected via set_key or constructor
            sortition: Arc::new(Mutex::new(Sortition::new(vec![0u8; 32]))),
            confidence: Arc::new(Mutex::new(ConfidenceTracker::new(6))), // Lambda = 6
            preferred_tip: [0u8; 32],
            samples: Vec::new(),
        }
    }
}

impl ApmftEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current preferred tip hash.
    pub fn get_preferred_tip(&self) -> [u8; 32] {
        self.preferred_tip
    }

    /// Returns the current confidence score for the preferred tip.
    /// Uses try_lock to avoid blocking in sync context; returns 0 if contended.
    pub fn get_confidence(&self) -> u32 {
        if let Ok(guard) = self.confidence.try_lock() {
            guard.get_score(&self.preferred_tip)
        } else {
            0
        }
    }

    /// Calculates the weighted median of the collected samples.
    fn calculate_median_tip(&self) -> [u8; 32] {
        if self.samples.is_empty() {
            return self.preferred_tip;
        }

        // Simple plurality voting for MVP.
        // Real implementation requires graph traversal to find common ancestor.
        let mut counts = HashMap::new();
        for hash in &self.samples {
            *counts.entry(*hash).or_insert(0) += 1;
        }

        counts
            .into_iter()
            .max_by_key(|&(_, count)| count)
            .map(|(hash, _)| hash)
            .unwrap_or(self.preferred_tip)
    }

    /// Handles a response from a peer query.
    pub fn handle_sample_response(&mut self, block_hash: [u8; 32]) {
        self.samples.push(block_hash);
    }
}

// [NEW] Implement ConsensusControl for ApmftEngine
impl ConsensusControl for ApmftEngine {
    fn switch_to_apmft(&mut self) {
        // No-op (Already A-PMFT)
    }
    fn switch_to_admft(&mut self) {
        // No-op (Handled by wrapper replacement)
    }
    fn get_apmft_tip(&self) -> Option<([u8; 32], u32)> {
        // Use the internal safe method
        Some((self.preferred_tip, self.get_confidence()))
    }
    fn feed_apmft_sample(&mut self, hash: [u8; 32]) {
        self.handle_sample_response(hash);
    }
}

#[async_trait]
impl PenaltyMechanism for ApmftEngine {
    async fn apply_penalty(
        &self,
        _state: &mut dyn StateAccess,
        _report: &FailureReport,
    ) -> Result<(), TransactionError> {
        // A-PMFT handles penalties via statistical weight reduction
        Ok(())
    }
}

impl PenaltyEngine for ApmftEngine {
    fn apply(
        &self,
        _sys: &mut dyn SystemState,
        _report: &FailureReport,
    ) -> Result<(), TransactionError> {
        Ok(())
    }
}

#[async_trait]
impl<T: Clone + Send + 'static + parity_scale_codec::Encode> ConsensusEngine<T> for ApmftEngine {
    async fn decide(
        &mut self,
        _our_account_id: &AccountId,
        height: u64,
        _view: u64,
        _parent_view: &dyn AnchoredStateView,
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        // [FIX] Prefix unused vars with underscore to suppress warnings
        let _ = height;
        let _ = known_peers;

        // 1. End previous round
        if !self.samples.is_empty() {
            let winner = self.calculate_median_tip();

            // If supermajority (> 2/3), increment confidence
            let support = self.samples.iter().filter(|&&h| h == winner).count();
            if support >= (self.samples.len() * 2 / 3) {
                self.confidence.lock().await.increment(winner);
            }

            // Update preference
            self.preferred_tip = winner;
            self.samples.clear();
            self.current_round += 1;
        }

        // 2. Start new round
        // We rely on the Orchestrator loop (run_sync_discoverer or similar)
        // to poll `get_apmft_tip` and `feed_apmft_sample`.

        ConsensusDecision::Stall
    }

    async fn handle_block_proposal<CS, ST>(
        &mut self,
        _block: Block<T>,
        _chain_view: &dyn ioi_api::chain::ChainView<CS, ST>,
    ) -> Result<(), ConsensusError>
    where
        CS: CommitmentScheme + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        // In A-PMFT, blocks are received via gossip and added to the candidate set
        Ok(())
    }

    async fn handle_vote(&mut self, _vote: ConsensusVote) -> Result<(), ConsensusError> {
        Ok(())
    }

    async fn handle_view_change(
        &mut self,
        _from: PeerId,
        _proof_bytes: &[u8],
    ) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn reset(&mut self, _height: u64) {}
}
