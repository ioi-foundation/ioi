// crates/consensus/src/solo/mod.rs

use crate::{ConsensusDecision, ConsensusEngine, PenaltyEngine, PenaltyMechanism};
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, ChainView};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::ConsensusControl; // [NEW] Import trait
use ioi_api::state::{StateAccess, StateManager};
use ioi_system::SystemState;
use ioi_types::app::{AccountId, Block, ChainStatus, FailureReport, ConsensusVote, QuorumCertificate};
use ioi_types::codec;
use ioi_types::error::{ConsensusError, TransactionError};
use ioi_types::keys::STATUS_KEY;
use libp2p::PeerId;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

/// A consensus engine for local/solo mode.
/// It always decides to produce a block immediately, acting as a single dictator.
#[derive(Debug, Clone, Default)]
pub struct SoloEngine;

impl SoloEngine {
    pub fn new() -> Self {
        Self
    }
}

// [NEW] Implement ConsensusControl for SoloEngine
impl ConsensusControl for SoloEngine {
    fn switch_to_apmft(&mut self) {
        // No-op for Solo mode (no hardware failure possible in local dev)
    }
    fn switch_to_admft(&mut self) {
        // No-op
    }
    fn get_apmft_tip(&self) -> Option<([u8; 32], u32)> {
        None
    }
    fn feed_apmft_sample(&mut self, _hash: [u8; 32]) {
        // No-op
    }
}

#[async_trait]
impl PenaltyMechanism for SoloEngine {
    async fn apply_penalty(
        &self,
        _state: &mut dyn StateAccess,
        _report: &FailureReport,
    ) -> Result<(), TransactionError> {
        // In local mode, the user owns the node; no penalties are applied.
        Ok(())
    }
}

impl PenaltyEngine for SoloEngine {
    fn apply(
        &self,
        _sys: &mut dyn SystemState,
        _report: &FailureReport,
    ) -> Result<(), TransactionError> {
        Ok(())
    }
}

#[async_trait]
impl<T: Clone + Send + 'static + parity_scale_codec::Encode> ConsensusEngine<T> for SoloEngine {
    async fn decide(
        &mut self,
        _our_account_id: &AccountId,
        _height: u64,
        view: u64,
        parent_view: &dyn AnchoredStateView,
        _known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        // Retrieve parent timestamp to ensure strict monotonicity
        let parent_ts = match parent_view.get(STATUS_KEY).await {
            Ok(Some(b)) => {
                if let Ok(status) = codec::from_bytes_canonical::<ChainStatus>(&b) {
                    status.latest_timestamp
                } else {
                    0
                }
            }
            _ => 0,
        };

        // Use system time, but force it to be at least parent + 1s
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let expected_timestamp_secs = std::cmp::max(now, parent_ts + 1);

        ConsensusDecision::ProduceBlock {
            transactions: vec![], // Transactions are injected by the Orchestrator mempool logic
            expected_timestamp_secs,
            view,
            parent_qc: QuorumCertificate::default(), // <--- Populate default
        }
    }

    async fn handle_block_proposal<CS, ST>(
        &mut self,
        _block: Block<T>,
        _chain_view: &dyn ChainView<CS, ST>,
    ) -> Result<(), ConsensusError>
    where
        CS: CommitmentScheme + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        // Solo engine accepts everything valid, but typically won't receive gossip in Mode 0.
        Ok(())
    }

    async fn handle_vote(
        &mut self,
        _vote: ConsensusVote,
    ) -> Result<(), ConsensusError> {
        // Solo mode does not process votes from peers.
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