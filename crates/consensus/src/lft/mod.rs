use crate::admft::AdmftEngine;
use crate::apmft::ApmftEngine;
use crate::{ConsensusDecision, ConsensusEngine, PenaltyEngine, PenaltyMechanism};
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, ChainView};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::ConsensusControl;
use ioi_api::state::{StateAccess, StateManager};
use ioi_system::SystemState;
use ioi_types::app::{AccountId, Block, ConsensusVote, FailureReport};
use ioi_types::error::{ConsensusError, TransactionError};
use libp2p::PeerId;
use std::collections::HashSet;

/// Lazarus fault-tolerance family wrapper.
///
/// This keeps A-DMFT and A-PMFT grouped under a single parent so config/runtime
/// dispatch can treat them as a distinct consensus family from classic PoA/PoS.
#[derive(Debug, Clone)]
pub enum LftEngine {
    Admft(AdmftEngine),
    Apmft(ApmftEngine),
}

impl Default for LftEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl LftEngine {
    pub fn new() -> Self {
        Self::Admft(AdmftEngine::new())
    }
}

impl ConsensusControl for LftEngine {
    fn switch_to_apmft(&mut self) {
        tracing::info!(target: "consensus", "PROTOCOL PHASE TRANSITION: A-DMFT -> A-PMFT");
        *self = Self::Apmft(ApmftEngine::new());
    }

    fn switch_to_admft(&mut self) {
        tracing::info!(target: "consensus", "PROTOCOL PHASE TRANSITION: A-PMFT -> A-DMFT (Lazarus Complete)");
        *self = Self::Admft(AdmftEngine::new());
    }

    fn get_apmft_tip(&self) -> Option<([u8; 32], u32)> {
        match self {
            Self::Apmft(engine) => engine.get_apmft_tip(),
            Self::Admft(_) => None,
        }
    }

    fn feed_apmft_sample(&mut self, hash: [u8; 32]) {
        if let Self::Apmft(engine) = self {
            engine.feed_apmft_sample(hash);
        }
    }
}

#[async_trait]
impl PenaltyMechanism for LftEngine {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccess,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        match self {
            Self::Admft(engine) => engine.apply_penalty(state, report).await,
            Self::Apmft(engine) => engine.apply_penalty(state, report).await,
        }
    }
}

impl PenaltyEngine for LftEngine {
    fn apply(
        &self,
        system: &mut dyn SystemState,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        match self {
            Self::Admft(engine) => engine.apply(system, report),
            Self::Apmft(engine) => engine.apply(system, report),
        }
    }
}

#[async_trait]
impl<T> ConsensusEngine<T> for LftEngine
where
    T: Clone + Send + Sync + 'static + parity_scale_codec::Encode,
{
    async fn decide(
        &mut self,
        our_account_id: &AccountId,
        height: u64,
        view: u64,
        parent_view: &dyn AnchoredStateView,
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        match self {
            Self::Admft(engine) => {
                engine
                    .decide(our_account_id, height, view, parent_view, known_peers)
                    .await
            }
            Self::Apmft(engine) => {
                engine
                    .decide(our_account_id, height, view, parent_view, known_peers)
                    .await
            }
        }
    }

    async fn handle_block_proposal<CS, ST>(
        &mut self,
        block: Block<T>,
        chain_view: &dyn ChainView<CS, ST>,
    ) -> Result<(), ConsensusError>
    where
        CS: CommitmentScheme + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        match self {
            Self::Admft(engine) => engine.handle_block_proposal(block, chain_view).await,
            Self::Apmft(engine) => engine.handle_block_proposal(block, chain_view).await,
        }
    }

    async fn handle_vote(&mut self, vote: ConsensusVote) -> Result<(), ConsensusError> {
        match self {
            Self::Admft(engine) => {
                <AdmftEngine as ConsensusEngine<T>>::handle_vote(engine, vote).await
            }
            Self::Apmft(engine) => {
                <ApmftEngine as ConsensusEngine<T>>::handle_vote(engine, vote).await
            }
        }
    }

    async fn handle_view_change(
        &mut self,
        from: PeerId,
        proof_bytes: &[u8],
    ) -> Result<(), ConsensusError> {
        match self {
            Self::Admft(engine) => {
                <AdmftEngine as ConsensusEngine<T>>::handle_view_change(engine, from, proof_bytes)
                    .await
            }
            Self::Apmft(engine) => {
                <ApmftEngine as ConsensusEngine<T>>::handle_view_change(engine, from, proof_bytes)
                    .await
            }
        }
    }

    fn reset(&mut self, height: u64) {
        match self {
            Self::Admft(engine) => <AdmftEngine as ConsensusEngine<T>>::reset(engine, height),
            Self::Apmft(engine) => <ApmftEngine as ConsensusEngine<T>>::reset(engine, height),
        }
    }
}
