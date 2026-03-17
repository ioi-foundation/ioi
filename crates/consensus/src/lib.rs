#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing
    )
)]
//! Consensus module implementations for the IOI Kernel.

#[cfg(feature = "aft")]
pub mod aft;
pub mod common;
#[cfg(feature = "poa")]
pub mod proof_of_authority;
#[cfg(feature = "pos")]
pub mod proof_of_stake;
pub mod service;
pub mod solo;
pub mod util;

use async_trait::async_trait;
use ioi_api::{
    chain::{AnchoredStateView, ChainView},
    commitment::CommitmentScheme,
    consensus::{ConsensusControl, ConsensusDecision, ConsensusEngine, PenaltyMechanism},
    state::{StateAccess, StateManager},
};
use ioi_system::SystemState;
use ioi_types::app::{
    AccountId, Block, BlockHeader, ConsensusVote, FailureReport, QuorumCertificate,
};
use ioi_types::config::ConsensusType;
use ioi_types::error::{ConsensusError, TransactionError};
use libp2p::PeerId;
use std::collections::HashSet;
use std::fmt::Debug;

#[cfg(feature = "aft")]
use aft::AftEngine;
#[cfg(feature = "poa")]
use proof_of_authority::ProofOfAuthorityEngine;
#[cfg(feature = "pos")]
use proof_of_stake::ProofOfStakeEngine;
use solo::SoloEngine;

pub use service::PenaltiesService;

/// Defines logic for applying penalties.
pub trait PenaltyEngine: Send + Sync {
    fn apply(
        &self,
        system: &mut dyn SystemState,
        report: &FailureReport,
    ) -> Result<(), TransactionError>;
}

/// An enum that wraps the various consensus engine implementations.
#[derive(Debug, Clone)]
pub enum Consensus<T: Clone> {
    #[cfg(feature = "aft")]
    Aft(AftEngine),
    #[cfg(feature = "poa")]
    ProofOfAuthority(ProofOfAuthorityEngine),
    #[cfg(feature = "pos")]
    ProofOfStake(ProofOfStakeEngine),
    Solo(SoloEngine),
    #[doc(hidden)]
    _Phantom(std::marker::PhantomData<T>),
}

impl<T: Clone> Consensus<T> {
    pub fn consensus_type(&self) -> ConsensusType {
        match self {
            #[cfg(feature = "aft")]
            Consensus::Aft(_) => ConsensusType::Aft,
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(_) => ConsensusType::ProofOfAuthority,
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(_) => ConsensusType::ProofOfStake,
            Consensus::Solo(_) => ConsensusType::Aft,
            Consensus::_Phantom(_) => unreachable!(),
        }
    }
}

impl<T: Clone + Send + Sync + 'static> ConsensusControl for Consensus<T> {
    fn experimental_sample_tip(&self) -> Option<([u8; 32], u32)> {
        match self {
            #[cfg(feature = "aft")]
            Consensus::Aft(engine) => engine.experimental_sample_tip(),
            _ => None,
        }
    }

    fn observe_experimental_sample(&mut self, hash: [u8; 32]) {
        match self {
            #[cfg(feature = "aft")]
            Consensus::Aft(engine) => engine.observe_experimental_sample(hash),
            _ => {}
        }
    }
}

#[async_trait]
impl<T> PenaltyMechanism for Consensus<T>
where
    T: Clone + Send + Sync + 'static,
{
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccess,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        match self {
            #[cfg(feature = "aft")]
            Consensus::Aft(engine) => engine.apply_penalty(state, report).await,
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(engine) => engine.apply_penalty(state, report).await,
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(engine) => engine.apply_penalty(state, report).await,
            Consensus::Solo(engine) => engine.apply_penalty(state, report).await,
            Consensus::_Phantom(_) => unreachable!(),
        }
    }
}

impl<T: Clone + Send + Sync + 'static> PenaltyEngine for Consensus<T> {
    fn apply(
        &self,
        system: &mut dyn SystemState,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        match self {
            #[cfg(feature = "aft")]
            Consensus::Aft(engine) => engine.apply(system, report),
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(engine) => engine.apply(system, report),
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(engine) => engine.apply(system, report),
            Consensus::Solo(engine) => engine.apply(system, report),
            Consensus::_Phantom(_) => unreachable!(),
        }
    }
}

#[async_trait]
impl<T> ConsensusEngine<T> for Consensus<T>
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
            #[cfg(feature = "aft")]
            Consensus::Aft(engine) => {
                engine
                    .decide(our_account_id, height, view, parent_view, known_peers)
                    .await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(engine) => {
                engine
                    .decide(our_account_id, height, view, parent_view, known_peers)
                    .await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(engine) => {
                engine
                    .decide(our_account_id, height, view, parent_view, known_peers)
                    .await
            }
            Consensus::Solo(engine) => {
                engine
                    .decide(our_account_id, height, view, parent_view, known_peers)
                    .await
            }
            Consensus::_Phantom(_) => unreachable!(),
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
            #[cfg(feature = "aft")]
            Consensus::Aft(engine) => engine.handle_block_proposal(block, chain_view).await,
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(engine) => {
                engine.handle_block_proposal(block, chain_view).await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(engine) => {
                engine.handle_block_proposal(block, chain_view).await
            }
            Consensus::Solo(engine) => engine.handle_block_proposal(block, chain_view).await,
            Consensus::_Phantom(_) => unreachable!(),
        }
    }

    async fn handle_vote(&mut self, vote: ConsensusVote) -> Result<(), ConsensusError> {
        match self {
            #[cfg(feature = "aft")]
            Consensus::Aft(engine) => {
                <AftEngine as ConsensusEngine<T>>::handle_vote(engine, vote).await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(engine) => {
                <ProofOfAuthorityEngine as ConsensusEngine<T>>::handle_vote(engine, vote).await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(engine) => {
                <ProofOfStakeEngine as ConsensusEngine<T>>::handle_vote(engine, vote).await
            }
            Consensus::Solo(engine) => {
                <SoloEngine as ConsensusEngine<T>>::handle_vote(engine, vote).await
            }
            Consensus::_Phantom(_) => unreachable!(),
        }
    }

    async fn handle_quorum_certificate(
        &mut self,
        qc: QuorumCertificate,
    ) -> Result<(), ConsensusError> {
        match self {
            #[cfg(feature = "aft")]
            Consensus::Aft(engine) => {
                <AftEngine as ConsensusEngine<T>>::handle_quorum_certificate(engine, qc).await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(engine) => {
                <ProofOfAuthorityEngine as ConsensusEngine<T>>::handle_quorum_certificate(
                    engine, qc,
                )
                .await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(engine) => {
                <ProofOfStakeEngine as ConsensusEngine<T>>::handle_quorum_certificate(engine, qc)
                    .await
            }
            Consensus::Solo(engine) => {
                <SoloEngine as ConsensusEngine<T>>::handle_quorum_certificate(engine, qc).await
            }
            Consensus::_Phantom(_) => unreachable!(),
        }
    }

    async fn handle_view_change(
        &mut self,
        from: PeerId,
        proof_bytes: &[u8],
    ) -> Result<(), ConsensusError> {
        match self {
            #[cfg(feature = "aft")]
            Consensus::Aft(engine) => {
                <AftEngine as ConsensusEngine<T>>::handle_view_change(engine, from, proof_bytes)
                    .await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(engine) => {
                <ProofOfAuthorityEngine as ConsensusEngine<T>>::handle_view_change(
                    engine,
                    from,
                    proof_bytes,
                )
                .await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(engine) => {
                <ProofOfStakeEngine as ConsensusEngine<T>>::handle_view_change(
                    engine,
                    from,
                    proof_bytes,
                )
                .await
            }
            Consensus::Solo(engine) => {
                <SoloEngine as ConsensusEngine<T>>::handle_view_change(engine, from, proof_bytes)
                    .await
            }
            Consensus::_Phantom(_) => unreachable!(),
        }
    }

    fn reset(&mut self, height: u64) {
        match self {
            #[cfg(feature = "aft")]
            Consensus::Aft(engine) => <AftEngine as ConsensusEngine<T>>::reset(engine, height),
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(engine) => {
                <ProofOfAuthorityEngine as ConsensusEngine<T>>::reset(engine, height)
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(engine) => {
                <ProofOfStakeEngine as ConsensusEngine<T>>::reset(engine, height)
            }
            Consensus::Solo(engine) => <SoloEngine as ConsensusEngine<T>>::reset(engine, height),
            Consensus::_Phantom(_) => unreachable!(),
        }
    }

    fn observe_committed_block(&mut self, header: &BlockHeader) {
        match self {
            #[cfg(feature = "aft")]
            Consensus::Aft(engine) => {
                <AftEngine as ConsensusEngine<T>>::observe_committed_block(engine, header)
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(engine) => {
                <ProofOfAuthorityEngine as ConsensusEngine<T>>::observe_committed_block(
                    engine, header,
                )
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(engine) => {
                <ProofOfStakeEngine as ConsensusEngine<T>>::observe_committed_block(
                    engine, header,
                )
            }
            Consensus::Solo(engine) => {
                <SoloEngine as ConsensusEngine<T>>::observe_committed_block(engine, header)
            }
            Consensus::_Phantom(_) => unreachable!(),
        }
    }

    fn header_for_quorum_certificate(&self, qc: &QuorumCertificate) -> Option<BlockHeader> {
        match self {
            #[cfg(feature = "aft")]
            Consensus::Aft(engine) => {
                <AftEngine as ConsensusEngine<T>>::header_for_quorum_certificate(engine, qc)
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(engine) => {
                <ProofOfAuthorityEngine as ConsensusEngine<T>>::header_for_quorum_certificate(
                    engine, qc,
                )
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(engine) => {
                <ProofOfStakeEngine as ConsensusEngine<T>>::header_for_quorum_certificate(
                    engine, qc,
                )
            }
            Consensus::Solo(engine) => {
                <SoloEngine as ConsensusEngine<T>>::header_for_quorum_certificate(engine, qc)
            }
            Consensus::_Phantom(_) => unreachable!(),
        }
    }

    fn take_pending_quorum_certificates(&mut self) -> Vec<QuorumCertificate> {
        match self {
            #[cfg(feature = "aft")]
            Consensus::Aft(engine) => {
                <AftEngine as ConsensusEngine<T>>::take_pending_quorum_certificates(engine)
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(engine) => {
                <ProofOfAuthorityEngine as ConsensusEngine<T>>::take_pending_quorum_certificates(
                    engine,
                )
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(engine) => {
                <ProofOfStakeEngine as ConsensusEngine<T>>::take_pending_quorum_certificates(engine)
            }
            Consensus::Solo(engine) => {
                <SoloEngine as ConsensusEngine<T>>::take_pending_quorum_certificates(engine)
            }
            Consensus::_Phantom(_) => unreachable!(),
        }
    }
}
