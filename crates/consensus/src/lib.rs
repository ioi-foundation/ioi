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

#[cfg(feature = "admft")]
pub mod admft;
#[cfg(feature = "admft")]
pub mod apmft;
pub mod common;
#[cfg(feature = "admft")]
pub mod lft;
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
use ioi_types::app::{AccountId, Block, ConsensusVote, FailureReport};
use ioi_types::config::ConsensusType;
use ioi_types::error::{ConsensusError, TransactionError};
use libp2p::PeerId;
use std::collections::HashSet;
use std::fmt::Debug;

#[cfg(feature = "admft")]
use lft::LftEngine;
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
    #[cfg(feature = "admft")]
    Lft(LftEngine),
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
            #[cfg(feature = "admft")]
            Consensus::Lft(_) => ConsensusType::Admft,
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(_) => ConsensusType::ProofOfAuthority,
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(_) => ConsensusType::ProofOfStake,
            Consensus::Solo(_) => ConsensusType::Admft,
            Consensus::_Phantom(_) => unreachable!(),
        }
    }
}

impl<T: Clone + Send + Sync + 'static> ConsensusControl for Consensus<T> {
    fn switch_to_apmft(&mut self) {
        match self {
            #[cfg(feature = "admft")]
            Consensus::Lft(engine) => engine.switch_to_apmft(),
            _ => {}
        }
    }

    fn switch_to_admft(&mut self) {
        match self {
            #[cfg(feature = "admft")]
            Consensus::Lft(engine) => engine.switch_to_admft(),
            _ => {}
        }
    }

    fn get_apmft_tip(&self) -> Option<([u8; 32], u32)> {
        match self {
            #[cfg(feature = "admft")]
            Consensus::Lft(engine) => engine.get_apmft_tip(),
            _ => None,
        }
    }

    fn feed_apmft_sample(&mut self, hash: [u8; 32]) {
        match self {
            #[cfg(feature = "admft")]
            Consensus::Lft(engine) => engine.feed_apmft_sample(hash),
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
            #[cfg(feature = "admft")]
            Consensus::Lft(engine) => engine.apply_penalty(state, report).await,
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
            #[cfg(feature = "admft")]
            Consensus::Lft(engine) => engine.apply(system, report),
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
            #[cfg(feature = "admft")]
            Consensus::Lft(engine) => {
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
            #[cfg(feature = "admft")]
            Consensus::Lft(engine) => engine.handle_block_proposal(block, chain_view).await,
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
            #[cfg(feature = "admft")]
            Consensus::Lft(engine) => {
                <LftEngine as ConsensusEngine<T>>::handle_vote(engine, vote).await
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

    async fn handle_view_change(
        &mut self,
        from: PeerId,
        proof_bytes: &[u8],
    ) -> Result<(), ConsensusError> {
        match self {
            #[cfg(feature = "admft")]
            Consensus::Lft(engine) => {
                <LftEngine as ConsensusEngine<T>>::handle_view_change(engine, from, proof_bytes)
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
            #[cfg(feature = "admft")]
            Consensus::Lft(engine) => <LftEngine as ConsensusEngine<T>>::reset(engine, height),
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
}
