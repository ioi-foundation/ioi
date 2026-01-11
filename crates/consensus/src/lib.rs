// Path: crates/consensus/src/lib.rs
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
//! Consensus module implementations for the IOI Kernel

pub mod admft;
pub mod common;
pub mod service;
pub mod util;

use async_trait::async_trait;
use ioi_api::{
    chain::{AnchoredStateView, ChainView},
    commitment::CommitmentScheme,
    consensus::{ConsensusDecision, ConsensusEngine, PenaltyMechanism},
    state::{StateAccess, StateManager},
};
use ioi_system::SystemState;
use ioi_types::app::{AccountId, Block, FailureReport};
use ioi_types::config::ConsensusType;
use ioi_types::error::{ConsensusError, TransactionError};
use libp2p::PeerId;
use std::collections::HashSet;
use std::fmt::Debug;

// Export the new engine
use admft::AdmftEngine;

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
/// Currently only A-DMFT is supported as the canonical engine.
#[derive(Debug, Clone)]
pub enum Consensus<T: Clone> {
    Admft(AdmftEngine),
    #[doc(hidden)]
    _Phantom(std::marker::PhantomData<T>),
}

impl<T: Clone> Consensus<T> {
    pub fn consensus_type(&self) -> ConsensusType {
        match self {
            Consensus::Admft(_) => ConsensusType::Admft, // Map A-DMFT to PoA config for now
            Consensus::_Phantom(_) => unreachable!(),
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
            Consensus::Admft(e) => e.apply_penalty(state, report).await,
            Consensus::_Phantom(_) => unreachable!(),
        }
    }
}

impl<T: Clone + Send + Sync + 'static> PenaltyEngine for Consensus<T> {
    fn apply(
        &self,
        sys: &mut dyn SystemState,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        match self {
            Consensus::Admft(e) => e.apply(sys, report),
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
            Consensus::Admft(e) => {
                e.decide(our_account_id, height, view, parent_view, known_peers)
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
            Consensus::Admft(e) => e.handle_block_proposal(block, chain_view).await,
            Consensus::_Phantom(_) => unreachable!(),
        }
    }

    async fn handle_view_change(
        &mut self,
        from: PeerId,
        height: u64,
        new_view: u64,
    ) -> Result<(), ConsensusError> {
        match self {
            Consensus::Admft(e) => {
                // [FIX] Use fully qualified path for disambiguation
                <AdmftEngine as ConsensusEngine<T>>::handle_view_change(e, from, height, new_view)
                    .await
            }
            Consensus::_Phantom(_) => unreachable!(),
        }
    }

    fn reset(&mut self, height: u64) {
        match self {
            Consensus::Admft(e) => {
                // [FIX] Use fully qualified path for disambiguation
                <AdmftEngine as ConsensusEngine<T>>::reset(e, height)
            }
            Consensus::_Phantom(_) => unreachable!(),
        }
    }
}
