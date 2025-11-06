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
//! Consensus module implementations for the DePIN SDK

#[cfg(feature = "round-robin")]
pub mod round_robin;

#[cfg(feature = "poa")]
pub mod proof_of_authority;

#[cfg(feature = "pos")]
pub mod proof_of_stake;

pub mod util;

use async_trait::async_trait;
use ioi_types::app::{AccountId, Block, FailureReport};
use ioi_types::config::ConsensusType;
use ioi_types::error::{ConsensusError, TransactionError};
use ioi_api::{
    chain::{AnchoredStateView, ChainView},
    commitment::CommitmentScheme,
    consensus::{ChainStateReader, ConsensusDecision, ConsensusEngine, PenaltyMechanism},
    state::{StateAccessor, StateManager},
};
use libp2p::PeerId;
use std::collections::HashSet;
use std::fmt::Debug;

// Re-export the concrete engine types for use in the enum.
#[cfg(feature = "poa")]
use proof_of_authority::ProofOfAuthorityEngine;
#[cfg(feature = "pos")]
use proof_of_stake::ProofOfStakeEngine;
#[cfg(feature = "round-robin")]
use round_robin::RoundRobinBftEngine;

/// An enum that wraps the various consensus engine implementations.
#[derive(Debug, Clone)]
pub enum Consensus<T: Clone> {
    #[cfg(feature = "round-robin")]
    RoundRobin(Box<RoundRobinBftEngine>),
    #[cfg(feature = "poa")]
    ProofOfAuthority(ProofOfAuthorityEngine),
    #[cfg(feature = "pos")]
    ProofOfStake(ProofOfStakeEngine),
    #[doc(hidden)]
    _Phantom(std::marker::PhantomData<T>),
}

impl<T: Clone> Consensus<T> {
    /// Returns the `ConsensusType` enum variant corresponding to the active engine.
    pub fn consensus_type(&self) -> ConsensusType {
        match self {
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(_) => ConsensusType::ProofOfAuthority,
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(_) => ConsensusType::ProofOfAuthority,
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(_) => ConsensusType::ProofOfStake,
            Consensus::_Phantom(_) => unreachable!("No consensus engine feature is enabled."),
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
        state: &mut dyn StateAccessor,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        match self {
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(e) => e.as_ref().apply_penalty(state, report).await,
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => e.apply_penalty(state, report).await,
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => e.apply_penalty(state, report).await,
            Consensus::_Phantom(_) => unreachable!("No consensus engine feature is enabled."),
        }
    }
}

#[async_trait]
impl<T> ConsensusEngine<T> for Consensus<T>
where
    T: Clone + Send + Sync + 'static + parity_scale_codec::Encode,
{
    async fn get_validator_data(
        &self,
        _state_reader: &dyn ChainStateReader,
    ) -> Result<Vec<Vec<u8>>, ConsensusError> {
        // This method is deprecated. Return a default value.
        Ok(vec![])
    }

    async fn decide(
        &mut self,
        our_account_id: &AccountId,
        height: u64,
        view: u64,
        parent_view: &dyn AnchoredStateView,
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        match self {
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(e) => {
                e.decide(our_account_id, height, view, parent_view, known_peers)
                    .await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => {
                e.decide(our_account_id, height, view, parent_view, known_peers)
                    .await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => {
                e.decide(our_account_id, height, view, parent_view, known_peers)
                    .await
            }
            Consensus::_Phantom(_) => unreachable!("No consensus engine feature is enabled."),
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
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(e) => {
                <RoundRobinBftEngine as ConsensusEngine<T>>::handle_block_proposal(
                    e.as_mut(),
                    block,
                    chain_view,
                )
                .await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => e.handle_block_proposal(block, chain_view).await,
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => e.handle_block_proposal(block, chain_view).await,
            Consensus::_Phantom(_) => unreachable!("No consensus engine feature is enabled."),
        }
    }

    async fn handle_view_change(
        &mut self,
        from: PeerId,
        height: u64,
        new_view: u64,
    ) -> Result<(), ConsensusError> {
        match self {
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(e) => {
                <RoundRobinBftEngine as ConsensusEngine<T>>::handle_view_change(
                    e.as_mut(),
                    from,
                    height,
                    new_view,
                )
                .await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => {
                <ProofOfAuthorityEngine as ConsensusEngine<T>>::handle_view_change(
                    e, from, height, new_view,
                )
                .await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => {
                <ProofOfStakeEngine as ConsensusEngine<T>>::handle_view_change(
                    e, from, height, new_view,
                )
                .await
            }
            Consensus::_Phantom(_) => unreachable!("No consensus engine feature is enabled."),
        }
    }

    fn reset(&mut self, height: u64) {
        match self {
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(e) => {
                <RoundRobinBftEngine as ConsensusEngine<T>>::reset(e.as_mut(), height)
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => {
                <ProofOfAuthorityEngine as ConsensusEngine<T>>::reset(e, height)
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => {
                <ProofOfStakeEngine as ConsensusEngine<T>>::reset(e, height)
            }
            Consensus::_Phantom(_) => unreachable!("No consensus engine feature is enabled."),
        }
    }
}
