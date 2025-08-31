// Path: crates/consensus/src/lib.rs

#![forbid(unsafe_code)]
//! Consensus module implementations for the DePIN SDK

// --- CORRECTED MODULE DECLARATIONS ---
#[cfg(feature = "round-robin")]
pub mod round_robin;

#[cfg(feature = "poa")]
pub mod proof_of_authority;

#[cfg(feature = "pos")]
pub mod proof_of_stake;

pub mod util;
// --- END CORRECTION ---

use async_trait::async_trait;
use depin_sdk_api::consensus::{
    ChainStateReader, ConsensusDecision, ConsensusEngine, PenaltyMechanism,
};
use depin_sdk_api::state::StateAccessor;
use depin_sdk_types::app::{Block, FailureReport};
use depin_sdk_types::config::ConsensusType;
use depin_sdk_types::error::{ConsensusError, TransactionError};
use libp2p::{identity::PublicKey, PeerId};
use std::collections::HashSet;

// Re-export the concrete engine types for use in the enum.
#[cfg(feature = "poa")]
use proof_of_authority::ProofOfAuthorityEngine;
#[cfg(feature = "pos")]
use proof_of_stake::ProofOfStakeEngine;
#[cfg(feature = "round-robin")]
use round_robin::RoundRobinBftEngine;

/// An enum that wraps the various consensus engine implementations.
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
            Consensus::_Phantom(_) => panic!("No consensus engine feature is enabled."),
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
            Consensus::_Phantom(_) => panic!("No consensus engine feature is enabled."),
        }
    }
}

#[async_trait]
impl<T> ConsensusEngine<T> for Consensus<T>
where
    T: Clone + Send + Sync + 'static,
{
    async fn get_validator_data(
        &self,
        state_reader: &dyn ChainStateReader,
    ) -> Result<Vec<Vec<u8>>, ConsensusError> {
        match self {
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(e) => {
                ConsensusEngine::<T>::get_validator_data(e.as_ref(), state_reader).await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => {
                ConsensusEngine::<T>::get_validator_data(e, state_reader).await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => {
                ConsensusEngine::<T>::get_validator_data(e, state_reader).await
            }
            Consensus::_Phantom(_) => panic!("No consensus engine feature is enabled."),
        }
    }

    async fn decide(
        &mut self,
        local_public_key: &PublicKey,
        height: u64,
        view: u64,
        validator_data: &[Vec<u8>],
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        match self {
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(e) => {
                <RoundRobinBftEngine as ConsensusEngine<T>>::decide(
                    e.as_mut(),
                    local_public_key,
                    height,
                    view,
                    validator_data,
                    known_peers,
                )
                .await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => {
                e.decide(local_public_key, height, view, validator_data, known_peers)
                    .await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => {
                e.decide(local_public_key, height, view, validator_data, known_peers)
                    .await
            }
            Consensus::_Phantom(_) => panic!("No consensus engine feature is enabled."),
        }
    }

    async fn handle_block_proposal(
        &mut self,
        block: Block<T>,
        state_reader: &dyn ChainStateReader,
    ) -> Result<(), ConsensusError> {
        match self {
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(e) => {
                <RoundRobinBftEngine as ConsensusEngine<T>>::handle_block_proposal(
                    e.as_mut(),
                    block,
                    state_reader,
                )
                .await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => e.handle_block_proposal(block, state_reader).await,
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => e.handle_block_proposal(block, state_reader).await,
            Consensus::_Phantom(_) => panic!("No consensus engine feature is enabled."),
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
            Consensus::_Phantom(_) => panic!("No consensus engine feature is enabled."),
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
            Consensus::_Phantom(_) => panic!("No consensus engine feature is enabled."),
        }
    }
}
