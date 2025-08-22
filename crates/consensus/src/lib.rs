// Path: crates/consensus/src/lib.rs

#![forbid(unsafe_code)]
//! Consensus module implementations for the DePIN SDK

#[cfg(feature = "round-robin")]
pub mod round_robin;

#[cfg(feature = "poa")]
pub mod proof_of_authority;

#[cfg(feature = "pos")]
pub mod proof_of_stake;

pub mod util;

use async_trait::async_trait;
use depin_sdk_api::chain::AppChain;
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_client::WorkloadClient;
use depin_sdk_types::app::Block;
use libp2p::PeerId;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;

// Re-export the concrete engine types for use in the enum.
#[cfg(feature = "poa")]
use proof_of_authority::ProofOfAuthorityEngine;
#[cfg(feature = "pos")]
use proof_of_stake::ProofOfStakeEngine;
#[cfg(feature = "round-robin")]
use round_robin::RoundRobinBftEngine;

/// Represents the decision a node should take in a given consensus round.
pub enum ConsensusDecision<T> {
    ProduceBlock(Vec<T>),
    WaitForBlock,
    ProposeViewChange,
}

/// An enum that wraps the various consensus engine implementations.
pub enum Consensus<T: Clone> {
    #[cfg(feature = "round-robin")]
    RoundRobin(RoundRobinBftEngine),
    #[cfg(feature = "poa")]
    ProofOfAuthority(ProofOfAuthorityEngine),
    #[cfg(feature = "pos")]
    ProofOfStake(ProofOfStakeEngine),
    #[doc(hidden)]
    _Phantom(std::marker::PhantomData<T>),
}

/// A trait defining the interface for a pluggable consensus engine.
#[async_trait]
pub trait ConsensusEngine<T: Clone>: Send + Sync {
    /// Fetches the specific validator data this engine needs for a decision.
    async fn get_validator_data(
        &self,
        workload_client: &Arc<WorkloadClient>,
    ) -> Result<Vec<Vec<u8>>, String>;

    /// Makes a consensus decision for the current round.
    async fn decide(
        &mut self,
        local_peer_id: &PeerId,
        height: u64,
        view: u64,
        validator_data: &[Vec<u8>],
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T>;

    /// Handles an incoming block proposal from a peer.
    async fn handle_block_proposal<CS, TM, ST>(
        &mut self,
        block: Block<T>,
        chain: &mut (dyn AppChain<CS, TM, ST> + Send + Sync),
        workload_client: &Arc<WorkloadClient>,
    ) -> Result<(), String>
    where
        CS: CommitmentScheme + Send + Sync,
        TM: TransactionModel<CommitmentScheme = CS> + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
            + Send
            + Sync
            + 'static
            + Debug,
        CS::Commitment: Send + Sync + Debug;

    /// Handles an incoming view change proposal from a peer.
    async fn handle_view_change(
        &mut self,
        from: PeerId,
        height: u64,
        new_view: u64,
    ) -> Result<(), String>;

    /// Resets the internal state of the engine for a given height.
    fn reset(&mut self, height: u64);
}

#[async_trait]
impl<T> ConsensusEngine<T> for Consensus<T>
where
    T: Clone + Send + Sync + 'static,
{
    async fn get_validator_data(
        &self,
        workload_client: &Arc<WorkloadClient>,
    ) -> Result<Vec<Vec<u8>>, String> {
        match self {
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(e) => {
                ConsensusEngine::<T>::get_validator_data(e, workload_client).await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => {
                ConsensusEngine::<T>::get_validator_data(e, workload_client).await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => {
                ConsensusEngine::<T>::get_validator_data(e, workload_client).await
            }
            Consensus::_Phantom(_) => panic!("No consensus engine feature is enabled."),
        }
    }

    async fn decide(
        &mut self,
        local_peer_id: &PeerId,
        height: u64,
        view: u64,
        validator_data: &[Vec<u8>],
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        match self {
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(e) => {
                ConsensusEngine::<T>::decide(
                    e,
                    local_peer_id,
                    height,
                    view,
                    validator_data,
                    known_peers,
                )
                .await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => {
                ConsensusEngine::<T>::decide(
                    e,
                    local_peer_id,
                    height,
                    view,
                    validator_data,
                    known_peers,
                )
                .await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => {
                ConsensusEngine::<T>::decide(
                    e,
                    local_peer_id,
                    height,
                    view,
                    validator_data,
                    known_peers,
                )
                .await
            }
            Consensus::_Phantom(_) => panic!("No consensus engine feature is enabled."),
        }
    }

    async fn handle_block_proposal<CS, TM, ST>(
        &mut self,
        block: Block<T>,
        chain: &mut (dyn AppChain<CS, TM, ST> + Send + Sync),
        workload_client: &Arc<WorkloadClient>,
    ) -> Result<(), String>
    where
        CS: CommitmentScheme + Send + Sync,
        TM: TransactionModel<CommitmentScheme = CS> + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
            + Send
            + Sync
            + 'static
            + Debug,
        CS::Commitment: Send + Sync + Debug,
    {
        match self {
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(e) => {
                ConsensusEngine::<T>::handle_block_proposal(e, block, chain, workload_client).await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => {
                ConsensusEngine::<T>::handle_block_proposal(e, block, chain, workload_client).await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => {
                ConsensusEngine::<T>::handle_block_proposal(e, block, chain, workload_client).await
            }
            Consensus::_Phantom(_) => panic!("No consensus engine feature is enabled."),
        }
    }

    async fn handle_view_change(
        &mut self,
        from: PeerId,
        height: u64,
        new_view: u64,
    ) -> Result<(), String> {
        match self {
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(e) => {
                ConsensusEngine::<T>::handle_view_change(e, from, height, new_view).await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => {
                ConsensusEngine::<T>::handle_view_change(e, from, height, new_view).await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => {
                ConsensusEngine::<T>::handle_view_change(e, from, height, new_view).await
            }
            Consensus::_Phantom(_) => panic!("No consensus engine feature is enabled."),
        }
    }

    fn reset(&mut self, height: u64) {
        match self {
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(e) => ConsensusEngine::<T>::reset(e, height),
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => ConsensusEngine::<T>::reset(e, height),
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => ConsensusEngine::<T>::reset(e, height),
            Consensus::_Phantom(_) => panic!("No consensus engine feature is enabled."),
        }
    }
}