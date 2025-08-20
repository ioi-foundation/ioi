// Path: crates/consensus/src/lib.rs

#![forbid(unsafe_code)]
//! Consensus module implementations for the DePIN SDK

#[cfg(feature = "round-robin")]
pub mod round_robin;

#[cfg(feature = "poa")]
pub mod proof_of_authority;

#[cfg(feature = "pos")]
pub mod proof_of_stake;

use async_trait::async_trait;
use depin_sdk_api::chain::AppChain;
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::WorkloadContainer;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::app::Block;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Debug;

// Re-export the concrete engine types for use in the enum.
#[cfg(feature = "poa")]
use proof_of_authority::ProofOfAuthorityEngine;
#[cfg(feature = "pos")]
use proof_of_stake::ProofOfStakeEngine;
#[cfg(feature = "round-robin")]
use round_robin::RoundRobinBftEngine;

/// Consensus algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusAlgorithm {
    /// Proof of Stake
    ProofOfStake,
    /// Proof of Authority
    ProofOfAuthority,
    /// Round Robin (deterministic, for testing/PoA)
    RoundRobin,
    /// Custom consensus algorithm
    Custom(u32),
}

/// Represents the decision a node should take in a given consensus round.
/// This is the primary output of the `ConsensusEngine::decide` method.
pub enum ConsensusDecision<T> {
    /// We are the leader and should produce a block with the given transactions.
    ProduceBlock(Vec<T>),
    /// We are a follower and should continue waiting for the leader's block.
    WaitForBlock,
    /// We have timed out waiting for the leader and should propose a view change.
    ProposeViewChange,
}

/// An enum that wraps the various consensus engine implementations,
/// allowing them to be used as a single concrete type, thus avoiding
/// issues with `dyn Trait` compatibility.
pub enum Consensus<T: Clone> {
    #[cfg(feature = "round-robin")]
    RoundRobin(Box<RoundRobinBftEngine>),
    #[cfg(feature = "poa")]
    ProofOfAuthority(ProofOfAuthorityEngine),
    #[cfg(feature = "pos")]
    ProofOfStake(ProofOfStakeEngine),
    /// A variant to ensure the enum is not empty if no features are enabled.
    #[doc(hidden)]
    _Phantom(std::marker::PhantomData<T>),
}

/// A trait defining the interface for a pluggable consensus engine.
#[async_trait]
pub trait ConsensusEngine<T: Clone>: Send + Sync {
    /// Fetches and serializes the specific validator data this engine needs for a decision.
    async fn get_validator_data<CS, ST>(
        &self,
        chain: &(dyn AppChain<CS, UnifiedTransactionModel<CS>, ST> + Send + Sync),
        workload: &WorkloadContainer<ST>,
    ) -> Result<Vec<Vec<u8>>, String>
    where
        CS: CommitmentScheme + Clone,
        <CS as CommitmentScheme>::Proof: Serialize + for<'de> Deserialize<'de> + Clone,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
            + Send
            + Sync
            + 'static
            + Debug;

    /// The `decide` method now receives this opaque, pre-fetched data.
    async fn decide(
        &mut self,
        local_peer_id: &PeerId,
        height: u64,
        view: u64,
        validator_data: &[Vec<u8>],
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T>;

    /// Handles an incoming block proposal from a peer.
    /// Needs access to the chain state to validate the block's integrity and producer.
    async fn handle_block_proposal<CS, TM, ST>(
        &mut self,
        block: Block<T>,
        chain: &mut (dyn AppChain<CS, TM, ST> + Send + Sync),
        workload: &WorkloadContainer<ST>,
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

    /// Resets the internal state of the engine for a given height. This is crucial
    /// when a block is successfully processed, to prevent stale timeout-based actions.
    fn reset(&mut self, height: u64);
}

// Implement the ConsensusEngine trait for the Consensus enum by dispatching
// the call to the appropriate inner engine.
#[async_trait]
impl<T> ConsensusEngine<T> for Consensus<T>
where
    T: Clone + Send + Sync + 'static,
{
    async fn get_validator_data<CS, ST>(
        &self,
        chain: &(dyn AppChain<CS, UnifiedTransactionModel<CS>, ST> + Send + Sync),
        workload: &WorkloadContainer<ST>,
    ) -> Result<Vec<Vec<u8>>, String>
    where
        CS: CommitmentScheme + Clone,
        <CS as CommitmentScheme>::Proof: Serialize + for<'de> Deserialize<'de> + Clone,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
            + Send
            + Sync
            + 'static
            + Debug,
    {
        match self {
            #[cfg(feature = "round-robin")]
            Consensus::RoundRobin(e) => {
                ConsensusEngine::<T>::get_validator_data(e.as_ref(), chain, workload).await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => {
                ConsensusEngine::<T>::get_validator_data(e, chain, workload).await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => {
                ConsensusEngine::<T>::get_validator_data(e, chain, workload).await
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
                e.decide(local_peer_id, height, view, validator_data, known_peers)
                    .await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => {
                e.decide(local_peer_id, height, view, validator_data, known_peers)
                    .await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => {
                e.decide(local_peer_id, height, view, validator_data, known_peers)
                    .await
            }
            Consensus::_Phantom(_) => panic!("No consensus engine feature is enabled."),
        }
    }

    async fn handle_block_proposal<CS, TM, ST>(
        &mut self,
        block: Block<T>,
        chain: &mut (dyn AppChain<CS, TM, ST> + Send + Sync),
        workload: &WorkloadContainer<ST>,
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
                ConsensusEngine::<T>::handle_block_proposal(e.as_mut(), block, chain, workload)
                    .await
            }
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => {
                ConsensusEngine::<T>::handle_block_proposal(e, block, chain, workload).await
            }
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => {
                ConsensusEngine::<T>::handle_block_proposal(e, block, chain, workload).await
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
                ConsensusEngine::<T>::handle_view_change(e.as_mut(), from, height, new_view).await
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
            Consensus::RoundRobin(e) => ConsensusEngine::<T>::reset(e.as_mut(), height),
            #[cfg(feature = "poa")]
            Consensus::ProofOfAuthority(e) => ConsensusEngine::<T>::reset(e, height),
            #[cfg(feature = "pos")]
            Consensus::ProofOfStake(e) => ConsensusEngine::<T>::reset(e, height),
            Consensus::_Phantom(_) => panic!("No consensus engine feature is enabled."),
        }
    }
}
