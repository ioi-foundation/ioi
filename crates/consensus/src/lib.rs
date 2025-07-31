//! Consensus module implementations for the DePIN SDK

#[cfg(feature = "round-robin")]
pub mod round_robin;

#[cfg(feature = "poa")]
pub mod proof_of_authority;

use async_trait::async_trait;
use depin_sdk_core::app::Block;
use libp2p::PeerId;
use std::collections::HashSet;

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

/// A trait defining the interface for a pluggable consensus engine.
#[async_trait]
pub trait ConsensusEngine<T>: Send + Sync {
    /// Determines the node's action for the current block height and view.
    async fn decide(
        &mut self,
        local_peer_id: &PeerId,
        height: u64,
        view: u64,
        validator_set: &[Vec<u8>],
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T>;

    /// Handles an incoming block proposal from a peer.
    async fn handle_block_proposal(&mut self, block: Block<T>) -> Result<(), String>;

    /// Handles an incoming view change proposal from a peer.
    async fn handle_view_change(&mut self, from: PeerId, height: u64, new_view: u64) -> Result<(), String>;
    
    /// Resets the internal state of the engine for a given height. This is crucial
    /// when a block is successfully processed, to prevent stale timeout-based actions.
    fn reset(&mut self, height: u64);
}