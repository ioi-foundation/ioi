// Path: crates/api/src/consensus/mod.rs

//! Defines the core `ConsensusEngine` trait for pluggable consensus algorithms.

use crate::chain::{ChainView, StateView};
use crate::commitment::CommitmentScheme;
use crate::state::{StateAccessor, StateManager};
use async_trait::async_trait;
use depin_sdk_types::app::{AccountId, Block};
use depin_sdk_types::error::{ConsensusError, TransactionError};
use libp2p::{identity::PublicKey, PeerId};
use std::collections::{BTreeMap, HashSet};

/// Represents the decision a node should take in a given consensus round.
pub enum ConsensusDecision<T> {
    /// The node should produce a new block with the given transactions.
    ProduceBlock(Vec<T>),
    /// The node should wait for a block proposal from the current leader.
    WaitForBlock,
    /// The node has timed out and should propose a view change to elect a new leader.
    ProposeViewChange,
    /// The node should stall and not produce a block, e.g., if there are no validators.
    Stall,
}

/// Provides a read-only, abstract view of chain state needed by the consensus engine.
///
/// This decouples the consensus logic from the concrete `AppChain` implementation,
/// allowing the engine to query necessary data (like validator sets) without
/// needing direct access to the entire chain state.
#[async_trait]
pub trait ChainStateReader: Send + Sync {
    /// Retrieves the active authority set for a Proof-of-Authority chain.
    async fn get_authority_set(&self) -> Result<Vec<Vec<u8>>, String>;
    /// Retrieves the validator set and their stakes for the next epoch/block in a Proof-of-Stake chain.
    async fn get_next_staked_validators(&self) -> Result<BTreeMap<String, u64>, String>;
    /// Retrieves the libp2p public key associated with a given on-chain AccountId.
    async fn get_public_key_for_account(
        &self,
        account_id: &depin_sdk_types::app::AccountId,
    ) -> Result<PublicKey, String>;
}

/// Defines the logic for applying penalties for misbehavior, specific to a consensus type.
///
/// For example, in PoS, this would slash stake, while in PoA, it might quarantine a validator.
#[async_trait]
pub trait PenaltyMechanism: Send + Sync {
    /// Applies the appropriate penalty for a given report.
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccessor, // CHANGED: Pass a dyn-safe StateAccessor
        report: &depin_sdk_types::app::FailureReport,
    ) -> Result<(), TransactionError>;
}

// Add a blanket implementation so that a reference to a PenaltyMechanism
// is also considered a PenaltyMechanism.
#[async_trait]
impl<T: PenaltyMechanism + ?Sized> PenaltyMechanism for &T {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccessor, // CHANGED: Update signature
        report: &depin_sdk_types::app::FailureReport,
    ) -> Result<(), TransactionError> {
        (**self).apply_penalty(state, report).await
    }
}

/// The core trait for a pluggable consensus engine, defining the interface for block production and validation.
#[async_trait]
pub trait ConsensusEngine<T: Clone>: PenaltyMechanism + Send + Sync {
    /// Retrieves the data necessary for consensus leader election (e.g., PoA authorities, PoS stakes).
    #[deprecated(
        note = "Consensus data should now be read from the StateView passed to decide/handle_block_proposal"
    )]
    async fn get_validator_data(
        &self,
        state_reader: &dyn ChainStateReader,
    ) -> Result<Vec<Vec<u8>>, ConsensusError>;
    /// Makes a consensus decision for the current round, determining if the local node should
    /// produce a block, wait, or propose a view change.
    async fn decide(
        &mut self,
        our_account_id: &AccountId, // Now accepts the stable AccountId
        height: u64,
        view: u64,
        parent_view: &dyn StateView, // Pass the parent state view for deterministic reads
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T>;
    /// Handles a block proposal from a peer, verifying its validity according to consensus rules
    /// (e.g., checking the producer's signature and leadership).
    async fn handle_block_proposal<CS, ST>(
        &mut self,
        block: Block<T>,
        chain_view: &dyn ChainView<CS, ST>, // Method is now generic over CS and ST
    ) -> Result<(), ConsensusError>
    where
        CS: CommitmentScheme + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static;
    /// Handles a view change proposal from a peer, which is part of liveness mechanisms
    /// in BFT-style consensus algorithms.
    async fn handle_view_change(
        &mut self,
        from: PeerId,
        height: u64,
        new_view: u64,
    ) -> Result<(), ConsensusError>;
    /// Resets any height-specific internal state of the consensus engine, typically called
    /// after a block has been successfully committed.
    fn reset(&mut self, height: u64);
}
