// Path: crates/api/src/consensus/mod.rs

//! Defines the core `ConsensusEngine` trait for pluggable consensus algorithms.

use crate::chain::{AnchoredStateView, ChainView};
use crate::commitment::CommitmentScheme;
use crate::state::{StateAccessor, StateManager};
use async_trait::async_trait;
use ioi_types::app::{AccountId, Block};
use ioi_types::error::{ConsensusError, TransactionError};
use libp2p::{identity::PublicKey, PeerId};
use std::collections::{BTreeMap, HashSet};

/// Represents the decision a node should take in a given consensus round.
#[derive(Debug)]
pub enum ConsensusDecision<T> {
    /// The node is the leader and should produce a block with the given transactions.
    ProduceBlock(Vec<T>),
    /// The node is not the leader and should wait for a block proposal from a peer.
    WaitForBlock,
    /// The node has detected a stall and should propose a view change (for BFT-style algorithms).
    ProposeViewChange,
    /// The node is unable to make a decision and should stall, neither producing nor waiting.
    Stall,
}

/// Provides a read-only, abstract view of chain state needed by the consensus engine.
#[async_trait]
pub trait ChainStateReader: Send + Sync {
    /// Fetches the current set of authorities for a Proof-of-Authority chain.
    async fn get_authority_set(&self) -> Result<Vec<Vec<u8>>, String>;
    /// Fetches the pending next set of staked validators for a Proof-of-Stake chain.
    async fn get_next_staked_validators(&self) -> Result<BTreeMap<AccountId, u64>, String>;
    /// Resolves an `AccountId` to its corresponding full `PublicKey`.
    async fn get_public_key_for_account(
        &self,
        account_id: &ioi_types::app::AccountId,
    ) -> Result<PublicKey, String>;
}

/// Defines the logic for applying penalties for misbehavior, specific to a consensus type.
#[async_trait]
pub trait PenaltyMechanism: Send + Sync {
    /// Applies a penalty to an account based on a verified `FailureReport`.
    ///
    /// This method mutates state to enforce the penalty, such as slashing stake
    /// in a PoS system or quarantining an authority in a PoA system.
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccessor,
        report: &ioi_types::app::FailureReport,
    ) -> Result<(), TransactionError>;
}

#[async_trait]
impl<T: PenaltyMechanism + ?Sized> PenaltyMechanism for &T {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccessor,
        report: &ioi_types::app::FailureReport,
    ) -> Result<(), TransactionError> {
        (**self).apply_penalty(state, report).await
    }
}

/// The core trait for a pluggable consensus engine, defining the interface for block production and validation.
#[async_trait]
pub trait ConsensusEngine<T: Clone + parity_scale_codec::Encode>:
    PenaltyMechanism + Send + Sync
{
    /// Retrieves the data necessary for consensus leader election (e.g., PoA authorities, PoS stakes).
    #[deprecated(
        note = "Consensus data should now be read from the AnchoredStateView passed to decide/handle_block_proposal"
    )]
    async fn get_validator_data(
        &self,
        state_reader: &dyn ChainStateReader,
    ) -> Result<Vec<Vec<u8>>, ConsensusError>;

    /// Makes a consensus decision for the current round, determining if the local node should
    /// produce a block, wait, or propose a view change.
    async fn decide(
        &mut self,
        our_account_id: &AccountId,
        height: u64,
        view: u64,
        parent_view: &dyn AnchoredStateView, // REFACTORED: Use the deterministic, anchored view.
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T>;

    /// Handles a block proposal from a peer, verifying its validity according to consensus rules
    /// (e.g., checking the producer's signature and leadership).
    async fn handle_block_proposal<CS, ST>(
        &mut self,
        block: Block<T>,
        chain_view: &dyn ChainView<CS, ST>,
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
