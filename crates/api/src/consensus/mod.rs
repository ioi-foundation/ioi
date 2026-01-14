// Path: crates/api/src/consensus/mod.rs

//! Defines the core `ConsensusEngine` trait for pluggable consensus algorithms.

use crate::chain::{AnchoredStateView, ChainView};
use crate::commitment::CommitmentScheme;
use crate::state::{StateAccess, StateManager};
use async_trait::async_trait;
use ioi_types::app::{AccountId, Block};
use ioi_types::error::{ConsensusError, TransactionError};
use libp2p::PeerId;
use std::collections::HashSet;

/// Represents the decision a node should take in a given consensus round.
#[derive(Debug)]
pub enum ConsensusDecision<T> {
    /// The node is the leader and should produce a block with the given transactions.
    /// `expected_timestamp_secs` is the exact block timestamp (UNIX seconds) the engine
    /// will later verify against. Pre-flight checks **must** use this same value.
    /// `view` is the consensus view number in which the block is produced.
    ProduceBlock {
        transactions: Vec<T>,
        expected_timestamp_secs: u64,
        view: u64, // <--- NEW
    },
    /// The node is not the leader and should wait for a block proposal from a peer.
    WaitForBlock,
    /// The node has detected a stall and should propose a view change (for BFT-style algorithms).
    ProposeViewChange,
    /// The node is unable to make a decision and should stall, neither producing nor waiting.
    Stall,
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
        state: &mut dyn StateAccess,
        report: &ioi_types::app::FailureReport,
    ) -> Result<(), TransactionError>;
}

#[async_trait]
impl<T: PenaltyMechanism + ?Sized> PenaltyMechanism for &T {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccess,
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
    /// Makes a consensus decision for the current round, determining if the local node should
    /// produce a block, wait, or propose a view change.
    async fn decide(
        &mut self,
        our_account_id: &AccountId,
        height: u64,
        view: u64,
        parent_view: &dyn AnchoredStateView, // deterministic, anchored view of parent (H-1)
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T>;

    /// Handles a block proposal from a peer, verifying its validity according to consensus rules
    /// (e.g., checking the producer's signature and leadership).
    async fn handle_block_proposal<CS, ST>(
        &mut self,
        block: Block<T>,
        chain_view: &dyn ChainView<CS, ST>,
        // metadata: ProposalMetadata, // Future extension for full A-DMFT
    ) -> Result<(), ConsensusError>
    where
        CS: CommitmentScheme + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static;

    /// Handles a view change proposal from a peer, which is part of liveness mechanisms
    /// in BFT-style consensus algorithms.
    ///
    /// The `proof_bytes` argument contains the serialized vote or timeout message, allowing
    /// the engine to verify signatures and update the view change tally.
    async fn handle_view_change(
        &mut self,
        from: PeerId,
        proof_bytes: &[u8],
    ) -> Result<(), ConsensusError>;

    /// Resets any height-specific internal state of the consensus engine, typically called
    /// after a block has been successfully committed.
    fn reset(&mut self, height: u64);
}