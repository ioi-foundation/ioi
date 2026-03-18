// Path: crates/api/src/consensus/mod.rs

//! Defines the core `ConsensusEngine` trait for pluggable consensus algorithms.

use crate::error::CoreError;
use crate::chain::{AnchoredStateView, ChainView};
use crate::commitment::CommitmentScheme;
use crate::state::{StateAccess, StateManager};
use async_trait::async_trait;
// [MODIFIED] Added ProofOfDivergence to imports
use ioi_types::app::{
    AccountId, Block, BlockHeader, CanonicalCollapseExtensionCertificate,
    CanonicalCollapseContinuityProofSystem, CanonicalCollapseContinuityPublicInputs,
    CanonicalCollapseObject, ConsensusVote, ProofOfDivergence, QuorumCertificate, TimeoutCertificate,
};
use ioi_types::error::{ConsensusError, TransactionError};
use libp2p::PeerId;
use std::collections::HashSet;

/// Represents the decision a node should take in a given consensus round.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ConsensusDecision<T> {
    /// The node is the leader and should produce a block with the given transactions.
    /// `expected_timestamp_secs` is the exact block timestamp (UNIX seconds) the engine
    /// will later verify against. Pre-flight checks **must** use this same value.
    /// `view` is the consensus view number in which the block is produced.
    ProduceBlock {
        transactions: Vec<T>,
        expected_timestamp_secs: u64,
        expected_timestamp_ms: u64,
        view: u64,                    // <--- NEW
        parent_qc: QuorumCertificate, // <--- NEW
        previous_canonical_collapse_commitment_hash: [u8; 32],
        canonical_collapse_extension_certificate: Option<CanonicalCollapseExtensionCertificate>,
        timeout_certificate: Option<TimeoutCertificate>,
    },
    /// The node needs to cast a vote for a valid block proposal.
    /// This signals the orchestrator to sign and broadcast the vote.
    Vote {
        block_hash: [u8; 32],
        height: u64,
        view: u64,
    },
    /// The node has detected a local timeout for the current view.
    /// This signals the orchestrator to broadcast a ViewChangeVote and reset local timers.
    Timeout { view: u64, height: u64 },
    /// The node is not the leader and should wait for a block proposal from a peer.
    WaitForBlock,
    /// The node has detected a stall and should propose a view change (for BFT-style algorithms).
    ProposeViewChange,
    /// The node is unable to make a decision and should stall, neither producing nor waiting.
    Stall,

    /// The node has detected equivocation or guardian divergence locally.
    /// The orchestrator should broadcast the evidence and quarantine the node
    /// from further voting until an operator or governance action intervenes.
    Panic(ProofOfDivergence),
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

pub trait ConsensusControl: Send + Sync {
    /// Returns the current experimental witness-sampling preference when the
    /// active safety mode supports research-only audit sampling.
    fn experimental_sample_tip(&self) -> Option<([u8; 32], u32)>;

    /// Records an experimental witness-sampling observation.
    fn observe_experimental_sample(&mut self, hash: [u8; 32]);
}

/// Verifies proof-carrying recursive continuity for canonical-collapse objects.
pub trait CanonicalCollapseContinuityVerifier: Send + Sync {
    /// Verifies a continuity proof against its public inputs under the declared proof system.
    fn verify_canonical_collapse_continuity(
        &self,
        proof_system: CanonicalCollapseContinuityProofSystem,
        proof: &[u8],
        public_inputs: &CanonicalCollapseContinuityPublicInputs,
    ) -> Result<(), CoreError>;
}

/// The core trait for a pluggable consensus engine, defining the interface for block production and validation.
#[async_trait]
pub trait ConsensusEngine<T: Clone + parity_scale_codec::Encode>:
    PenaltyMechanism + ConsensusControl + Send + Sync
{
    /// Makes a consensus decision for the current round, determining if the local node should
    /// produce a block, wait, vote, or propose a view change.
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
        // metadata: ProposalMetadata, // Future extension for full Aft deterministic
    ) -> Result<(), ConsensusError>
    where
        CS: CommitmentScheme + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static;

    /// Handles a vote from a peer.
    /// This is used to aggregate votes towards a Quorum Certificate (QC).
    async fn handle_vote(&mut self, vote: ConsensusVote) -> Result<(), ConsensusError>;

    /// Handles a quorum certificate that was propagated directly by a peer.
    ///
    /// Engines that do not need explicit QC propagation can ignore this.
    async fn handle_quorum_certificate(
        &mut self,
        _qc: QuorumCertificate,
    ) -> Result<(), ConsensusError> {
        Ok(())
    }

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

    /// Returns newly formed quorum certificates that should be propagated to peers.
    fn take_pending_quorum_certificates(&mut self) -> Vec<QuorumCertificate> {
        Vec::new()
    }

    /// Records a locally committed block header so engines can use it as a
    /// deterministic liveness hint when QC propagation lags behind local commit.
    ///
    /// Engines that treat committed-header ingestion as theorem-critical can
    /// require the caller to pass a verified `CanonicalCollapseObject` alongside
    /// the header and ignore hints that are not collapse-backed.
    fn observe_committed_block(
        &mut self,
        _header: &BlockHeader,
        _collapse: Option<&CanonicalCollapseObject>,
    ) -> bool {
        true
    }

    /// Returns the locally known parent header that corresponds to a QC, if the
    /// engine has already verified or committed that branch.
    fn header_for_quorum_certificate(&self, _qc: &QuorumCertificate) -> Option<BlockHeader> {
        None
    }

    /// Resets any height-specific internal state of the consensus engine, typically called
    /// after a block has been successfully committed.
    fn reset(&mut self, height: u64);
}
