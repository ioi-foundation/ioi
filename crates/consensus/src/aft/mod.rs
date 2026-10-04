pub mod adversarial_campaigns;
pub mod authenticated_quorum;
pub mod boundary_ring_trace;
pub mod experimental;
pub mod guardian_majority;
pub mod hash_async;
pub mod query_unanimity;
pub mod ring_membership_sim;

use crate::{ConsensusDecision, ConsensusEngine, PenaltyEngine, PenaltyMechanism};
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, ChainView};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::{ConsensusControl, NativeAftFinalizedEvidence};
use ioi_api::state::{StateAccess, StateManager};
use ioi_system::SystemState;
use ioi_types::app::{
    AccountId, AftAsyncParentProofV1, AftFallbackScopeV1, AftRecoveredCertifiedHeaderEntry,
    AftRecoveredConsensusHeaderEntry, AftRecoveredRestartHeaderEntry, AftTimeoutCertificateV1,
    AftTimeoutSafeStateV1, AftTimeoutVoteV1, Block, BlockHeader, ConsensusVote, FailureReport,
    FallbackStartCertificateV1, QuorumCertificate, TimeoutCertificate, ValidatorSetsV1,
};
use ioi_types::config::AftSafetyMode;
use ioi_types::error::{ConsensusError, TransactionError};
use libp2p::PeerId;
use std::collections::HashSet;

use self::experimental::ExperimentalSamplingEngine;
use self::guardian_majority::GuardianMajorityEngine;

/// Aft Fault Tolerance wrapper.
///
/// Production decisions are made by the deterministic aft core. The
/// retained experimental sampling path survives only as a sidecar for
/// `ExperimentalNestedGuardian`.
#[derive(Debug, Clone)]
pub struct AftEngine {
    core: GuardianMajorityEngine,
    experimental_observability: ExperimentalSamplingEngine,
}

impl Default for AftEngine {
    fn default() -> Self {
        Self::new(AftSafetyMode::ClassicBft)
    }
}

impl AftEngine {
    pub fn new(mode: AftSafetyMode) -> Self {
        Self::with_view_timeout(mode, std::time::Duration::from_secs(5))
    }

    pub fn with_view_timeout(mode: AftSafetyMode, view_timeout: std::time::Duration) -> Self {
        Self {
            core: GuardianMajorityEngine::with_view_timeout(mode, view_timeout),
            experimental_observability: ExperimentalSamplingEngine::new(),
        }
    }

    fn experimental_sampling_enabled(&self) -> bool {
        matches!(
            self.core.safety_mode(),
            AftSafetyMode::ExperimentalNestedGuardian
        )
    }
}

impl ConsensusControl for AftEngine {
    fn experimental_sample_tip(&self) -> Option<([u8; 32], u32)> {
        if self.experimental_sampling_enabled() {
            self.experimental_observability.experimental_sample_tip()
        } else {
            None
        }
    }

    fn observe_experimental_sample(&mut self, hash: [u8; 32]) {
        if self.experimental_sampling_enabled() {
            self.experimental_observability
                .observe_experimental_sample(hash);
        }
    }
}

#[async_trait]
impl PenaltyMechanism for AftEngine {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccess,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        self.core.apply_penalty(state, report).await
    }
}

impl PenaltyEngine for AftEngine {
    fn apply(
        &self,
        system: &mut dyn SystemState,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        self.core.apply(system, report)
    }
}

#[async_trait]
impl<T> ConsensusEngine<T> for AftEngine
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
        if self.experimental_sampling_enabled() {
            let _: ConsensusDecision<T> = self
                .experimental_observability
                .decide(our_account_id, height, view, parent_view, known_peers)
                .await;
        }

        self.core
            .decide(our_account_id, height, view, parent_view, known_peers)
            .await
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
        self.core.handle_block_proposal(block, chain_view).await
    }

    async fn handle_vote(&mut self, vote: ConsensusVote) -> Result<(), ConsensusError> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::handle_vote(&mut self.core, vote).await
    }

    async fn admit_local_vote(&mut self, header: &BlockHeader) -> Result<(), ConsensusError> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::admit_local_vote(&mut self.core, header)
            .await
    }

    async fn verify_synced_certificate(
        &mut self,
        qc: &QuorumCertificate,
        view: &dyn AnchoredStateView,
    ) -> Result<(), ConsensusError> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::verify_synced_certificate(
            &mut self.core,
            qc,
            view,
        )
        .await
    }

    async fn handle_quorum_certificate(
        &mut self,
        qc: QuorumCertificate,
    ) -> Result<(), ConsensusError> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::handle_quorum_certificate(
            &mut self.core,
            qc,
        )
        .await
    }

    async fn handle_timeout_certificate(
        &mut self,
        certificate: TimeoutCertificate,
    ) -> Result<(), ConsensusError> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::handle_timeout_certificate(
            &mut self.core,
            certificate,
        )
        .await
    }

    async fn handle_aft_timeout_vote(
        &mut self,
        from: PeerId,
        vote: AftTimeoutVoteV1,
    ) -> Result<(), ConsensusError> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::handle_aft_timeout_vote(
            &mut self.core,
            from,
            vote,
        )
        .await
    }

    async fn handle_aft_timeout_certificate(
        &mut self,
        certificate: AftTimeoutCertificateV1,
    ) -> Result<(), ConsensusError> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::handle_aft_timeout_certificate(
            &mut self.core,
            certificate,
        )
        .await
    }

    async fn handle_fallback_start_certificate(
        &mut self,
        certificate: FallbackStartCertificateV1,
    ) -> Result<(), ConsensusError> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::handle_fallback_start_certificate(
            &mut self.core,
            certificate,
        )
        .await
    }

    fn observe_aft_async_parent_proof(
        &mut self,
        proof: AftAsyncParentProofV1,
    ) -> Result<(), ConsensusError> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::observe_aft_async_parent_proof(
            &mut self.core,
            proof,
        )
    }

    fn aft_timeout_safe_state(&self, height: u64) -> Option<AftTimeoutSafeStateV1> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::aft_timeout_safe_state(&self.core, height)
    }

    fn aft_timeout_vote_for_relay(
        &self,
        height: u64,
        view: u64,
        voter: &AccountId,
    ) -> Option<AftTimeoutVoteV1> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::aft_timeout_vote_for_relay(
            &self.core, height, view, voter,
        )
    }

    fn configure_fallback_journal(
        &mut self,
        scope: AftFallbackScopeV1,
        path: &std::path::Path,
    ) -> Result<(), ConsensusError> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::configure_fallback_journal(
            &mut self.core,
            scope,
            path,
        )
    }

    async fn handle_view_change(
        &mut self,
        from: PeerId,
        proof_bytes: &[u8],
    ) -> Result<(), ConsensusError> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::handle_view_change(
            &mut self.core,
            from,
            proof_bytes,
        )
        .await
    }

    fn reset(&mut self, height: u64) {
        <GuardianMajorityEngine as ConsensusEngine<T>>::reset(&mut self.core, height);
        <ExperimentalSamplingEngine as ConsensusEngine<T>>::reset(
            &mut self.experimental_observability,
            height,
        );
    }

    fn observe_committed_block(
        &mut self,
        header: &BlockHeader,
        collapse: Option<&ioi_types::app::CanonicalCollapseObject>,
    ) -> bool {
        <GuardianMajorityEngine as ConsensusEngine<T>>::observe_committed_block(
            &mut self.core,
            header,
            collapse,
        )
    }

    fn observe_validator_sets(&mut self, height: u64, sets: &ValidatorSetsV1) -> bool {
        <GuardianMajorityEngine as ConsensusEngine<T>>::observe_validator_sets(
            &mut self.core,
            height,
            sets,
        )
    }

    fn canonical_collapse_for_committed_height(
        &self,
        height: u64,
    ) -> Option<ioi_types::app::CanonicalCollapseObject> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::canonical_collapse_for_committed_height(
            &self.core, height,
        )
    }

    fn observe_aft_recovered_consensus_header(
        &mut self,
        header: &AftRecoveredConsensusHeaderEntry,
    ) -> bool {
        <GuardianMajorityEngine as ConsensusEngine<T>>::observe_aft_recovered_consensus_header(
            &mut self.core,
            header,
        )
    }

    fn aft_recovered_consensus_header_for_quorum_certificate(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<AftRecoveredConsensusHeaderEntry> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::aft_recovered_consensus_header_for_quorum_certificate(
            &self.core, qc,
        )
    }

    fn observe_aft_recovered_certified_header(
        &mut self,
        header: &AftRecoveredCertifiedHeaderEntry,
    ) -> bool {
        <GuardianMajorityEngine as ConsensusEngine<T>>::observe_aft_recovered_certified_header(
            &mut self.core,
            header,
        )
    }

    fn aft_recovered_certified_header_for_quorum_certificate(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<AftRecoveredCertifiedHeaderEntry> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::aft_recovered_certified_header_for_quorum_certificate(
            &self.core, qc,
        )
    }

    fn observe_aft_recovered_restart_header(
        &mut self,
        header: &AftRecoveredRestartHeaderEntry,
    ) -> bool {
        <GuardianMajorityEngine as ConsensusEngine<T>>::observe_aft_recovered_restart_header(
            &mut self.core,
            header,
        )
    }

    fn aft_recovered_restart_header_for_quorum_certificate(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<AftRecoveredRestartHeaderEntry> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::aft_recovered_restart_header_for_quorum_certificate(
            &self.core, qc,
        )
    }

    fn retain_recovered_ancestry_ranges(&mut self, keep_ranges: &[(u64, u64)]) {
        <GuardianMajorityEngine as ConsensusEngine<T>>::retain_recovered_ancestry_ranges(
            &mut self.core,
            keep_ranges,
        )
    }

    fn header_for_quorum_certificate(&self, qc: &QuorumCertificate) -> Option<BlockHeader> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::header_for_quorum_certificate(
            &self.core, qc,
        )
    }

    fn take_pending_quorum_certificates(&mut self) -> Vec<QuorumCertificate> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::take_pending_quorum_certificates(
            &mut self.core,
        )
    }

    fn take_pending_timeout_certificates(&mut self) -> Vec<TimeoutCertificate> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::take_pending_timeout_certificates(
            &mut self.core,
        )
    }

    fn take_pending_aft_timeout_certificates(&mut self) -> Vec<AftTimeoutCertificateV1> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::take_pending_aft_timeout_certificates(
            &mut self.core,
        )
    }

    fn take_pending_fallback_starts(&mut self) -> Vec<FallbackStartCertificateV1> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::take_pending_fallback_starts(&mut self.core)
    }

    fn drain_finalized_native_quorums(&mut self) -> Vec<NativeAftFinalizedEvidence> {
        <GuardianMajorityEngine as ConsensusEngine<T>>::drain_finalized_native_quorums(
            &mut self.core,
        )
    }

    fn observe_admitted_finality_height(&mut self, height: u64) -> bool {
        <GuardianMajorityEngine as ConsensusEngine<T>>::observe_admitted_finality_height(
            &mut self.core,
            height,
        )
    }

    fn observe_validator_public_key(&mut self, protobuf_public_key: &[u8]) -> bool {
        <GuardianMajorityEngine as ConsensusEngine<T>>::observe_validator_public_key(
            &mut self.core,
            protobuf_public_key,
        )
    }
}

#[cfg(test)]
mod admit_local_vote_forwarding {
    //! P7: every wrapper forwards `admit_local_vote` to the AFT core. A wrapper that fell back to
    //! the trait's default (`Ok`) would bypass every vote rule; one block per slot is the rule a
    //! fresh engine can show, so the second block in a slot must be refused through each layer.
    use super::*;
    use crate::Consensus;
    use ioi_types::app::{ChainTransaction, SignatureSuite, StateRoot};

    fn header(transactions_byte: u8) -> BlockHeader {
        BlockHeader {
            height: 5,
            view: 0,
            parent_hash: [4u8; 32],
            parent_state_root: StateRoot(vec![4u8; 32]),
            state_root: StateRoot(vec![15u8; 32]),
            transactions_root: vec![transactions_byte; 32],
            timestamp: 5,
            timestamp_ms: 5_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([35u8; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [36u8; 32],
            producer_pubkey: vec![37u8; 32],
            oracle_counter: 5,
            oracle_trace_hash: [38u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            timeout_certificate: None,
            aft_timeout_certificate: None,
            signature: vec![39u8; 64],
        }
    }

    #[tokio::test]
    async fn aft_engine_forwards_to_the_core() {
        let mut engine = AftEngine::new(AftSafetyMode::ClassicBft);
        <AftEngine as ConsensusEngine<ChainTransaction>>::admit_local_vote(&mut engine, &header(1))
            .await
            .unwrap();
        assert!(
            <AftEngine as ConsensusEngine<ChainTransaction>>::admit_local_vote(
                &mut engine,
                &header(2)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn the_consensus_enum_forwards_to_the_aft_engine() {
        let mut engine: Consensus<ChainTransaction> =
            Consensus::Aft(AftEngine::new(AftSafetyMode::ClassicBft));
        engine.admit_local_vote(&header(1)).await.unwrap();
        assert!(engine.admit_local_vote(&header(2)).await.is_err());
    }
}

#[cfg(test)]
mod verify_synced_certificate_forwarding {
    //! P7 G1: every wrapper forwards `verify_synced_certificate` to the AFT core. A view without
    //! a membership cannot authenticate a height-5 certificate, so the core refuses; the trait's
    //! default would accept.
    use super::*;
    use crate::Consensus;
    use async_trait::async_trait;
    use ioi_api::chain::RemoteStateView;
    use ioi_types::app::ChainTransaction;
    use ioi_types::error::ChainError;

    struct EmptyView;

    #[async_trait]
    impl RemoteStateView for EmptyView {
        async fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
            Ok(None)
        }
        fn height(&self) -> u64 {
            4
        }
        fn state_root(&self) -> &[u8] {
            &[]
        }
    }

    #[async_trait]
    impl AnchoredStateView for EmptyView {
        async fn gas_used(&self) -> Result<u64, ChainError> {
            Ok(0)
        }
    }

    fn qc() -> QuorumCertificate {
        QuorumCertificate {
            height: 5,
            view: 0,
            block_hash: [5u8; 32],
            signatures: Vec::new(),
            aggregated_signature: Vec::new(),
            signers_bitfield: Vec::new(),
        }
    }

    #[tokio::test]
    async fn aft_engine_forwards_to_the_core() {
        let mut engine = AftEngine::new(AftSafetyMode::ClassicBft);
        assert!(
            <AftEngine as ConsensusEngine<ChainTransaction>>::verify_synced_certificate(
                &mut engine,
                &qc(),
                &EmptyView
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn the_consensus_enum_forwards_to_the_aft_engine() {
        let mut engine: Consensus<ChainTransaction> =
            Consensus::Aft(AftEngine::new(AftSafetyMode::ClassicBft));
        assert!(engine
            .verify_synced_certificate(&qc(), &EmptyView)
            .await
            .is_err());
    }
}
