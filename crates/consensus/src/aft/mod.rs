pub mod experimental;
pub mod guardian_majority;

use crate::{ConsensusDecision, ConsensusEngine, PenaltyEngine, PenaltyMechanism};
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, ChainView};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::ConsensusControl;
use ioi_api::state::{StateAccess, StateManager};
use ioi_system::SystemState;
use ioi_types::app::{
    AccountId, AftRecoveredCertifiedHeaderEntry, AftRecoveredConsensusHeaderEntry,
    AftRecoveredRestartHeaderEntry, Block, BlockHeader, ConsensusVote, FailureReport,
    QuorumCertificate,
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
}
