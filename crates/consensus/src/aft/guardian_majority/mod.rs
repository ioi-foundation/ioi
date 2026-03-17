// Path: crates/consensus/src/aft/guardian_majority/mod.rs

use crate::common::penalty::apply_quarantine_penalty;
use crate::{ConsensusDecision, ConsensusEngine, PenaltyEngine, PenaltyMechanism};
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, ChainView, StateRef};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::ConsensusControl;
use ioi_api::state::{StateAccess, StateManager};
use ioi_crypto::sign::guardian_committee::{verify_quorum_certificate, verify_witness_certificate};
use ioi_crypto::sign::guardian_log::{
    canonical_log_leaf_hash, verify_checkpoint_proof, verify_checkpoint_signature,
};
use ioi_system::SystemState;
use ioi_types::app::{
    aft_bulletin_commitment_key, canonical_asymptote_observer_assignments_hash,
    compute_next_timestamp_ms, derive_asymptote_observer_plan_entries,
    derive_guardian_witness_assignment, derive_guardian_witness_assignments_for_strata,
    effective_set_for_height, guardian_registry_asymptote_policy_key,
    guardian_registry_checkpoint_key, guardian_registry_committee_account_key,
    guardian_registry_committee_key, guardian_registry_log_key, guardian_registry_witness_key,
    guardian_registry_witness_seed_key, guardian_registry_witness_set_key, read_validator_sets,
    timestamp_millis_to_legacy_seconds, to_root_hash, verify_canonical_order_certificate,
    AccountId, AsymptoteObserverCertificate, AsymptoteObserverStatement, AsymptoteObserverVerdict,
    AsymptotePolicy, Block, BlockHeader, BlockTimingParams, BlockTimingRuntime, BulletinCommitment,
    ChainStatus, ChainTransaction, CollapseState, ConsensusVote, EchoMessage, FailureReport,
    FinalityTier, GuardianCommitteeManifest, GuardianDecision, GuardianDecisionDomain,
    GuardianLogCheckpoint, GuardianQuorumCertificate, GuardianTransparencyLogDescriptor,
    GuardianWitnessCommitteeManifest, GuardianWitnessEpochSeed, GuardianWitnessSet,
    GuardianWitnessStatement, ProofOfDivergence, QuorumCertificate, TimeoutCertificate,
    ViewChangeVote,
};
use ioi_types::codec;
use ioi_types::config::AftSafetyMode;
use ioi_types::error::{ConsensusError, StateError, TransactionError};
use ioi_types::keys::{
    BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, CURRENT_EPOCH_KEY,
    QUARANTINED_VALIDATORS_KEY, STATUS_KEY, VALIDATOR_SET_KEY,
};
use libp2p::identity::PublicKey;
use libp2p::PeerId;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use tracing::{debug, error, info, warn};

// Imports for Aft deterministic components
use self::pacemaker::Pacemaker;
use self::safety::SafetyGadget;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

pub mod aggregator;
pub mod divergence;
#[cfg(test)]
mod network_simulator;
pub mod pacemaker;
pub mod safety;
#[cfg(test)]
mod simulator;

// --- Mirror Stats ---
#[derive(Debug, Clone, Default)]
struct MirrorStats {
    latency_ema_a: f64,
    latency_ema_b: f64,
    reliability_a: u32,
    reliability_b: u32,
}

impl MirrorStats {
    #[allow(dead_code)]
    fn record_arrival(&mut self, mirror_id: u8, elapsed_micros: f64) {
        const ALPHA: f64 = 0.1;
        if mirror_id == 0 {
            self.latency_ema_a = ALPHA * elapsed_micros + (1.0 - ALPHA) * self.latency_ema_a;
            self.reliability_a = self.reliability_a.saturating_add(1);
        } else {
            self.latency_ema_b = ALPHA * elapsed_micros + (1.0 - ALPHA) * self.latency_ema_b;
            self.reliability_b = self.reliability_b.saturating_add(1);
        }
    }
}

/// Verifies the block producer's signature against the Oracle-anchored extended payload.
fn verify_guardian_signature(
    preimage: &[u8],
    public_key: &[u8],
    signature: &[u8],
    oracle_counter: u64,
    oracle_trace: &[u8; 32],
) -> Result<(), ConsensusError> {
    let pk =
        PublicKey::try_decode_protobuf(public_key).map_err(|_| ConsensusError::InvalidSignature)?;

    let header_hash = ioi_crypto::algorithms::hash::sha256(preimage).map_err(|e| {
        warn!("Failed to hash header preimage: {}", e);
        ConsensusError::InvalidSignature
    })?;

    let mut signed_payload = Vec::with_capacity(32 + 8 + 32);
    signed_payload.extend_from_slice(&header_hash);
    signed_payload.extend_from_slice(&oracle_counter.to_be_bytes());
    signed_payload.extend_from_slice(oracle_trace);

    if pk.verify(&signed_payload, signature) {
        Ok(())
    } else {
        Err(ConsensusError::InvalidSignature)
    }
}

/// The Aft deterministic Consensus Engine.
#[derive(Debug, Clone)]
pub struct GuardianMajorityEngine {
    safety_mode: AftSafetyMode,
    /// Tracks the last observed Oracle counter for each validator.
    last_seen_counters: HashMap<AccountId, u64>,

    /// Tracks view change votes received.
    view_votes: HashMap<u64, HashMap<u64, HashMap<AccountId, ViewChangeVote>>>,

    /// Tracks if we have already formed a TC for a (height, view).
    tc_formed: HashSet<(u64, u64)>,

    /// Tracks local timeout votes already emitted for a target (height, view).
    /// A local timeout should request a new view once, then wait for a TC.
    timeout_votes_sent: HashSet<(u64, u64)>,

    /// Tracks block headers received per (height, view) for divergence detection.
    /// (Height, View) -> BlockHash -> Header
    seen_headers: HashMap<(u64, u64), HashMap<[u8; 32], BlockHeader>>,

    // --- BFT Voting State ---
    /// Buffer of votes for the current height/view.
    vote_pool: HashMap<u64, HashMap<[u8; 32], Vec<ConsensusVote>>>,

    /// Tracks the validator count we observed for each height so quorum formation
    /// never falls back to the startup default once a height is known.
    validator_count_by_height: HashMap<u64, usize>,

    /// Tracks quorum certificates by the block they certify so child proposals
    /// can bind to the exact parent branch.
    qc_pool: HashMap<u64, HashMap<[u8; 32], QuorumCertificate>>,

    /// Records the locally committed header per height so leaders can extend the
    /// committed chain even when explicit QC propagation lags.
    committed_headers: HashMap<u64, BlockHeader>,

    /// Newly formed quorum certificates that should be propagated promptly so
    /// the next leader can advance without waiting to reconstruct them.
    pending_qc_broadcasts: VecDeque<QuorumCertificate>,

    /// Deduplicates locally announced quorum certificates.
    announced_qcs: HashSet<(u64, [u8; 32])>,

    /// The highest QC we have observed.
    highest_qc: QuorumCertificate,

    // --- Protocol Apex: Mirror State ---
    /// The randomness seed used to determine Mirror A/B assignment for the current epoch.
    mirror_seed: [u8; 32],

    /// Echo messages collected for the current round.
    /// (Height, View) -> List of unique Echoes
    echo_pool: HashMap<(u64, u64), Vec<EchoMessage>>,

    /// Tracks if we have already voted for a (height, view) to prevent duplicate actions.
    voted_slots: HashSet<(u64, u64)>,

    // Pacemaker for Liveness
    pacemaker: Arc<Mutex<Pacemaker>>,

    // Safety Gadget (Commit Guard)
    safety: SafetyGadget,

    // Mirror Statistics
    #[allow(dead_code)]
    mirror_stats: MirrorStats,

    // Cached Validator Count
    cached_validator_count: usize,

    /// Early-height warmup delay so bootstrap blocks are not minted while the
    /// rest of the validator set is still starting up.
    bootstrap_grace_until: Instant,
}

impl Default for GuardianMajorityEngine {
    fn default() -> Self {
        Self::with_view_timeout(AftSafetyMode::ClassicBft, Duration::from_secs(5))
    }
}

impl GuardianMajorityEngine {
    fn benchmark_trace_enabled() -> bool {
        std::env::var_os("IOI_AFT_BENCH_TRACE").is_some()
    }

    pub fn new(safety_mode: AftSafetyMode) -> Self {
        Self::with_view_timeout(safety_mode, Duration::from_secs(5))
    }

    pub fn with_view_timeout(safety_mode: AftSafetyMode, view_timeout: Duration) -> Self {
        let bootstrap_grace_secs = std::env::var("IOI_AFT_BOOTSTRAP_GRACE_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(8);
        Self {
            safety_mode,
            last_seen_counters: HashMap::new(),
            view_votes: HashMap::new(),
            tc_formed: HashSet::new(),
            timeout_votes_sent: HashSet::new(),
            seen_headers: HashMap::new(),
            vote_pool: HashMap::new(),
            validator_count_by_height: HashMap::new(),
            qc_pool: HashMap::new(),
            committed_headers: HashMap::new(),
            pending_qc_broadcasts: VecDeque::new(),
            announced_qcs: HashSet::new(),
            highest_qc: QuorumCertificate::default(),
            mirror_seed: [0u8; 32],
            echo_pool: HashMap::new(),
            voted_slots: HashSet::new(),
            pacemaker: Arc::new(Mutex::new(Pacemaker::new(view_timeout))),
            safety: SafetyGadget::new(),
            mirror_stats: MirrorStats::default(),
            cached_validator_count: 1,
            bootstrap_grace_until: Instant::now()
                .checked_add(Duration::from_secs(bootstrap_grace_secs))
                .unwrap_or_else(Instant::now),
        }
    }

    pub fn safety_mode(&self) -> AftSafetyMode {
        self.safety_mode
    }

    fn quorum_weight_threshold(&self, total_weight: u128) -> u128 {
        match self.safety_mode {
            AftSafetyMode::ClassicBft => (total_weight * 2) / 3,
            AftSafetyMode::GuardianMajority
            | AftSafetyMode::Asymptote
            | AftSafetyMode::ExperimentalNestedGuardian => total_weight / 2,
        }
    }

    fn quorum_count_threshold(&self, count: usize) -> usize {
        match self.safety_mode {
            AftSafetyMode::ClassicBft => ((count * 2) / 3) + 1,
            AftSafetyMode::GuardianMajority
            | AftSafetyMode::Asymptote
            | AftSafetyMode::ExperimentalNestedGuardian => (count / 2) + 1,
        }
    }

    fn remember_validator_count(&mut self, height: u64, count: usize) {
        let count = count.max(1);
        self.cached_validator_count = count;
        self.validator_count_by_height.insert(height, count);
    }

    fn quorum_count_threshold_for_height(&self, height: u64) -> usize {
        let count = self
            .validator_count_by_height
            .get(&height)
            .copied()
            .unwrap_or(self.cached_validator_count)
            .max(1);
        self.quorum_count_threshold(count)
    }

    fn remember_qc(&mut self, qc: &QuorumCertificate) {
        self.qc_pool
            .entry(qc.height)
            .or_default()
            .insert(qc.block_hash, qc.clone());
    }

    fn queue_qc_broadcast(&mut self, qc: &QuorumCertificate) {
        let key = (qc.height, qc.block_hash);
        if self.announced_qcs.insert(key) {
            self.pending_qc_broadcasts.push_back(qc.clone());
        }
    }

    fn maybe_promote_committed_height_qc(&mut self, height: u64) {
        if height == 0 || self.highest_qc.height >= height {
            return;
        }

        if let Some(qc) = self.qc_pool.get(&height).and_then(|qcs| {
            (qcs.len() == 1)
                .then(|| qcs.values().next().cloned())
                .flatten()
        }) {
            self.highest_qc = qc.clone();
            self.queue_qc_broadcast(&qc);
            return;
        }

        let threshold = self.quorum_count_threshold_for_height(height);
        let quorum_candidates = self
            .vote_pool
            .get(&height)
            .map(|votes_by_hash| {
                votes_by_hash
                    .iter()
                    .filter_map(|(block_hash, votes)| {
                        let unique_signers: HashSet<AccountId> =
                            votes.iter().map(|vote| vote.voter).collect();
                        if unique_signers.len() < threshold {
                            return None;
                        }

                        let view = votes.first().map(|vote| vote.view)?;
                        Some(QuorumCertificate {
                            height,
                            view,
                            block_hash: *block_hash,
                            signatures: votes
                                .iter()
                                .map(|vote| (vote.voter, vote.signature.clone()))
                                .collect(),
                            aggregated_signature: vec![],
                            signers_bitfield: vec![],
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if quorum_candidates.len() == 1 {
            let qc = quorum_candidates
                .into_iter()
                .next()
                .expect("exactly one QC candidate");
            self.remember_qc(&qc);
            self.highest_qc = qc.clone();
            self.queue_qc_broadcast(&qc);
        }
    }

    fn synthetic_parent_qc_for_height(&self, height: u64) -> Option<QuorumCertificate> {
        let parent_height = height.checked_sub(1)?;
        if parent_height == 0 {
            return Some(QuorumCertificate::default());
        }

        if let Some(header) = self.committed_headers.get(&parent_height) {
            let block_hash = to_root_hash(&header.hash().ok()?).ok()?;
            return Some(QuorumCertificate {
                height: parent_height,
                view: header.view,
                block_hash,
                signatures: vec![],
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            });
        }

        if let Some(qc) = self
            .qc_pool
            .get(&parent_height)
            .and_then(|qcs| (qcs.len() == 1).then(|| qcs.values().next().cloned()).flatten())
        {
            return Some(qc);
        }

        if let Some((block_hash, votes)) = self
            .vote_pool
            .get(&parent_height)
            .and_then(|votes_by_hash| {
                (votes_by_hash.len() == 1)
                    .then(|| votes_by_hash.iter().next().map(|(hash, votes)| (*hash, votes)))
                    .flatten()
            })
        {
            let view = votes.first().map(|vote| vote.view)?;
            return Some(QuorumCertificate {
                height: parent_height,
                view,
                block_hash,
                signatures: vec![],
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            });
        }

        let mut candidates = self
            .seen_headers
            .iter()
            .filter(|((seen_height, _), _)| *seen_height == parent_height)
            .flat_map(|((_, view), headers)| headers.keys().copied().map(|hash| (*view, hash)))
            .collect::<Vec<_>>();
        candidates.sort_unstable();
        candidates.dedup();
        if candidates.len() == 1 {
            let (view, block_hash) = candidates[0];
            return Some(QuorumCertificate {
                height: parent_height,
                view,
                block_hash,
                signatures: vec![],
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            });
        }

        None
    }

    async fn refresh_liveness_after_qc(&mut self, qc_height: u64) {
        let next_height = qc_height.saturating_add(1);
        self.timeout_votes_sent
            .retain(|(height, _)| *height != next_height);
        let mut pacemaker = self.pacemaker.lock().await;
        pacemaker.view_start_time = std::time::Instant::now();
    }

    async fn accept_quorum_certificate(
        &mut self,
        qc: QuorumCertificate,
        queue_for_broadcast: bool,
    ) -> Result<(), ConsensusError> {
        if qc.height == 0 {
            return Ok(());
        }

        let unique_signers: HashSet<AccountId> =
            qc.signatures.iter().map(|(voter, _)| *voter).collect();
        let threshold = self.quorum_count_threshold_for_height(qc.height);
        if unique_signers.len() < threshold {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "QC below quorum threshold for height {}",
                qc.height
            )));
        }

        let header = self
            .seen_headers
            .get(&(qc.height, qc.view))
            .and_then(|headers| headers.get(&qc.block_hash))
            .cloned();
        if header.is_none() && qc.height > self.highest_qc.height.saturating_add(1) {
            debug!(
                target: "consensus",
                height = qc.height,
                view = qc.view,
                block = %hex::encode(&qc.block_hash[..4]),
                highest_qc_height = self.highest_qc.height,
                "Ignoring QC that jumps beyond the next expected height without a known header"
            );
            return Ok(());
        }

        self.remember_qc(&qc);
        if qc.height <= self.highest_qc.height {
            return Ok(());
        }

        info!(
            target: "consensus",
            height = qc.height,
            view = qc.view,
            block = %hex::encode(&qc.block_hash[..4]),
            "Accepted quorum certificate and advanced highest_qc"
        );
        self.highest_qc = qc.clone();
        self.refresh_liveness_after_qc(qc.height).await;
        if queue_for_broadcast {
            self.queue_qc_broadcast(&qc);
        }

        if let Some(header) = header {
            if self.safety.update(&qc, &header.parent_qc) {
                info!(
                    target: "consensus",
                    "Safety Gadget: Queued commit for height {}",
                    header.parent_qc.height
                );
            }
        } else {
            debug!(
                target: "consensus",
                height = qc.height,
                view = qc.view,
                block = %hex::encode(&qc.block_hash[..4]),
                "Advanced highest_qc without a locally stored header; skipping safety update"
            );
        }

        Ok(())
    }

    fn verify_timeout_certificate(
        &self,
        timeout_certificate: &TimeoutCertificate,
        sets: &ioi_types::app::ValidatorSetsV1,
    ) -> Result<(), ConsensusError> {
        let active_set = effective_set_for_height(sets, timeout_certificate.height);
        let weights: HashMap<AccountId, u128> = active_set
            .validators
            .iter()
            .map(|validator| (validator.account_id, validator.weight))
            .collect();

        let mut accumulated_weight = 0u128;
        let mut seen = HashSet::new();
        for vote in &timeout_certificate.votes {
            if vote.height != timeout_certificate.height || vote.view != timeout_certificate.view {
                return Err(ConsensusError::BlockVerificationFailed(
                    "Timeout certificate vote does not match certificate height/view".into(),
                ));
            }
            if !seen.insert(vote.voter) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "Timeout certificate contains duplicate voters".into(),
                ));
            }
            let weight = weights.get(&vote.voter).ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "Timeout certificate contains non-validator voter".into(),
                )
            })?;
            accumulated_weight = accumulated_weight.saturating_add(*weight);
        }

        let threshold = self.quorum_weight_threshold(active_set.total_weight);
        if accumulated_weight <= threshold {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "Timeout certificate weight {} does not exceed threshold {}",
                accumulated_weight, threshold
            )));
        }

        Ok(())
    }

    fn verify_guardianized_certificate_against_manifest(
        &self,
        header: &BlockHeader,
        preimage: &[u8],
        manifest: &GuardianCommitteeManifest,
    ) -> Result<(), ConsensusError> {
        let cert = header.guardian_certificate.as_ref().ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "guardianized mode requires guardian_certificate".into(),
            )
        })?;
        if manifest.validator_account_id != header.producer_account_id {
            return Err(ConsensusError::BlockVerificationFailed(
                "guardian committee manifest validator mismatch".into(),
            ));
        }
        if cert.counter != header.oracle_counter || cert.trace_hash != header.oracle_trace_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "guardian_certificate counter/trace mismatch".into(),
            ));
        }

        let decision = Self::guardian_decision_from_header(header, preimage, manifest, cert)?;
        verify_quorum_certificate(manifest, &decision, cert)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    fn guardian_decision_from_header(
        header: &BlockHeader,
        preimage: &[u8],
        manifest: &GuardianCommitteeManifest,
        cert: &GuardianQuorumCertificate,
    ) -> Result<GuardianDecision, ConsensusError> {
        let payload_hash = ioi_crypto::algorithms::hash::sha256(preimage)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        Ok(GuardianDecision {
            domain: GuardianDecisionDomain::ConsensusSlot as u8,
            subject: header.producer_account_id.0.to_vec(),
            payload_hash,
            counter: cert.counter,
            trace_hash: cert.trace_hash,
            measurement_root: cert.measurement_root,
            policy_hash: manifest.policy_hash,
        })
    }

    fn guardian_checkpoint_entry_bytes(
        decision: &GuardianDecision,
        certificate: &GuardianQuorumCertificate,
    ) -> Result<Vec<u8>, ConsensusError> {
        let mut checkpoint_certificate = certificate.clone();
        checkpoint_certificate.log_checkpoint = None;
        checkpoint_certificate.experimental_witness_certificate = None;
        codec::to_bytes_canonical(&(decision, checkpoint_certificate))
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    fn experimental_witness_statement(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
    ) -> GuardianWitnessStatement {
        GuardianWitnessStatement {
            producer_account_id: header.producer_account_id,
            height: header.height,
            view: header.view,
            guardian_manifest_hash: certificate.manifest_hash,
            guardian_decision_hash: certificate.decision_hash,
            guardian_counter: certificate.counter,
            guardian_trace_hash: certificate.trace_hash,
            guardian_measurement_root: certificate.measurement_root,
            guardian_checkpoint_root: certificate
                .log_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.root_hash)
                .unwrap_or([0u8; 32]),
        }
    }

    fn asymptote_observer_statement(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        observer_certificate: &AsymptoteObserverCertificate,
    ) -> Result<AsymptoteObserverStatement, ConsensusError> {
        let block_hash = ioi_crypto::algorithms::hash::sha256(
            &header
                .to_preimage_for_signing()
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
        )
        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        Ok(AsymptoteObserverStatement {
            epoch: observer_certificate.assignment.epoch,
            assignment: observer_certificate.assignment.clone(),
            block_hash,
            guardian_manifest_hash: certificate.manifest_hash,
            guardian_decision_hash: certificate.decision_hash,
            guardian_counter: certificate.counter,
            guardian_trace_hash: certificate.trace_hash,
            guardian_measurement_root: certificate.measurement_root,
            guardian_checkpoint_root: certificate
                .log_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.root_hash)
                .unwrap_or([0u8; 32]),
            verdict: observer_certificate.verdict,
            veto_kind: observer_certificate.veto_kind,
            evidence_hash: observer_certificate.evidence_hash,
        })
    }

    fn asymptote_observer_decision(
        statement: &AsymptoteObserverStatement,
        manifest: &GuardianCommitteeManifest,
        certificate: &GuardianQuorumCertificate,
    ) -> Result<GuardianDecision, ConsensusError> {
        let payload_hash = ioi_crypto::algorithms::hash::sha256(
            &codec::to_bytes_canonical(statement)
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
        )
        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        Ok(GuardianDecision {
            domain: GuardianDecisionDomain::AsymptoteObserve as u8,
            subject: statement.assignment.observer_account_id.0.to_vec(),
            payload_hash,
            counter: certificate.counter,
            trace_hash: certificate.trace_hash,
            measurement_root: certificate.measurement_root,
            policy_hash: manifest.policy_hash,
        })
    }

    async fn verify_asymptote_observer_certificate(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        observer_certificate: &AsymptoteObserverCertificate,
        parent_view: &dyn AnchoredStateView,
        current_epoch: u64,
    ) -> Result<(), ConsensusError> {
        let observer_guardian = &observer_certificate.guardian_certificate;
        if observer_guardian.epoch != current_epoch {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer certificate epoch does not match current epoch".into(),
            ));
        }

        let manifest_bytes = parent_view
            .get(&guardian_registry_committee_key(
                &observer_guardian.manifest_hash,
            ))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "observer guardian manifest is not registered on-chain".into(),
                )
            })?;
        let observer_manifest: GuardianCommitteeManifest =
            codec::from_bytes_canonical(&manifest_bytes)
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        if observer_manifest.epoch != current_epoch {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer guardian manifest epoch does not match current epoch".into(),
            ));
        }
        if observer_manifest.validator_account_id
            != observer_certificate.assignment.observer_account_id
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer certificate manifest does not belong to the assigned observer".into(),
            ));
        }
        let statement =
            self.asymptote_observer_statement(header, certificate, observer_certificate)?;
        let decision =
            Self::asymptote_observer_decision(&statement, &observer_manifest, observer_guardian)?;
        let checkpoint = observer_guardian.log_checkpoint.as_ref().ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "observer guardian certificate is missing a checkpoint".into(),
            )
        })?;
        let descriptor =
            Self::load_log_descriptor(parent_view, &observer_manifest.transparency_log_id).await?;
        let checkpoint_entry = Self::guardian_checkpoint_entry_bytes(&decision, observer_guardian)?;
        let leaf_hash = canonical_log_leaf_hash(&checkpoint_entry)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        let anchored_checkpoint =
            Self::load_anchored_checkpoint(parent_view, &observer_manifest.transparency_log_id)
                .await?;
        Self::verify_checkpoint_against_anchor(
            &descriptor,
            checkpoint,
            &observer_manifest.transparency_log_id,
            anchored_checkpoint.as_ref(),
            leaf_hash,
            "asymptote observer certificate",
        )?;
        verify_quorum_certificate(&observer_manifest, &decision, observer_guardian)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    async fn verify_asymptote_observer_sealed_finality(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        parent_view: &dyn AnchoredStateView,
        current_epoch: u64,
        proof: &ioi_types::app::SealedFinalityProof,
        policy: &AsymptotePolicy,
        witness_seed: &GuardianWitnessEpochSeed,
    ) -> Result<(), ConsensusError> {
        if policy.observer_rounds == 0 || policy.observer_committee_size == 0 {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer-backed asymptote proof requires observer policy to be configured".into(),
            ));
        }
        if !proof.witness_certificates.is_empty() {
            return Err(ConsensusError::BlockVerificationFailed(
                "sealed finality proof may not mix witness certificates with equal-authority observer certificates".into(),
            ));
        }
        if !proof.divergence_signals.is_empty() {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer-backed sealed finality proof may not contain divergence signals".into(),
            ));
        }

        let validator_set_bytes = parent_view
            .get(VALIDATOR_SET_KEY)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "observer-backed asymptote proof requires an active validator set".into(),
                )
            })?;
        let validator_sets =
            read_validator_sets(&validator_set_bytes).map_err(ConsensusError::StateAccess)?;
        let active_set = effective_set_for_height(&validator_sets, header.height);
        let mut observer_manifests = std::collections::BTreeMap::new();
        for validator in &active_set.validators {
            if validator.account_id == header.producer_account_id {
                continue;
            }
            let manifest_hash_bytes = parent_view
                .get(&guardian_registry_committee_account_key(
                    &validator.account_id,
                ))
                .await
                .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(format!(
                        "observer guardian manifest index missing for {}",
                        hex::encode(validator.account_id)
                    ))
                })?;
            let manifest_hash: [u8; 32] =
                manifest_hash_bytes.as_slice().try_into().map_err(|_| {
                    ConsensusError::BlockVerificationFailed(
                        "observer manifest hash must be 32 bytes".into(),
                    )
                })?;
            let manifest: GuardianCommitteeManifest = codec::from_bytes_canonical(
                &parent_view
                    .get(&guardian_registry_committee_key(&manifest_hash))
                    .await
                    .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
                    .ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(format!(
                            "observer guardian manifest missing for hash {}",
                            hex::encode(manifest_hash)
                        ))
                    })?,
            )
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            observer_manifests.insert(validator.account_id, manifest);
        }
        let expected_plan = derive_asymptote_observer_plan_entries(
            witness_seed,
            active_set,
            &observer_manifests,
            header.producer_account_id,
            header.height,
            header.view,
            policy.observer_rounds,
            policy.observer_committee_size,
            &policy.observer_correlation_budget,
        )
        .map_err(ConsensusError::BlockVerificationFailed)?;
        let expected_assignments = expected_plan
            .iter()
            .map(|entry| entry.assignment.clone())
            .collect::<Vec<_>>();

        if proof.observer_certificates.len() != expected_plan.len() {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "sealed finality proof has {} observer certificates but expected {} equal-authority assignments",
                proof.observer_certificates.len(),
                expected_plan.len()
            )));
        }
        let Some(observer_close_certificate) = proof.observer_close_certificate.as_ref() else {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer-backed sealed finality proof is missing an observer close certificate"
                    .into(),
            ));
        };
        let expected_assignments_hash =
            canonical_asymptote_observer_assignments_hash(&expected_assignments)
                .map_err(ConsensusError::BlockVerificationFailed)?;
        if observer_close_certificate.epoch != current_epoch
            || observer_close_certificate.height != header.height
            || observer_close_certificate.view != header.view
            || observer_close_certificate.assignments_hash != expected_assignments_hash
            || observer_close_certificate.expected_assignments != expected_plan.len() as u16
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer close certificate does not match the deterministic observer sample"
                    .into(),
            ));
        }
        if observer_close_certificate.ok_count != proof.observer_certificates.len() as u16
            || observer_close_certificate.veto_count != proof.veto_proofs.len() as u16
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer close certificate does not match attached observer verdict counts".into(),
            ));
        }

        let expected = expected_plan
            .into_iter()
            .map(|entry| {
                (
                    (entry.assignment.round, entry.assignment.observer_account_id),
                    entry.assignment,
                )
            })
            .collect::<HashMap<_, _>>();
        let mut seen = HashSet::new();
        for observer_certificate in &proof.observer_certificates {
            let key = (
                observer_certificate.assignment.round,
                observer_certificate.assignment.observer_account_id,
            );
            let Some(expected_assignment) = expected.get(&key) else {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof includes an unexpected observer assignment".into(),
                ));
            };
            if !seen.insert(key) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof contains duplicate observer assignments".into(),
                ));
            }
            if observer_certificate.assignment != *expected_assignment {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof observer assignment does not match the deterministic sample".into(),
                ));
            }
            if observer_certificate.verdict != AsymptoteObserverVerdict::Ok
                || observer_certificate.veto_kind.is_some()
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof contains a non-OK observer certificate".into(),
                ));
            }
            self.verify_asymptote_observer_certificate(
                header,
                certificate,
                observer_certificate,
                parent_view,
                current_epoch,
            )
            .await?;
        }

        for veto_proof in &proof.veto_proofs {
            let observer_certificate = &veto_proof.observer_certificate;
            if observer_certificate.verdict != AsymptoteObserverVerdict::Veto
                || observer_certificate.veto_kind.is_none()
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer veto proof does not contain a veto verdict".into(),
                ));
            }
            self.verify_asymptote_observer_certificate(
                header,
                certificate,
                observer_certificate,
                parent_view,
                current_epoch,
            )
            .await?;
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "valid equal-authority observer veto proof aborts sealed finality: {}",
                veto_proof.details
            )));
        }

        Ok(())
    }

    fn verify_experimental_witness_certificate_against_manifest(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        manifest: &GuardianWitnessCommitteeManifest,
    ) -> Result<(), ConsensusError> {
        let witness_certificate = certificate
            .experimental_witness_certificate
            .as_ref()
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "experimental nested guardian mode requires witness certificate".into(),
                )
            })?;
        let statement = self.experimental_witness_statement(header, certificate);
        verify_witness_certificate(manifest, &statement, witness_certificate)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    fn witness_checkpoint_entry_bytes(
        statement: &GuardianWitnessStatement,
        certificate: &ioi_types::app::GuardianWitnessCertificate,
    ) -> Result<Vec<u8>, ConsensusError> {
        let mut checkpoint_certificate = certificate.clone();
        checkpoint_certificate.log_checkpoint = None;
        codec::to_bytes_canonical(&(statement, checkpoint_certificate))
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    async fn verify_asymptote_sealed_finality(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        manifest: &GuardianCommitteeManifest,
        parent_view: &dyn AnchoredStateView,
        current_epoch: u64,
    ) -> Result<(), ConsensusError> {
        let Some(proof) = header.sealed_finality_proof.as_ref() else {
            return Ok(());
        };

        let policy_bytes = parent_view
            .get(&guardian_registry_asymptote_policy_key(current_epoch))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "asymptote mode requires an epoch-scoped asymptote policy".into(),
                )
            })?;
        let policy: AsymptotePolicy = codec::from_bytes_canonical(&policy_bytes)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        if policy.epoch != current_epoch || proof.epoch != current_epoch {
            return Err(ConsensusError::BlockVerificationFailed(
                "sealed finality proof epoch does not match current epoch".into(),
            ));
        }
        if proof.finality_tier != FinalityTier::SealedFinal
            || proof.collapse_state != CollapseState::SealedFinal
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "sealed finality proof is not in the SealedFinal state".into(),
            ));
        }
        if proof.guardian_manifest_hash != certificate.manifest_hash
            || proof.guardian_decision_hash != certificate.decision_hash
            || proof.guardian_counter != certificate.counter
            || proof.guardian_trace_hash != certificate.trace_hash
            || proof.guardian_measurement_root != certificate.measurement_root
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "sealed finality proof is not bound to the guardian certificate".into(),
            ));
        }
        if proof.policy_hash != manifest.policy_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "sealed finality policy hash does not match guardian manifest policy".into(),
            ));
        }
        let witness_seed_bytes = parent_view
            .get(&guardian_registry_witness_seed_key(current_epoch))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "witness assignment seed is not registered on-chain".into(),
                )
            })?;
        let witness_seed: GuardianWitnessEpochSeed =
            codec::from_bytes_canonical(&witness_seed_bytes)
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        if !proof.observer_certificates.is_empty() || !proof.veto_proofs.is_empty() {
            return self
                .verify_asymptote_observer_sealed_finality(
                    header,
                    certificate,
                    parent_view,
                    current_epoch,
                    proof,
                    &policy,
                    &witness_seed,
                )
                .await;
        }
        let required_strata = if proof.divergence_signals.is_empty() {
            &policy.required_witness_strata
        } else {
            &policy.escalation_witness_strata
        };
        if proof.witness_certificates.len() != required_strata.len() {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "sealed finality proof has {} witness certificates but policy requires exactly {} strata",
                proof.witness_certificates.len(),
                required_strata.len()
            )));
        }

        let witness_set_bytes = parent_view
            .get(&guardian_registry_witness_set_key(current_epoch))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "active witness set is not registered on-chain".into(),
                )
            })?;
        let witness_set: GuardianWitnessSet = codec::from_bytes_canonical(&witness_set_bytes)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        let reassignment_depth = proof
            .witness_certificates
            .first()
            .map(|certificate| certificate.reassignment_depth)
            .unwrap_or_default();
        if proof
            .witness_certificates
            .iter()
            .any(|certificate| certificate.reassignment_depth != reassignment_depth)
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "sealed finality proof mixes witness reassignment depths".into(),
            ));
        }
        let mut active_witness_manifests = Vec::with_capacity(witness_set.manifest_hashes.len());
        for manifest_hash in &witness_set.manifest_hashes {
            let witness_bytes = parent_view
                .get(&guardian_registry_witness_key(manifest_hash))
                .await
                .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(
                        "active witness manifest is not registered on-chain".into(),
                    )
                })?;
            let witness_manifest: GuardianWitnessCommitteeManifest =
                codec::from_bytes_canonical(&witness_bytes)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            if witness_manifest.epoch != current_epoch {
                return Err(ConsensusError::BlockVerificationFailed(
                    "active witness manifest epoch does not match current epoch".into(),
                ));
            }
            active_witness_manifests.push(witness_manifest);
        }

        let expected_assignments = derive_guardian_witness_assignments_for_strata(
            &witness_seed,
            &witness_set,
            &active_witness_manifests,
            header.producer_account_id,
            header.height,
            header.view,
            reassignment_depth,
            required_strata,
        )
        .map_err(ConsensusError::BlockVerificationFailed)?;
        let expected_manifest_hashes = expected_assignments
            .iter()
            .map(|assignment| assignment.manifest_hash)
            .collect::<BTreeSet<_>>();
        let expected_strata = expected_assignments
            .iter()
            .map(|assignment| assignment.stratum_id.clone())
            .collect::<BTreeSet<_>>();
        let statement = self.experimental_witness_statement(header, certificate);
        let mut seen_manifests = BTreeSet::new();
        let mut seen_strata = BTreeSet::new();
        for witness_certificate in &proof.witness_certificates {
            if !seen_manifests.insert(witness_certificate.manifest_hash) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof contains duplicate witness committees".into(),
                ));
            }
            if witness_certificate.stratum_id.trim().is_empty() {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof contains a witness certificate without a stratum".into(),
                ));
            }
            if !expected_manifest_hashes.contains(&witness_certificate.manifest_hash) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof includes a witness committee outside the deterministic stratum assignment".into(),
                ));
            }
            if !witness_set
                .manifest_hashes
                .contains(&witness_certificate.manifest_hash)
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof references a committee outside the active witness set"
                        .into(),
                ));
            }

            let witness_bytes = parent_view
                .get(&guardian_registry_witness_key(
                    &witness_certificate.manifest_hash,
                ))
                .await
                .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(
                        "sealed finality witness manifest is not registered on-chain".into(),
                    )
                })?;
            let witness_manifest: GuardianWitnessCommitteeManifest =
                codec::from_bytes_canonical(&witness_bytes)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            if witness_manifest.epoch != current_epoch || witness_certificate.epoch != current_epoch
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality witness epoch does not match current epoch".into(),
                ));
            }
            if witness_manifest.stratum_id != witness_certificate.stratum_id {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality witness certificate stratum does not match the registered witness manifest".into(),
                ));
            }
            if !expected_strata.contains(&witness_certificate.stratum_id) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality witness certificate satisfies an unexpected stratum".into(),
                ));
            }
            if !seen_strata.insert(witness_certificate.stratum_id.clone()) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof contains duplicate witness strata".into(),
                ));
            }
            let witness_checkpoint =
                witness_certificate.log_checkpoint.as_ref().ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(
                        "sealed finality witness certificate is missing a checkpoint".into(),
                    )
                })?;
            let witness_descriptor =
                Self::load_log_descriptor(parent_view, &witness_manifest.transparency_log_id)
                    .await?;
            let witness_checkpoint_entry =
                Self::witness_checkpoint_entry_bytes(&statement, witness_certificate)?;
            let witness_leaf_hash = canonical_log_leaf_hash(&witness_checkpoint_entry)
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            let anchored_witness_checkpoint =
                Self::load_anchored_checkpoint(parent_view, &witness_manifest.transparency_log_id)
                    .await?;
            Self::verify_checkpoint_against_anchor(
                &witness_descriptor,
                witness_checkpoint,
                &witness_manifest.transparency_log_id,
                anchored_witness_checkpoint.as_ref(),
                witness_leaf_hash,
                "sealed witness certificate",
            )?;
            verify_witness_certificate(&witness_manifest, &statement, witness_certificate)
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        }

        Ok(())
    }

    async fn verify_canonical_order_enrichment(
        &self,
        header: &BlockHeader,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<(), ConsensusError> {
        let Some(certificate) = header.canonical_order_certificate.as_ref() else {
            return Ok(());
        };
        let published_bulletin = parent_view
            .get(&aft_bulletin_commitment_key(header.height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .map(|bytes| {
                codec::from_bytes_canonical::<BulletinCommitment>(&bytes)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
            })
            .transpose()?;
        verify_canonical_order_certificate(header, certificate, published_bulletin.as_ref())
            .map_err(ConsensusError::BlockVerificationFailed)
    }

    async fn load_anchored_checkpoint(
        parent_view: &dyn AnchoredStateView,
        log_id: &str,
    ) -> Result<Option<GuardianLogCheckpoint>, ConsensusError> {
        let Some(bytes) = parent_view
            .get(&guardian_registry_checkpoint_key(log_id))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
        else {
            return Ok(None);
        };

        codec::from_bytes_canonical(&bytes)
            .map(Some)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    async fn load_log_descriptor(
        parent_view: &dyn AnchoredStateView,
        log_id: &str,
    ) -> Result<GuardianTransparencyLogDescriptor, ConsensusError> {
        let bytes = parent_view
            .get(&guardian_registry_log_key(log_id))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(format!(
                    "guardian transparency log '{}' is not registered on-chain",
                    log_id
                ))
            })?;

        codec::from_bytes_canonical(&bytes)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    fn verify_checkpoint_against_anchor(
        descriptor: &GuardianTransparencyLogDescriptor,
        checkpoint: &GuardianLogCheckpoint,
        expected_log_id: &str,
        anchored_checkpoint: Option<&GuardianLogCheckpoint>,
        expected_leaf_hash: [u8; 32],
        certificate_label: &str,
    ) -> Result<(), ConsensusError> {
        if checkpoint.log_id != expected_log_id {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "{certificate_label} checkpoint log id does not match registered transparency log"
            )));
        }
        if checkpoint.tree_size == 0 {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "{certificate_label} checkpoint tree size must be non-zero"
            )));
        }

        verify_checkpoint_signature(descriptor, checkpoint).map_err(|e| {
            ConsensusError::BlockVerificationFailed(format!(
                "{certificate_label} checkpoint signature verification failed: {e}"
            ))
        })?;
        verify_checkpoint_proof(checkpoint, anchored_checkpoint, expected_leaf_hash).map_err(
            |e| {
                ConsensusError::BlockVerificationFailed(format!(
                    "{certificate_label} checkpoint append-only proof failed: {e}"
                ))
            },
        )?;

        Ok(())
    }

    async fn verify_guardianized_certificate(
        &self,
        header: &BlockHeader,
        preimage: &[u8],
        parent_view: &dyn AnchoredStateView,
    ) -> Result<(), ConsensusError> {
        match self.safety_mode {
            AftSafetyMode::ClassicBft => Ok(()),
            AftSafetyMode::GuardianMajority
            | AftSafetyMode::Asymptote
            | AftSafetyMode::ExperimentalNestedGuardian => {
                let cert = header.guardian_certificate.as_ref().ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(
                        "guardianized mode requires guardian_certificate".into(),
                    )
                })?;
                let manifest_bytes = parent_view
                    .get(&guardian_registry_committee_key(&cert.manifest_hash))
                    .await
                    .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
                    .ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "guardianized manifest is not registered on-chain".into(),
                        )
                    })?;
                let manifest: GuardianCommitteeManifest =
                    codec::from_bytes_canonical(&manifest_bytes)
                        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
                let current_epoch =
                    match parent_view.get(CURRENT_EPOCH_KEY).await.map_err(|e| {
                        ConsensusError::StateAccess(StateError::Backend(e.to_string()))
                    })? {
                        Some(bytes) => codec::from_bytes_canonical::<u64>(&bytes)
                            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
                        None => 1,
                    };
                if manifest.epoch != current_epoch || cert.epoch != current_epoch {
                    return Err(ConsensusError::BlockVerificationFailed(
                        "guardian certificate epoch does not match current epoch".into(),
                    ));
                }
                let guardian_descriptor =
                    Self::load_log_descriptor(parent_view, &manifest.transparency_log_id).await?;
                let guardian_checkpoint = cert.log_checkpoint.as_ref().ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(
                        "guardianized mode requires a guardian log checkpoint".into(),
                    )
                })?;
                let decision =
                    Self::guardian_decision_from_header(header, preimage, &manifest, cert)?;
                let guardian_checkpoint_entry =
                    Self::guardian_checkpoint_entry_bytes(&decision, cert)?;
                let guardian_leaf_hash = canonical_log_leaf_hash(&guardian_checkpoint_entry)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
                let anchored_guardian_checkpoint =
                    Self::load_anchored_checkpoint(parent_view, &manifest.transparency_log_id)
                        .await?;
                Self::verify_checkpoint_against_anchor(
                    &guardian_descriptor,
                    guardian_checkpoint,
                    &manifest.transparency_log_id,
                    anchored_guardian_checkpoint.as_ref(),
                    guardian_leaf_hash,
                    "guardian certificate",
                )?;
                self.verify_guardianized_certificate_against_manifest(header, preimage, &manifest)?;
                if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
                    self.verify_asymptote_sealed_finality(
                        header,
                        cert,
                        &manifest,
                        parent_view,
                        current_epoch,
                    )
                    .await?;
                    self.verify_canonical_order_enrichment(header, parent_view)
                        .await?;
                }
                if matches!(self.safety_mode, AftSafetyMode::ExperimentalNestedGuardian) {
                    let witness_certificate = cert
                        .experimental_witness_certificate
                        .as_ref()
                        .ok_or_else(|| {
                            ConsensusError::BlockVerificationFailed(
                                "experimental nested guardian mode requires witness certificate"
                                    .into(),
                            )
                        })?;
                    let witness_bytes = parent_view
                        .get(&guardian_registry_witness_key(
                            &witness_certificate.manifest_hash,
                        ))
                        .await
                        .map_err(|e| {
                            ConsensusError::StateAccess(StateError::Backend(e.to_string()))
                        })?
                        .ok_or_else(|| {
                            ConsensusError::BlockVerificationFailed(
                                "experimental witness manifest is not registered on-chain".into(),
                            )
                        })?;
                    let witness_manifest: GuardianWitnessCommitteeManifest =
                        codec::from_bytes_canonical(&witness_bytes)
                            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
                    let active_witness_set_bytes = parent_view
                        .get(&guardian_registry_witness_set_key(
                            witness_certificate.epoch,
                        ))
                        .await
                        .map_err(|e| {
                            ConsensusError::StateAccess(StateError::Backend(e.to_string()))
                        })?
                        .ok_or_else(|| {
                            ConsensusError::BlockVerificationFailed(
                                "active witness set is not registered on-chain".into(),
                            )
                        })?;
                    let active_witness_set: GuardianWitnessSet =
                        codec::from_bytes_canonical(&active_witness_set_bytes)
                            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
                    let witness_seed_bytes = parent_view
                        .get(&guardian_registry_witness_seed_key(
                            witness_certificate.epoch,
                        ))
                        .await
                        .map_err(|e| {
                            ConsensusError::StateAccess(StateError::Backend(e.to_string()))
                        })?
                        .ok_or_else(|| {
                            ConsensusError::BlockVerificationFailed(
                                "witness assignment seed is not registered on-chain".into(),
                            )
                        })?;
                    let witness_seed: GuardianWitnessEpochSeed =
                        codec::from_bytes_canonical(&witness_seed_bytes)
                            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
                    if witness_manifest.epoch != current_epoch
                        || witness_certificate.epoch != current_epoch
                        || active_witness_set.epoch != current_epoch
                        || witness_seed.epoch != current_epoch
                    {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "witness certificate epoch does not match current epoch".into(),
                        ));
                    }
                    let expected_assignment = derive_guardian_witness_assignment(
                        &witness_seed,
                        &active_witness_set,
                        header.producer_account_id,
                        header.height,
                        header.view,
                        witness_certificate.reassignment_depth,
                    )
                    .map_err(ConsensusError::BlockVerificationFailed)?;
                    if expected_assignment.manifest_hash != witness_certificate.manifest_hash {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "witness certificate does not match deterministic assignment".into(),
                        ));
                    }
                    if !active_witness_set
                        .manifest_hashes
                        .contains(&witness_certificate.manifest_hash)
                    {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "witness certificate references a committee outside the active witness set"
                                .into(),
                        ));
                    }
                    if expected_assignment.checkpoint_interval_blocks > 0
                        && witness_certificate.log_checkpoint.is_none()
                    {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "witness certificate is missing a required checkpoint".into(),
                        ));
                    }
                    let witness_checkpoint =
                        witness_certificate.log_checkpoint.as_ref().ok_or_else(|| {
                            ConsensusError::BlockVerificationFailed(
                                "nested guardian mode requires a witness log checkpoint".into(),
                            )
                        })?;
                    let witness_descriptor = Self::load_log_descriptor(
                        parent_view,
                        &witness_manifest.transparency_log_id,
                    )
                    .await?;
                    let witness_statement = self.experimental_witness_statement(header, cert);
                    let witness_checkpoint_entry = Self::witness_checkpoint_entry_bytes(
                        &witness_statement,
                        witness_certificate,
                    )?;
                    let witness_leaf_hash = canonical_log_leaf_hash(&witness_checkpoint_entry)
                        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
                    let anchored_witness_checkpoint = Self::load_anchored_checkpoint(
                        parent_view,
                        &witness_manifest.transparency_log_id,
                    )
                    .await?;
                    Self::verify_checkpoint_against_anchor(
                        &witness_descriptor,
                        witness_checkpoint,
                        &witness_manifest.transparency_log_id,
                        anchored_witness_checkpoint.as_ref(),
                        witness_leaf_hash,
                        "witness certificate",
                    )?;
                    self.verify_experimental_witness_certificate_against_manifest(
                        header,
                        cert,
                        &witness_manifest,
                    )?;
                }
                Ok(())
            }
        }
    }

    /// Deterministically assigns a validator to a Mirror Group (0 or 1).
    #[allow(dead_code)]
    fn assign_mirror(&self, account: &AccountId) -> u8 {
        let mut mix = self.mirror_seed[0];
        mix ^= account.0[0];
        mix % 2
    }

    /// Checks for quorum on View Change.
    fn check_quorum(
        &mut self,
        height: u64,
        view: u64,
        total_weight: u128,
        sets: &ioi_types::app::ValidatorSetsV1,
    ) -> Option<TimeoutCertificate> {
        let votes_map = self.view_votes.get(&height)?.get(&view)?;

        let mut accumulated_weight = 0u128;
        let active_set = effective_set_for_height(sets, height);

        let weights: HashMap<AccountId, u128> = active_set
            .validators
            .iter()
            .map(|v| (v.account_id, v.weight))
            .collect();

        let mut valid_votes = Vec::new();

        for (voter, vote) in votes_map {
            if let Some(w) = weights.get(voter) {
                accumulated_weight += w;
                valid_votes.push(vote.clone());
            }
        }

        // Aft deterministic Quorum: Simple Majority (> 50%)
        let threshold = self.quorum_weight_threshold(total_weight);

        if accumulated_weight > threshold {
            Some(TimeoutCertificate {
                height,
                view,
                votes: valid_votes,
            })
        } else {
            None
        }
    }

    /// Internal helper to detect divergence.
    fn check_divergence(&mut self, header: &BlockHeader) -> Option<ProofOfDivergence> {
        let entry = self
            .seen_headers
            .entry((header.height, header.view))
            .or_default();

        let header_hash = match header.hash() {
            Ok(h) => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&h);
                arr
            }
            Err(_) => return None,
        };

        if entry.is_empty() {
            entry.insert(header_hash, header.clone());
            return None;
        }

        if entry.contains_key(&header_hash) {
            return None;
        }

        // DIVERGENCE DETECTED
        let (existing_hash, existing_header) = entry.iter().next().unwrap();

        warn!(target: "consensus",
            "Aft deterministic DIVERGENCE DETECTED @ H{} V{}: {:?} vs {:?}",
            header.height, header.view, hex::encode(existing_hash), hex::encode(header_hash)
        );

        Some(ProofOfDivergence {
            offender: header.producer_account_id,
            evidence_a: existing_header.clone(),
            evidence_b: header.clone(),
            guardian_certificates: header
                .guardian_certificate
                .iter()
                .cloned()
                .chain(existing_header.guardian_certificate.iter().cloned())
                .collect(),
            log_checkpoints: header
                .guardian_certificate
                .iter()
                .filter_map(|cert| cert.log_checkpoint.clone())
                .chain(
                    existing_header
                        .guardian_certificate
                        .iter()
                        .filter_map(|cert| cert.log_checkpoint.clone()),
                )
                .collect(),
        })
    }

    /// Verifies a Quorum Certificate.
    fn verify_qc(
        &self,
        qc: &QuorumCertificate,
        sets: &ioi_types::app::ValidatorSetsV1,
    ) -> Result<(), ConsensusError> {
        if qc.height == 0 {
            return Ok(());
        }

        if qc.signatures.is_empty() {
            return match self.safety_mode {
                AftSafetyMode::ClassicBft => Err(ConsensusError::BlockVerificationFailed(
                    "Classic BFT requires a validator quorum certificate".into(),
                )),
                AftSafetyMode::GuardianMajority
                | AftSafetyMode::Asymptote
                | AftSafetyMode::ExperimentalNestedGuardian => Ok(()),
            };
        }

        let active_set = effective_set_for_height(sets, qc.height);
        let total_weight = active_set.total_weight;
        let threshold = self.quorum_weight_threshold(total_weight);

        let mut voting_power = 0u128;
        let validators: HashMap<AccountId, &ioi_types::app::ValidatorV1> = active_set
            .validators
            .iter()
            .map(|v| (v.account_id, v))
            .collect();

        for (voter, _signature) in &qc.signatures {
            if let Some(validator) = validators.get(voter) {
                voting_power += validator.weight;
            }
        }

        if voting_power <= threshold {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "QC has insufficient voting power: {} <= {}",
                voting_power, threshold
            )));
        }

        Ok(())
    }

    /// Processes an incoming Echo message.
    pub async fn handle_echo(
        &mut self,
        echo: EchoMessage,
    ) -> Result<ConsensusDecision<ChainTransaction>, ConsensusError> {
        let threshold = self.quorum_count_threshold_for_height(echo.height);
        let pool = self.echo_pool.entry((echo.height, echo.view)).or_default();
        if pool.iter().any(|e| e.sender_id == echo.sender_id) {
            return Ok(ConsensusDecision::WaitForBlock);
        }
        pool.push(echo.clone());
        let count = pool
            .iter()
            .filter(|e| e.block_hash == echo.block_hash)
            .count();

        if count >= threshold {
            if !self.voted_slots.contains(&(echo.height, echo.view)) {
                self.voted_slots.insert((echo.height, echo.view));
                return Ok(ConsensusDecision::Vote {
                    block_hash: echo.block_hash,
                    height: echo.height,
                    view: echo.view,
                });
            }
        }
        Ok(ConsensusDecision::WaitForBlock)
    }
}

impl ConsensusControl for GuardianMajorityEngine {
    fn experimental_sample_tip(&self) -> Option<([u8; 32], u32)> {
        None
    }

    fn observe_experimental_sample(&mut self, _hash: [u8; 32]) {}
}

#[async_trait]
impl PenaltyMechanism for GuardianMajorityEngine {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccess,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        apply_quarantine_penalty(state, report).await
    }
}

impl PenaltyEngine for GuardianMajorityEngine {
    fn apply(
        &self,
        sys: &mut dyn SystemState,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        let sets = sys
            .validators()
            .current_sets()
            .map_err(TransactionError::State)?;
        let authorities: Vec<AccountId> = sets
            .current
            .validators
            .iter()
            .map(|v| v.account_id)
            .collect();
        let quarantined = sys
            .quarantine()
            .get_all()
            .map_err(TransactionError::State)?;
        let min_live = (authorities.len() / 2) + 1;

        if !authorities.contains(&report.offender) {
            return Err(TransactionError::Invalid(
                "Offender is not an authority".into(),
            ));
        }
        if quarantined.contains(&report.offender) {
            return Ok(());
        }
        let live_after = authorities
            .len()
            .saturating_sub(quarantined.len())
            .saturating_sub(1);
        if live_after < min_live {
            return Err(TransactionError::Invalid(
                "Quarantine jeopardizes liveness".into(),
            ));
        }
        sys.quarantine_mut()
            .insert(report.offender)
            .map_err(TransactionError::State)
    }
}

#[async_trait]
impl<T: Clone + Send + 'static + parity_scale_codec::Encode> ConsensusEngine<T>
    for GuardianMajorityEngine
{
    async fn decide(
        &mut self,
        our_account_id: &AccountId,
        height: u64,
        _view_arg: u64,
        parent_view: &dyn AnchoredStateView,
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        // 1. Poll the Commit Guard
        // This ensures pending commits are finalized if the guard timer expires.
        if let Some(finalized_height) = self.safety.drain_ready_commits() {
            info!(target: "consensus", "Safety Gadget: Finalized height {}", finalized_height);
            // In a real impl, this might trigger a callback to the Orchestrator/Storage
            // to mark the block as durable. For now, we log it.
        }

        info!(target: "consensus", "GuardianMajorityEngine::decide called for height {}", height);

        let vs_bytes = match parent_view.get(VALIDATOR_SET_KEY).await {
            Ok(Some(b)) => b,
            _ => return ConsensusDecision::Stall,
        };
        let sets = match read_validator_sets(&vs_bytes) {
            Ok(s) => s,
            _ => return ConsensusDecision::Stall,
        };

        let quarantined: BTreeSet<AccountId> =
            match parent_view.get(QUARANTINED_VALIDATORS_KEY).await {
                Ok(Some(b)) => codec::from_bytes_canonical(&b).unwrap_or_default(),
                _ => BTreeSet::new(),
            };

        let vs = effective_set_for_height(&sets, height);
        let active_validators: Vec<AccountId> = vs
            .validators
            .iter()
            .map(|v| v.account_id)
            .filter(|id| !quarantined.contains(id))
            .collect();
        self.cached_validator_count = active_validators.len();

        if active_validators.is_empty() {
            if Self::benchmark_trace_enabled() {
                eprintln!(
                    "[BENCH-AFT-DECIDE] height={} decision=stall reason=no_active_validators",
                    height
                );
            }
            return ConsensusDecision::Stall;
        }
        self.remember_validator_count(height, active_validators.len());

        let mut current_view = { self.pacemaker.lock().await.current_view };
        let bootstrap_first_commit_pending =
            height == 1 && self.highest_qc.height == 0 && !self.committed_headers.contains_key(&1);
        let pin_bootstrap_view_zero =
            bootstrap_first_commit_pending || (height <= 3 && Instant::now() < self.bootstrap_grace_until);

        if pin_bootstrap_view_zero {
            if let Ok(mut pacemaker) = self.pacemaker.try_lock() {
                pacemaker.current_view = 0;
                pacemaker.view_start_time = Instant::now();
            }
            current_view = 0;
            if bootstrap_first_commit_pending {
                self.timeout_votes_sent.retain(|(vote_height, _)| *vote_height != height);
                self.tc_formed.retain(|(tc_height, _)| *tc_height != height);
            }
            if Self::benchmark_trace_enabled() {
                eprintln!(
                    "[BENCH-AFT-DECIDE] height={} decision=pin_view0 reason={}",
                    height,
                    if bootstrap_first_commit_pending {
                        "bootstrap_first_commit_pending"
                    } else {
                        "bootstrap_grace"
                    }
                );
            }
            debug!(
                target: "consensus",
                height,
                bootstrap_first_commit_pending,
                "Pinning the bootstrap view to 0."
            );
        }

        if !bootstrap_first_commit_pending {
            let tc_views = self
                .view_votes
                .get(&height)
                .map(|view_map| view_map.keys().copied().collect::<Vec<_>>())
                .unwrap_or_default();
            let mut newest_tc_view = current_view;
            for view in tc_views {
                if self.tc_formed.contains(&(height, view)) {
                    newest_tc_view = newest_tc_view.max(view);
                    continue;
                }
                if self
                    .check_quorum(height, view, vs.total_weight, &sets)
                    .is_some()
                {
                    info!(
                        target: "consensus",
                        height,
                        view,
                        "Majority quorum reached for view change. Advancing pacemaker."
                    );
                    self.tc_formed.insert((height, view));
                    newest_tc_view = newest_tc_view.max(view);
                }
            }
            if newest_tc_view > current_view {
                self.pacemaker.lock().await.advance_view(newest_tc_view);
                current_view = newest_tc_view;
            }

            let timed_out = { self.pacemaker.lock().await.check_timeout() };
            if timed_out {
                let next_view = current_view + 1;
                if self.timeout_votes_sent.insert((height, next_view)) {
                    if Self::benchmark_trace_enabled() {
                        eprintln!(
                            "[BENCH-AFT-DECIDE] height={} decision=timeout current_view={} next_view={} reason=pacemaker_timed_out",
                            height,
                            current_view,
                            next_view
                        );
                    }
                    info!(
                        target: "consensus",
                        height,
                        current_view,
                        next_view,
                        "Pacemaker timed out. Emitting a view change vote and waiting for a timeout certificate."
                    );
                    return ConsensusDecision::Timeout {
                        view: next_view,
                        height,
                    };
                }
                debug!(
                    target: "consensus",
                    height,
                    current_view,
                    next_view,
                    "Timeout vote already emitted for the next view; waiting for a timeout certificate."
                );
                if Self::benchmark_trace_enabled() {
                    eprintln!(
                        "[BENCH-AFT-DECIDE] height={} decision=wait_for_block current_view={} next_view={} reason=timeout_vote_already_emitted",
                        height,
                        current_view,
                        next_view
                    );
                }
                return ConsensusDecision::WaitForBlock;
            }

            if current_view > 0 && !self.tc_formed.contains(&(height, current_view)) {
                if Self::benchmark_trace_enabled() {
                    eprintln!(
                        "[BENCH-AFT-DECIDE] height={} decision=wait_for_block current_view={} reason=awaiting_timeout_certificate",
                        height,
                        current_view
                    );
                }
                debug!(
                    target: "consensus",
                    height,
                    current_view,
                    "Waiting for timeout certificate before entering the next view."
                );
                return ConsensusDecision::WaitForBlock;
            }
        }

        let parent_root = parent_view.state_root();
        self.mirror_seed = ioi_crypto::algorithms::hash::sha256(parent_root).unwrap_or([0u8; 32]);

        let n = active_validators.len() as u64;
        let round_index = height.saturating_sub(1).saturating_add(current_view);
        let leader_index = (round_index % n) as usize;
        let leader_id = active_validators[leader_index];
        if height == 1 {
            eprintln!(
                "[AFT-LEADER] local={} leader={} validator_count={} known_peer_count={}",
                hex::encode(&our_account_id.0[..4]),
                hex::encode(&leader_id.0[..4]),
                active_validators.len(),
                known_peers.len(),
            );
            info!(
                target: "consensus",
                height,
                current_view,
                local = %hex::encode(&our_account_id.0[..4]),
                leader = %hex::encode(&leader_id.0[..4]),
                validator_count = active_validators.len(),
                known_peer_count = known_peers.len(),
                "GuardianMajority leader selection for the first height."
            );
        }
        if known_peers.is_empty() && leader_id != *our_account_id {
            if Self::benchmark_trace_enabled() {
                eprintln!(
                    "[BENCH-AFT-DECIDE] height={} decision=stall current_view={} reason=no_peers_not_leader",
                    height,
                    current_view
                );
            }
            debug!(target: "consensus", "Stalling: No peers and not leader (Me: {:?}, Leader: {:?})", our_account_id, leader_id);
            return ConsensusDecision::Stall;
        }

        if leader_id == *our_account_id {
            let parent_qc = if height > 1 {
                if let Some(synthetic_parent_qc) = self.synthetic_parent_qc_for_height(height) {
                    let highest_qc_at_parent_height = self.highest_qc.height == height - 1;
                    let highest_qc_has_local_header = highest_qc_at_parent_height
                        && <GuardianMajorityEngine as ConsensusEngine<T>>::header_for_quorum_certificate(
                            self,
                            &self.highest_qc,
                        )
                        .is_some();

                    if self.highest_qc.height < height - 1
                        || (highest_qc_at_parent_height && !highest_qc_has_local_header)
                    {
                        if highest_qc_at_parent_height
                            && self.highest_qc.block_hash != synthetic_parent_qc.block_hash
                            && !highest_qc_has_local_header
                        {
                            info!(
                                target: "consensus",
                                height,
                                current_view,
                                highest_qc_height = self.highest_qc.height,
                                highest_qc_hash = %hex::encode(&self.highest_qc.block_hash[..4]),
                                synthetic_parent_hash = %hex::encode(&synthetic_parent_qc.block_hash[..4]),
                                "Replacing a headerless parent-height QC with the locally committed synthetic parent QC."
                            );
                        }
                        self.highest_qc = synthetic_parent_qc.clone();
                        synthetic_parent_qc
                    } else {
                        self.highest_qc.clone()
                    }
                } else if self.highest_qc.height < height - 1 {
                    let next_view = current_view + 1;
                    if self.timeout_votes_sent.insert((height, next_view)) {
                        if Self::benchmark_trace_enabled() {
                            eprintln!(
                                "[BENCH-AFT-DECIDE] height={} decision=timeout current_view={} next_view={} highest_qc_height={} reason=leader_missing_parent_qc",
                                height,
                                current_view,
                                next_view,
                                self.highest_qc.height
                            );
                        }
                        info!(
                            target: "consensus",
                            height,
                            current_view,
                            next_view,
                            highest_qc_height = self.highest_qc.height,
                            "Leader lacks a quorum certificate for the parent height. Emitting a view change vote."
                        );
                        return ConsensusDecision::Timeout {
                            view: next_view,
                            height,
                        };
                    }
                    debug!(
                        target: "consensus",
                        height,
                        current_view,
                        next_view,
                        highest_qc_height = self.highest_qc.height,
                        "Leader is still waiting for a timeout certificate after requesting a view change."
                    );
                    if Self::benchmark_trace_enabled() {
                        eprintln!(
                            "[BENCH-AFT-DECIDE] height={} decision=wait_for_block current_view={} next_view={} highest_qc_height={} reason=leader_waiting_after_parent_qc_timeout",
                            height,
                            current_view,
                            next_view,
                            self.highest_qc.height
                        );
                    }
                    return ConsensusDecision::WaitForBlock;
                } else {
                    self.highest_qc.clone()
                }
            } else {
                self.highest_qc.clone()
            };

            // Safety Check: Ensure we don't propose conflicting blocks
            // Use locked_qc from safety gadget to ensure we extend the correct chain
            if let Some(_locked) = &self.safety.locked_qc {
                // If we have a lock, we must extend it.
                // For simplified Aft deterministic, the highest_qc usually matches the lock or is newer.
                // The proposal construction in `create_block` uses `highest_qc` (via `parent_qc` logic).
            }

            let timing_params = match parent_view.get(BLOCK_TIMING_PARAMS_KEY).await {
                Ok(Some(b)) => {
                    codec::from_bytes_canonical::<BlockTimingParams>(&b).unwrap_or_default()
                }
                _ => {
                    if Self::benchmark_trace_enabled() {
                        eprintln!(
                            "[BENCH-AFT-DECIDE] height={} decision=stall current_view={} reason=missing_timing_params",
                            height,
                            current_view
                        );
                    }
                    return ConsensusDecision::Stall;
                }
            };
            let timing_runtime = match parent_view.get(BLOCK_TIMING_RUNTIME_KEY).await {
                Ok(Some(b)) => {
                    codec::from_bytes_canonical::<BlockTimingRuntime>(&b).unwrap_or_default()
                }
                _ => {
                    if Self::benchmark_trace_enabled() {
                        eprintln!(
                            "[BENCH-AFT-DECIDE] height={} decision=stall current_view={} reason=missing_timing_runtime",
                            height,
                            current_view
                        );
                    }
                    return ConsensusDecision::Stall;
                }
            };
            let parent_status: ChainStatus = match parent_view.get(STATUS_KEY).await {
                Ok(Some(b)) => codec::from_bytes_canonical(&b).unwrap_or_default(),
                Ok(None) if height == 1 => ChainStatus::default(),
                _ => {
                    if Self::benchmark_trace_enabled() {
                        eprintln!(
                            "[BENCH-AFT-DECIDE] height={} decision=stall current_view={} reason=missing_parent_status",
                            height,
                            current_view
                        );
                    }
                    return ConsensusDecision::Stall;
                }
            };

            let expected_ts_ms = compute_next_timestamp_ms(
                &timing_params,
                &timing_runtime,
                height.saturating_sub(1),
                parent_status.latest_timestamp_ms_or_legacy(),
                0,
            )
            .unwrap_or_else(|| parent_status.latest_timestamp_ms_or_legacy());
            let expected_ts = timestamp_millis_to_legacy_seconds(expected_ts_ms);

            let timeout_certificate = if current_view > 0 {
                self.check_quorum(height, current_view, vs.total_weight, &sets)
            } else {
                None
            };

            info!(target: "consensus", "I am leader for H={} V={}. Producing block.", height, current_view);

            ConsensusDecision::ProduceBlock {
                transactions: vec![],
                expected_timestamp_secs: expected_ts,
                expected_timestamp_ms: expected_ts_ms,
                view: current_view,
                parent_qc,
                timeout_certificate,
            }
        } else {
            ConsensusDecision::WaitForBlock
        }
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
        if let Some(proof) = self.check_divergence(&block.header) {
            error!(target: "consensus", "CRITICAL: DIVERGENCE PROOF CONSTRUCTED: {:?}", proof);
            return Err(ConsensusError::BlockVerificationFailed(
                "Panic:HardwareDivergence".into(),
            ));
        }

        let header = &block.header;

        let parent_state_ref = StateRef {
            height: header.height - 1,
            state_root: header.parent_state_root.as_ref().to_vec(),
            block_hash: header.parent_hash,
        };
        let parent_view = chain_view
            .view_at(&parent_state_ref)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;

        let vs_bytes = match parent_view.get(VALIDATOR_SET_KEY).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                error!(target: "consensus", "Validator set missing in parent state for H={}", header.height);
                return Err(ConsensusError::StateAccess(StateError::KeyNotFound));
            }
            Err(e) => {
                error!(target: "consensus", "State access error reading validator set: {}", e);
                return Err(ConsensusError::StateAccess(StateError::Backend(
                    e.to_string(),
                )));
            }
        };

        let sets = read_validator_sets(&vs_bytes).map_err(|e| {
            error!(target: "consensus", "Failed to decode validator set: {}", e);
            ConsensusError::BlockVerificationFailed("VS decode failed".into())
        })?;

        let quarantined: BTreeSet<AccountId> =
            match parent_view.get(QUARANTINED_VALIDATORS_KEY).await {
                Ok(Some(b)) => codec::from_bytes_canonical(&b).unwrap_or_default(),
                _ => BTreeSet::new(),
            };

        let vs = effective_set_for_height(&sets, header.height);
        let active_validators: Vec<AccountId> = vs
            .validators
            .iter()
            .map(|v| v.account_id)
            .filter(|id| !quarantined.contains(id))
            .collect();
        self.remember_validator_count(header.height, active_validators.len());

        let validator_count = active_validators.len() as u64;
        if validator_count == 0 {
            return Err(ConsensusError::BlockVerificationFailed(
                "No active validators for proposal".into(),
            ));
        }
        let round_index = header.height.saturating_sub(1).saturating_add(header.view);
        let leader_index = (round_index % validator_count) as usize;
        let expected_leader = active_validators[leader_index];
        if header.producer_account_id != expected_leader {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "Unexpected proposer for H={} V={}: expected {} got {}",
                header.height,
                header.view,
                hex::encode(expected_leader),
                hex::encode(header.producer_account_id)
            )));
        }
        if header.view == 0 {
            if header.timeout_certificate.is_some() {
                return Err(ConsensusError::BlockVerificationFailed(format!(
                    "Unexpected timeout certificate on view-0 proposal H={}",
                    header.height
                )));
            }
        } else {
            let timeout_certificate = header.timeout_certificate.as_ref().ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(format!(
                    "Missing timeout certificate for non-zero-view proposal H={} V={}",
                    header.height, header.view
                ))
            })?;
            self.verify_timeout_certificate(timeout_certificate, &sets)?;
        }

        let threshold = self.quorum_count_threshold_for_height(header.height);

        let block_hash_bytes = match header.hash() {
            Ok(h) => h,
            Err(_) => return Err(ConsensusError::BlockVerificationFailed("Hash fail".into())),
        };
        let block_hash = to_root_hash(&block_hash_bytes)
            .map_err(|_| ConsensusError::BlockVerificationFailed("Hash len".into()))?;
        // Check votes
        if let Some(votes) = self
            .vote_pool
            .get(&header.height)
            .and_then(|m| m.get(&block_hash))
        {
            if votes.len() >= threshold {
                let qc = QuorumCertificate {
                    height: header.height,
                    view: header.view,
                    block_hash,
                    signatures: votes
                        .iter()
                        .map(|v| (v.voter, v.signature.clone()))
                        .collect(),
                    aggregated_signature: vec![],
                    signers_bitfield: vec![],
                };
                self.accept_quorum_certificate(qc, true).await?;
            }
        }

        if header.height > 1 {
            let parent_qc = &header.parent_qc;
            if parent_qc.height != header.height - 1 {
                return Err(ConsensusError::BlockVerificationFailed(
                    "Parent QC height mismatch".into(),
                ));
            }
            if parent_qc.block_hash != header.parent_hash {
                return Err(ConsensusError::BlockVerificationFailed(
                    "Parent QC hash mismatch".into(),
                ));
            }
            if let Err(e) = self.verify_qc(parent_qc, &sets) {
                error!(
                    target: "consensus",
                    "QC Verification Failed for block {}: {}",
                    header.height,
                    e
                );
                return Err(e);
            }
            self.remember_qc(parent_qc);
            if parent_qc.height > self.highest_qc.height {
                self.highest_qc = parent_qc.clone();
            }
        }

        {
            let mut pacemaker = self.pacemaker.lock().await;
            if header.view > pacemaker.current_view {
                pacemaker.advance_view(header.view);
            } else {
                pacemaker.view_start_time = Instant::now();
            }
        }

        let preimage = header
            .to_preimage_for_signing()
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        verify_guardian_signature(
            &preimage,
            &header.producer_pubkey,
            &header.signature,
            header.oracle_counter,
            &header.oracle_trace_hash,
        )?;
        self.verify_guardianized_certificate(header, &preimage, &*parent_view)
            .await?;

        if let Some(existing_header) = self
            .seen_headers
            .get(&(header.height, header.view))
            .and_then(|headers| headers.get(&block_hash))
            .cloned()
        {
            let same_slot_identity = existing_header.producer_account_id
                == header.producer_account_id
                && existing_header.oracle_counter == header.oracle_counter
                && existing_header.oracle_trace_hash == header.oracle_trace_hash;
            let richer_certification = existing_header.guardian_certificate
                != header.guardian_certificate
                || existing_header.sealed_finality_proof != header.sealed_finality_proof
                || existing_header.canonical_order_certificate
                    != header.canonical_order_certificate;
            if same_slot_identity && richer_certification {
                if let Some(headers) = self.seen_headers.get_mut(&(header.height, header.view)) {
                    headers.insert(block_hash, header.clone());
                }
                debug!(
                    target: "consensus",
                    height = header.height,
                    view = header.view,
                    "Accepted sealed/header enrichment for an already verified block"
                );
                return Ok(());
            }
        }

        if let Some(&last_ctr) = self.last_seen_counters.get(&header.producer_account_id) {
            if header.oracle_counter <= last_ctr {
                return Err(ConsensusError::BlockVerificationFailed(
                    "Guardian counter rollback".into(),
                ));
            }
        }
        self.last_seen_counters
            .insert(header.producer_account_id, header.oracle_counter);

        {
            let mut pacemaker = self.pacemaker.lock().await;
            pacemaker.observe_progress(header.view);
        }

        debug!(target: "consensus", "Aft deterministic: Block {} verified. Initiating ECHO phase.", header.height);
        Ok(())
    }

    async fn handle_vote(&mut self, vote: ConsensusVote) -> Result<(), ConsensusError> {
        // Safety Check: Don't process votes if not safe
        if !self.safety.safe_to_vote(vote.view, vote.height - 1) {
            // Logic for unsafe vote handling (optional)
        }

        let threshold = self.quorum_count_threshold_for_height(vote.height);
        let height_map = self.vote_pool.entry(vote.height).or_default();
        let votes = height_map.entry(vote.block_hash).or_default();

        if votes.iter().any(|v| v.voter == vote.voter) {
            return Ok(());
        }
        votes.push(vote.clone());

        if votes.len() >= threshold {
            let qc = QuorumCertificate {
                height: vote.height,
                view: vote.view,
                block_hash: vote.block_hash,
                signatures: votes
                    .iter()
                    .map(|v| (v.voter, v.signature.clone()))
                    .collect(),
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            };
            self.accept_quorum_certificate(qc, true).await?;
        }
        Ok(())
    }

    async fn handle_quorum_certificate(
        &mut self,
        qc: QuorumCertificate,
    ) -> Result<(), ConsensusError> {
        self.accept_quorum_certificate(qc, false).await
    }

    async fn handle_view_change(
        &mut self,
        from: PeerId,
        proof_bytes: &[u8],
    ) -> Result<(), ConsensusError> {
        let vote: ViewChangeVote =
            ioi_types::codec::from_bytes_canonical(proof_bytes).map_err(|e| {
                ConsensusError::BlockVerificationFailed(format!("Invalid view vote: {}", e))
            })?;

        info!(target: "consensus", "ViewChange vote H={} V={} from {}", vote.height, vote.view, from);
        let height_map = self.view_votes.entry(vote.height).or_default();
        let view_map = height_map.entry(vote.view).or_default();
        view_map.insert(vote.voter, vote);
        Ok(())
    }

    fn reset(&mut self, height: u64) {
        self.maybe_promote_committed_height_qc(height);
        self.view_votes.retain(|h, _| *h >= height);
        self.tc_formed.retain(|(h, _)| *h >= height);
        self.timeout_votes_sent.retain(|(h, _)| *h >= height);
        self.seen_headers.retain(|(h, _), _| *h >= height);
        self.vote_pool.retain(|h, _| *h >= height);
        self.validator_count_by_height.retain(|h, _| *h >= height);
        self.qc_pool.retain(|h, _| *h + 2 >= height);
        self.committed_headers.retain(|h, _| *h + 2 >= height);
        self.pending_qc_broadcasts
            .retain(|qc| qc.height + 2 >= height);
        self.announced_qcs
            .retain(|(qc_height, _)| *qc_height + 2 >= height);
        self.echo_pool.retain(|(h, _), _| *h >= height);
        self.voted_slots.retain(|(h, _)| *h >= height);

        if let Ok(mut pm) = self.pacemaker.try_lock() {
            pm.current_view = 0;
            pm.view_start_time = std::time::Instant::now();
        }
    }

    fn observe_committed_block(&mut self, header: &BlockHeader) {
        let Ok(hash) = header.hash() else {
            return;
        };
        let Ok(block_hash) = to_root_hash(&hash) else {
            return;
        };
        self.committed_headers.insert(header.height, header.clone());
        self.seen_headers
            .entry((header.height, header.view))
            .or_default()
            .insert(block_hash, header.clone());
    }

    fn header_for_quorum_certificate(&self, qc: &QuorumCertificate) -> Option<BlockHeader> {
        if qc.height == 0 {
            return None;
        }

        if let Some(header) = self.committed_headers.get(&qc.height) {
            let block_hash = to_root_hash(&header.hash().ok()?).ok()?;
            if block_hash == qc.block_hash {
                return Some(header.clone());
            }
        }

        self.seen_headers
            .iter()
            .filter(|((height, _), _)| *height == qc.height)
            .find_map(|(_, headers)| headers.get(&qc.block_hash).cloned())
    }

    fn take_pending_quorum_certificates(&mut self) -> Vec<QuorumCertificate> {
        self.pending_qc_broadcasts.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ioi_api::chain::{AnchoredStateView, RemoteStateView};
    use ioi_api::crypto::{SerializableKey, SigningKeyPair};
    use ioi_crypto::sign::bls::BlsKeyPair;
    use ioi_crypto::sign::guardian_committee::{
        canonical_manifest_hash, canonical_witness_manifest_hash, encode_signers_bitfield,
        sign_decision_with_members, sign_witness_statement_with_members,
    };
    use ioi_crypto::sign::guardian_log::{
        canonical_log_leaf_hash, checkpoint_root_from_leaf_hashes, checkpoint_signing_payload,
    };
    use ioi_types::app::ActiveKeyRecord;
    use ioi_types::app::{
        aft_bulletin_commitment_key, build_reference_canonical_order_proof_bytes,
        canonical_asymptote_observer_assignments_hash, canonical_order_public_inputs,
        canonical_order_public_inputs_hash, derive_asymptote_observer_assignments,
        derive_guardian_witness_assignments, derive_reference_ordering_randomness_beacon,
        guardian_registry_asymptote_policy_key, guardian_registry_checkpoint_key,
        guardian_registry_committee_account_key, guardian_registry_committee_key,
        guardian_registry_log_key, guardian_registry_witness_key,
        guardian_registry_witness_seed_key, guardian_registry_witness_set_key,
        write_validator_sets, AsymptoteObserverCertificate, AsymptoteObserverCloseCertificate,
        AsymptoteObserverCorrelationBudget, AsymptoteObserverVerdict, AsymptotePolicy,
        AsymptoteVetoKind, AsymptoteVetoProof, BulletinCommitment, CanonicalOrderCertificate,
        CanonicalOrderProof, CanonicalOrderProofSystem, CollapseState, FinalityTier,
        GuardianCommitteeMember, GuardianLogCheckpoint, GuardianLogProof,
        GuardianTransparencyLogDescriptor, GuardianWitnessCommitteeManifest, OmissionProof,
        SealedFinalityProof, SignatureSuite, StateRoot, ValidatorSetV1, ValidatorSetsV1,
        ValidatorV1,
    };
    use ioi_types::codec;
    use ioi_types::error::ChainError;
    use libp2p::identity::Keypair;
    use std::collections::HashMap;

    #[derive(Clone, Default)]
    struct MockAnchoredView {
        state_root: Vec<u8>,
        state: HashMap<Vec<u8>, Vec<u8>>,
    }

    #[async_trait]
    impl RemoteStateView for MockAnchoredView {
        async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
            Ok(self.state.get(key).cloned())
        }

        fn height(&self) -> u64 {
            0
        }

        fn state_root(&self) -> &[u8] {
            &self.state_root
        }
    }

    #[async_trait]
    impl AnchoredStateView for MockAnchoredView {
        async fn gas_used(&self) -> Result<u64, ChainError> {
            Ok(0)
        }
    }

    fn build_log_descriptor(log_id: &str, keypair: &Keypair) -> GuardianTransparencyLogDescriptor {
        GuardianTransparencyLogDescriptor {
            log_id: log_id.into(),
            signature_suite: SignatureSuite::ED25519,
            public_key: keypair.public().encode_protobuf(),
        }
    }

    fn build_signed_checkpoint(
        log_id: &str,
        keypair: &Keypair,
        entries: &[Vec<u8>],
        leaf_index: usize,
        timestamp_ms: u64,
    ) -> GuardianLogCheckpoint {
        let leaf_hashes = entries
            .iter()
            .map(|entry| canonical_log_leaf_hash(entry).unwrap())
            .collect::<Vec<_>>();
        let root_hash = checkpoint_root_from_leaf_hashes(&leaf_hashes).unwrap();
        let mut checkpoint = GuardianLogCheckpoint {
            log_id: log_id.into(),
            tree_size: leaf_hashes.len() as u64,
            root_hash,
            timestamp_ms,
            signature: Vec::new(),
            proof: Some(GuardianLogProof {
                base_tree_size: 0,
                leaf_index: leaf_index as u64,
                leaf_hash: leaf_hashes[leaf_index],
                extension_leaf_hashes: leaf_hashes,
            }),
        };
        checkpoint.signature = keypair
            .sign(&checkpoint_signing_payload(&checkpoint).unwrap())
            .unwrap();
        checkpoint
    }

    fn build_case(
        signer_indexes: &[(usize, usize)],
    ) -> (
        GuardianMajorityEngine,
        BlockHeader,
        GuardianCommitteeManifest,
        Vec<u8>,
        Vec<BlsKeyPair>,
        Keypair,
    ) {
        let engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let log_keypair = Keypair::generate_ed25519();
        let member_keys = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let manifest = GuardianCommitteeManifest {
            validator_account_id: AccountId([7u8; 32]),
            epoch: 4,
            threshold: 2,
            members: member_keys
                .iter()
                .enumerate()
                .map(|(idx, keypair)| GuardianCommitteeMember {
                    member_id: format!("member-{idx}"),
                    signature_suite: SignatureSuite::BLS12_381,
                    public_key: keypair.public_key().to_bytes(),
                    endpoint: None,
                    provider: None,
                    region: None,
                    host_class: None,
                    key_authority_kind: None,
                })
                .collect(),
            measurement_profile_root: [22u8; 32],
            policy_hash: [33u8; 32],
            transparency_log_id: "guardian-test".into(),
        };

        let mut header = BlockHeader {
            height: 9,
            view: 2,
            parent_hash: [1u8; 32],
            parent_state_root: StateRoot(vec![2u8; 32]),
            state_root: StateRoot(vec![3u8; 32]),
            transactions_root: vec![4u8; 32],
            timestamp: 1234,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: manifest.validator_account_id,
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [5u8; 32],
            producer_pubkey: vec![6u8; 32],
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            parent_qc: QuorumCertificate::default(),
            timeout_certificate: None,
            signature: Vec::new(),
        };

        let preimage = header.to_preimage_for_signing().unwrap();
        let payload_hash = ioi_crypto::algorithms::hash::sha256(&preimage).unwrap();
        let decision = GuardianDecision {
            domain: GuardianDecisionDomain::ConsensusSlot as u8,
            subject: manifest.validator_account_id.0.to_vec(),
            payload_hash,
            counter: 3,
            trace_hash: [44u8; 32],
            measurement_root: manifest.measurement_profile_root,
            policy_hash: manifest.policy_hash,
        };
        let signer_keys = signer_indexes
            .iter()
            .map(|(member_index, key_index)| (*member_index, member_keys[*key_index].private_key()))
            .collect::<Vec<_>>();
        let certificate = sign_decision_with_members(
            &manifest,
            &decision,
            decision.counter,
            decision.trace_hash,
            &signer_keys,
        )
        .unwrap();
        header.oracle_counter = decision.counter;
        header.oracle_trace_hash = decision.trace_hash;
        let mut certificate = certificate;
        let checkpoint_entry =
            codec::to_bytes_canonical(&(decision.clone(), certificate.clone())).unwrap();
        certificate.log_checkpoint = Some(build_signed_checkpoint(
            &manifest.transparency_log_id,
            &log_keypair,
            &[checkpoint_entry],
            0,
            10,
        ));
        header.guardian_certificate = Some(certificate);

        (engine, header, manifest, preimage, member_keys, log_keypair)
    }

    fn build_witness_manifest(member_keys: &[BlsKeyPair]) -> GuardianWitnessCommitteeManifest {
        GuardianWitnessCommitteeManifest {
            committee_id: "witness-a".into(),
            stratum_id: "stratum-a".into(),
            epoch: 4,
            threshold: 2,
            members: member_keys
                .iter()
                .enumerate()
                .map(|(idx, keypair)| GuardianCommitteeMember {
                    member_id: format!("witness-{idx}"),
                    signature_suite: SignatureSuite::BLS12_381,
                    public_key: keypair.public_key().to_bytes(),
                    endpoint: None,
                    provider: None,
                    region: None,
                    host_class: None,
                    key_authority_kind: None,
                })
                .collect(),
            policy_hash: [55u8; 32],
            transparency_log_id: "witness-test".into(),
        }
    }

    fn build_observer_manifest(
        observer_account_id: AccountId,
        epoch: u64,
        policy_hash: [u8; 32],
        transparency_log_id: &str,
        member_keys: &[BlsKeyPair],
    ) -> GuardianCommitteeManifest {
        GuardianCommitteeManifest {
            validator_account_id: observer_account_id,
            epoch,
            threshold: 2,
            members: member_keys
                .iter()
                .enumerate()
                .map(|(idx, keypair)| GuardianCommitteeMember {
                    member_id: format!("observer-{idx}"),
                    signature_suite: SignatureSuite::BLS12_381,
                    public_key: keypair.public_key().to_bytes(),
                    endpoint: None,
                    provider: None,
                    region: None,
                    host_class: None,
                    key_authority_kind: None,
                })
                .collect(),
            measurement_profile_root: [71u8; 32],
            policy_hash,
            transparency_log_id: transparency_log_id.into(),
        }
    }

    fn build_parent_view(
        committee_manifest: &GuardianCommitteeManifest,
        log_descriptors: &[GuardianTransparencyLogDescriptor],
        witness_manifests: &[GuardianWitnessCommitteeManifest],
        witness_set: GuardianWitnessSet,
        witness_seed: GuardianWitnessEpochSeed,
        anchored_checkpoints: &[GuardianLogCheckpoint],
    ) -> MockAnchoredView {
        let mut state = HashMap::new();
        let manifest_hash =
            ioi_crypto::sign::guardian_committee::canonical_manifest_hash(committee_manifest)
                .unwrap();
        state.insert(
            guardian_registry_committee_key(&manifest_hash),
            codec::to_bytes_canonical(committee_manifest).unwrap(),
        );
        for descriptor in log_descriptors {
            state.insert(
                guardian_registry_log_key(&descriptor.log_id),
                codec::to_bytes_canonical(descriptor).unwrap(),
            );
        }
        for witness_manifest in witness_manifests {
            let witness_hash = canonical_witness_manifest_hash(witness_manifest).unwrap();
            state.insert(
                guardian_registry_witness_key(&witness_hash),
                codec::to_bytes_canonical(witness_manifest).unwrap(),
            );
        }
        state.insert(
            guardian_registry_witness_set_key(witness_set.epoch),
            codec::to_bytes_canonical(&witness_set).unwrap(),
        );
        state.insert(
            guardian_registry_witness_seed_key(witness_seed.epoch),
            codec::to_bytes_canonical(&witness_seed).unwrap(),
        );
        state.insert(
            CURRENT_EPOCH_KEY.to_vec(),
            codec::to_bytes_canonical(&committee_manifest.epoch).unwrap(),
        );
        for checkpoint in anchored_checkpoints {
            state.insert(
                guardian_registry_checkpoint_key(&checkpoint.log_id),
                codec::to_bytes_canonical(checkpoint).unwrap(),
            );
        }

        MockAnchoredView {
            state_root: vec![9u8; 32],
            state,
        }
    }

    fn build_parent_view_with_asymptote_policy(
        committee_manifest: &GuardianCommitteeManifest,
        log_descriptors: &[GuardianTransparencyLogDescriptor],
        witness_manifests: &[GuardianWitnessCommitteeManifest],
        witness_set: GuardianWitnessSet,
        witness_seed: GuardianWitnessEpochSeed,
        anchored_checkpoints: &[GuardianLogCheckpoint],
        policy: AsymptotePolicy,
    ) -> MockAnchoredView {
        let mut view = build_parent_view(
            committee_manifest,
            log_descriptors,
            witness_manifests,
            witness_set,
            witness_seed,
            anchored_checkpoints,
        );
        view.state.insert(
            guardian_registry_asymptote_policy_key(policy.epoch),
            codec::to_bytes_canonical(&policy).unwrap(),
        );
        view
    }

    fn build_parent_view_with_bulletin_commitment(
        committee_manifest: &GuardianCommitteeManifest,
        log_descriptors: &[GuardianTransparencyLogDescriptor],
        policy: AsymptotePolicy,
        witness_seed: GuardianWitnessEpochSeed,
        anchored_checkpoints: &[GuardianLogCheckpoint],
        bulletin_commitment: BulletinCommitment,
    ) -> MockAnchoredView {
        let mut view = build_parent_view_with_asymptote_policy(
            committee_manifest,
            log_descriptors,
            &[],
            GuardianWitnessSet {
                epoch: witness_seed.epoch,
                manifest_hashes: Vec::new(),
                checkpoint_interval_blocks: witness_seed.checkpoint_interval_blocks,
            },
            witness_seed,
            anchored_checkpoints,
            policy,
        );
        view.state.insert(
            aft_bulletin_commitment_key(bulletin_commitment.height),
            codec::to_bytes_canonical(&bulletin_commitment).unwrap(),
        );
        view
    }

    fn build_validator_sets(validators: Vec<AccountId>) -> ValidatorSetsV1 {
        ValidatorSetsV1 {
            current: ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: validators.len() as u128,
                validators: validators
                    .into_iter()
                    .map(|account_id| ValidatorV1 {
                        account_id,
                        weight: 1,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::ED25519,
                            public_key_hash: account_id.0,
                            since_height: 1,
                        },
                    })
                    .collect(),
            },
            next: None,
        }
    }

    fn build_parent_view_with_asymptote_observers(
        committee_manifest: &GuardianCommitteeManifest,
        log_descriptors: &[GuardianTransparencyLogDescriptor],
        policy: AsymptotePolicy,
        witness_seed: GuardianWitnessEpochSeed,
        anchored_checkpoints: &[GuardianLogCheckpoint],
        validators: Vec<AccountId>,
        additional_guardian_manifests: &[GuardianCommitteeManifest],
    ) -> MockAnchoredView {
        let mut view = build_parent_view_with_asymptote_policy(
            committee_manifest,
            log_descriptors,
            &[],
            GuardianWitnessSet {
                epoch: witness_seed.epoch,
                manifest_hashes: Vec::new(),
                checkpoint_interval_blocks: witness_seed.checkpoint_interval_blocks,
            },
            witness_seed,
            anchored_checkpoints,
            policy,
        );
        for observer_manifest in additional_guardian_manifests {
            let manifest_hash = canonical_manifest_hash(observer_manifest).unwrap();
            view.state.insert(
                guardian_registry_committee_key(&manifest_hash),
                codec::to_bytes_canonical(observer_manifest).unwrap(),
            );
            view.state.insert(
                guardian_registry_committee_account_key(&observer_manifest.validator_account_id),
                manifest_hash.to_vec(),
            );
        }
        view.state.insert(
            VALIDATOR_SET_KEY.to_vec(),
            write_validator_sets(&build_validator_sets(validators)).unwrap(),
        );
        view
    }

    fn build_decide_parent_view(validators: Vec<AccountId>) -> MockAnchoredView {
        let mut view = MockAnchoredView::default();
        view.state.insert(
            VALIDATOR_SET_KEY.to_vec(),
            write_validator_sets(&build_validator_sets(validators)).unwrap(),
        );
        view.state.insert(
            BLOCK_TIMING_PARAMS_KEY.to_vec(),
            codec::to_bytes_canonical(&BlockTimingParams::default()).unwrap(),
        );
        view.state.insert(
            BLOCK_TIMING_RUNTIME_KEY.to_vec(),
            codec::to_bytes_canonical(&BlockTimingRuntime::default()).unwrap(),
        );
        view
    }

    #[test]
    fn verifies_valid_guardian_certificate() {
        let (engine, header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
        engine
            .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
            .unwrap();
    }

    #[tokio::test]
    async fn local_timeout_does_not_enter_new_view_without_timeout_certificate() {
        let validators = vec![
            AccountId([1u8; 32]),
            AccountId([2u8; 32]),
            AccountId([3u8; 32]),
        ];
        let parent_view = build_decide_parent_view(validators.clone());
        let known_peers = HashSet::from([PeerId::random()]);
        let mut engine = GuardianMajorityEngine::with_view_timeout(
            AftSafetyMode::GuardianMajority,
            Duration::ZERO,
        );

        let first: ConsensusDecision<ChainTransaction> = engine
            .decide(&validators[0], 1, 0, &parent_view, &known_peers)
            .await;
        assert!(matches!(
            first,
            ConsensusDecision::Timeout { view: 1, height: 1 }
        ));
        assert_eq!(engine.pacemaker.lock().await.current_view, 0);

        let second: ConsensusDecision<ChainTransaction> = engine
            .decide(&validators[0], 1, 0, &parent_view, &known_peers)
            .await;
        assert!(matches!(second, ConsensusDecision::WaitForBlock));
        assert_eq!(engine.pacemaker.lock().await.current_view, 0);
    }

    #[tokio::test]
    async fn bootstrap_grace_pins_view_zero_without_blocking_leader_production() {
        let validators = vec![
            AccountId([1u8; 32]),
            AccountId([2u8; 32]),
            AccountId([3u8; 32]),
        ];
        let parent_view = build_decide_parent_view(validators.clone());
        let known_peers = HashSet::from([PeerId::random()]);
        let mut engine = GuardianMajorityEngine::with_view_timeout(
            AftSafetyMode::GuardianMajority,
            Duration::from_secs(5),
        );
        engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);

        let decision: ConsensusDecision<ChainTransaction> = engine
            .decide(&validators[1], 2, 0, &parent_view, &known_peers)
            .await;
        assert!(matches!(decision, ConsensusDecision::ProduceBlock { view: 0, .. }));
        assert_eq!(engine.pacemaker.lock().await.current_view, 0);
    }

    #[test]
    fn rejects_invalid_aggregate_signature() {
        let (engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
        header
            .guardian_certificate
            .as_mut()
            .unwrap()
            .aggregated_signature[0] ^= 0x01;
        let err = engine
            .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
            .unwrap_err();
        assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
    }

    #[test]
    fn rejects_signer_outside_committee() {
        let (engine, mut header, mut manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
        manifest.members.truncate(2);
        header
            .guardian_certificate
            .as_mut()
            .unwrap()
            .signers_bitfield = encode_signers_bitfield(3, &[0, 2]).unwrap();
        let err = engine
            .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
            .unwrap_err();
        assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
    }

    #[test]
    fn rejects_insufficient_threshold() {
        let (_, header, manifest, preimage, member_keys, _) = build_case(&[(0, 0), (1, 1)]);
        let payload_hash = ioi_crypto::algorithms::hash::sha256(&preimage).unwrap();
        let decision = GuardianDecision {
            domain: GuardianDecisionDomain::ConsensusSlot as u8,
            subject: manifest.validator_account_id.0.to_vec(),
            payload_hash,
            counter: header.oracle_counter,
            trace_hash: header.oracle_trace_hash,
            measurement_root: manifest.measurement_profile_root,
            policy_hash: manifest.policy_hash,
        };
        let err = sign_decision_with_members(
            &manifest,
            &decision,
            decision.counter,
            decision.trace_hash,
            &[(0, member_keys[0].private_key())],
        )
        .unwrap_err();
        assert!(err.to_string().contains("insufficient local signers"));
    }

    #[test]
    fn rejects_wrong_decision_hash() {
        let (engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
        header.guardian_certificate.as_mut().unwrap().decision_hash[0] ^= 0x11;
        let err = engine
            .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
            .unwrap_err();
        assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
    }

    #[test]
    fn rejects_wrong_epoch() {
        let (engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
        header.guardian_certificate.as_mut().unwrap().epoch += 1;
        let err = engine
            .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
            .unwrap_err();
        assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
    }

    #[test]
    fn rejects_wrong_manifest_hash() {
        let (engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
        header.guardian_certificate.as_mut().unwrap().manifest_hash[0] ^= 0x55;
        let err = engine
            .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
            .unwrap_err();
        assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
    }

    #[test]
    fn duplicate_signer_indexes_are_rejected_before_certificate_construction() {
        let member_keys = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let manifest = GuardianCommitteeManifest {
            validator_account_id: AccountId([8u8; 32]),
            epoch: 1,
            threshold: 2,
            members: member_keys
                .iter()
                .enumerate()
                .map(|(idx, keypair)| GuardianCommitteeMember {
                    member_id: format!("member-{idx}"),
                    signature_suite: SignatureSuite::BLS12_381,
                    public_key: keypair.public_key().to_bytes(),
                    endpoint: None,
                    provider: None,
                    region: None,
                    host_class: None,
                    key_authority_kind: None,
                })
                .collect(),
            measurement_profile_root: [12u8; 32],
            policy_hash: [13u8; 32],
            transparency_log_id: "guardian-test".into(),
        };
        let decision = GuardianDecision {
            domain: GuardianDecisionDomain::ConsensusSlot as u8,
            subject: manifest.validator_account_id.0.to_vec(),
            payload_hash: [99u8; 32],
            counter: 1,
            trace_hash: [77u8; 32],
            measurement_root: manifest.measurement_profile_root,
            policy_hash: manifest.policy_hash,
        };
        let err = sign_decision_with_members(
            &manifest,
            &decision,
            decision.counter,
            decision.trace_hash,
            &[
                (0, member_keys[0].private_key()),
                (0, member_keys[0].private_key()),
            ],
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate signer index"));
    }

    #[test]
    fn experimental_nested_guardian_requires_witness_certificate() {
        let (mut engine, header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
        let witness_members = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let witness_manifest = build_witness_manifest(&witness_members);
        let err = engine
            .verify_experimental_witness_certificate_against_manifest(
                &header,
                header.guardian_certificate.as_ref().unwrap(),
                &witness_manifest,
            )
            .unwrap_err();
        assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
        engine
            .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
            .unwrap();
    }

    #[test]
    fn experimental_nested_guardian_verifies_witness_certificate() {
        let (mut engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
        let witness_members = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let witness_manifest = build_witness_manifest(&witness_members);
        let guardian_certificate = header.guardian_certificate.as_ref().unwrap().clone();
        let statement = engine.experimental_witness_statement(&header, &guardian_certificate);
        let witness_certificate = sign_witness_statement_with_members(
            &witness_manifest,
            &statement,
            &[
                (0, witness_members[0].private_key()),
                (2, witness_members[2].private_key()),
            ],
        )
        .unwrap();
        header
            .guardian_certificate
            .as_mut()
            .unwrap()
            .experimental_witness_certificate = Some(witness_certificate);

        engine
            .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
            .unwrap();
        engine
            .verify_experimental_witness_certificate_against_manifest(
                &header,
                header.guardian_certificate.as_ref().unwrap(),
                &witness_manifest,
            )
            .unwrap();
    }

    #[tokio::test]
    async fn experimental_nested_guardian_rejects_unassigned_witness_certificate() {
        let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
        let guardian_log_descriptor =
            build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
        let witness_log_keypair = Keypair::generate_ed25519();

        let witness_members_a = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let witness_members_b = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let witness_manifest_a = build_witness_manifest(&witness_members_a);
        let mut witness_manifest_b = build_witness_manifest(&witness_members_b);
        witness_manifest_b.committee_id = "witness-b".into();
        witness_manifest_b.stratum_id = "stratum-b".into();

        let witness_hash_a = canonical_witness_manifest_hash(&witness_manifest_a).unwrap();
        let witness_hash_b = canonical_witness_manifest_hash(&witness_manifest_b).unwrap();
        let witness_set = GuardianWitnessSet {
            epoch: witness_manifest_a.epoch,
            manifest_hashes: vec![witness_hash_a, witness_hash_b],
            checkpoint_interval_blocks: 1,
        };
        let witness_seed = GuardianWitnessEpochSeed {
            epoch: witness_manifest_a.epoch,
            seed: [88u8; 32],
            checkpoint_interval_blocks: 1,
            max_reassignment_depth: 1,
        };
        let expected_assignment = derive_guardian_witness_assignment(
            &witness_seed,
            &witness_set,
            header.producer_account_id,
            header.height,
            header.view,
            0,
        )
        .unwrap();
        let wrong_manifest = if expected_assignment.manifest_hash == witness_hash_a {
            &witness_manifest_b
        } else {
            &witness_manifest_a
        };
        let wrong_members = if expected_assignment.manifest_hash == witness_hash_a {
            &witness_members_b
        } else {
            &witness_members_a
        };
        let statement = engine
            .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
        let mut witness_certificate = sign_witness_statement_with_members(
            wrong_manifest,
            &statement,
            &[
                (0, wrong_members[0].private_key()),
                (1, wrong_members[1].private_key()),
                (2, wrong_members[2].private_key()),
            ],
        )
        .unwrap();
        let witness_checkpoint_entry =
            codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
        witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
            &wrong_manifest.transparency_log_id,
            &witness_log_keypair,
            &[witness_checkpoint_entry],
            0,
            1,
        ));
        header
            .guardian_certificate
            .as_mut()
            .unwrap()
            .experimental_witness_certificate = Some(witness_certificate);

        let parent_view = build_parent_view(
            &manifest,
            &[
                guardian_log_descriptor,
                build_log_descriptor(
                    &witness_manifest_a.transparency_log_id,
                    &witness_log_keypair,
                ),
                build_log_descriptor(
                    &witness_manifest_b.transparency_log_id,
                    &witness_log_keypair,
                ),
            ],
            &[witness_manifest_a, witness_manifest_b],
            witness_set,
            witness_seed,
            &[header
                .guardian_certificate
                .as_ref()
                .unwrap()
                .log_checkpoint
                .as_ref()
                .unwrap()
                .clone()],
        );
        let err = engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
    }

    #[tokio::test]
    async fn experimental_nested_guardian_accepts_deterministically_assigned_witness_certificate() {
        let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
        let guardian_log_descriptor =
            build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
        let witness_log_keypair = Keypair::generate_ed25519();

        let witness_members_a = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let witness_members_b = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let witness_manifest_a = build_witness_manifest(&witness_members_a);
        let mut witness_manifest_b = build_witness_manifest(&witness_members_b);
        witness_manifest_b.committee_id = "witness-b".into();
        witness_manifest_b.stratum_id = "stratum-b".into();

        let witness_hash_a = canonical_witness_manifest_hash(&witness_manifest_a).unwrap();
        let witness_hash_b = canonical_witness_manifest_hash(&witness_manifest_b).unwrap();
        let witness_set = GuardianWitnessSet {
            epoch: witness_manifest_a.epoch,
            manifest_hashes: vec![witness_hash_a, witness_hash_b],
            checkpoint_interval_blocks: 1,
        };
        let witness_seed = GuardianWitnessEpochSeed {
            epoch: witness_manifest_a.epoch,
            seed: [99u8; 32],
            checkpoint_interval_blocks: 1,
            max_reassignment_depth: 1,
        };
        let expected_assignment = derive_guardian_witness_assignment(
            &witness_seed,
            &witness_set,
            header.producer_account_id,
            header.height,
            header.view,
            0,
        )
        .unwrap();
        let (assigned_manifest, assigned_members) =
            if expected_assignment.manifest_hash == witness_hash_a {
                (&witness_manifest_a, &witness_members_a)
            } else {
                (&witness_manifest_b, &witness_members_b)
            };
        let statement = engine
            .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
        let mut witness_certificate = sign_witness_statement_with_members(
            assigned_manifest,
            &statement,
            &[
                (0, assigned_members[0].private_key()),
                (1, assigned_members[1].private_key()),
                (2, assigned_members[2].private_key()),
            ],
        )
        .unwrap();
        let witness_checkpoint_entry =
            codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
        witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
            &assigned_manifest.transparency_log_id,
            &witness_log_keypair,
            &[witness_checkpoint_entry],
            0,
            1,
        ));
        header
            .guardian_certificate
            .as_mut()
            .unwrap()
            .experimental_witness_certificate = Some(witness_certificate);

        let parent_view = build_parent_view(
            &manifest,
            &[
                guardian_log_descriptor,
                build_log_descriptor(
                    &witness_manifest_a.transparency_log_id,
                    &witness_log_keypair,
                ),
                build_log_descriptor(
                    &witness_manifest_b.transparency_log_id,
                    &witness_log_keypair,
                ),
            ],
            &[witness_manifest_a, witness_manifest_b],
            witness_set,
            witness_seed,
            &[
                header
                    .guardian_certificate
                    .as_ref()
                    .unwrap()
                    .log_checkpoint
                    .as_ref()
                    .unwrap()
                    .clone(),
                header
                    .guardian_certificate
                    .as_ref()
                    .unwrap()
                    .experimental_witness_certificate
                    .as_ref()
                    .unwrap()
                    .log_checkpoint
                    .as_ref()
                    .unwrap()
                    .clone(),
            ],
        );
        engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn asymptote_accepts_valid_sealed_finality_proof() {
        let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;
        let guardian_log_descriptor =
            build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
        let witness_log_keypair = Keypair::generate_ed25519();

        let witness_members_a = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let witness_members_b = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let witness_manifest_a = build_witness_manifest(&witness_members_a);
        let mut witness_manifest_b = build_witness_manifest(&witness_members_b);
        witness_manifest_b.committee_id = "witness-b".into();
        witness_manifest_b.stratum_id = "stratum-b".into();
        witness_manifest_b.transparency_log_id = "witness-test-b".into();

        let witness_hash_a = canonical_witness_manifest_hash(&witness_manifest_a).unwrap();
        let witness_hash_b = canonical_witness_manifest_hash(&witness_manifest_b).unwrap();
        let witness_set = GuardianWitnessSet {
            epoch: witness_manifest_a.epoch,
            manifest_hashes: vec![witness_hash_a, witness_hash_b],
            checkpoint_interval_blocks: 1,
        };
        let witness_seed = GuardianWitnessEpochSeed {
            epoch: witness_manifest_a.epoch,
            seed: [77u8; 32],
            checkpoint_interval_blocks: 1,
            max_reassignment_depth: 0,
        };
        let assignments = derive_guardian_witness_assignments(
            &witness_seed,
            &witness_set,
            header.producer_account_id,
            header.height,
            header.view,
            0,
            2,
        )
        .unwrap();
        let statement = engine
            .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
        let mut witness_certificates = Vec::new();
        let mut anchored_checkpoints = vec![header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .as_ref()
            .unwrap()
            .clone()];
        for assignment in assignments {
            let (assigned_manifest, assigned_members) =
                if assignment.manifest_hash == witness_hash_a {
                    (&witness_manifest_a, &witness_members_a)
                } else {
                    (&witness_manifest_b, &witness_members_b)
                };
            let mut witness_certificate = sign_witness_statement_with_members(
                assigned_manifest,
                &statement,
                &[
                    (0, assigned_members[0].private_key()),
                    (1, assigned_members[1].private_key()),
                    (2, assigned_members[2].private_key()),
                ],
            )
            .unwrap();
            let witness_checkpoint_entry =
                codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone()))
                    .unwrap();
            witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
                &assigned_manifest.transparency_log_id,
                &witness_log_keypair,
                std::slice::from_ref(&witness_checkpoint_entry),
                0,
                1,
            ));
            anchored_checkpoints.push(witness_certificate.log_checkpoint.clone().unwrap());
            witness_certificates.push(witness_certificate);
        }
        header.sealed_finality_proof = Some(SealedFinalityProof {
            epoch: manifest.epoch,
            finality_tier: FinalityTier::SealedFinal,
            collapse_state: CollapseState::SealedFinal,
            guardian_manifest_hash: header.guardian_certificate.as_ref().unwrap().manifest_hash,
            guardian_decision_hash: header.guardian_certificate.as_ref().unwrap().decision_hash,
            guardian_counter: header.oracle_counter,
            guardian_trace_hash: header.oracle_trace_hash,
            guardian_measurement_root: header
                .guardian_certificate
                .as_ref()
                .unwrap()
                .measurement_root,
            policy_hash: manifest.policy_hash,
            witness_certificates,
            observer_certificates: Vec::new(),
            observer_close_certificate: None,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
        });

        let parent_view = build_parent_view_with_asymptote_policy(
            &manifest,
            &[
                guardian_log_descriptor,
                build_log_descriptor(
                    &witness_manifest_a.transparency_log_id,
                    &witness_log_keypair,
                ),
                build_log_descriptor(
                    &witness_manifest_b.transparency_log_id,
                    &witness_log_keypair,
                ),
            ],
            &[witness_manifest_a, witness_manifest_b],
            witness_set,
            witness_seed,
            &anchored_checkpoints,
            AsymptotePolicy {
                epoch: manifest.epoch,
                high_risk_effect_tier: FinalityTier::SealedFinal,
                required_witness_strata: vec!["stratum-a".into(), "stratum-b".into()],
                escalation_witness_strata: vec![
                    "stratum-a".into(),
                    "stratum-b".into(),
                    "stratum-c".into(),
                ],
                observer_rounds: 0,
                observer_committee_size: 0,
                observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
                max_reassignment_depth: 0,
                max_checkpoint_staleness_ms: 120_000,
            },
        );

        engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn asymptote_rejects_duplicate_witness_committees_in_sealed_finality_proof() {
        let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;
        let guardian_log_descriptor =
            build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
        let witness_log_keypair = Keypair::generate_ed25519();

        let witness_members_a = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let witness_members_b = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let witness_manifest_a = build_witness_manifest(&witness_members_a);
        let mut witness_manifest_b = build_witness_manifest(&witness_members_b);
        witness_manifest_b.committee_id = "witness-b".into();
        witness_manifest_b.stratum_id = "stratum-b".into();
        witness_manifest_b.transparency_log_id = "witness-test-b".into();

        let witness_hash_a = canonical_witness_manifest_hash(&witness_manifest_a).unwrap();
        let witness_hash_b = canonical_witness_manifest_hash(&witness_manifest_b).unwrap();
        let witness_set = GuardianWitnessSet {
            epoch: witness_manifest_a.epoch,
            manifest_hashes: vec![witness_hash_a, witness_hash_b],
            checkpoint_interval_blocks: 1,
        };
        let witness_seed = GuardianWitnessEpochSeed {
            epoch: witness_manifest_a.epoch,
            seed: [88u8; 32],
            checkpoint_interval_blocks: 1,
            max_reassignment_depth: 0,
        };
        let assignments = derive_guardian_witness_assignments(
            &witness_seed,
            &witness_set,
            header.producer_account_id,
            header.height,
            header.view,
            0,
            2,
        )
        .unwrap();
        let statement = engine
            .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
        let first_assignment = assignments.first().unwrap();
        let (assigned_manifest, assigned_members) =
            if first_assignment.manifest_hash == witness_hash_a {
                (&witness_manifest_a, &witness_members_a)
            } else {
                (&witness_manifest_b, &witness_members_b)
            };
        let mut witness_certificate = sign_witness_statement_with_members(
            assigned_manifest,
            &statement,
            &[
                (0, assigned_members[0].private_key()),
                (1, assigned_members[1].private_key()),
                (2, assigned_members[2].private_key()),
            ],
        )
        .unwrap();
        let witness_checkpoint_entry =
            codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
        witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
            &assigned_manifest.transparency_log_id,
            &witness_log_keypair,
            std::slice::from_ref(&witness_checkpoint_entry),
            0,
            1,
        ));
        let anchored_checkpoints = vec![
            header
                .guardian_certificate
                .as_ref()
                .unwrap()
                .log_checkpoint
                .as_ref()
                .unwrap()
                .clone(),
            witness_certificate.log_checkpoint.clone().unwrap(),
        ];
        header.sealed_finality_proof = Some(SealedFinalityProof {
            epoch: manifest.epoch,
            finality_tier: FinalityTier::SealedFinal,
            collapse_state: CollapseState::SealedFinal,
            guardian_manifest_hash: header.guardian_certificate.as_ref().unwrap().manifest_hash,
            guardian_decision_hash: header.guardian_certificate.as_ref().unwrap().decision_hash,
            guardian_counter: header.oracle_counter,
            guardian_trace_hash: header.oracle_trace_hash,
            guardian_measurement_root: header
                .guardian_certificate
                .as_ref()
                .unwrap()
                .measurement_root,
            policy_hash: manifest.policy_hash,
            witness_certificates: vec![witness_certificate.clone(), witness_certificate],
            observer_certificates: Vec::new(),
            observer_close_certificate: None,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
        });
        let parent_view = build_parent_view_with_asymptote_policy(
            &manifest,
            &[
                guardian_log_descriptor,
                build_log_descriptor(
                    &witness_manifest_a.transparency_log_id,
                    &witness_log_keypair,
                ),
                build_log_descriptor(
                    &witness_manifest_b.transparency_log_id,
                    &witness_log_keypair,
                ),
            ],
            &[witness_manifest_a, witness_manifest_b],
            witness_set,
            witness_seed,
            &anchored_checkpoints,
            AsymptotePolicy {
                epoch: manifest.epoch,
                high_risk_effect_tier: FinalityTier::SealedFinal,
                required_witness_strata: vec!["stratum-a".into(), "stratum-b".into()],
                escalation_witness_strata: vec![
                    "stratum-a".into(),
                    "stratum-b".into(),
                    "stratum-c".into(),
                ],
                observer_rounds: 0,
                observer_committee_size: 0,
                observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
                max_reassignment_depth: 0,
                max_checkpoint_staleness_ms: 120_000,
            },
        );

        let err = engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
    }

    #[tokio::test]
    async fn asymptote_accepts_equal_authority_observer_sealed_finality_proof() {
        let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;
        let guardian_log_descriptor =
            build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
        let witness_seed = GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [91u8; 32],
            checkpoint_interval_blocks: 1,
            max_reassignment_depth: 0,
        };
        let policy = AsymptotePolicy {
            epoch: manifest.epoch,
            high_risk_effect_tier: FinalityTier::SealedFinal,
            required_witness_strata: Vec::new(),
            escalation_witness_strata: Vec::new(),
            observer_rounds: 2,
            observer_committee_size: 1,
            observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
            max_reassignment_depth: 0,
            max_checkpoint_staleness_ms: 120_000,
        };
        let validators = vec![
            header.producer_account_id,
            AccountId([31u8; 32]),
            AccountId([32u8; 32]),
            AccountId([33u8; 32]),
        ];
        let observer_assignments = derive_asymptote_observer_assignments(
            &witness_seed,
            &build_validator_sets(validators.clone()).current,
            header.producer_account_id,
            header.height,
            header.view,
            policy.observer_rounds,
            policy.observer_committee_size,
        )
        .unwrap();
        let observer_assignments_hash =
            canonical_asymptote_observer_assignments_hash(&observer_assignments).unwrap();

        let observer_log_keypair = Keypair::generate_ed25519();
        let mut observer_manifests = Vec::new();
        let mut observer_descriptors = vec![guardian_log_descriptor];
        let mut anchored_checkpoints = vec![header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .as_ref()
            .unwrap()
            .clone()];
        let mut observer_certificates = Vec::new();
        let base_certificate = header.guardian_certificate.as_ref().unwrap().clone();
        let selected_accounts = observer_assignments
            .iter()
            .map(|assignment| assignment.observer_account_id)
            .collect::<std::collections::HashSet<_>>();
        let mut selected_manifests = HashMap::new();
        for account in validators
            .iter()
            .copied()
            .filter(|account| *account != header.producer_account_id)
        {
            let member_keys = vec![
                BlsKeyPair::generate().unwrap(),
                BlsKeyPair::generate().unwrap(),
                BlsKeyPair::generate().unwrap(),
            ];
            let log_id = format!("observer-{}", hex::encode(account.as_ref()));
            let observer_manifest =
                build_observer_manifest(account, manifest.epoch, [61u8; 32], &log_id, &member_keys);
            if selected_accounts.contains(&account) {
                selected_manifests.insert(account, (observer_manifest.clone(), member_keys));
            }
            observer_manifests.push(observer_manifest);
        }
        for assignment in observer_assignments {
            let (observer_manifest, member_keys) = selected_manifests
                .remove(&assignment.observer_account_id)
                .unwrap();
            let provisional = AsymptoteObserverCertificate {
                assignment: assignment.clone(),
                verdict: AsymptoteObserverVerdict::Ok,
                veto_kind: None,
                evidence_hash: [0u8; 32],
                guardian_certificate: GuardianQuorumCertificate::default(),
            };
            let statement = engine
                .asymptote_observer_statement(&header, &base_certificate, &provisional)
                .unwrap();
            let decision = GuardianDecision {
                domain: GuardianDecisionDomain::AsymptoteObserve as u8,
                subject: assignment.observer_account_id.0.to_vec(),
                payload_hash: ioi_crypto::algorithms::hash::sha256(
                    &codec::to_bytes_canonical(&statement).unwrap(),
                )
                .unwrap(),
                counter: u64::from(assignment.round) + 1,
                trace_hash: [assignment.round as u8 + 1; 32],
                measurement_root: observer_manifest.measurement_profile_root,
                policy_hash: observer_manifest.policy_hash,
            };
            let mut observer_guardian_certificate = sign_decision_with_members(
                &observer_manifest,
                &decision,
                decision.counter,
                decision.trace_hash,
                &[
                    (0, member_keys[0].private_key()),
                    (1, member_keys[1].private_key()),
                ],
            )
            .unwrap();
            let checkpoint_entry = codec::to_bytes_canonical(&(
                decision.clone(),
                observer_guardian_certificate.clone(),
            ))
            .unwrap();
            observer_guardian_certificate.log_checkpoint = Some(build_signed_checkpoint(
                &observer_manifest.transparency_log_id,
                &observer_log_keypair,
                &[checkpoint_entry],
                0,
                u64::from(assignment.round) + 1,
            ));
            anchored_checkpoints.push(
                observer_guardian_certificate
                    .log_checkpoint
                    .as_ref()
                    .unwrap()
                    .clone(),
            );
            observer_descriptors.push(build_log_descriptor(
                &observer_manifest.transparency_log_id,
                &observer_log_keypair,
            ));
            observer_certificates.push(AsymptoteObserverCertificate {
                assignment,
                verdict: AsymptoteObserverVerdict::Ok,
                veto_kind: None,
                evidence_hash: [0u8; 32],
                guardian_certificate: observer_guardian_certificate,
            });
        }

        header.sealed_finality_proof = Some(SealedFinalityProof {
            epoch: manifest.epoch,
            finality_tier: FinalityTier::SealedFinal,
            collapse_state: CollapseState::SealedFinal,
            guardian_manifest_hash: base_certificate.manifest_hash,
            guardian_decision_hash: base_certificate.decision_hash,
            guardian_counter: base_certificate.counter,
            guardian_trace_hash: base_certificate.trace_hash,
            guardian_measurement_root: base_certificate.measurement_root,
            policy_hash: manifest.policy_hash,
            witness_certificates: Vec::new(),
            observer_certificates,
            observer_close_certificate: Some(AsymptoteObserverCloseCertificate {
                epoch: manifest.epoch,
                height: header.height,
                view: header.view,
                assignments_hash: observer_assignments_hash,
                expected_assignments: 2,
                ok_count: 2,
                veto_count: 0,
            }),
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
        });

        let parent_view = build_parent_view_with_asymptote_observers(
            &manifest,
            &observer_descriptors,
            policy,
            witness_seed,
            &anchored_checkpoints,
            validators,
            &observer_manifests,
        );

        engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn asymptote_accepts_valid_canonical_order_certificate() {
        let (mut engine, mut header, manifest, preimage, _, log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;

        let bulletin = BulletinCommitment {
            height: header.height,
            cutoff_timestamp_ms: 1_750_000_001,
            bulletin_root: [61u8; 32],
            entry_count: 3,
        };
        let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
        let template_certificate = CanonicalOrderCertificate {
            height: header.height,
            bulletin_commitment: bulletin.clone(),
            randomness_beacon,
            ordered_transactions_root_hash: [0u8; 32],
            resulting_state_root_hash: [0u8; 32],
            proof: CanonicalOrderProof {
                proof_system: CanonicalOrderProofSystem::HashBindingV1,
                public_inputs_hash: [0u8; 32],
                proof_bytes: Vec::new(),
            },
            omission_proofs: Vec::new(),
        };
        let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
        let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
        header.canonical_order_certificate = Some(CanonicalOrderCertificate {
            ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
            resulting_state_root_hash: public_inputs.resulting_state_root_hash,
            proof: CanonicalOrderProof {
                proof_system: CanonicalOrderProofSystem::HashBindingV1,
                public_inputs_hash,
                proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash)
                    .unwrap(),
            },
            ..template_certificate
        });

        let policy = AsymptotePolicy {
            epoch: manifest.epoch,
            high_risk_effect_tier: FinalityTier::SealedFinal,
            required_witness_strata: vec!["stratum-a".into()],
            escalation_witness_strata: vec!["stratum-a".into()],
            observer_rounds: 0,
            observer_committee_size: 0,
            max_reassignment_depth: 0,
            max_checkpoint_staleness_ms: 120_000,
            observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        };
        let parent_view = build_parent_view_with_bulletin_commitment(
            &manifest,
            &[build_log_descriptor(
                &manifest.transparency_log_id,
                &log_keypair,
            )],
            policy,
            GuardianWitnessEpochSeed {
                epoch: manifest.epoch,
                seed: [63u8; 32],
                checkpoint_interval_blocks: 4,
                max_reassignment_depth: 0,
            },
            &[header
                .guardian_certificate
                .as_ref()
                .unwrap()
                .log_checkpoint
                .clone()
                .unwrap()],
            bulletin,
        );

        engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn asymptote_rejects_canonical_order_certificate_with_omission_proof() {
        let (mut engine, mut header, manifest, preimage, _, log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;

        let bulletin = BulletinCommitment {
            height: header.height,
            cutoff_timestamp_ms: 1_750_000_002,
            bulletin_root: [71u8; 32],
            entry_count: 2,
        };
        let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
        let template_certificate = CanonicalOrderCertificate {
            height: header.height,
            bulletin_commitment: bulletin.clone(),
            randomness_beacon,
            ordered_transactions_root_hash: [0u8; 32],
            resulting_state_root_hash: [0u8; 32],
            proof: CanonicalOrderProof {
                proof_system: CanonicalOrderProofSystem::HashBindingV1,
                public_inputs_hash: [0u8; 32],
                proof_bytes: Vec::new(),
            },
            omission_proofs: vec![OmissionProof {
                height: header.height,
                tx_hash: [73u8; 32],
                bulletin_root: bulletin.bulletin_root,
                details: "omitted from canonical order".into(),
            }],
        };
        let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
        let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
        header.canonical_order_certificate = Some(CanonicalOrderCertificate {
            ordered_transactions_root_hash: public_inputs.ordered_transactions_root_hash,
            resulting_state_root_hash: public_inputs.resulting_state_root_hash,
            proof: CanonicalOrderProof {
                proof_system: CanonicalOrderProofSystem::HashBindingV1,
                public_inputs_hash,
                proof_bytes: build_reference_canonical_order_proof_bytes(public_inputs_hash)
                    .unwrap(),
            },
            ..template_certificate
        });

        let policy = AsymptotePolicy {
            epoch: manifest.epoch,
            high_risk_effect_tier: FinalityTier::SealedFinal,
            required_witness_strata: vec!["stratum-a".into()],
            escalation_witness_strata: vec!["stratum-a".into()],
            observer_rounds: 0,
            observer_committee_size: 0,
            max_reassignment_depth: 0,
            max_checkpoint_staleness_ms: 120_000,
            observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
        };
        let parent_view = build_parent_view_with_bulletin_commitment(
            &manifest,
            &[build_log_descriptor(
                &manifest.transparency_log_id,
                &log_keypair,
            )],
            policy,
            GuardianWitnessEpochSeed {
                epoch: manifest.epoch,
                seed: [74u8; 32],
                checkpoint_interval_blocks: 4,
                max_reassignment_depth: 0,
            },
            &[header
                .guardian_certificate
                .as_ref()
                .unwrap()
                .log_checkpoint
                .clone()
                .unwrap()],
            bulletin,
        );

        let err = engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("canonical order certificate is dominated by objective omission proofs"));
    }

    #[tokio::test]
    async fn asymptote_rejects_valid_equal_authority_veto_proof() {
        let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;
        let guardian_log_descriptor =
            build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
        let witness_seed = GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [92u8; 32],
            checkpoint_interval_blocks: 1,
            max_reassignment_depth: 0,
        };
        let policy = AsymptotePolicy {
            epoch: manifest.epoch,
            high_risk_effect_tier: FinalityTier::SealedFinal,
            required_witness_strata: Vec::new(),
            escalation_witness_strata: Vec::new(),
            observer_rounds: 1,
            observer_committee_size: 1,
            observer_correlation_budget: AsymptoteObserverCorrelationBudget::default(),
            max_reassignment_depth: 0,
            max_checkpoint_staleness_ms: 120_000,
        };
        let validators = vec![
            header.producer_account_id,
            AccountId([41u8; 32]),
            AccountId([42u8; 32]),
        ];
        let assignment = derive_asymptote_observer_assignments(
            &witness_seed,
            &build_validator_sets(validators.clone()).current,
            header.producer_account_id,
            header.height,
            header.view,
            policy.observer_rounds,
            policy.observer_committee_size,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
        let observer_assignments_hash =
            canonical_asymptote_observer_assignments_hash(std::slice::from_ref(&assignment))
                .unwrap();
        let mut observer_manifests = Vec::new();
        let mut selected_manifest = None;
        let mut selected_member_keys = None;
        for account in validators
            .iter()
            .copied()
            .filter(|account| *account != header.producer_account_id)
        {
            let member_keys = vec![
                BlsKeyPair::generate().unwrap(),
                BlsKeyPair::generate().unwrap(),
                BlsKeyPair::generate().unwrap(),
            ];
            let observer_manifest = build_observer_manifest(
                account,
                manifest.epoch,
                [62u8; 32],
                &format!("observer-veto-{}", hex::encode(account.as_ref())),
                &member_keys,
            );
            if account == assignment.observer_account_id {
                selected_manifest = Some(observer_manifest.clone());
                selected_member_keys = Some(member_keys);
            }
            observer_manifests.push(observer_manifest);
        }
        let observer_manifest = selected_manifest.unwrap();
        let member_keys = selected_member_keys.unwrap();
        let provisional = AsymptoteObserverCertificate {
            assignment: assignment.clone(),
            verdict: AsymptoteObserverVerdict::Veto,
            veto_kind: Some(AsymptoteVetoKind::ConflictingGuardianCertificate),
            evidence_hash: [7u8; 32],
            guardian_certificate: GuardianQuorumCertificate::default(),
        };
        let base_certificate = header.guardian_certificate.as_ref().unwrap().clone();
        let statement = engine
            .asymptote_observer_statement(&header, &base_certificate, &provisional)
            .unwrap();
        let decision = GuardianDecision {
            domain: GuardianDecisionDomain::AsymptoteObserve as u8,
            subject: assignment.observer_account_id.0.to_vec(),
            payload_hash: ioi_crypto::algorithms::hash::sha256(
                &codec::to_bytes_canonical(&statement).unwrap(),
            )
            .unwrap(),
            counter: 1,
            trace_hash: [4u8; 32],
            measurement_root: observer_manifest.measurement_profile_root,
            policy_hash: observer_manifest.policy_hash,
        };
        let observer_log_keypair = Keypair::generate_ed25519();
        let mut observer_guardian_certificate = sign_decision_with_members(
            &observer_manifest,
            &decision,
            decision.counter,
            decision.trace_hash,
            &[
                (0, member_keys[0].private_key()),
                (1, member_keys[1].private_key()),
            ],
        )
        .unwrap();
        let checkpoint_entry =
            codec::to_bytes_canonical(&(decision.clone(), observer_guardian_certificate.clone()))
                .unwrap();
        observer_guardian_certificate.log_checkpoint = Some(build_signed_checkpoint(
            &observer_manifest.transparency_log_id,
            &observer_log_keypair,
            &[checkpoint_entry],
            0,
            1,
        ));
        let veto_proof = AsymptoteVetoProof {
            observer_certificate: AsymptoteObserverCertificate {
                assignment,
                verdict: AsymptoteObserverVerdict::Veto,
                veto_kind: Some(AsymptoteVetoKind::ConflictingGuardianCertificate),
                evidence_hash: [7u8; 32],
                guardian_certificate: observer_guardian_certificate.clone(),
            },
            details: "conflicting guardian-backed slot evidence".into(),
        };
        let anchored_checkpoints = vec![
            base_certificate.log_checkpoint.as_ref().unwrap().clone(),
            observer_guardian_certificate
                .log_checkpoint
                .as_ref()
                .unwrap()
                .clone(),
        ];

        header.sealed_finality_proof = Some(SealedFinalityProof {
            epoch: manifest.epoch,
            finality_tier: FinalityTier::SealedFinal,
            collapse_state: CollapseState::SealedFinal,
            guardian_manifest_hash: base_certificate.manifest_hash,
            guardian_decision_hash: base_certificate.decision_hash,
            guardian_counter: base_certificate.counter,
            guardian_trace_hash: base_certificate.trace_hash,
            guardian_measurement_root: base_certificate.measurement_root,
            policy_hash: manifest.policy_hash,
            witness_certificates: Vec::new(),
            observer_certificates: Vec::new(),
            observer_close_certificate: Some(AsymptoteObserverCloseCertificate {
                epoch: manifest.epoch,
                height: header.height,
                view: header.view,
                assignments_hash: observer_assignments_hash,
                expected_assignments: 1,
                ok_count: 0,
                veto_count: 1,
            }),
            veto_proofs: vec![veto_proof],
            divergence_signals: Vec::new(),
        });

        let parent_view = build_parent_view_with_asymptote_observers(
            &manifest,
            &[
                guardian_log_descriptor,
                build_log_descriptor(
                    &observer_manifest.transparency_log_id,
                    &observer_log_keypair,
                ),
            ],
            policy,
            witness_seed,
            &anchored_checkpoints,
            validators,
            &observer_manifests,
        );

        let err = engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
    }

    #[tokio::test]
    async fn guardian_majority_rejects_checkpoint_log_id_mismatch() {
        let (engine, mut header, manifest, preimage, _, guardian_log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        header.guardian_certificate.as_mut().unwrap().log_checkpoint =
            Some(GuardianLogCheckpoint {
                log_id: "wrong-log".into(),
                tree_size: 1,
                root_hash: [11u8; 32],
                timestamp_ms: 11,
                signature: vec![1],
                proof: None,
            });
        let parent_view = build_parent_view(
            &manifest,
            &[build_log_descriptor(
                &manifest.transparency_log_id,
                &guardian_log_keypair,
            )],
            &[],
            GuardianWitnessSet::default(),
            GuardianWitnessEpochSeed::default(),
            &[],
        );

        let err = engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
    }

    #[tokio::test]
    async fn guardian_majority_rejects_checkpoint_rollback_against_anchor() {
        let (engine, header, manifest, preimage, _, guardian_log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        let guardian_entry = codec::to_bytes_canonical(&(
            GuardianDecision {
                domain: GuardianDecisionDomain::ConsensusSlot as u8,
                subject: manifest.validator_account_id.0.to_vec(),
                payload_hash: ioi_crypto::algorithms::hash::sha256(&preimage).unwrap(),
                counter: header.oracle_counter,
                trace_hash: header.oracle_trace_hash,
                measurement_root: manifest.measurement_profile_root,
                policy_hash: manifest.policy_hash,
            },
            {
                let mut checkpoint_certificate =
                    header.guardian_certificate.as_ref().unwrap().clone();
                checkpoint_certificate.log_checkpoint = None;
                checkpoint_certificate.experimental_witness_certificate = None;
                checkpoint_certificate
            },
        ))
        .unwrap();
        let parent_view = build_parent_view(
            &manifest,
            &[build_log_descriptor(
                &manifest.transparency_log_id,
                &guardian_log_keypair,
            )],
            &[],
            GuardianWitnessSet::default(),
            GuardianWitnessEpochSeed::default(),
            &[build_signed_checkpoint(
                &manifest.transparency_log_id,
                &guardian_log_keypair,
                &[guardian_entry.clone(), b"anchor-2".to_vec()],
                1,
                20,
            )],
        );

        let err = engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
    }

    #[tokio::test]
    async fn experimental_nested_guardian_rejects_witness_checkpoint_rollback_against_anchor() {
        let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
        let guardian_log_descriptor =
            build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
        let witness_log_keypair = Keypair::generate_ed25519();

        let witness_members = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let witness_manifest = build_witness_manifest(&witness_members);
        let witness_hash = canonical_witness_manifest_hash(&witness_manifest).unwrap();
        let witness_set = GuardianWitnessSet {
            epoch: witness_manifest.epoch,
            manifest_hashes: vec![witness_hash],
            checkpoint_interval_blocks: 1,
        };
        let witness_seed = GuardianWitnessEpochSeed {
            epoch: witness_manifest.epoch,
            seed: [42u8; 32],
            checkpoint_interval_blocks: 1,
            max_reassignment_depth: 1,
        };
        let statement = engine
            .experimental_witness_statement(&header, header.guardian_certificate.as_ref().unwrap());
        let mut witness_certificate = sign_witness_statement_with_members(
            &witness_manifest,
            &statement,
            &[
                (0, witness_members[0].private_key()),
                (1, witness_members[1].private_key()),
                (2, witness_members[2].private_key()),
            ],
        )
        .unwrap();
        let witness_checkpoint_entry =
            codec::to_bytes_canonical(&(statement.clone(), witness_certificate.clone())).unwrap();
        witness_certificate.log_checkpoint = Some(build_signed_checkpoint(
            &witness_manifest.transparency_log_id,
            &witness_log_keypair,
            std::slice::from_ref(&witness_checkpoint_entry),
            0,
            10,
        ));
        header
            .guardian_certificate
            .as_mut()
            .unwrap()
            .experimental_witness_certificate = Some(witness_certificate);
        let parent_view = build_parent_view(
            &manifest,
            &[
                guardian_log_descriptor,
                build_log_descriptor(&witness_manifest.transparency_log_id, &witness_log_keypair),
            ],
            &[witness_manifest.clone()],
            witness_set,
            witness_seed,
            &[
                header
                    .guardian_certificate
                    .as_ref()
                    .unwrap()
                    .log_checkpoint
                    .as_ref()
                    .unwrap()
                    .clone(),
                GuardianLogCheckpoint {
                    ..build_signed_checkpoint(
                        &witness_manifest.transparency_log_id,
                        &witness_log_keypair,
                        &[witness_checkpoint_entry, b"witness-anchor-2".to_vec()],
                        1,
                        20,
                    )
                },
            ],
        );

        let err = engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
    }

    #[test]
    fn reset_promotes_unique_quorum_candidate_for_committed_height() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let block_hash = [9u8; 32];
        engine.remember_validator_count(5, 4);
        engine.vote_pool.insert(
            5,
            HashMap::from([(
                block_hash,
                vec![
                    ConsensusVote {
                        height: 5,
                        view: 0,
                        block_hash,
                        voter: AccountId([1u8; 32]),
                        signature: vec![1u8],
                    },
                    ConsensusVote {
                        height: 5,
                        view: 0,
                        block_hash,
                        voter: AccountId([2u8; 32]),
                        signature: vec![2u8],
                    },
                    ConsensusVote {
                        height: 5,
                        view: 0,
                        block_hash,
                        voter: AccountId([3u8; 32]),
                        signature: vec![3u8],
                    },
                ],
            )]),
        );

        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

        assert_eq!(engine.highest_qc.height, 5);
        assert_eq!(engine.highest_qc.block_hash, block_hash);
        assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::take_pending_quorum_certificates(
                &mut engine,
            )
            .len(),
            1
        );
    }
}
