// Path: crates/consensus/src/aft/guardian_majority/mod.rs

use crate::common::penalty::apply_quarantine_penalty;
use crate::{ConsensusDecision, ConsensusEngine, PenaltyEngine, PenaltyMechanism};
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, ChainView, StateRef};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::{CanonicalCollapseContinuityVerifier, ConsensusControl};
use ioi_api::state::{StateAccess, StateManager};
use ioi_crypto::sign::guardian_committee::{verify_quorum_certificate, verify_witness_certificate};
use ioi_crypto::sign::guardian_log::{
    canonical_log_leaf_hash, verify_checkpoint_proof, verify_checkpoint_signature,
};
use ioi_system::SystemState;
use ioi_types::app::{
    aft_bulletin_availability_certificate_key, aft_bulletin_commitment_key,
    aft_canonical_bulletin_close_key, aft_canonical_collapse_object_key,
    aft_canonical_order_abort_key, aft_publication_frontier_contradiction_key,
    aft_publication_frontier_key, bind_canonical_collapse_continuity,
    build_canonical_bulletin_close, canonical_asymptote_observer_assignment_hash,
    canonical_asymptote_observer_assignments_hash,
    canonical_asymptote_observer_canonical_close_hash,
    canonical_asymptote_observer_challenges_hash,
    canonical_asymptote_observer_observation_request_hash,
    canonical_asymptote_observer_transcript_hash, canonical_asymptote_observer_transcripts_hash,
    canonical_bulletin_availability_certificate_hash, canonical_bulletin_close_hash,
    canonical_bulletin_commitment_hash, canonical_collapse_commitment,
    canonical_collapse_commitment_hash_from_object, canonical_collapse_continuity_public_inputs,
    canonical_collapse_extension_certificate, canonical_order_certificate_hash,
    canonical_publication_frontier_hash, canonical_sealed_finality_proof_signing_bytes,
    compute_next_timestamp_ms, derive_asymptote_observer_plan_entries,
    derive_canonical_sealing_collapse, derive_guardian_witness_assignment,
    derive_guardian_witness_assignments_for_strata, effective_set_for_height,
    guardian_registry_asymptote_policy_key, guardian_registry_checkpoint_key,
    guardian_registry_committee_account_key, guardian_registry_committee_key,
    guardian_registry_log_key, guardian_registry_observer_canonical_abort_key,
    guardian_registry_observer_canonical_close_key,
    guardian_registry_observer_challenge_commitment_key,
    guardian_registry_observer_transcript_commitment_key, guardian_registry_witness_key,
    guardian_registry_witness_seed_key, guardian_registry_witness_set_key,
    guardian_witness_statement_for_header,
    guardian_witness_statement_for_header_with_recovery_binding, read_validator_sets,
    timestamp_millis_to_legacy_seconds, to_root_hash,
    verify_block_header_canonical_collapse_evidence, verify_canonical_collapse_continuity,
    verify_canonical_order_certificate, verify_publication_frontier_binding,
    verify_publication_frontier_chain, AccountId, AftRecoveredCertifiedHeaderEntry,
    AftRecoveredConsensusHeaderEntry, AftRecoveredRestartHeaderEntry, AsymptoteObserverAssignment,
    AsymptoteObserverCanonicalAbort, AsymptoteObserverCanonicalClose, AsymptoteObserverCertificate,
    AsymptoteObserverChallengeKind, AsymptoteObserverObservationRequest,
    AsymptoteObserverSealingMode, AsymptoteObserverStatement, AsymptoteObserverTranscript,
    AsymptoteObserverVerdict, AsymptotePolicy, Block, BlockHeader, BlockTimingParams,
    BlockTimingRuntime, BulletinAvailabilityCertificate, BulletinCommitment,
    CanonicalBulletinClose, CanonicalCollapseContinuityProofSystem,
    CanonicalCollapseExtensionCertificate, CanonicalCollapseKind, CanonicalCollapseObject,
    CanonicalOrderAbort, CanonicalOrderingCollapse, ChainStatus, ChainTransaction, CollapseState,
    ConsensusVote, EchoMessage, FailureReport, FinalityTier, GuardianCommitteeManifest,
    GuardianDecision, GuardianDecisionDomain, GuardianLogCheckpoint, GuardianQuorumCertificate,
    GuardianTransparencyLogDescriptor, GuardianWitnessCommitteeManifest, GuardianWitnessEpochSeed,
    GuardianWitnessSet, GuardianWitnessStatement, ProofOfDivergence, PublicationFrontier,
    PublicationFrontierContradiction, QuorumCertificate, RecoveredCanonicalHeaderEntry,
    RecoveredCertifiedHeaderEntry, RecoveredRestartBlockHeaderEntry, TimeoutCertificate,
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
use zk_driver_succinct::SuccinctDriver;

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

fn verify_sealed_finality_proof_signature(
    header: &BlockHeader,
    proof: &ioi_types::app::SealedFinalityProof,
) -> Result<(), ConsensusError> {
    if proof.proof_signature.public_key.is_empty() || proof.proof_signature.signature.is_empty() {
        return Err(ConsensusError::BlockVerificationFailed(
            "sealed finality proof is missing its producer signature".into(),
        ));
    }
    if proof.proof_signature.public_key != header.producer_pubkey {
        return Err(ConsensusError::BlockVerificationFailed(
            "sealed finality proof signer does not match the block producer".into(),
        ));
    }
    let pk = PublicKey::try_decode_protobuf(&proof.proof_signature.public_key)
        .map_err(|_| ConsensusError::InvalidSignature)?;
    let sign_bytes = canonical_sealed_finality_proof_signing_bytes(proof)
        .map_err(ConsensusError::BlockVerificationFailed)?;
    if pk.verify(&sign_bytes, &proof.proof_signature.signature) {
        Ok(())
    } else {
        Err(ConsensusError::BlockVerificationFailed(
            "sealed finality proof producer signature is invalid".into(),
        ))
    }
}

/// The Aft deterministic Consensus Engine.
#[derive(Clone)]
pub struct GuardianMajorityEngine {
    safety_mode: AftSafetyMode,
    continuity_verifier: SharedContinuityVerifier,
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

    /// Records the locally committed canonical collapse object per height so
    /// committed hints can prove rolling continuity rather than only single-slot collapse.
    committed_collapses: HashMap<u64, CanonicalCollapseObject>,

    /// Records bounded recovered canonical-header ancestry so restart continuity
    /// can still seed parent/QC selection when the full committed block is not
    /// locally available.
    recovered_headers: HashMap<u64, RecoveredCanonicalHeaderEntry>,

    /// Records bounded recovered certified-header ancestry so restart continuity
    /// can still reconcile multi-hop QC/header progress when the full
    /// committed header cache is not locally available.
    recovered_certified_headers: HashMap<u64, RecoveredCertifiedHeaderEntry>,

    /// Records bounded recovered restart block-header entries so restart-time
    /// QC/header lookup can use a compact header cache derived from recovered
    /// closed-slot surfaces.
    recovered_restart_headers: HashMap<u64, RecoveredRestartBlockHeaderEntry>,

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

#[derive(Clone)]
struct SharedContinuityVerifier(Arc<dyn CanonicalCollapseContinuityVerifier>);

impl Default for SharedContinuityVerifier {
    fn default() -> Self {
        Self(Arc::new(SuccinctDriver::default()))
    }
}

impl std::fmt::Debug for SharedContinuityVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SharedContinuityVerifier")
            .field(&"CanonicalCollapseContinuityVerifier")
            .finish()
    }
}

impl std::fmt::Debug for GuardianMajorityEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardianMajorityEngine")
            .field("safety_mode", &self.safety_mode)
            .field("continuity_verifier", &self.continuity_verifier)
            .field("highest_qc", &self.highest_qc)
            .field("cached_validator_count", &self.cached_validator_count)
            .finish_non_exhaustive()
    }
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
            continuity_verifier: SharedContinuityVerifier::default(),
            last_seen_counters: HashMap::new(),
            view_votes: HashMap::new(),
            tc_formed: HashSet::new(),
            timeout_votes_sent: HashSet::new(),
            seen_headers: HashMap::new(),
            vote_pool: HashMap::new(),
            validator_count_by_height: HashMap::new(),
            qc_pool: HashMap::new(),
            committed_headers: HashMap::new(),
            committed_collapses: HashMap::new(),
            recovered_headers: HashMap::new(),
            recovered_certified_headers: HashMap::new(),
            recovered_restart_headers: HashMap::new(),
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

    fn verify_canonical_collapse_backend(
        &self,
        collapse: &CanonicalCollapseObject,
    ) -> Result<(), ConsensusError> {
        let proof = &collapse.continuity_recursive_proof;
        match proof.proof_system {
            CanonicalCollapseContinuityProofSystem::HashPcdV1 => Ok(()),
            CanonicalCollapseContinuityProofSystem::SuccinctSp1V1 => {
                let public_inputs = canonical_collapse_continuity_public_inputs(
                    &proof.commitment,
                    proof.previous_canonical_collapse_commitment_hash,
                    proof.payload_hash,
                    proof.previous_recursive_proof_hash,
                );
                self.continuity_verifier
                    .0
                    .verify_canonical_collapse_continuity(
                        proof.proof_system,
                        &proof.proof_bytes,
                        &public_inputs,
                    )
                    .map_err(|error| {
                        ConsensusError::BlockVerificationFailed(format!(
                            "canonical collapse continuity backend verification failed for height {}: {}",
                            collapse.height, error
                        ))
                    })
            }
        }
    }

    fn verify_runtime_canonical_collapse_continuity(
        &self,
        collapse: &CanonicalCollapseObject,
        previous: Option<&CanonicalCollapseObject>,
    ) -> Result<(), ConsensusError> {
        verify_canonical_collapse_continuity(collapse, previous)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        self.verify_canonical_collapse_backend(collapse)
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

    fn local_recovered_header_for_qc(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<RecoveredCanonicalHeaderEntry> {
        let header = self.recovered_headers.get(&qc.height)?;
        (header.canonical_block_commitment_hash == qc.block_hash && header.view == qc.view)
            .then(|| header.clone())
    }

    fn local_recovered_certified_header_for_qc(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<RecoveredCertifiedHeaderEntry> {
        let entry = self.recovered_certified_headers.get(&qc.height)?;
        let certified_qc = entry.certified_quorum_certificate();
        (certified_qc.block_hash == qc.block_hash && certified_qc.view == qc.view)
            .then(|| entry.clone())
    }

    fn local_recovered_restart_header_for_qc(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<RecoveredRestartBlockHeaderEntry> {
        let entry = self.recovered_restart_headers.get(&qc.height)?;
        let certified_qc = entry.certified_quorum_certificate();
        (certified_qc.block_hash == qc.block_hash && certified_qc.view == qc.view)
            .then(|| entry.clone())
    }

    fn local_recovered_qc_for_height(&self, height: u64) -> Option<QuorumCertificate> {
        self.recovered_headers
            .get(&height)
            .map(RecoveredCanonicalHeaderEntry::synthetic_quorum_certificate)
    }

    fn qc_has_local_restart_context(&self, qc: &QuorumCertificate) -> bool {
        self.local_header_for_qc(qc).is_some()
            || self.local_recovered_header_for_qc(qc).is_some()
            || self.local_recovered_certified_header_for_qc(qc).is_some()
            || self.local_recovered_restart_header_for_qc(qc).is_some()
    }

    fn queue_qc_broadcast(&mut self, qc: &QuorumCertificate) {
        let key = (qc.height, qc.block_hash);
        if self.announced_qcs.insert(key) {
            self.pending_qc_broadcasts.push_back(qc.clone());
        }
    }

    fn canonical_ordering_collapse_from_header(
        header: &BlockHeader,
    ) -> Result<CanonicalOrderingCollapse, ConsensusError> {
        match header.canonical_order_certificate.as_ref() {
            Some(certificate) => {
                let bulletin_close = build_canonical_bulletin_close(
                    &certificate.bulletin_commitment,
                    &certificate.bulletin_availability_certificate,
                )
                .map_err(|error| {
                    ConsensusError::BlockVerificationFailed(format!(
                        "failed to rebuild canonical bulletin close for collapse derivation: {}",
                        error
                    ))
                })?;
                Ok(CanonicalOrderingCollapse {
                    height: header.height,
                    kind: if certificate.omission_proofs.is_empty() {
                        CanonicalCollapseKind::Close
                    } else {
                        CanonicalCollapseKind::Abort
                    },
                    bulletin_commitment_hash: canonical_bulletin_commitment_hash(
                        &certificate.bulletin_commitment,
                    )
                    .map_err(ConsensusError::BlockVerificationFailed)?,
                    bulletin_availability_certificate_hash:
                        canonical_bulletin_availability_certificate_hash(
                            &certificate.bulletin_availability_certificate,
                        )
                        .map_err(ConsensusError::BlockVerificationFailed)?,
                    bulletin_close_hash: canonical_bulletin_close_hash(&bulletin_close)
                        .map_err(ConsensusError::BlockVerificationFailed)?,
                    canonical_order_certificate_hash: canonical_order_certificate_hash(certificate)
                        .map_err(ConsensusError::BlockVerificationFailed)?,
                })
            }
            None => Ok(CanonicalOrderingCollapse {
                height: header.height,
                kind: CanonicalCollapseKind::Abort,
                bulletin_commitment_hash: [0u8; 32],
                bulletin_availability_certificate_hash: [0u8; 32],
                bulletin_close_hash: [0u8; 32],
                canonical_order_certificate_hash: [0u8; 32],
            }),
        }
    }

    fn canonical_collapse_from_header_surface_with_previous(
        &self,
        header: &BlockHeader,
        previous: Option<&CanonicalCollapseObject>,
    ) -> Result<CanonicalCollapseObject, ConsensusError> {
        verify_block_header_canonical_collapse_evidence(header, previous)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let ordering = Self::canonical_ordering_collapse_from_header(header)?;
        let sealing = header
            .sealed_finality_proof
            .as_ref()
            .map(derive_canonical_sealing_collapse)
            .transpose()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let mut collapse = CanonicalCollapseObject {
            height: header.height,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering,
            sealing,
            transactions_root_hash: to_root_hash(&header.transactions_root)
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
            resulting_state_root_hash: to_root_hash(&header.state_root.0)
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        bind_canonical_collapse_continuity(&mut collapse, previous)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        self.verify_runtime_canonical_collapse_continuity(&collapse, previous)?;
        Ok(collapse)
    }

    fn quorum_certificate_from_header(
        header: &BlockHeader,
    ) -> Result<QuorumCertificate, ConsensusError> {
        let block_hash = to_root_hash(
            &header
                .hash()
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
        )
        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        Ok(QuorumCertificate {
            height: header.height,
            view: header.view,
            block_hash,
            signatures: vec![],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        })
    }

    fn verify_local_canonical_collapse_chain(
        &self,
        collapse: &CanonicalCollapseObject,
    ) -> Result<(), ConsensusError> {
        let mut chain = Vec::new();
        let mut current = collapse.clone();
        loop {
            chain.push(current.clone());
            if current.height <= 1 {
                break;
            }
            current = self
                .committed_collapses
                .get(&(current.height - 1))
                .cloned()
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(format!(
                        "missing locally committed canonical collapse object for height {}",
                        current.height - 1
                    ))
                })?;
        }
        chain.reverse();
        let mut previous: Option<&CanonicalCollapseObject> = None;
        for current in &chain {
            self.verify_runtime_canonical_collapse_continuity(current, previous)?;
            previous = Some(current);
        }
        Ok(())
    }

    async fn load_published_canonical_collapse_object(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<Option<CanonicalCollapseObject>, ConsensusError> {
        let Some(bytes) = parent_view
            .get(&aft_canonical_collapse_object_key(height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
        else {
            return Ok(None);
        };

        codec::from_bytes_canonical(&bytes)
            .map(Some)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    async fn canonical_collapse_for_height(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<Option<CanonicalCollapseObject>, ConsensusError> {
        if height == 0 {
            return Ok(None);
        }
        if let Some(collapse) = self.committed_collapses.get(&height) {
            self.verify_canonical_collapse_backend(collapse)?;
            return Ok(Some(collapse.clone()));
        }
        let collapse = self
            .load_published_canonical_collapse_object(height, parent_view)
            .await?;
        if let Some(collapse) = collapse.as_ref() {
            self.verify_canonical_collapse_backend(collapse)?;
        }
        Ok(collapse)
    }

    async fn previous_canonical_collapse_for_height(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<Option<CanonicalCollapseObject>, ConsensusError> {
        if height <= 1 {
            return Ok(None);
        }
        if let Some(previous) = self.committed_collapses.get(&(height - 1)) {
            self.verify_canonical_collapse_backend(previous)?;
            return Ok(Some(previous.clone()));
        }
        match self
            .load_published_canonical_collapse_object(height - 1, parent_view)
            .await?
        {
            Some(previous) => {
                self.verify_canonical_collapse_backend(&previous)?;
                Ok(Some(previous))
            }
            None => Err(ConsensusError::BlockVerificationFailed(format!(
                "missing previous canonical collapse object for height {}",
                height
            ))),
        }
    }

    async fn verify_canonical_collapse_chain_with_parent_view(
        &self,
        collapse: &CanonicalCollapseObject,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<(), ConsensusError> {
        let mut chain = Vec::new();
        let mut current = collapse.clone();
        loop {
            chain.push(current.clone());
            if current.height <= 1 {
                break;
            }
            current = self
                .canonical_collapse_for_height(current.height - 1, parent_view)
                .await?
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(format!(
                        "missing canonical collapse object for height {}",
                        current.height - 1
                    ))
                })?;
        }
        chain.reverse();
        let mut previous: Option<&CanonicalCollapseObject> = None;
        for current in &chain {
            self.verify_runtime_canonical_collapse_continuity(current, previous)?;
            previous = Some(current);
        }
        Ok(())
    }

    async fn canonical_collapse_extension_certificate_for_height(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<([u8; 32], CanonicalCollapseExtensionCertificate), ConsensusError> {
        if height <= 1 {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "height {} does not admit a canonical collapse extension certificate",
                height
            )));
        }
        let Some(head) = self
            .previous_canonical_collapse_for_height(height, parent_view)
            .await?
        else {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "missing previous canonical collapse object for height {}",
                height
            )));
        };
        self.verify_canonical_collapse_chain_with_parent_view(&head, parent_view)
            .await?;
        let certificate = canonical_collapse_extension_certificate(height, &head)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let hash = canonical_collapse_commitment_hash_from_object(&head)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        Ok((hash, certificate))
    }

    async fn canonical_collapse_from_header_surface_with_parent_view(
        &self,
        header: &BlockHeader,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<CanonicalCollapseObject, ConsensusError> {
        let previous = self
            .previous_canonical_collapse_for_height(header.height, parent_view)
            .await?;
        if let Some(previous) = previous.as_ref() {
            self.verify_canonical_collapse_chain_with_parent_view(previous, parent_view)
                .await?;
        }
        self.canonical_collapse_from_header_surface_with_previous(header, previous.as_ref())
    }

    async fn header_is_collapse_backed(
        &self,
        header: &BlockHeader,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<bool, ConsensusError> {
        let derived = self
            .canonical_collapse_from_header_surface_with_parent_view(header, parent_view)
            .await?;
        match self
            .load_published_canonical_collapse_object(header.height, parent_view)
            .await?
        {
            Some(published) => {
                self.verify_canonical_collapse_chain_with_parent_view(&published, parent_view)
                    .await?;
                Ok(published == derived)
            }
            None => Ok(true),
        }
    }

    fn header_links_to_local_previous_collapse(
        &self,
        header: &BlockHeader,
    ) -> Result<bool, ConsensusError> {
        let previous = if header.height <= 1 {
            None
        } else {
            self.committed_collapses.get(&(header.height - 1))
        };
        if verify_block_header_canonical_collapse_evidence(header, previous).is_err() {
            return Ok(false);
        }
        if let Some(local) = previous {
            if self.verify_local_canonical_collapse_chain(local).is_err() {
                return Ok(false);
            }
            let Some(certificate) = header.canonical_collapse_extension_certificate.as_ref() else {
                return Ok(false);
            };
            if certificate.predecessor_commitment != canonical_collapse_commitment(local) {
                return Ok(false);
            }
            let expected_proof_hash = ioi_types::app::canonical_collapse_recursive_proof_hash(
                &local.continuity_recursive_proof,
            )
            .map_err(ConsensusError::BlockVerificationFailed)?;
            if certificate.predecessor_recursive_proof_hash != expected_proof_hash {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn quorum_certificate_is_collapse_backed(
        &self,
        qc: &QuorumCertificate,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<bool, ConsensusError> {
        if qc.height == 0 {
            return Ok(true);
        }

        if let Some(header) = self.committed_headers.get(&qc.height) {
            let expected = Self::quorum_certificate_from_header(header)?;
            if expected.block_hash == qc.block_hash
                && expected.height == qc.height
                && expected.view == qc.view
            {
                return self.header_is_collapse_backed(header, parent_view).await;
            }
        }

        let header = self
            .seen_headers
            .iter()
            .filter(|((height, _), _)| *height == qc.height)
            .find_map(|(_, headers)| headers.get(&qc.block_hash).cloned());
        let Some(header) = header else {
            return Ok(false);
        };
        let expected = Self::quorum_certificate_from_header(&header)?;
        if expected.block_hash != qc.block_hash
            || expected.height != qc.height
            || expected.view != qc.view
        {
            return Ok(false);
        }
        self.header_is_collapse_backed(&header, parent_view).await
    }

    async fn collapse_backed_parent_qc_for_height(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<Option<QuorumCertificate>, ConsensusError> {
        let parent_height = match height.checked_sub(1) {
            Some(parent_height) => parent_height,
            None => return Ok(None),
        };
        if parent_height == 0 {
            return Ok(Some(QuorumCertificate::default()));
        }

        if let Some(header) = self.committed_headers.get(&parent_height) {
            if self.header_is_collapse_backed(header, parent_view).await? {
                return Ok(Some(Self::quorum_certificate_from_header(header)?));
            }
        }

        let mut candidates = self
            .seen_headers
            .iter()
            .filter(|((seen_height, _), _)| *seen_height == parent_height)
            .flat_map(|(_, headers)| headers.values().cloned())
            .collect::<Vec<_>>();
        candidates.sort_by(|a, b| {
            a.view
                .cmp(&b.view)
                .then_with(|| a.producer_account_id.0.cmp(&b.producer_account_id.0))
        });
        candidates.reverse();

        for candidate in candidates {
            if self
                .header_is_collapse_backed(&candidate, parent_view)
                .await?
            {
                return Ok(Some(Self::quorum_certificate_from_header(&candidate)?));
            }
        }

        Ok(None)
    }

    fn local_header_for_qc(&self, qc: &QuorumCertificate) -> Option<BlockHeader> {
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

    fn maybe_promote_committed_height_qc(&mut self, height: u64) {
        if height == 0 || self.highest_qc.height >= height {
            return;
        }

        if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
            let Some(header) = self.committed_headers.get(&height) else {
                return;
            };
            if !self.committed_collapses.contains_key(&height) {
                return;
            }
            let Ok(qc) = Self::quorum_certificate_from_header(header) else {
                return;
            };
            self.highest_qc = qc.clone();
            self.queue_qc_broadcast(&qc);
            return;
        }

        if let Some(qc) = self.local_recovered_qc_for_height(height) {
            self.highest_qc = qc.clone();
            self.queue_qc_broadcast(&qc);
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

        if let Some(qc) = self.local_recovered_qc_for_height(parent_height) {
            return Some(qc);
        }

        if let Some(qc) = self.qc_pool.get(&parent_height).and_then(|qcs| {
            (qcs.len() == 1)
                .then(|| qcs.values().next().cloned())
                .flatten()
        }) {
            return Some(qc);
        }

        if let Some((block_hash, votes)) =
            self.vote_pool
                .get(&parent_height)
                .and_then(|votes_by_hash| {
                    (votes_by_hash.len() == 1)
                        .then(|| {
                            votes_by_hash
                                .iter()
                                .next()
                                .map(|(hash, votes)| (*hash, votes))
                        })
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

        let header = self.local_header_for_qc(&qc);
        let recovered_header = self.local_recovered_header_for_qc(&qc);
        if header.is_none()
            && recovered_header.is_none()
            && qc.height > self.highest_qc.height.saturating_add(1)
        {
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

        if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
            let Some(header) = header.as_ref() else {
                debug!(
                    target: "consensus",
                    height = qc.height,
                    view = qc.view,
                    block = %hex::encode(&qc.block_hash[..4]),
                    "Ignoring QC without a locally known collapse-derivable header in Asymptote"
                );
                return Ok(());
            };
            if !self.header_links_to_local_previous_collapse(header)? {
                debug!(
                    target: "consensus",
                    height = qc.height,
                    view = qc.view,
                    block = %hex::encode(&qc.block_hash[..4]),
                    "Ignoring QC whose locally known header is not linked to the previous canonical collapse object"
                );
                return Ok(());
            }
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
        guardian_witness_statement_for_header(header, certificate)
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

    fn asymptote_observer_observation_request(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        assignment: &AsymptoteObserverAssignment,
    ) -> Result<AsymptoteObserverObservationRequest, ConsensusError> {
        let block_hash = ioi_crypto::algorithms::hash::sha256(
            &header
                .to_preimage_for_signing()
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
        )
        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        Ok(AsymptoteObserverObservationRequest {
            epoch: assignment.epoch,
            assignment: assignment.clone(),
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
        let statement =
            self.asymptote_observer_statement(header, certificate, observer_certificate)?;
        self.verify_asymptote_observer_statement_certificate(
            &statement,
            &observer_certificate.guardian_certificate,
            parent_view,
            current_epoch,
        )
        .await
    }

    async fn verify_asymptote_observer_statement_certificate(
        &self,
        statement: &AsymptoteObserverStatement,
        observer_guardian: &GuardianQuorumCertificate,
        parent_view: &dyn AnchoredStateView,
        current_epoch: u64,
    ) -> Result<(), ConsensusError> {
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
        if observer_manifest.validator_account_id != statement.assignment.observer_account_id {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer certificate manifest does not belong to the assigned observer".into(),
            ));
        }
        let decision =
            Self::asymptote_observer_decision(statement, &observer_manifest, observer_guardian)?;
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

    async fn verify_asymptote_observer_transcript(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        transcript: &AsymptoteObserverTranscript,
        parent_view: &dyn AnchoredStateView,
        current_epoch: u64,
    ) -> Result<(), ConsensusError> {
        let observer_certificate = AsymptoteObserverCertificate {
            assignment: transcript.statement.assignment.clone(),
            verdict: transcript.statement.verdict,
            veto_kind: transcript.statement.veto_kind,
            evidence_hash: transcript.statement.evidence_hash,
            guardian_certificate: transcript.guardian_certificate.clone(),
        };
        let expected_statement =
            self.asymptote_observer_statement(header, certificate, &observer_certificate)?;
        if transcript.statement != expected_statement {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer transcript statement does not match the canonical slot binding".into(),
            ));
        }
        self.verify_asymptote_observer_statement_certificate(
            &transcript.statement,
            &transcript.guardian_certificate,
            parent_view,
            current_epoch,
        )
        .await
    }

    async fn derive_expected_asymptote_observer_assignments(
        &self,
        header: &BlockHeader,
        parent_view: &dyn AnchoredStateView,
        witness_seed: &GuardianWitnessEpochSeed,
        policy: &AsymptotePolicy,
    ) -> Result<Vec<AsymptoteObserverAssignment>, ConsensusError> {
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
        Ok(expected_plan
            .into_iter()
            .map(|entry| entry.assignment)
            .collect())
    }

    async fn verify_asymptote_canonical_observer_sealed_finality(
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
                "canonical observer sealing requires observer policy to be configured".into(),
            ));
        }
        if policy.observer_challenge_window_ms == 0 {
            return Err(ConsensusError::BlockVerificationFailed(
                "canonical observer sealing requires a non-zero challenge window".into(),
            ));
        }
        if !proof.witness_certificates.is_empty() {
            return Err(ConsensusError::BlockVerificationFailed(
                "canonical observer sealing may not mix witness certificates with observer transcripts"
                    .into(),
            ));
        }
        if !proof.observer_certificates.is_empty()
            || !proof.veto_proofs.is_empty()
            || proof.observer_close_certificate.is_some()
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "canonical observer sealing may not mix sampled observer certificates, veto proofs, or legacy close certificates".into(),
            ));
        }
        if !proof.divergence_signals.is_empty() {
            return Err(ConsensusError::BlockVerificationFailed(
                "canonical observer sealing proof may not contain divergence signals".into(),
            ));
        }

        let transcript_commitment =
            proof
                .observer_transcript_commitment
                .as_ref()
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(
                        "canonical observer sealing proof is missing a transcript commitment"
                            .into(),
                    )
                })?;
        let challenge_commitment =
            proof
                .observer_challenge_commitment
                .as_ref()
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(
                        "canonical observer sealing proof is missing a challenge commitment".into(),
                    )
                })?;
        if proof.observer_canonical_close.is_some() == proof.observer_canonical_abort.is_some() {
            return Err(ConsensusError::BlockVerificationFailed(
                "canonical observer sealing proof must carry exactly one of canonical close or canonical abort".into(),
            ));
        }
        let canonical_close = proof.observer_canonical_close.as_ref();
        let canonical_abort = proof.observer_canonical_abort.as_ref();

        let expected_assignments = self
            .derive_expected_asymptote_observer_assignments(
                header,
                parent_view,
                witness_seed,
                policy,
            )
            .await?;
        let expected_assignments_hash =
            canonical_asymptote_observer_assignments_hash(&expected_assignments)
                .map_err(ConsensusError::BlockVerificationFailed)?;

        let expected_transcript_count =
            u16::try_from(expected_assignments.len()).map_err(|_| {
                ConsensusError::BlockVerificationFailed(
                    "deterministic observer transcript surface exceeds u16 capacity".into(),
                )
            })?;
        let expected_challenge_root =
            canonical_asymptote_observer_challenges_hash(&proof.observer_challenges)
                .map_err(ConsensusError::BlockVerificationFailed)?;
        let expected_transcript_root =
            canonical_asymptote_observer_transcripts_hash(&proof.observer_transcripts)
                .map_err(ConsensusError::BlockVerificationFailed)?;

        if transcript_commitment.epoch != current_epoch
            || transcript_commitment.height != header.height
            || transcript_commitment.view != header.view
            || transcript_commitment.assignments_hash != expected_assignments_hash
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer transcript commitment does not match the canonical slot assignment surface".into(),
            ));
        }
        if challenge_commitment.epoch != current_epoch
            || challenge_commitment.height != header.height
            || challenge_commitment.view != header.view
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer challenge commitment does not match the sealed slot".into(),
            ));
        }
        if let Some(canonical_close) = canonical_close {
            if canonical_close.epoch != current_epoch
                || canonical_close.height != header.height
                || canonical_close.view != header.view
                || canonical_close.assignments_hash != expected_assignments_hash
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer canonical close does not match the canonical slot assignment surface"
                        .into(),
                ));
            }
            if canonical_close.challenge_cutoff_timestamp_ms == 0 {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer canonical close must carry a non-zero challenge cutoff".into(),
                ));
            }
        }
        if let Some(canonical_abort) = canonical_abort {
            if canonical_abort.epoch != current_epoch
                || canonical_abort.height != header.height
                || canonical_abort.view != header.view
                || canonical_abort.assignments_hash != expected_assignments_hash
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer canonical abort does not match the canonical slot assignment surface"
                        .into(),
                ));
            }
            if canonical_abort.challenge_cutoff_timestamp_ms == 0 {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer canonical abort must carry a non-zero challenge cutoff".into(),
                ));
            }
        }

        let stored_transcript_commitment = parent_view
            .get(&guardian_registry_observer_transcript_commitment_key(
                current_epoch,
                header.height,
                header.view,
            ))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;
        if let Some(stored_transcript_commitment) = stored_transcript_commitment {
            let stored_transcript_commitment: ioi_types::app::AsymptoteObserverTranscriptCommitment =
                codec::from_bytes_canonical(&stored_transcript_commitment)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            if &stored_transcript_commitment != transcript_commitment {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer transcript commitment does not match the on-chain registry copy"
                        .into(),
                ));
            }
        }

        let stored_challenge_commitment = parent_view
            .get(&guardian_registry_observer_challenge_commitment_key(
                current_epoch,
                header.height,
                header.view,
            ))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;
        if let Some(stored_challenge_commitment) = stored_challenge_commitment {
            let stored_challenge_commitment: ioi_types::app::AsymptoteObserverChallengeCommitment =
                codec::from_bytes_canonical(&stored_challenge_commitment)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            if &stored_challenge_commitment != challenge_commitment {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer challenge commitment does not match the on-chain registry copy"
                        .into(),
                ));
            }
        }

        let stored_canonical_close = parent_view
            .get(&guardian_registry_observer_canonical_close_key(
                current_epoch,
                header.height,
                header.view,
            ))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;
        if let Some(stored_canonical_close) = stored_canonical_close {
            let stored_canonical_close: AsymptoteObserverCanonicalClose =
                codec::from_bytes_canonical(&stored_canonical_close)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            if Some(&stored_canonical_close) != canonical_close {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer canonical close does not match the on-chain registry copy".into(),
                ));
            }
        }
        let stored_canonical_abort = parent_view
            .get(&guardian_registry_observer_canonical_abort_key(
                current_epoch,
                header.height,
                header.view,
            ))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;
        if let Some(stored_canonical_abort) = stored_canonical_abort {
            let stored_canonical_abort: AsymptoteObserverCanonicalAbort =
                codec::from_bytes_canonical(&stored_canonical_abort)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            if Some(&stored_canonical_abort) != canonical_abort {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer canonical abort does not match the on-chain registry copy".into(),
                ));
            }
        }

        if transcript_commitment.transcripts_root != expected_transcript_root
            || canonical_close
                .map(|close| close.transcripts_root != expected_transcript_root)
                .unwrap_or(false)
            || canonical_abort
                .map(|abort| abort.transcripts_root != expected_transcript_root)
                .unwrap_or(false)
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer transcript surface root does not match the proof-carried transcripts"
                    .into(),
            ));
        }
        if canonical_close
            .map(|close| {
                transcript_commitment.transcript_count != expected_transcript_count
                    || close.transcript_count != expected_transcript_count
            })
            .unwrap_or(false)
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer transcript counts do not match the deterministic assignment surface"
                    .into(),
            ));
        }
        if challenge_commitment.challenges_root != expected_challenge_root
            || canonical_close
                .map(|close| close.challenges_root != expected_challenge_root)
                .unwrap_or(false)
            || canonical_abort
                .map(|abort| abort.challenges_root != expected_challenge_root)
                .unwrap_or(false)
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer challenge surface root does not match the proof-carried challenges"
                    .into(),
            ));
        }
        let proof_challenge_count =
            u16::try_from(proof.observer_challenges.len()).map_err(|_| {
                ConsensusError::BlockVerificationFailed(
                    "deterministic observer challenge surface exceeds u16 capacity".into(),
                )
            })?;
        if challenge_commitment.challenge_count != proof_challenge_count
            || canonical_close
                .map(|close| close.challenge_count != challenge_commitment.challenge_count)
                .unwrap_or(false)
            || canonical_abort
                .map(|abort| abort.challenge_count != challenge_commitment.challenge_count)
                .unwrap_or(false)
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer challenge counts do not match the proof-carried challenge surface".into(),
            ));
        }

        let expected = expected_assignments
            .into_iter()
            .map(|assignment| {
                (
                    (assignment.round, assignment.observer_account_id),
                    assignment,
                )
            })
            .collect::<HashMap<_, _>>();
        let mut seen = HashSet::new();
        for transcript in &proof.observer_transcripts {
            let key = (
                transcript.statement.assignment.round,
                transcript.statement.assignment.observer_account_id,
            );
            let Some(expected_assignment) = expected.get(&key) else {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer transcript surface includes an unexpected assignment".into(),
                ));
            };
            if !seen.insert(key) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer transcript surface contains duplicate assignments".into(),
                ));
            }
            if transcript.statement.assignment != *expected_assignment {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer transcript assignment does not match the deterministic sample".into(),
                ));
            }
            self.verify_asymptote_observer_transcript(
                header,
                certificate,
                transcript,
                parent_view,
                current_epoch,
            )
            .await?;
        }

        let mut challenged_assignments = HashSet::new();
        for challenge in &proof.observer_challenges {
            if challenge.epoch != current_epoch
                || challenge.height != header.height
                || challenge.view != header.view
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer challenge does not match the sealed slot".into(),
                ));
            }
            let mut normalized_challenge = challenge.clone();
            normalized_challenge.challenge_id = [0u8; 32];
            let expected_challenge_id = ioi_crypto::algorithms::hash::sha256(
                &codec::to_bytes_canonical(&normalized_challenge)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
            )
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            if challenge.challenge_id != expected_challenge_id {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer challenge id does not match its canonical payload".into(),
                ));
            }
            match challenge.kind {
                AsymptoteObserverChallengeKind::MissingTranscript => {
                    let assignment = challenge.assignment.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "missing-transcript challenge must be assignment scoped".into(),
                        )
                    })?;
                    let key = (assignment.round, assignment.observer_account_id);
                    if expected.get(&key) != Some(assignment) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "missing-transcript challenge references an unexpected assignment"
                                .into(),
                        ));
                    }
                    if seen.contains(&key) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "missing-transcript challenge references an assignment that already has a transcript".into(),
                        ));
                    }
                    if challenge.observation_request.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "missing-transcript challenge may not carry an observation request"
                                .into(),
                        ));
                    }
                    if challenge.transcript.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "missing-transcript challenge may not carry a transcript".into(),
                        ));
                    }
                    if challenge.canonical_close.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "missing-transcript challenge may not carry a canonical close".into(),
                        ));
                    }
                    let assignment_hash = canonical_asymptote_observer_assignment_hash(assignment)
                        .map_err(ConsensusError::BlockVerificationFailed)?;
                    if challenge.evidence_hash != assignment_hash {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "missing-transcript challenge evidence hash does not match the assignment".into(),
                        ));
                    }
                    challenged_assignments.insert(key);
                }
                AsymptoteObserverChallengeKind::TranscriptMismatch => {
                    let assignment = challenge.assignment.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "transcript-mismatch challenge must be assignment scoped".into(),
                        )
                    })?;
                    let request = challenge.observation_request.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "transcript-mismatch challenge must carry the offending observation request".into(),
                        )
                    })?;
                    let key = (assignment.round, assignment.observer_account_id);
                    if expected.get(&key) != Some(assignment) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "transcript-mismatch challenge references an unexpected assignment"
                                .into(),
                        ));
                    }
                    if seen.contains(&key) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "transcript-mismatch challenge references an assignment that already has a transcript".into(),
                        ));
                    }
                    if challenge.transcript.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "transcript-mismatch challenge may not carry a transcript".into(),
                        ));
                    }
                    let expected_request = self.asymptote_observer_observation_request(
                        header,
                        certificate,
                        assignment,
                    )?;
                    let request_hash =
                        canonical_asymptote_observer_observation_request_hash(request)
                            .map_err(ConsensusError::BlockVerificationFailed)?;
                    if challenge.evidence_hash != request_hash {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "transcript-mismatch challenge evidence hash does not match the offending request".into(),
                        ));
                    }
                    if request == &expected_request {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "transcript-mismatch challenge does not contain an objective mismatch"
                                .into(),
                        ));
                    }
                    challenged_assignments.insert(key);
                }
                AsymptoteObserverChallengeKind::VetoTranscriptPresent => {
                    let assignment = challenge.assignment.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge must be assignment scoped".into(),
                        )
                    })?;
                    let transcript = challenge.transcript.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge must carry the offending transcript".into(),
                        )
                    })?;
                    let key = (assignment.round, assignment.observer_account_id);
                    if expected.get(&key) != Some(assignment) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge references an unexpected assignment".into(),
                        ));
                    }
                    if seen.contains(&key) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge references an assignment that already has a transcript".into(),
                        ));
                    }
                    if challenge.observation_request.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge may not carry an observation request".into(),
                        ));
                    }
                    if transcript.statement.assignment != *assignment {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge transcript does not match its assignment"
                                .into(),
                        ));
                    }
                    let transcript_hash = canonical_asymptote_observer_transcript_hash(transcript)
                        .map_err(ConsensusError::BlockVerificationFailed)?;
                    if challenge.evidence_hash != transcript_hash {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge evidence hash does not match the offending transcript".into(),
                        ));
                    }
                    let observer_certificate = AsymptoteObserverCertificate {
                        assignment: transcript.statement.assignment.clone(),
                        verdict: transcript.statement.verdict,
                        veto_kind: transcript.statement.veto_kind,
                        evidence_hash: transcript.statement.evidence_hash,
                        guardian_certificate: transcript.guardian_certificate.clone(),
                    };
                    let expected_statement = self.asymptote_observer_statement(
                        header,
                        certificate,
                        &observer_certificate,
                    )?;
                    if transcript.statement != expected_statement {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge does not bind the canonical slot surface"
                                .into(),
                        ));
                    }
                    self.verify_asymptote_observer_statement_certificate(
                        &transcript.statement,
                        &transcript.guardian_certificate,
                        parent_view,
                        current_epoch,
                    )
                    .await?;
                    if transcript.statement.verdict == AsymptoteObserverVerdict::Ok
                        && transcript.statement.veto_kind.is_none()
                    {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge does not carry an admissible veto".into(),
                        ));
                    }
                    challenged_assignments.insert(key);
                }
                AsymptoteObserverChallengeKind::ConflictingTranscript => {
                    let assignment = challenge.assignment.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "conflicting-transcript challenge must be assignment scoped".into(),
                        )
                    })?;
                    let transcript = challenge.transcript.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "conflicting-transcript challenge must carry the offending transcript"
                                .into(),
                        )
                    })?;
                    let key = (assignment.round, assignment.observer_account_id);
                    if expected.get(&key) != Some(assignment) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "conflicting-transcript challenge references an unexpected assignment"
                                .into(),
                        ));
                    }
                    if seen.contains(&key) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "conflicting-transcript challenge references an assignment that already has a transcript".into(),
                        ));
                    }
                    if challenge.observation_request.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "conflicting-transcript challenge may not carry an observation request"
                                .into(),
                        ));
                    }
                    let transcript_hash = canonical_asymptote_observer_transcript_hash(transcript)
                        .map_err(ConsensusError::BlockVerificationFailed)?;
                    if challenge.evidence_hash != transcript_hash {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "conflicting-transcript challenge evidence hash does not match the offending transcript".into(),
                        ));
                    }
                    self.verify_asymptote_observer_statement_certificate(
                        &transcript.statement,
                        &transcript.guardian_certificate,
                        parent_view,
                        current_epoch,
                    )
                    .await?;
                    let observer_certificate = AsymptoteObserverCertificate {
                        assignment: assignment.clone(),
                        verdict: transcript.statement.verdict,
                        veto_kind: transcript.statement.veto_kind,
                        evidence_hash: transcript.statement.evidence_hash,
                        guardian_certificate: transcript.guardian_certificate.clone(),
                    };
                    let expected_statement = self.asymptote_observer_statement(
                        header,
                        certificate,
                        &observer_certificate,
                    )?;
                    if transcript.statement.assignment == *assignment
                        && transcript.statement == expected_statement
                    {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "conflicting-transcript challenge does not contain a conflicting transcript".into(),
                        ));
                    }
                    challenged_assignments.insert(key);
                }
                AsymptoteObserverChallengeKind::InvalidCanonicalClose => {
                    let close = challenge.canonical_close.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "invalid-canonical-close challenge must carry the offending canonical close".into(),
                        )
                    })?;
                    if challenge.assignment.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "invalid-canonical-close challenge may not be assignment scoped".into(),
                        ));
                    }
                    if challenge.observation_request.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "invalid-canonical-close challenge may not carry an observation request"
                                .into(),
                        ));
                    }
                    if challenge.transcript.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "invalid-canonical-close challenge may not carry a transcript".into(),
                        ));
                    }
                    let close_hash = canonical_asymptote_observer_canonical_close_hash(close)
                        .map_err(ConsensusError::BlockVerificationFailed)?;
                    if challenge.evidence_hash != close_hash {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "invalid-canonical-close challenge evidence hash does not match the offending close".into(),
                        ));
                    }
                    let empty_challenges_root = canonical_asymptote_observer_challenges_hash(&[])
                        .map_err(ConsensusError::BlockVerificationFailed)?;
                    let transcripts_are_all_ok =
                        proof.observer_transcripts.iter().all(|transcript| {
                            transcript.statement.verdict == AsymptoteObserverVerdict::Ok
                                && transcript.statement.veto_kind.is_none()
                        });
                    let close_is_valid = close.epoch == current_epoch
                        && close.height == header.height
                        && close.view == header.view
                        && close.assignments_hash == expected_assignments_hash
                        && close.transcripts_root == expected_transcript_root
                        && close.transcript_count == proof.observer_transcripts.len() as u16
                        && close.challenges_root == empty_challenges_root
                        && close.challenge_count == 0
                        && close.challenge_cutoff_timestamp_ms != 0
                        && seen.len() == expected.len()
                        && transcripts_are_all_ok;
                    if close_is_valid {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "invalid-canonical-close challenge does not contain an objectively invalid close".into(),
                        ));
                    }
                }
            }
        }

        if let Some(canonical_close) = canonical_close {
            if proof.finality_tier != FinalityTier::SealedFinal
                || proof.collapse_state != CollapseState::SealedFinal
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "canonical observer close must appear only in a SealedFinal proof".into(),
                ));
            }
            if !proof.observer_challenges.is_empty() {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer challenge surface is non-empty; canonical close is challenge-dominated".into(),
                ));
            }
            if canonical_close.challenge_count != 0 {
                return Err(ConsensusError::BlockVerificationFailed(
                    "canonical observer close may not carry dominant challenges".into(),
                ));
            }
            if seen.len() != expected.len() {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer transcript surface does not cover every deterministic assignment"
                        .into(),
                ));
            }
            for transcript in &proof.observer_transcripts {
                if transcript.statement.verdict != AsymptoteObserverVerdict::Ok
                    || transcript.statement.veto_kind.is_some()
                {
                    return Err(ConsensusError::BlockVerificationFailed(
                        "observer transcript surface contains a non-OK verdict; SealedFinal is dominated".into(),
                    ));
                }
            }
        }
        if let Some(canonical_abort) = canonical_abort {
            if proof.finality_tier != FinalityTier::BaseFinal
                || proof.collapse_state != CollapseState::Abort
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "canonical observer abort must appear only in an Abort proof".into(),
                ));
            }
            if proof.observer_challenges.is_empty() {
                return Err(ConsensusError::BlockVerificationFailed(
                    "canonical observer abort requires at least one dominant challenge".into(),
                ));
            }
            if canonical_abort.challenge_count == 0 {
                return Err(ConsensusError::BlockVerificationFailed(
                    "canonical observer abort must bind a non-empty challenge surface".into(),
                ));
            }
            for assignment in expected.values() {
                let key = (assignment.round, assignment.observer_account_id);
                if !seen.contains(&key) && !challenged_assignments.contains(&key) {
                    return Err(ConsensusError::BlockVerificationFailed(
                        "canonical observer abort does not account for every deterministic assignment".into(),
                    ));
                }
            }
        }

        Ok(())
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
        if proof.finality_tier != FinalityTier::SealedFinal
            || proof.collapse_state != CollapseState::SealedFinal
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer-backed sealed finality proof is not in the SealedFinal state".into(),
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

        let expected_assignments = self
            .derive_expected_asymptote_observer_assignments(
                header,
                parent_view,
                witness_seed,
                policy,
            )
            .await?;

        if proof.observer_certificates.len() != expected_assignments.len() {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "sealed finality proof has {} observer certificates but expected {} equal-authority assignments",
                proof.observer_certificates.len(),
                expected_assignments.len()
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
            || observer_close_certificate.expected_assignments != expected_assignments.len() as u16
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

        let expected = expected_assignments
            .into_iter()
            .map(|assignment| {
                (
                    (assignment.round, assignment.observer_account_id),
                    assignment,
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
        verify_sealed_finality_proof_signature(header, proof)?;
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
        if policy.observer_sealing_mode == AsymptoteObserverSealingMode::CanonicalChallengeV1
            || !proof.observer_transcripts.is_empty()
            || !proof.observer_challenges.is_empty()
            || proof.observer_transcript_commitment.is_some()
            || proof.observer_challenge_commitment.is_some()
            || proof.observer_canonical_close.is_some()
        {
            return self
                .verify_asymptote_canonical_observer_sealed_finality(
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
        if proof.finality_tier != FinalityTier::SealedFinal
            || proof.collapse_state != CollapseState::SealedFinal
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "witness-backed sealed finality proof is not in the SealedFinal state".into(),
            ));
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
            let statement = guardian_witness_statement_for_header_with_recovery_binding(
                header,
                certificate,
                witness_certificate.recovery_binding.clone(),
            );
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
        let published_order_abort = parent_view
            .get(&aft_canonical_order_abort_key(header.height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .map(|bytes| {
                codec::from_bytes_canonical::<CanonicalOrderAbort>(&bytes)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
            })
            .transpose()?;
        let published_bulletin_availability = parent_view
            .get(&aft_bulletin_availability_certificate_key(header.height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .map(|bytes| {
                codec::from_bytes_canonical::<BulletinAvailabilityCertificate>(&bytes)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
            })
            .transpose()?;
        let published_bulletin_close = parent_view
            .get(&aft_canonical_bulletin_close_key(header.height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .map(|bytes| {
                codec::from_bytes_canonical::<CanonicalBulletinClose>(&bytes)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
            })
            .transpose()?;
        let Some(certificate) = header.canonical_order_certificate.as_ref() else {
            if published_order_abort.is_some() {
                if published_bulletin_availability.is_some() || published_bulletin_close.is_some() {
                    return Err(ConsensusError::BlockVerificationFailed(format!(
                        "parent state for slot {} is inconsistent: canonical order abort coexists with positive published ordering artifacts",
                        header.height
                    )));
                }
                return Ok(());
            }
            return Ok(());
        };
        if let Some(order_abort) = published_order_abort.as_ref() {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "canonical order abort already dominates slot {}: {}",
                header.height, order_abort.details
            )));
        }
        let published_bulletin = parent_view
            .get(&aft_bulletin_commitment_key(header.height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .map(|bytes| {
                codec::from_bytes_canonical::<BulletinCommitment>(&bytes)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
            })
            .transpose()?;
        verify_canonical_order_certificate(
            header,
            certificate,
            published_bulletin.as_ref(),
            published_bulletin_availability.as_ref(),
            published_bulletin_close.as_ref(),
        )
        .map_err(ConsensusError::BlockVerificationFailed)
    }

    async fn load_published_publication_frontier(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<Option<PublicationFrontier>, ConsensusError> {
        let Some(bytes) = parent_view
            .get(&aft_publication_frontier_key(height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
        else {
            return Ok(None);
        };

        codec::from_bytes_canonical(&bytes)
            .map(Some)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    async fn load_published_publication_frontier_contradiction(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<Option<PublicationFrontierContradiction>, ConsensusError> {
        let Some(bytes) = parent_view
            .get(&aft_publication_frontier_contradiction_key(height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
        else {
            return Ok(None);
        };

        codec::from_bytes_canonical(&bytes)
            .map(Some)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    async fn previous_publication_frontier_for_height(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<Option<PublicationFrontier>, ConsensusError> {
        if height <= 1 {
            return Ok(None);
        }
        if let Some(local) = self
            .committed_headers
            .get(&(height - 1))
            .and_then(|header| header.publication_frontier.clone())
        {
            return Ok(Some(local));
        }
        self.load_published_publication_frontier(height - 1, parent_view)
            .await
    }

    async fn verify_publication_frontier_enrichment(
        &self,
        header: &BlockHeader,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<(), ConsensusError> {
        if let Some(contradiction) = self
            .load_published_publication_frontier_contradiction(header.height, parent_view)
            .await?
        {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "publication frontier contradiction already dominates slot {}: {}",
                header.height,
                hex::encode(
                    canonical_publication_frontier_hash(&contradiction.candidate_frontier)
                        .map_err(ConsensusError::BlockVerificationFailed)?
                ),
            )));
        }

        let Some(certificate) = header.canonical_order_certificate.as_ref() else {
            if header.publication_frontier.is_some() {
                return Err(ConsensusError::BlockVerificationFailed(
                    "publication frontier requires a canonical-order certificate".into(),
                ));
            }
            return Ok(());
        };

        let frontier = header.publication_frontier.as_ref().ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(format!(
                "canonical-order certificate for slot {} requires a publication frontier",
                header.height
            ))
        })?;

        verify_publication_frontier_binding(header, frontier)
            .map_err(ConsensusError::BlockVerificationFailed)?;

        if let Some(previous) = self
            .previous_publication_frontier_for_height(header.height, parent_view)
            .await?
            .as_ref()
        {
            verify_publication_frontier_chain(frontier, previous)
                .map_err(ConsensusError::BlockVerificationFailed)?;
        }

        if frontier.bulletin_commitment_hash
            != canonical_bulletin_commitment_hash(&certificate.bulletin_commitment)
                .map_err(ConsensusError::BlockVerificationFailed)?
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "publication frontier does not match the canonical-order bulletin commitment"
                    .into(),
            ));
        }

        if let Some(published) = self
            .load_published_publication_frontier(header.height, parent_view)
            .await?
        {
            if published != *frontier {
                return Err(ConsensusError::BlockVerificationFailed(format!(
                    "publication frontier for slot {} conflicts with the published same-slot frontier",
                    header.height
                )));
            }
        }

        Ok(())
    }

    async fn verify_published_canonical_collapse_object(
        &self,
        header: &BlockHeader,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<(), ConsensusError> {
        let Some(published) = self
            .load_published_canonical_collapse_object(header.height, parent_view)
            .await?
        else {
            return Ok(());
        };
        let derived = self
            .canonical_collapse_from_header_surface_with_parent_view(header, parent_view)
            .await?;
        if published != derived {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "published canonical collapse object does not match the proof-carried surface for slot {}",
                header.height
            )));
        }
        self.verify_canonical_collapse_chain_with_parent_view(&published, parent_view)
            .await?;
        Ok(())
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
                    self.verify_publication_frontier_enrichment(header, parent_view)
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
        // Ready commits only become internal finality once their committed slot is
        // also backed by the canonical collapse surface in Asymptote mode.
        loop {
            let Some(ready_commit) = self.safety.next_ready_commit() else {
                break;
            };
            let collapse_backed = if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
                self.quorum_certificate_is_collapse_backed(&ready_commit, parent_view)
                    .await
                    .unwrap_or(false)
            } else {
                true
            };
            if !collapse_backed {
                debug!(
                    target: "consensus",
                    height = ready_commit.height,
                    view = ready_commit.view,
                    "Deferring ready commit until the corresponding canonical collapse object is available"
                );
                break;
            }
            if let Some(finalized_qc) = self.safety.accept_next_ready_commit() {
                info!(
                    target: "consensus",
                    "Safety Gadget: Finalized height {}",
                    finalized_qc.height
                );
            } else {
                break;
            }
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
        let pin_bootstrap_view_zero = bootstrap_first_commit_pending
            || (height <= 3 && Instant::now() < self.bootstrap_grace_until);

        if pin_bootstrap_view_zero {
            if let Ok(mut pacemaker) = self.pacemaker.try_lock() {
                pacemaker.current_view = 0;
                pacemaker.view_start_time = Instant::now();
            }
            current_view = 0;
            if bootstrap_first_commit_pending {
                self.timeout_votes_sent
                    .retain(|(vote_height, _)| *vote_height != height);
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
                let progress_parent_qc = if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
                    self.collapse_backed_parent_qc_for_height(height, parent_view)
                        .await
                        .ok()
                        .flatten()
                } else {
                    self.synthetic_parent_qc_for_height(height)
                };
                if let Some(synthetic_parent_qc) = progress_parent_qc {
                    let highest_qc_at_parent_height = self.highest_qc.height == height - 1;
                    let highest_qc_has_local_header =
                        if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
                            highest_qc_at_parent_height
                                && self
                                    .quorum_certificate_is_collapse_backed(
                                        &self.highest_qc,
                                        parent_view,
                                    )
                                    .await
                                    .unwrap_or(false)
                        } else {
                            highest_qc_at_parent_height
                                && self.qc_has_local_restart_context(&self.highest_qc)
                        };

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
                } else if self.highest_qc.height < height - 1
                    || (matches!(self.safety_mode, AftSafetyMode::Asymptote)
                        && self.highest_qc.height == height - 1
                        && !self
                            .quorum_certificate_is_collapse_backed(&self.highest_qc, parent_view)
                            .await
                            .unwrap_or(false))
                {
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

            let (
                previous_canonical_collapse_commitment_hash,
                canonical_collapse_extension_certificate,
            ) = if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
                match self
                    .canonical_collapse_extension_certificate_for_height(height, parent_view)
                    .await
                {
                    Ok((hash, certificate)) => (hash, Some(certificate)),
                    Err(error) => {
                        debug!(
                            target: "consensus",
                            height,
                            current_view,
                            error = %error,
                            "Stalling block production until the canonical collapse extension certificate is available"
                        );
                        return ConsensusDecision::Stall;
                    }
                }
            } else {
                ([0u8; 32], None)
            };

            info!(target: "consensus", "I am leader for H={} V={}. Producing block.", height, current_view);

            ConsensusDecision::ProduceBlock {
                transactions: vec![],
                expected_timestamp_secs: expected_ts,
                expected_timestamp_ms: expected_ts_ms,
                view: current_view,
                parent_qc,
                previous_canonical_collapse_commitment_hash,
                canonical_collapse_extension_certificate,
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
            if matches!(self.safety_mode, AftSafetyMode::Asymptote)
                && !self
                    .quorum_certificate_is_collapse_backed(parent_qc, &*parent_view)
                    .await?
            {
                return Err(ConsensusError::BlockVerificationFailed(format!(
                    "Parent QC is not backed by a canonical collapse object for height {}",
                    parent_qc.height
                )));
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
        if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
            self.canonical_collapse_from_header_surface_with_parent_view(header, &*parent_view)
                .await?;
            self.verify_published_canonical_collapse_object(header, &*parent_view)
                .await?;
        }

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
        self.committed_collapses.retain(|h, _| *h + 2 >= height);
        self.recovered_headers.retain(|h, _| *h + 2 >= height);
        self.recovered_certified_headers
            .retain(|h, _| *h + 2 >= height);
        self.recovered_restart_headers
            .retain(|h, _| *h + 2 >= height);
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

    fn observe_committed_block(
        &mut self,
        header: &BlockHeader,
        collapse: Option<&CanonicalCollapseObject>,
    ) -> bool {
        if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
            let Some(expected_collapse) = collapse else {
                debug!(
                    target: "consensus",
                    height = header.height,
                    view = header.view,
                    "Ignoring committed header hint without a verified canonical collapse object in Asymptote"
                );
                return false;
            };
            let previous = if header.height <= 1 {
                None
            } else {
                let Some(previous) = self.committed_collapses.get(&(header.height - 1)) else {
                    debug!(
                        target: "consensus",
                        height = header.height,
                        view = header.view,
                        "Ignoring committed header hint because the previous canonical collapse object is not locally known"
                    );
                    return false;
                };
                if let Err(error) = self.verify_local_canonical_collapse_chain(previous) {
                    debug!(
                        target: "consensus",
                        height = header.height,
                        view = header.view,
                        "Ignoring committed header hint because the local predecessor collapse chain failed recursive continuity verification: {}",
                        error
                    );
                    return false;
                }
                Some(previous)
            };
            let Ok(derived) =
                self.canonical_collapse_from_header_surface_with_previous(header, previous)
            else {
                debug!(
                    target: "consensus",
                    height = header.height,
                    view = header.view,
                    "Ignoring committed header hint because the canonical collapse surface could not be derived"
                );
                return false;
            };
            if &derived != expected_collapse {
                debug!(
                    target: "consensus",
                    height = header.height,
                    view = header.view,
                    "Ignoring committed header hint because the supplied canonical collapse object does not match the header surface"
                );
                return false;
            }
            if let Err(error) =
                self.verify_runtime_canonical_collapse_continuity(expected_collapse, previous)
            {
                debug!(
                    target: "consensus",
                    height = header.height,
                    view = header.view,
                    "Ignoring committed header hint because the canonical collapse object failed backend verification: {}",
                    error
                );
                return false;
            }
        }

        let Ok(hash) = header.hash() else {
            return false;
        };
        let Ok(block_hash) = to_root_hash(&hash) else {
            return false;
        };
        self.committed_headers.insert(header.height, header.clone());
        if let Some(collapse) = collapse {
            self.committed_collapses
                .insert(header.height, collapse.clone());
        }
        self.seen_headers
            .entry((header.height, header.view))
            .or_default()
            .insert(block_hash, header.clone());
        true
    }

    fn observe_aft_recovered_consensus_header(
        &mut self,
        header: &AftRecoveredConsensusHeaderEntry,
    ) -> bool {
        if let Some(existing) = self.recovered_headers.get(&header.height) {
            return existing == header;
        }

        if header.height > 1 {
            if let Some(previous) = self.recovered_headers.get(&(header.height - 1)) {
                if previous.canonical_block_commitment_hash != header.parent_block_commitment_hash {
                    return false;
                }
            } else if let Some(previous) = self.committed_headers.get(&(header.height - 1)) {
                let Ok(previous_hash) = previous.hash() else {
                    return false;
                };
                let Ok(previous_hash) = to_root_hash(&previous_hash) else {
                    return false;
                };
                if previous_hash != header.parent_block_commitment_hash {
                    return false;
                }
            }
        }

        self.recovered_headers.insert(header.height, header.clone());
        true
    }

    fn observe_aft_recovered_certified_header(
        &mut self,
        entry: &AftRecoveredCertifiedHeaderEntry,
    ) -> bool {
        if let Some(existing) = self.recovered_certified_headers.get(&entry.header.height) {
            return existing == entry;
        }

        let certified_qc = entry.certified_quorum_certificate();
        if certified_qc.height != entry.header.height
            || certified_qc.view != entry.header.view
            || certified_qc.block_hash != entry.header.canonical_block_commitment_hash
        {
            return false;
        }

        if entry.header.height > 1 {
            if entry.certified_parent_quorum_certificate.height + 1 != entry.header.height
                || entry.certified_parent_quorum_certificate.block_hash
                    != entry.header.parent_block_commitment_hash
            {
                return false;
            }

            if let Some(previous) = self
                .recovered_certified_headers
                .get(&(entry.header.height - 1))
            {
                if previous.certified_quorum_certificate()
                    != entry.certified_parent_quorum_certificate
                    || previous.header.resulting_state_root_hash
                        != entry.certified_parent_resulting_state_root_hash
                {
                    return false;
                }
            } else if let Some(previous) = self.recovered_headers.get(&(entry.header.height - 1)) {
                if previous.synthetic_quorum_certificate()
                    != entry.certified_parent_quorum_certificate
                    || previous.resulting_state_root_hash
                        != entry.certified_parent_resulting_state_root_hash
                {
                    return false;
                }
            } else if let Some(previous) = self.committed_headers.get(&(entry.header.height - 1)) {
                let Ok(previous_hash) = previous.hash() else {
                    return false;
                };
                let Ok(previous_hash) = to_root_hash(&previous_hash) else {
                    return false;
                };
                if previous.height != entry.certified_parent_quorum_certificate.height
                    || previous.view != entry.certified_parent_quorum_certificate.view
                    || previous_hash != entry.certified_parent_quorum_certificate.block_hash
                    || previous.state_root.as_ref()
                        != entry.certified_parent_resulting_state_root_hash.as_slice()
                {
                    return false;
                }
            }
        } else if entry.certified_parent_quorum_certificate != QuorumCertificate::default()
            || entry.certified_parent_resulting_state_root_hash != [0u8; 32]
        {
            return false;
        }

        if !<GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_aft_recovered_consensus_header(
            self,
            &entry.header,
        ) {
            return false;
        }

        self.recovered_certified_headers
            .insert(entry.header.height, entry.clone());
        true
    }

    fn aft_recovered_consensus_header_for_quorum_certificate(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<AftRecoveredConsensusHeaderEntry> {
        self.local_recovered_header_for_qc(qc)
    }

    fn aft_recovered_certified_header_for_quorum_certificate(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<AftRecoveredCertifiedHeaderEntry> {
        self.local_recovered_certified_header_for_qc(qc)
    }

    fn observe_aft_recovered_restart_header(
        &mut self,
        entry: &AftRecoveredRestartHeaderEntry,
    ) -> bool {
        if let Some(existing) = self.recovered_restart_headers.get(&entry.header.height) {
            return existing == entry;
        }

        if !<GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_aft_recovered_certified_header(
            self,
            &entry.certified_header,
        ) {
            return false;
        }

        let certified = &entry.certified_header;
        let header = &entry.header;
        if header.height != certified.header.height
            || header.view != certified.header.view
            || header.parent_hash != certified.header.parent_block_commitment_hash
            || header.transactions_root != certified.header.transactions_root_hash.to_vec()
            || header.state_root.0 != certified.header.resulting_state_root_hash.to_vec()
            || header.parent_qc != certified.certified_parent_quorum_certificate
            || header.previous_canonical_collapse_commitment_hash
                != certified.header.previous_canonical_collapse_commitment_hash
        {
            return false;
        }

        let expected_parent_state_root = if header.height <= 1 {
            vec![0u8; 32]
        } else {
            certified
                .certified_parent_resulting_state_root_hash
                .to_vec()
        };
        if header.parent_state_root.0 != expected_parent_state_root {
            return false;
        }

        let Some(certificate) = header.canonical_order_certificate.as_ref() else {
            return false;
        };
        if certificate.height != header.height
            || certificate.ordered_transactions_root_hash != certified.header.transactions_root_hash
            || certificate.resulting_state_root_hash != certified.header.resulting_state_root_hash
            || header.timestamp_ms != certificate.bulletin_commitment.cutoff_timestamp_ms
            || header.timestamp
                != timestamp_millis_to_legacy_seconds(
                    certificate.bulletin_commitment.cutoff_timestamp_ms,
                )
        {
            return false;
        }

        self.recovered_restart_headers
            .insert(entry.header.height, entry.clone());
        true
    }

    fn aft_recovered_restart_header_for_quorum_certificate(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<AftRecoveredRestartHeaderEntry> {
        self.local_recovered_restart_header_for_qc(qc)
    }

    fn retain_recovered_ancestry_ranges(&mut self, keep_ranges: &[(u64, u64)]) {
        let keep_height = |height: u64| {
            keep_ranges
                .iter()
                .any(|(start, end)| *start <= height && height <= *end)
        };

        self.recovered_headers
            .retain(|height, _| keep_height(*height));
        self.recovered_certified_headers
            .retain(|height, _| keep_height(*height));
        self.recovered_restart_headers
            .retain(|height, _| keep_height(*height));
    }

    fn header_for_quorum_certificate(&self, qc: &QuorumCertificate) -> Option<BlockHeader> {
        self.local_header_for_qc(qc).or_else(|| {
            self.local_recovered_restart_header_for_qc(qc)
                .map(|entry| entry.header)
        })
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
        aft_bulletin_availability_certificate_key, aft_bulletin_commitment_key,
        aft_canonical_bulletin_close_key, aft_canonical_collapse_object_key,
        aft_canonical_order_abort_key, aft_publication_frontier_key,
        build_bulletin_availability_certificate, build_canonical_bulletin_close,
        build_publication_frontier, build_reference_canonical_order_proof_bytes,
        canonical_asymptote_observer_assignments_hash,
        canonical_asymptote_observer_challenges_hash,
        canonical_asymptote_observer_transcripts_hash, canonical_collapse_commitment,
        canonical_collapse_commitment_hash_from_object,
        canonical_collapse_continuity_public_inputs, canonical_collapse_recursive_proof_hash,
        canonical_collapse_succinct_mock_proof_bytes, canonical_order_public_inputs,
        canonical_order_public_inputs_hash, canonical_sealed_finality_proof_signing_bytes,
        derive_asymptote_observer_assignments, derive_canonical_collapse_object,
        derive_canonical_collapse_object_with_previous, derive_guardian_witness_assignments,
        derive_reference_ordering_randomness_beacon, guardian_registry_asymptote_policy_key,
        guardian_registry_checkpoint_key, guardian_registry_committee_account_key,
        guardian_registry_committee_key, guardian_registry_log_key,
        guardian_registry_observer_canonical_abort_key,
        guardian_registry_observer_canonical_close_key,
        guardian_registry_observer_challenge_commitment_key,
        guardian_registry_observer_transcript_commitment_key, guardian_registry_witness_key,
        guardian_registry_witness_seed_key, guardian_registry_witness_set_key,
        recovered_restart_block_header_entry, write_validator_sets, AftRecoveredStateSurface,
        AsymptoteObserverCanonicalAbort, AsymptoteObserverCanonicalClose,
        AsymptoteObserverCertificate, AsymptoteObserverChallenge,
        AsymptoteObserverChallengeCommitment, AsymptoteObserverCloseCertificate,
        AsymptoteObserverCorrelationBudget, AsymptoteObserverTranscript,
        AsymptoteObserverTranscriptCommitment, AsymptoteObserverVerdict, AsymptotePolicy,
        AsymptoteVetoKind, AsymptoteVetoProof, BulletinAvailabilityCertificate, BulletinCommitment,
        CanonicalCollapseContinuityProofSystem, CanonicalOrderAbort, CanonicalOrderAbortReason,
        CanonicalOrderCertificate, CanonicalOrderProof, CanonicalOrderProofSystem, CollapseState,
        FinalityTier, GuardianCommitteeMember, GuardianLogCheckpoint, GuardianLogProof,
        GuardianTransparencyLogDescriptor, GuardianWitnessCommitteeManifest,
        GuardianWitnessRecoveryBinding, OmissionProof, RecoverableSlotPayloadV5,
        SealedFinalityProof, SignatureProof, SignatureSuite, StateRoot, ValidatorSetV1,
        ValidatorSetsV1, ValidatorV1,
    };
    use ioi_types::codec;
    use ioi_types::error::ChainError;
    use libp2p::identity::Keypair;
    use std::collections::HashMap;
    use std::sync::{Mutex as StdMutex, OnceLock};

    fn sample_recovered_restart_entry(
        parent_header: &RecoveredCanonicalHeaderEntry,
        parent_qc: QuorumCertificate,
        parent_state_root: [u8; 32],
        height: u64,
        view: u64,
        block_seed: u8,
        tx_seed: u8,
        state_seed: u8,
        collapse_seed: u8,
        producer_seed: u8,
        bulletin_seed: u8,
    ) -> RecoveredRestartBlockHeaderEntry {
        let certified_entry = RecoveredCertifiedHeaderEntry {
            header: RecoveredCanonicalHeaderEntry {
                height,
                view,
                canonical_block_commitment_hash: [block_seed; 32],
                parent_block_commitment_hash: parent_header.canonical_block_commitment_hash,
                transactions_root_hash: [tx_seed; 32],
                resulting_state_root_hash: [state_seed; 32],
                previous_canonical_collapse_commitment_hash: [collapse_seed; 32],
            },
            certified_parent_quorum_certificate: parent_qc,
            certified_parent_resulting_state_root_hash: parent_state_root,
        };
        let payload = RecoverableSlotPayloadV5 {
            height,
            view,
            producer_account_id: AccountId([producer_seed; 32]),
            block_commitment_hash: certified_entry.header.canonical_block_commitment_hash,
            parent_block_hash: certified_entry.header.parent_block_commitment_hash,
            canonical_order_certificate: CanonicalOrderCertificate {
                height,
                bulletin_commitment: BulletinCommitment {
                    height,
                    cutoff_timestamp_ms: 1_760_000_000_000 + height * 1_000,
                    bulletin_root: [bulletin_seed; 32],
                    entry_count: 0,
                },
                bulletin_availability_certificate: BulletinAvailabilityCertificate {
                    height,
                    bulletin_commitment_hash: [bulletin_seed.wrapping_add(1); 32],
                    recoverability_root: [bulletin_seed.wrapping_add(2); 32],
                },
                randomness_beacon: [bulletin_seed.wrapping_add(3); 32],
                ordered_transactions_root_hash: certified_entry.header.transactions_root_hash,
                resulting_state_root_hash: certified_entry.header.resulting_state_root_hash,
                proof: CanonicalOrderProof::default(),
                omission_proofs: Vec::new(),
            },
            ordered_transaction_bytes: Vec::new(),
            canonical_order_publication_bundle_bytes: Vec::new(),
            canonical_bulletin_close_bytes: Vec::new(),
            canonical_bulletin_availability_certificate_bytes: Vec::new(),
            bulletin_surface_entries: Vec::new(),
        };
        recovered_restart_block_header_entry(&payload, &certified_entry).expect("restart entry")
    }

    fn sample_recovered_restart_entry_branch(
        previous_header: &RecoveredCanonicalHeaderEntry,
        first_view: u64,
        depth: usize,
        seed_base: u8,
    ) -> Vec<RecoveredRestartBlockHeaderEntry> {
        let mut branch = Vec::with_capacity(depth);
        let mut parent_header = previous_header.clone();
        let mut parent_qc = previous_header.synthetic_quorum_certificate();
        let mut parent_state_root = previous_header.resulting_state_root_hash;
        for offset in 0..depth {
            let seed = seed_base.wrapping_add(offset as u8);
            let entry = sample_recovered_restart_entry(
                &parent_header,
                parent_qc.clone(),
                parent_state_root,
                previous_header.height + 1 + offset as u64,
                first_view + offset as u64,
                seed,
                seed.wrapping_add(0x10),
                seed.wrapping_add(0x20),
                seed.wrapping_add(0x30),
                seed.wrapping_add(0x40),
                seed.wrapping_add(0x50),
            );
            parent_header = entry.certified_header.header.clone();
            parent_qc = entry.certified_quorum_certificate();
            parent_state_root = entry.certified_header.header.resulting_state_root_hash;
            branch.push(entry);
        }
        branch
    }

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
            timestamp_ms: 1_234_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: manifest.validator_account_id,
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: ioi_crypto::algorithms::hash::sha256(
                &log_keypair.public().encode_protobuf(),
            )
            .unwrap(),
            producer_pubkey: log_keypair.public().encode_protobuf(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
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

    fn sign_test_sealed_finality_proof(
        proof: &mut SealedFinalityProof,
        producer_keypair: &Keypair,
    ) {
        proof.proof_signature = SignatureProof::default();
        let sign_bytes = canonical_sealed_finality_proof_signing_bytes(proof).unwrap();
        proof.proof_signature = SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: producer_keypair.public().encode_protobuf(),
            signature: producer_keypair.sign(&sign_bytes).unwrap(),
        };
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

    struct CanonicalObserverFixture {
        engine: GuardianMajorityEngine,
        header: BlockHeader,
        manifest: GuardianCommitteeManifest,
        preimage: Vec<u8>,
        guardian_log_keypair: Keypair,
        policy: AsymptotePolicy,
        witness_seed: GuardianWitnessEpochSeed,
        validators: Vec<AccountId>,
        observer_manifests: Vec<GuardianCommitteeManifest>,
        observer_descriptors: Vec<GuardianTransparencyLogDescriptor>,
        anchored_checkpoints: Vec<GuardianLogCheckpoint>,
        observer_assignments: Vec<AsymptoteObserverAssignment>,
        observer_transcripts: Vec<AsymptoteObserverTranscript>,
    }

    fn build_canonical_observer_fixture() -> CanonicalObserverFixture {
        let (mut engine, header, manifest, preimage, _, guardian_log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;
        let guardian_log_descriptor =
            build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
        let witness_seed = GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [111u8; 32],
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
            observer_sealing_mode: AsymptoteObserverSealingMode::CanonicalChallengeV1,
            observer_challenge_window_ms: 5_000,
            max_reassignment_depth: 0,
            max_checkpoint_staleness_ms: 120_000,
        };
        let validators = vec![
            header.producer_account_id,
            AccountId([61u8; 32]),
            AccountId([62u8; 32]),
            AccountId([63u8; 32]),
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
            let log_id = format!(
                "observer-canonical-fixture-{}",
                hex::encode(account.as_ref())
            );
            let observer_manifest =
                build_observer_manifest(account, manifest.epoch, [91u8; 32], &log_id, &member_keys);
            if selected_accounts.contains(&account) {
                selected_manifests.insert(account, (observer_manifest.clone(), member_keys));
            }
            observer_manifests.push(observer_manifest);
        }

        let mut observer_transcripts = Vec::new();
        for assignment in observer_assignments.iter().cloned() {
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
                trace_hash: [assignment.round as u8 + 21; 32],
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
                u64::from(assignment.round) + 80,
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
            observer_transcripts.push(AsymptoteObserverTranscript {
                statement,
                guardian_certificate: observer_guardian_certificate,
            });
        }

        CanonicalObserverFixture {
            engine,
            header,
            manifest,
            preimage,
            guardian_log_keypair,
            policy,
            witness_seed,
            validators,
            observer_manifests,
            observer_descriptors,
            anchored_checkpoints,
            observer_assignments,
            observer_transcripts,
        }
    }

    fn canonical_observer_parent_view(fixture: &CanonicalObserverFixture) -> MockAnchoredView {
        build_parent_view_with_asymptote_observers(
            &fixture.manifest,
            &fixture.observer_descriptors,
            fixture.policy.clone(),
            fixture.witness_seed.clone(),
            &fixture.anchored_checkpoints,
            fixture.validators.clone(),
            &fixture.observer_manifests,
        )
    }

    fn finalize_observer_challenge_id(challenge: &mut AsymptoteObserverChallenge) {
        let mut normalized = challenge.clone();
        normalized.challenge_id = [0u8; 32];
        challenge.challenge_id =
            ioi_crypto::algorithms::hash::sha256(&codec::to_bytes_canonical(&normalized).unwrap())
                .unwrap();
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
        view.state.insert(
            STATUS_KEY.to_vec(),
            codec::to_bytes_canonical(&ChainStatus::default()).unwrap(),
        );
        view
    }

    fn build_progress_parent_header(height: u64, view: u64) -> BlockHeader {
        BlockHeader {
            height,
            view,
            parent_hash: [height.saturating_sub(1) as u8; 32],
            parent_state_root: StateRoot(vec![height.saturating_sub(1) as u8; 32]),
            state_root: StateRoot(vec![height as u8 + 10; 32]),
            transactions_root: vec![height as u8 + 20; 32],
            timestamp: height,
            timestamp_ms: height.saturating_mul(1_000),
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([height as u8 + 30; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [height as u8 + 31; 32],
            producer_pubkey: vec![height as u8 + 32; 32],
            oracle_counter: height,
            oracle_trace_hash: [height as u8 + 33; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            parent_qc: if height > 1 {
                QuorumCertificate {
                    height: height - 1,
                    view,
                    block_hash: [height.saturating_sub(1) as u8; 32],
                    signatures: vec![],
                    aggregated_signature: vec![],
                    signers_bitfield: vec![],
                }
            } else {
                QuorumCertificate::default()
            },
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            timeout_certificate: None,
            signature: vec![height as u8 + 34; 64],
        }
    }

    fn extension_certificate_from_predecessor(
        predecessor: &CanonicalCollapseObject,
        covered_height: u64,
    ) -> CanonicalCollapseExtensionCertificate {
        canonical_collapse_extension_certificate(covered_height, predecessor)
            .expect("extension certificate")
    }

    fn continuity_env_lock() -> &'static StdMutex<()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
    }

    fn test_canonical_collapse_object(
        height: u64,
        previous: Option<&CanonicalCollapseObject>,
        transactions_root_hash: [u8; 32],
        resulting_state_root_hash: [u8; 32],
    ) -> CanonicalCollapseObject {
        let mut collapse = CanonicalCollapseObject {
            height,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering: Default::default(),
            sealing: None,
            transactions_root_hash,
            resulting_state_root_hash,
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        bind_canonical_collapse_continuity(&mut collapse, previous)
            .expect("bind test canonical collapse continuity");
        collapse
    }

    fn bind_succinct_mock_continuity(collapse: &mut CanonicalCollapseObject) {
        let proof = &mut collapse.continuity_recursive_proof;
        let public_inputs = canonical_collapse_continuity_public_inputs(
            &proof.commitment,
            proof.previous_canonical_collapse_commitment_hash,
            proof.payload_hash,
            proof.previous_recursive_proof_hash,
        );
        proof.proof_system = CanonicalCollapseContinuityProofSystem::SuccinctSp1V1;
        proof.proof_bytes = canonical_collapse_succinct_mock_proof_bytes(&public_inputs)
            .expect("succinct mock proof bytes");
    }

    fn link_header_to_previous_collapse(
        header: &mut BlockHeader,
        previous: &CanonicalCollapseObject,
    ) {
        header.previous_canonical_collapse_commitment_hash =
            canonical_collapse_commitment_hash_from_object(previous).unwrap();
        header.canonical_collapse_extension_certificate = Some(
            extension_certificate_from_predecessor(previous, header.height),
        );
        header.parent_state_root = StateRoot(previous.resulting_state_root_hash.to_vec());
    }

    fn link_header_to_collapse_chain(header: &mut BlockHeader, chain: &[CanonicalCollapseObject]) {
        let previous = chain
            .first()
            .expect("collapse chain requires at least one object");
        header.previous_canonical_collapse_commitment_hash =
            canonical_collapse_commitment_hash_from_object(previous).unwrap();
        header.canonical_collapse_extension_certificate = Some(
            extension_certificate_from_predecessor(previous, header.height),
        );
        header.parent_state_root = StateRoot(previous.resulting_state_root_hash.to_vec());
    }

    #[test]
    fn verify_canonical_collapse_backend_accepts_and_rejects_succinct_mock_proofs() {
        let engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        let mut collapse = test_canonical_collapse_object(1, None, [0x21u8; 32], [0x22u8; 32]);
        let proof = &mut collapse.continuity_recursive_proof;
        let public_inputs = canonical_collapse_continuity_public_inputs(
            &proof.commitment,
            proof.previous_canonical_collapse_commitment_hash,
            proof.payload_hash,
            proof.previous_recursive_proof_hash,
        );
        proof.proof_system = CanonicalCollapseContinuityProofSystem::SuccinctSp1V1;
        proof.proof_bytes = canonical_collapse_succinct_mock_proof_bytes(&public_inputs)
            .expect("succinct mock proof bytes");

        engine
            .verify_canonical_collapse_backend(&collapse)
            .expect("succinct backend proof should verify");

        let mut mutated = collapse.clone();
        mutated.continuity_recursive_proof.proof_bytes[0] ^= 0xFF;
        assert!(engine.verify_canonical_collapse_backend(&mutated).is_err());
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
        assert!(matches!(
            decision,
            ConsensusDecision::ProduceBlock { view: 0, .. }
        ));
        assert_eq!(engine.pacemaker.lock().await.current_view, 0);
    }

    #[tokio::test]
    async fn asymptote_decide_times_out_when_parent_qc_is_not_collapse_backed() {
        let validators = vec![
            AccountId([1u8; 32]),
            AccountId([2u8; 32]),
            AccountId([3u8; 32]),
        ];
        let parent_view = build_decide_parent_view(validators.clone());
        let known_peers = HashSet::from([PeerId::random()]);
        let mut engine = GuardianMajorityEngine::with_view_timeout(
            AftSafetyMode::Asymptote,
            Duration::from_secs(5),
        );
        engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);
        engine.highest_qc = QuorumCertificate {
            height: 1,
            view: 0,
            block_hash: [77u8; 32],
            signatures: vec![
                (validators[0], vec![1u8; 64]),
                (validators[1], vec![2u8; 64]),
            ],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };

        let decision: ConsensusDecision<ChainTransaction> = engine
            .decide(&validators[1], 2, 0, &parent_view, &known_peers)
            .await;
        assert!(matches!(
            decision,
            ConsensusDecision::Timeout { view: 1, height: 2 }
        ));
    }

    #[tokio::test]
    async fn asymptote_decide_produces_when_parent_is_collapse_backed() {
        let validators = vec![
            AccountId([1u8; 32]),
            AccountId([2u8; 32]),
            AccountId([3u8; 32]),
        ];
        let known_peers = HashSet::from([PeerId::random()]);
        let mut parent_view = build_decide_parent_view(validators.clone());
        let mut engine = GuardianMajorityEngine::with_view_timeout(
            AftSafetyMode::Asymptote,
            Duration::from_secs(5),
        );
        engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);

        let parent_header = build_progress_parent_header(1, 0);
        let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
        let collapse = derive_canonical_collapse_object(&parent_header, &[]).unwrap();
        let collapse_commitment_hash =
            canonical_collapse_commitment_hash_from_object(&collapse).unwrap();
        parent_view.state.insert(
            aft_canonical_collapse_object_key(parent_header.height),
            codec::to_bytes_canonical(&collapse).unwrap(),
        );
        engine
            .committed_headers
            .insert(parent_header.height, parent_header.clone());
        engine
            .seen_headers
            .entry((parent_header.height, parent_header.view))
            .or_default()
            .insert(parent_hash, parent_header.clone());
        engine.highest_qc = QuorumCertificate {
            height: 1,
            view: 0,
            block_hash: parent_hash,
            signatures: vec![
                (validators[0], vec![1u8; 64]),
                (validators[1], vec![2u8; 64]),
            ],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };

        let decision: ConsensusDecision<ChainTransaction> = engine
            .decide(&validators[1], 2, 0, &parent_view, &known_peers)
            .await;
        assert!(matches!(
            decision,
            ConsensusDecision::ProduceBlock {
                view: 0,
                previous_canonical_collapse_commitment_hash,
                canonical_collapse_extension_certificate,
                ..
            } if previous_canonical_collapse_commitment_hash == collapse_commitment_hash
                && canonical_collapse_extension_certificate.as_ref()
                    == Some(&extension_certificate_from_predecessor(&collapse, 2))
        ));
    }

    #[tokio::test]
    async fn asymptote_decide_produces_canonical_collapse_extension_certificate_when_available() {
        let validators = vec![
            AccountId([1u8; 32]),
            AccountId([2u8; 32]),
            AccountId([3u8; 32]),
        ];
        let known_peers = HashSet::from([PeerId::random()]);
        let mut parent_view = build_decide_parent_view(validators.clone());
        let mut engine = GuardianMajorityEngine::with_view_timeout(
            AftSafetyMode::Asymptote,
            Duration::from_secs(5),
        );
        engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);

        let grandparent_header = build_progress_parent_header(1, 0);
        let grandparent_collapse =
            derive_canonical_collapse_object(&grandparent_header, &[]).unwrap();
        parent_view.state.insert(
            aft_canonical_collapse_object_key(grandparent_header.height),
            codec::to_bytes_canonical(&grandparent_collapse).unwrap(),
        );

        let mut parent_header = build_progress_parent_header(2, 0);
        link_header_to_previous_collapse(&mut parent_header, &grandparent_collapse);
        let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
        let parent_collapse = derive_canonical_collapse_object_with_previous(
            &parent_header,
            &[],
            Some(&grandparent_collapse),
        )
        .unwrap();
        let parent_collapse_commitment_hash =
            canonical_collapse_commitment_hash_from_object(&parent_collapse).unwrap();
        parent_view.state.insert(
            aft_canonical_collapse_object_key(parent_header.height),
            codec::to_bytes_canonical(&parent_collapse).unwrap(),
        );
        engine
            .committed_headers
            .insert(parent_header.height, parent_header.clone());
        engine
            .seen_headers
            .entry((parent_header.height, parent_header.view))
            .or_default()
            .insert(parent_hash, parent_header);
        engine.highest_qc = QuorumCertificate {
            height: 2,
            view: 0,
            block_hash: parent_hash,
            signatures: vec![
                (validators[0], vec![1u8; 64]),
                (validators[1], vec![2u8; 64]),
            ],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };

        let decision: ConsensusDecision<ChainTransaction> = engine
            .decide(&validators[2], 3, 0, &parent_view, &known_peers)
            .await;
        assert!(matches!(
            decision,
            ConsensusDecision::ProduceBlock {
                view: 0,
                previous_canonical_collapse_commitment_hash,
                canonical_collapse_extension_certificate,
                ..
            } if previous_canonical_collapse_commitment_hash == parent_collapse_commitment_hash
                && canonical_collapse_extension_certificate.as_ref()
                    == Some(&extension_certificate_from_predecessor(&parent_collapse, 3))
        ));
    }

    #[tokio::test]
    async fn asymptote_decide_stalls_when_previous_collapse_is_missing_for_current_height() {
        let validators = vec![
            AccountId([1u8; 32]),
            AccountId([2u8; 32]),
            AccountId([3u8; 32]),
        ];
        let known_peers = HashSet::from([PeerId::random()]);
        let mut parent_view = build_decide_parent_view(validators.clone());
        let mut engine = GuardianMajorityEngine::with_view_timeout(
            AftSafetyMode::Asymptote,
            Duration::from_secs(5),
        );
        engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);

        let parent_of_parent_header = build_progress_parent_header(1, 0);
        let parent_of_parent_collapse =
            derive_canonical_collapse_object(&parent_of_parent_header, &[]).unwrap();
        parent_view.state.insert(
            aft_canonical_collapse_object_key(parent_of_parent_header.height),
            codec::to_bytes_canonical(&parent_of_parent_collapse).unwrap(),
        );

        let mut parent_header = build_progress_parent_header(2, 0);
        link_header_to_previous_collapse(&mut parent_header, &parent_of_parent_collapse);
        let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
        engine
            .seen_headers
            .entry((parent_header.height, parent_header.view))
            .or_default()
            .insert(parent_hash, parent_header.clone());
        engine.highest_qc = QuorumCertificate {
            height: 2,
            view: 0,
            block_hash: parent_hash,
            signatures: vec![
                (validators[0], vec![1u8; 64]),
                (validators[1], vec![2u8; 64]),
            ],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };

        let decision: ConsensusDecision<ChainTransaction> = engine
            .decide(&validators[2], 3, 0, &parent_view, &known_peers)
            .await;
        assert!(matches!(decision, ConsensusDecision::Stall));
    }

    #[tokio::test]
    async fn asymptote_defers_ready_commit_until_parent_is_collapse_backed() {
        let validators = vec![
            AccountId([1u8; 32]),
            AccountId([2u8; 32]),
            AccountId([3u8; 32]),
        ];
        let known_peers = HashSet::from([PeerId::random()]);
        let parent_view = build_decide_parent_view(validators.clone());
        let mut engine = GuardianMajorityEngine::with_view_timeout(
            AftSafetyMode::Asymptote,
            Duration::from_secs(5),
        );
        engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);
        engine.safety = SafetyGadget::new().with_guard_duration(Duration::ZERO);

        let parent_qc = QuorumCertificate {
            height: 1,
            view: 0,
            block_hash: [77u8; 32],
            signatures: vec![
                (validators[0], vec![1u8; 64]),
                (validators[1], vec![2u8; 64]),
            ],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };
        engine.highest_qc = parent_qc.clone();
        assert!(engine.safety.update(
            &QuorumCertificate {
                height: 2,
                view: 1,
                block_hash: [90u8; 32],
                signatures: vec![],
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            },
            &parent_qc,
        ));

        let _: ConsensusDecision<ChainTransaction> = engine
            .decide(&validators[1], 2, 0, &parent_view, &known_peers)
            .await;
        assert!(engine.safety.committed_qc.is_none());
        assert!(engine.safety.next_ready_commit().is_some());
    }

    #[tokio::test]
    async fn asymptote_accepts_ready_commit_once_parent_is_collapse_backed() {
        let validators = vec![
            AccountId([1u8; 32]),
            AccountId([2u8; 32]),
            AccountId([3u8; 32]),
        ];
        let known_peers = HashSet::from([PeerId::random()]);
        let mut parent_view = build_decide_parent_view(validators.clone());
        let mut engine = GuardianMajorityEngine::with_view_timeout(
            AftSafetyMode::Asymptote,
            Duration::from_secs(5),
        );
        engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);
        engine.safety = SafetyGadget::new().with_guard_duration(Duration::ZERO);

        let parent_header = build_progress_parent_header(1, 0);
        let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
        let collapse = derive_canonical_collapse_object(&parent_header, &[]).unwrap();
        parent_view.state.insert(
            aft_canonical_collapse_object_key(parent_header.height),
            codec::to_bytes_canonical(&collapse).unwrap(),
        );
        engine
            .committed_headers
            .insert(parent_header.height, parent_header.clone());
        engine
            .seen_headers
            .entry((parent_header.height, parent_header.view))
            .or_default()
            .insert(parent_hash, parent_header.clone());
        let parent_qc = QuorumCertificate {
            height: 1,
            view: 0,
            block_hash: parent_hash,
            signatures: vec![
                (validators[0], vec![1u8; 64]),
                (validators[1], vec![2u8; 64]),
            ],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };
        engine.highest_qc = parent_qc.clone();
        assert!(engine.safety.update(
            &QuorumCertificate {
                height: 2,
                view: 1,
                block_hash: [91u8; 32],
                signatures: vec![],
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            },
            &parent_qc,
        ));

        let _: ConsensusDecision<ChainTransaction> = engine
            .decide(&validators[1], 2, 0, &parent_view, &known_peers)
            .await;
        assert_eq!(
            engine.safety.committed_qc.as_ref().map(|qc| qc.height),
            Some(1)
        );
        assert!(engine.safety.next_ready_commit().is_none());
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

    #[test]
    fn experimental_nested_guardian_rejects_tampered_recovery_binding() {
        let (mut engine, mut header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::ExperimentalNestedGuardian;
        let witness_members = vec![
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
            BlsKeyPair::generate().unwrap(),
        ];
        let witness_manifest = build_witness_manifest(&witness_members);
        let guardian_certificate = header.guardian_certificate.as_ref().unwrap().clone();
        let mut statement = engine.experimental_witness_statement(&header, &guardian_certificate);
        statement.recovery_binding = Some(GuardianWitnessRecoveryBinding {
            recovery_capsule_hash: [61u8; 32],
            share_commitment_hash: [62u8; 32],
        });
        let mut witness_certificate = sign_witness_statement_with_members(
            &witness_manifest,
            &statement,
            &[
                (0, witness_members[0].private_key()),
                (2, witness_members[2].private_key()),
            ],
        )
        .unwrap();
        witness_certificate.recovery_binding = Some(GuardianWitnessRecoveryBinding {
            recovery_capsule_hash: [63u8; 32],
            share_commitment_hash: [64u8; 32],
        });
        header
            .guardian_certificate
            .as_mut()
            .unwrap()
            .experimental_witness_certificate = Some(witness_certificate);

        engine
            .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
            .unwrap();
        let err = engine
            .verify_experimental_witness_certificate_against_manifest(
                &header,
                header.guardian_certificate.as_ref().unwrap(),
                &witness_manifest,
            )
            .unwrap_err();
        assert!(matches!(err, ConsensusError::BlockVerificationFailed(_)));
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
            observer_transcripts: Vec::new(),
            observer_challenges: Vec::new(),
            observer_transcript_commitment: None,
            observer_challenge_commitment: None,
            observer_canonical_close: None,
            observer_canonical_abort: None,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        });
        sign_test_sealed_finality_proof(
            header.sealed_finality_proof.as_mut().unwrap(),
            &guardian_log_keypair,
        );

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
                observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
                observer_challenge_window_ms: 0,
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
    async fn asymptote_accepts_sealed_finality_proof_with_distinct_recovery_bindings() {
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
            seed: [79u8; 32],
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
        let recovery_capsule_hash = [0x91u8; 32];
        let mut witness_certificates = Vec::new();
        let mut anchored_checkpoints = vec![header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .log_checkpoint
            .as_ref()
            .unwrap()
            .clone()];
        for (index, assignment) in assignments.into_iter().enumerate() {
            let (assigned_manifest, assigned_members) =
                if assignment.manifest_hash == witness_hash_a {
                    (&witness_manifest_a, &witness_members_a)
                } else {
                    (&witness_manifest_b, &witness_members_b)
                };
            let recovery_binding = GuardianWitnessRecoveryBinding {
                recovery_capsule_hash,
                share_commitment_hash: [0xA0u8.saturating_add(index as u8); 32],
            };
            let statement =
                ioi_types::app::guardian_witness_statement_for_header_with_recovery_binding(
                    &header,
                    header.guardian_certificate.as_ref().unwrap(),
                    Some(recovery_binding.clone()),
                );
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
            observer_transcripts: Vec::new(),
            observer_challenges: Vec::new(),
            observer_transcript_commitment: None,
            observer_challenge_commitment: None,
            observer_canonical_close: None,
            observer_canonical_abort: None,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        });
        sign_test_sealed_finality_proof(
            header.sealed_finality_proof.as_mut().unwrap(),
            &guardian_log_keypair,
        );

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
                observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
                observer_challenge_window_ms: 0,
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
            observer_transcripts: Vec::new(),
            observer_challenges: Vec::new(),
            observer_transcript_commitment: None,
            observer_challenge_commitment: None,
            observer_canonical_close: None,
            observer_canonical_abort: None,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        });
        sign_test_sealed_finality_proof(
            header.sealed_finality_proof.as_mut().unwrap(),
            &guardian_log_keypair,
        );
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
                observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
                observer_challenge_window_ms: 0,
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
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
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
            observer_transcripts: Vec::new(),
            observer_challenges: Vec::new(),
            observer_transcript_commitment: None,
            observer_challenge_commitment: None,
            observer_canonical_close: None,
            observer_canonical_abort: None,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        });
        sign_test_sealed_finality_proof(
            header.sealed_finality_proof.as_mut().unwrap(),
            &guardian_log_keypair,
        );

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
    async fn asymptote_accepts_canonical_observer_sealed_finality_proof() {
        let (mut engine, mut header, manifest, preimage, _, guardian_log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;
        let guardian_log_descriptor =
            build_log_descriptor(&manifest.transparency_log_id, &guardian_log_keypair);
        let witness_seed = GuardianWitnessEpochSeed {
            epoch: manifest.epoch,
            seed: [101u8; 32],
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
            observer_sealing_mode: AsymptoteObserverSealingMode::CanonicalChallengeV1,
            observer_challenge_window_ms: 5_000,
            max_reassignment_depth: 0,
            max_checkpoint_staleness_ms: 120_000,
        };
        let validators = vec![
            header.producer_account_id,
            AccountId([51u8; 32]),
            AccountId([52u8; 32]),
            AccountId([53u8; 32]),
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
            let log_id = format!("observer-canonical-{}", hex::encode(account.as_ref()));
            let observer_manifest =
                build_observer_manifest(account, manifest.epoch, [81u8; 32], &log_id, &member_keys);
            if selected_accounts.contains(&account) {
                selected_manifests.insert(account, (observer_manifest.clone(), member_keys));
            }
            observer_manifests.push(observer_manifest);
        }

        let mut observer_transcripts = Vec::new();
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
                trace_hash: [assignment.round as u8 + 11; 32],
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
                u64::from(assignment.round) + 50,
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
            observer_transcripts.push(AsymptoteObserverTranscript {
                statement,
                guardian_certificate: observer_guardian_certificate,
            });
        }

        let observer_challenges = Vec::<AsymptoteObserverChallenge>::new();
        let transcripts_root =
            canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
        let challenges_root =
            canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
        let transcript_commitment = AsymptoteObserverTranscriptCommitment {
            epoch: manifest.epoch,
            height: header.height,
            view: header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            transcript_count: observer_transcripts.len() as u16,
        };
        let challenge_commitment = AsymptoteObserverChallengeCommitment {
            epoch: manifest.epoch,
            height: header.height,
            view: header.view,
            challenges_root,
            challenge_count: 0,
        };
        let canonical_close = AsymptoteObserverCanonicalClose {
            epoch: manifest.epoch,
            height: header.height,
            view: header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            challenges_root,
            transcript_count: observer_transcripts.len() as u16,
            challenge_count: 0,
            challenge_cutoff_timestamp_ms: 25_000,
        };

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
            observer_close_certificate: None,
            observer_transcripts: observer_transcripts.clone(),
            observer_challenges: observer_challenges.clone(),
            observer_transcript_commitment: Some(transcript_commitment.clone()),
            observer_challenge_commitment: Some(challenge_commitment.clone()),
            observer_canonical_close: Some(canonical_close.clone()),
            observer_canonical_abort: None,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        });
        sign_test_sealed_finality_proof(
            header.sealed_finality_proof.as_mut().unwrap(),
            &guardian_log_keypair,
        );

        let mut parent_view = build_parent_view_with_asymptote_observers(
            &manifest,
            &observer_descriptors,
            policy,
            witness_seed,
            &anchored_checkpoints,
            validators,
            &observer_manifests,
        );
        parent_view.state.insert(
            guardian_registry_observer_transcript_commitment_key(
                manifest.epoch,
                header.height,
                header.view,
            ),
            codec::to_bytes_canonical(&transcript_commitment).unwrap(),
        );
        parent_view.state.insert(
            guardian_registry_observer_challenge_commitment_key(
                manifest.epoch,
                header.height,
                header.view,
            ),
            codec::to_bytes_canonical(&challenge_commitment).unwrap(),
        );
        parent_view.state.insert(
            guardian_registry_observer_canonical_close_key(
                manifest.epoch,
                header.height,
                header.view,
            ),
            codec::to_bytes_canonical(&canonical_close).unwrap(),
        );

        engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn asymptote_accepts_canonical_observer_sealed_finality_proof_without_registry_copies() {
        let mut fixture = build_canonical_observer_fixture();
        let base_certificate = fixture
            .header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .clone();
        let observer_assignments_hash =
            canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
        let observer_challenges = Vec::<AsymptoteObserverChallenge>::new();
        let transcripts_root =
            canonical_asymptote_observer_transcripts_hash(&fixture.observer_transcripts).unwrap();
        let challenges_root =
            canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
        let transcript_commitment = AsymptoteObserverTranscriptCommitment {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            transcript_count: fixture.observer_transcripts.len() as u16,
        };
        let challenge_commitment = AsymptoteObserverChallengeCommitment {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            challenges_root,
            challenge_count: 0,
        };
        let canonical_close = AsymptoteObserverCanonicalClose {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            challenges_root,
            transcript_count: fixture.observer_transcripts.len() as u16,
            challenge_count: 0,
            challenge_cutoff_timestamp_ms: 30_000,
        };

        fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
            epoch: fixture.manifest.epoch,
            finality_tier: FinalityTier::SealedFinal,
            collapse_state: CollapseState::SealedFinal,
            guardian_manifest_hash: base_certificate.manifest_hash,
            guardian_decision_hash: base_certificate.decision_hash,
            guardian_counter: base_certificate.counter,
            guardian_trace_hash: base_certificate.trace_hash,
            guardian_measurement_root: base_certificate.measurement_root,
            policy_hash: fixture.manifest.policy_hash,
            witness_certificates: Vec::new(),
            observer_certificates: Vec::new(),
            observer_close_certificate: None,
            observer_transcripts: fixture.observer_transcripts.clone(),
            observer_challenges: observer_challenges.clone(),
            observer_transcript_commitment: Some(transcript_commitment),
            observer_challenge_commitment: Some(challenge_commitment),
            observer_canonical_close: Some(canonical_close),
            observer_canonical_abort: None,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        });
        sign_test_sealed_finality_proof(
            fixture.header.sealed_finality_proof.as_mut().unwrap(),
            &fixture.guardian_log_keypair,
        );

        let parent_view = canonical_observer_parent_view(&fixture);
        fixture
            .engine
            .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn asymptote_rejects_canonical_observer_sealed_finality_proof_with_mismatched_registry_copy(
    ) {
        let mut fixture = build_canonical_observer_fixture();
        let base_certificate = fixture
            .header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .clone();
        let observer_assignments_hash =
            canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
        let observer_challenges = Vec::<AsymptoteObserverChallenge>::new();
        let transcripts_root =
            canonical_asymptote_observer_transcripts_hash(&fixture.observer_transcripts).unwrap();
        let challenges_root =
            canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
        let transcript_commitment = AsymptoteObserverTranscriptCommitment {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            transcript_count: fixture.observer_transcripts.len() as u16,
        };
        let challenge_commitment = AsymptoteObserverChallengeCommitment {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            challenges_root,
            challenge_count: 0,
        };
        let canonical_close = AsymptoteObserverCanonicalClose {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            challenges_root,
            transcript_count: fixture.observer_transcripts.len() as u16,
            challenge_count: 0,
            challenge_cutoff_timestamp_ms: 31_000,
        };

        fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
            epoch: fixture.manifest.epoch,
            finality_tier: FinalityTier::SealedFinal,
            collapse_state: CollapseState::SealedFinal,
            guardian_manifest_hash: base_certificate.manifest_hash,
            guardian_decision_hash: base_certificate.decision_hash,
            guardian_counter: base_certificate.counter,
            guardian_trace_hash: base_certificate.trace_hash,
            guardian_measurement_root: base_certificate.measurement_root,
            policy_hash: fixture.manifest.policy_hash,
            witness_certificates: Vec::new(),
            observer_certificates: Vec::new(),
            observer_close_certificate: None,
            observer_transcripts: fixture.observer_transcripts.clone(),
            observer_challenges: observer_challenges.clone(),
            observer_transcript_commitment: Some(transcript_commitment.clone()),
            observer_challenge_commitment: Some(challenge_commitment),
            observer_canonical_close: Some(canonical_close),
            observer_canonical_abort: None,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        });
        sign_test_sealed_finality_proof(
            fixture.header.sealed_finality_proof.as_mut().unwrap(),
            &fixture.guardian_log_keypair,
        );

        let mut parent_view = canonical_observer_parent_view(&fixture);
        let mut mismatched_transcript_commitment = transcript_commitment;
        mismatched_transcript_commitment.transcripts_root = [0xabu8; 32];
        parent_view.state.insert(
            guardian_registry_observer_transcript_commitment_key(
                fixture.manifest.epoch,
                fixture.header.height,
                fixture.header.view,
            ),
            codec::to_bytes_canonical(&mismatched_transcript_commitment).unwrap(),
        );

        let err = fixture
            .engine
            .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("observer transcript commitment does not match the on-chain registry copy"));
    }

    #[tokio::test]
    async fn asymptote_accepts_canonical_observer_abort_proof() {
        let mut fixture = build_canonical_observer_fixture();
        let base_certificate = fixture
            .header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .clone();
        let observer_assignments_hash =
            canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
        let challenged_assignment = fixture.observer_assignments[0].clone();
        let observer_transcripts = fixture
            .observer_transcripts
            .iter()
            .filter(|transcript| transcript.statement.assignment != challenged_assignment)
            .cloned()
            .collect::<Vec<_>>();
        let mut challenge = AsymptoteObserverChallenge {
            challenge_id: [0u8; 32],
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            kind: AsymptoteObserverChallengeKind::MissingTranscript,
            challenger_account_id: fixture.header.producer_account_id,
            assignment: Some(challenged_assignment),
            observation_request: None,
            transcript: None,
            canonical_close: None,
            evidence_hash: canonical_asymptote_observer_assignment_hash(
                &fixture.observer_assignments[0],
            )
            .unwrap(),
            details: "observer transcript was omitted from the canonical surface".into(),
        };
        finalize_observer_challenge_id(&mut challenge);
        let observer_challenges = vec![challenge.clone()];
        let transcripts_root =
            canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
        let challenges_root =
            canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
        let transcript_commitment = AsymptoteObserverTranscriptCommitment {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            transcript_count: observer_transcripts.len() as u16,
        };
        let challenge_commitment = AsymptoteObserverChallengeCommitment {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            challenges_root,
            challenge_count: observer_challenges.len() as u16,
        };
        let canonical_abort = AsymptoteObserverCanonicalAbort {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            challenges_root,
            transcript_count: observer_transcripts.len() as u16,
            challenge_count: observer_challenges.len() as u16,
            challenge_cutoff_timestamp_ms: 32_000,
        };

        fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
            epoch: fixture.manifest.epoch,
            finality_tier: FinalityTier::BaseFinal,
            collapse_state: CollapseState::Abort,
            guardian_manifest_hash: base_certificate.manifest_hash,
            guardian_decision_hash: base_certificate.decision_hash,
            guardian_counter: base_certificate.counter,
            guardian_trace_hash: base_certificate.trace_hash,
            guardian_measurement_root: base_certificate.measurement_root,
            policy_hash: fixture.manifest.policy_hash,
            witness_certificates: Vec::new(),
            observer_certificates: Vec::new(),
            observer_close_certificate: None,
            observer_transcripts: observer_transcripts.clone(),
            observer_challenges: observer_challenges.clone(),
            observer_transcript_commitment: Some(transcript_commitment.clone()),
            observer_challenge_commitment: Some(challenge_commitment.clone()),
            observer_canonical_close: None,
            observer_canonical_abort: Some(canonical_abort.clone()),
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        });
        sign_test_sealed_finality_proof(
            fixture.header.sealed_finality_proof.as_mut().unwrap(),
            &fixture.guardian_log_keypair,
        );

        let mut parent_view = canonical_observer_parent_view(&fixture);
        parent_view.state.insert(
            guardian_registry_observer_transcript_commitment_key(
                fixture.manifest.epoch,
                fixture.header.height,
                fixture.header.view,
            ),
            codec::to_bytes_canonical(&transcript_commitment).unwrap(),
        );
        parent_view.state.insert(
            guardian_registry_observer_challenge_commitment_key(
                fixture.manifest.epoch,
                fixture.header.height,
                fixture.header.view,
            ),
            codec::to_bytes_canonical(&challenge_commitment).unwrap(),
        );
        parent_view.state.insert(
            guardian_registry_observer_canonical_abort_key(
                fixture.manifest.epoch,
                fixture.header.height,
                fixture.header.view,
            ),
            codec::to_bytes_canonical(&canonical_abort).unwrap(),
        );

        fixture
            .engine
            .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn asymptote_accepts_invalid_canonical_close_challenge_abort_proof() {
        let mut fixture = build_canonical_observer_fixture();
        let base_certificate = fixture
            .header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .clone();
        let observer_assignments_hash =
            canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
        let observer_transcripts = fixture.observer_transcripts.clone();
        let transcripts_root =
            canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
        let empty_challenges: Vec<AsymptoteObserverChallenge> = Vec::new();
        let empty_challenges_root =
            canonical_asymptote_observer_challenges_hash(&empty_challenges).unwrap();
        let mut invalid_close = AsymptoteObserverCanonicalClose {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            challenges_root: empty_challenges_root,
            transcript_count: observer_transcripts.len() as u16,
            challenge_count: 0,
            challenge_cutoff_timestamp_ms: 34_000,
        };
        invalid_close.transcripts_root[0] ^= 0xFF;
        let mut challenge = AsymptoteObserverChallenge {
            challenge_id: [0u8; 32],
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
            challenger_account_id: fixture.header.producer_account_id,
            assignment: None,
            observation_request: None,
            transcript: None,
            canonical_close: Some(invalid_close.clone()),
            evidence_hash: canonical_asymptote_observer_canonical_close_hash(&invalid_close)
                .unwrap(),
            details: "proof-carried canonical close does not match the transcript surface".into(),
        };
        finalize_observer_challenge_id(&mut challenge);
        let observer_challenges = vec![challenge];
        let challenges_root =
            canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
        let transcript_commitment = AsymptoteObserverTranscriptCommitment {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            transcript_count: observer_transcripts.len() as u16,
        };
        let challenge_commitment = AsymptoteObserverChallengeCommitment {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            challenges_root,
            challenge_count: observer_challenges.len() as u16,
        };
        let canonical_abort = AsymptoteObserverCanonicalAbort {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            challenges_root,
            transcript_count: observer_transcripts.len() as u16,
            challenge_count: observer_challenges.len() as u16,
            challenge_cutoff_timestamp_ms: 34_000,
        };

        fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
            epoch: fixture.manifest.epoch,
            finality_tier: FinalityTier::BaseFinal,
            collapse_state: CollapseState::Abort,
            guardian_manifest_hash: base_certificate.manifest_hash,
            guardian_decision_hash: base_certificate.decision_hash,
            guardian_counter: base_certificate.counter,
            guardian_trace_hash: base_certificate.trace_hash,
            guardian_measurement_root: base_certificate.measurement_root,
            policy_hash: fixture.manifest.policy_hash,
            witness_certificates: Vec::new(),
            observer_certificates: Vec::new(),
            observer_close_certificate: None,
            observer_transcripts: observer_transcripts.clone(),
            observer_challenges: observer_challenges.clone(),
            observer_transcript_commitment: Some(transcript_commitment.clone()),
            observer_challenge_commitment: Some(challenge_commitment.clone()),
            observer_canonical_close: None,
            observer_canonical_abort: Some(canonical_abort.clone()),
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        });
        sign_test_sealed_finality_proof(
            fixture.header.sealed_finality_proof.as_mut().unwrap(),
            &fixture.guardian_log_keypair,
        );

        let mut parent_view = canonical_observer_parent_view(&fixture);
        parent_view.state.insert(
            guardian_registry_observer_transcript_commitment_key(
                fixture.manifest.epoch,
                fixture.header.height,
                fixture.header.view,
            ),
            codec::to_bytes_canonical(&transcript_commitment).unwrap(),
        );
        parent_view.state.insert(
            guardian_registry_observer_challenge_commitment_key(
                fixture.manifest.epoch,
                fixture.header.height,
                fixture.header.view,
            ),
            codec::to_bytes_canonical(&challenge_commitment).unwrap(),
        );
        parent_view.state.insert(
            guardian_registry_observer_canonical_abort_key(
                fixture.manifest.epoch,
                fixture.header.height,
                fixture.header.view,
            ),
            codec::to_bytes_canonical(&canonical_abort).unwrap(),
        );

        fixture
            .engine
            .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn asymptote_rejects_missing_transcript_challenge_with_wrong_assignment_hash() {
        let mut fixture = build_canonical_observer_fixture();
        let base_certificate = fixture
            .header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .clone();
        let observer_assignments_hash =
            canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
        let challenged_assignment = fixture.observer_assignments[0].clone();
        let observer_transcripts = fixture
            .observer_transcripts
            .iter()
            .filter(|transcript| transcript.statement.assignment != challenged_assignment)
            .cloned()
            .collect::<Vec<_>>();
        let mut challenge = AsymptoteObserverChallenge {
            challenge_id: [0u8; 32],
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            kind: AsymptoteObserverChallengeKind::MissingTranscript,
            challenger_account_id: fixture.header.producer_account_id,
            assignment: Some(challenged_assignment),
            observation_request: None,
            transcript: None,
            canonical_close: None,
            evidence_hash: [0xAAu8; 32],
            details: "observer transcript was omitted from the canonical surface".into(),
        };
        finalize_observer_challenge_id(&mut challenge);
        let observer_challenges = vec![challenge];
        let transcripts_root =
            canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
        let challenges_root =
            canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
        let transcript_commitment = AsymptoteObserverTranscriptCommitment {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            transcript_count: observer_transcripts.len() as u16,
        };
        let challenge_commitment = AsymptoteObserverChallengeCommitment {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            challenges_root,
            challenge_count: observer_challenges.len() as u16,
        };
        let canonical_abort = AsymptoteObserverCanonicalAbort {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            challenges_root,
            transcript_count: observer_transcripts.len() as u16,
            challenge_count: observer_challenges.len() as u16,
            challenge_cutoff_timestamp_ms: 35_000,
        };

        fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
            epoch: fixture.manifest.epoch,
            finality_tier: FinalityTier::BaseFinal,
            collapse_state: CollapseState::Abort,
            guardian_manifest_hash: base_certificate.manifest_hash,
            guardian_decision_hash: base_certificate.decision_hash,
            guardian_counter: base_certificate.counter,
            guardian_trace_hash: base_certificate.trace_hash,
            guardian_measurement_root: base_certificate.measurement_root,
            policy_hash: fixture.manifest.policy_hash,
            witness_certificates: Vec::new(),
            observer_certificates: Vec::new(),
            observer_close_certificate: None,
            observer_transcripts: observer_transcripts.clone(),
            observer_challenges: observer_challenges.clone(),
            observer_transcript_commitment: Some(transcript_commitment),
            observer_challenge_commitment: Some(challenge_commitment),
            observer_canonical_close: None,
            observer_canonical_abort: Some(canonical_abort),
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        });
        sign_test_sealed_finality_proof(
            fixture.header.sealed_finality_proof.as_mut().unwrap(),
            &fixture.guardian_log_keypair,
        );

        let parent_view = canonical_observer_parent_view(&fixture);
        let err = fixture
            .engine
            .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("missing-transcript challenge evidence hash does not match the assignment"));
    }

    #[tokio::test]
    async fn asymptote_rejects_invalid_canonical_close_challenge_when_close_is_valid() {
        let mut fixture = build_canonical_observer_fixture();
        let base_certificate = fixture
            .header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .clone();
        let observer_assignments_hash =
            canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
        let observer_transcripts = fixture.observer_transcripts.clone();
        let transcripts_root =
            canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
        let empty_challenges: Vec<AsymptoteObserverChallenge> = Vec::new();
        let empty_challenges_root =
            canonical_asymptote_observer_challenges_hash(&empty_challenges).unwrap();
        let valid_close = AsymptoteObserverCanonicalClose {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            challenges_root: empty_challenges_root,
            transcript_count: observer_transcripts.len() as u16,
            challenge_count: 0,
            challenge_cutoff_timestamp_ms: 35_000,
        };
        let mut challenge = AsymptoteObserverChallenge {
            challenge_id: [0u8; 32],
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            kind: AsymptoteObserverChallengeKind::InvalidCanonicalClose,
            challenger_account_id: fixture.header.producer_account_id,
            assignment: None,
            observation_request: None,
            transcript: None,
            canonical_close: Some(valid_close.clone()),
            evidence_hash: canonical_asymptote_observer_canonical_close_hash(&valid_close).unwrap(),
            details: "claiming a valid close is invalid should fail".into(),
        };
        finalize_observer_challenge_id(&mut challenge);
        let observer_challenges = vec![challenge];
        let challenges_root =
            canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
        let transcript_commitment = AsymptoteObserverTranscriptCommitment {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            transcript_count: observer_transcripts.len() as u16,
        };
        let challenge_commitment = AsymptoteObserverChallengeCommitment {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            challenges_root,
            challenge_count: observer_challenges.len() as u16,
        };
        let canonical_abort = AsymptoteObserverCanonicalAbort {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            challenges_root,
            transcript_count: observer_transcripts.len() as u16,
            challenge_count: observer_challenges.len() as u16,
            challenge_cutoff_timestamp_ms: 35_000,
        };

        fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
            epoch: fixture.manifest.epoch,
            finality_tier: FinalityTier::BaseFinal,
            collapse_state: CollapseState::Abort,
            guardian_manifest_hash: base_certificate.manifest_hash,
            guardian_decision_hash: base_certificate.decision_hash,
            guardian_counter: base_certificate.counter,
            guardian_trace_hash: base_certificate.trace_hash,
            guardian_measurement_root: base_certificate.measurement_root,
            policy_hash: fixture.manifest.policy_hash,
            witness_certificates: Vec::new(),
            observer_certificates: Vec::new(),
            observer_close_certificate: None,
            observer_transcripts: observer_transcripts.clone(),
            observer_challenges: observer_challenges.clone(),
            observer_transcript_commitment: Some(transcript_commitment),
            observer_challenge_commitment: Some(challenge_commitment),
            observer_canonical_close: None,
            observer_canonical_abort: Some(canonical_abort),
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        });
        sign_test_sealed_finality_proof(
            fixture.header.sealed_finality_proof.as_mut().unwrap(),
            &fixture.guardian_log_keypair,
        );

        let parent_view = canonical_observer_parent_view(&fixture);
        let err = fixture
            .engine
            .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(
            "invalid-canonical-close challenge does not contain an objectively invalid close"
        ));
    }

    #[tokio::test]
    async fn asymptote_rejects_sealed_final_canonical_close_when_challenge_surface_is_non_empty() {
        let mut fixture = build_canonical_observer_fixture();
        let base_certificate = fixture
            .header
            .guardian_certificate
            .as_ref()
            .unwrap()
            .clone();
        let observer_assignments_hash =
            canonical_asymptote_observer_assignments_hash(&fixture.observer_assignments).unwrap();
        let challenged_assignment = fixture.observer_assignments[0].clone();
        let observer_transcripts = fixture
            .observer_transcripts
            .iter()
            .filter(|transcript| transcript.statement.assignment != challenged_assignment)
            .cloned()
            .collect::<Vec<_>>();
        let mut challenge = AsymptoteObserverChallenge {
            challenge_id: [0u8; 32],
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            kind: AsymptoteObserverChallengeKind::MissingTranscript,
            challenger_account_id: fixture.header.producer_account_id,
            assignment: Some(challenged_assignment),
            observation_request: None,
            transcript: None,
            canonical_close: None,
            evidence_hash: canonical_asymptote_observer_assignment_hash(
                &fixture.observer_assignments[0],
            )
            .unwrap(),
            details: "observer transcript missing at close".into(),
        };
        finalize_observer_challenge_id(&mut challenge);
        let observer_challenges = vec![challenge];
        let transcripts_root =
            canonical_asymptote_observer_transcripts_hash(&observer_transcripts).unwrap();
        let challenges_root =
            canonical_asymptote_observer_challenges_hash(&observer_challenges).unwrap();
        let transcript_commitment = AsymptoteObserverTranscriptCommitment {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            transcript_count: observer_transcripts.len() as u16,
        };
        let challenge_commitment = AsymptoteObserverChallengeCommitment {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            challenges_root,
            challenge_count: observer_challenges.len() as u16,
        };
        let canonical_close = AsymptoteObserverCanonicalClose {
            epoch: fixture.manifest.epoch,
            height: fixture.header.height,
            view: fixture.header.view,
            assignments_hash: observer_assignments_hash,
            transcripts_root,
            challenges_root,
            transcript_count: observer_transcripts.len() as u16,
            challenge_count: observer_challenges.len() as u16,
            challenge_cutoff_timestamp_ms: 33_000,
        };

        fixture.header.sealed_finality_proof = Some(SealedFinalityProof {
            epoch: fixture.manifest.epoch,
            finality_tier: FinalityTier::SealedFinal,
            collapse_state: CollapseState::SealedFinal,
            guardian_manifest_hash: base_certificate.manifest_hash,
            guardian_decision_hash: base_certificate.decision_hash,
            guardian_counter: base_certificate.counter,
            guardian_trace_hash: base_certificate.trace_hash,
            guardian_measurement_root: base_certificate.measurement_root,
            policy_hash: fixture.manifest.policy_hash,
            witness_certificates: Vec::new(),
            observer_certificates: Vec::new(),
            observer_close_certificate: None,
            observer_transcripts: observer_transcripts.clone(),
            observer_challenges: observer_challenges.clone(),
            observer_transcript_commitment: Some(transcript_commitment),
            observer_challenge_commitment: Some(challenge_commitment),
            observer_canonical_close: Some(canonical_close),
            observer_canonical_abort: None,
            veto_proofs: Vec::new(),
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        });
        sign_test_sealed_finality_proof(
            fixture.header.sealed_finality_proof.as_mut().unwrap(),
            &fixture.guardian_log_keypair,
        );

        let parent_view = canonical_observer_parent_view(&fixture);
        let err = fixture
            .engine
            .verify_guardianized_certificate(&fixture.header, &fixture.preimage, &parent_view)
            .await
            .unwrap_err();
        let err_text = err.to_string();
        assert!(
            err_text.contains(
                "observer challenge surface is non-empty; canonical close is challenge-dominated"
            ) || err_text.contains("canonical observer close may not carry dominant challenges")
                || err_text.contains(
                    "observer transcript counts do not match the deterministic assignment surface"
                ),
            "unexpected canonical-close rejection: {err_text}"
        );
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
            bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
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
        let bulletin_availability_certificate = build_bulletin_availability_certificate(
            &bulletin,
            &randomness_beacon,
            &public_inputs.ordered_transactions_root_hash,
            &public_inputs.resulting_state_root_hash,
        )
        .unwrap();
        header.canonical_order_certificate = Some(CanonicalOrderCertificate {
            bulletin_availability_certificate,
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
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
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
        let mut parent_view = parent_view;
        let bulletin_availability_certificate = header
            .canonical_order_certificate
            .as_ref()
            .unwrap()
            .bulletin_availability_certificate
            .clone();
        parent_view.state.insert(
            aft_bulletin_availability_certificate_key(header.height),
            codec::to_bytes_canonical(&bulletin_availability_certificate).unwrap(),
        );
        let bulletin_close = build_canonical_bulletin_close(
            &header
                .canonical_order_certificate
                .as_ref()
                .unwrap()
                .bulletin_commitment,
            &bulletin_availability_certificate,
        )
        .unwrap();
        parent_view.state.insert(
            aft_canonical_bulletin_close_key(header.height),
            codec::to_bytes_canonical(&bulletin_close).unwrap(),
        );

        engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn asymptote_rejects_canonical_order_certificate_with_mismatched_published_availability()
    {
        let (mut engine, mut header, manifest, preimage, _, log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;

        let bulletin = BulletinCommitment {
            height: header.height,
            cutoff_timestamp_ms: 1_750_000_001,
            bulletin_root: [81u8; 32],
            entry_count: 3,
        };
        let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
        let template_certificate = CanonicalOrderCertificate {
            height: header.height,
            bulletin_commitment: bulletin.clone(),
            bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
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
        let bulletin_availability_certificate = build_bulletin_availability_certificate(
            &bulletin,
            &randomness_beacon,
            &public_inputs.ordered_transactions_root_hash,
            &public_inputs.resulting_state_root_hash,
        )
        .unwrap();
        header.canonical_order_certificate = Some(CanonicalOrderCertificate {
            bulletin_availability_certificate,
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
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
        };
        let mut parent_view = build_parent_view_with_bulletin_commitment(
            &manifest,
            &[build_log_descriptor(
                &manifest.transparency_log_id,
                &log_keypair,
            )],
            policy,
            GuardianWitnessEpochSeed {
                epoch: manifest.epoch,
                seed: [82u8; 32],
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
        let mut mismatched_availability = header
            .canonical_order_certificate
            .as_ref()
            .unwrap()
            .bulletin_availability_certificate
            .clone();
        mismatched_availability.recoverability_root = [83u8; 32];
        parent_view.state.insert(
            aft_bulletin_availability_certificate_key(header.height),
            codec::to_bytes_canonical(&mismatched_availability).unwrap(),
        );

        let err = engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(
            "canonical order certificate bulletin availability certificate does not match published bulletin availability"
        ));
    }

    #[tokio::test]
    async fn asymptote_rejects_canonical_order_certificate_with_mismatched_published_bulletin_close(
    ) {
        let (mut engine, mut header, manifest, preimage, _, log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;

        let bulletin = BulletinCommitment {
            height: header.height,
            cutoff_timestamp_ms: 1_750_000_011,
            bulletin_root: [91u8; 32],
            entry_count: 3,
        };
        let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
        let template_certificate = CanonicalOrderCertificate {
            height: header.height,
            bulletin_commitment: bulletin.clone(),
            bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
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
        let bulletin_availability_certificate = build_bulletin_availability_certificate(
            &bulletin,
            &randomness_beacon,
            &public_inputs.ordered_transactions_root_hash,
            &public_inputs.resulting_state_root_hash,
        )
        .unwrap();
        header.canonical_order_certificate = Some(CanonicalOrderCertificate {
            bulletin_availability_certificate: bulletin_availability_certificate.clone(),
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
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
        };
        let mut parent_view = build_parent_view_with_bulletin_commitment(
            &manifest,
            &[build_log_descriptor(
                &manifest.transparency_log_id,
                &log_keypair,
            )],
            policy,
            GuardianWitnessEpochSeed {
                epoch: manifest.epoch,
                seed: [92u8; 32],
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
        parent_view.state.insert(
            aft_bulletin_availability_certificate_key(header.height),
            codec::to_bytes_canonical(&bulletin_availability_certificate).unwrap(),
        );
        let mut mismatched_bulletin_close = build_canonical_bulletin_close(
            &header
                .canonical_order_certificate
                .as_ref()
                .unwrap()
                .bulletin_commitment,
            &bulletin_availability_certificate,
        )
        .unwrap();
        mismatched_bulletin_close.entry_count =
            mismatched_bulletin_close.entry_count.saturating_add(1);
        parent_view.state.insert(
            aft_canonical_bulletin_close_key(header.height),
            codec::to_bytes_canonical(&mismatched_bulletin_close).unwrap(),
        );

        let err = engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(
            "canonical bulletin close entry count does not match the bulletin commitment"
        ));
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
            bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
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
                offender_account_id: manifest.validator_account_id,
                tx_hash: [73u8; 32],
                bulletin_root: bulletin.bulletin_root,
                details: "omitted from canonical order".into(),
            }],
        };
        let public_inputs = canonical_order_public_inputs(&header, &template_certificate).unwrap();
        let public_inputs_hash = canonical_order_public_inputs_hash(&public_inputs).unwrap();
        let bulletin_availability_certificate = build_bulletin_availability_certificate(
            &bulletin,
            &randomness_beacon,
            &public_inputs.ordered_transactions_root_hash,
            &public_inputs.resulting_state_root_hash,
        )
        .unwrap();
        header.canonical_order_certificate = Some(CanonicalOrderCertificate {
            bulletin_availability_certificate,
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
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
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
    async fn asymptote_rejects_canonical_order_certificate_when_published_abort_exists() {
        let (mut engine, mut header, manifest, preimage, _, log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;

        let bulletin = BulletinCommitment {
            height: header.height,
            cutoff_timestamp_ms: 1_750_000_021,
            bulletin_root: [101u8; 32],
            entry_count: 3,
        };
        let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
        let template_certificate = CanonicalOrderCertificate {
            height: header.height,
            bulletin_commitment: bulletin.clone(),
            bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
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
        let bulletin_availability_certificate = build_bulletin_availability_certificate(
            &bulletin,
            &randomness_beacon,
            &public_inputs.ordered_transactions_root_hash,
            &public_inputs.resulting_state_root_hash,
        )
        .unwrap();
        header.canonical_order_certificate = Some(CanonicalOrderCertificate {
            bulletin_availability_certificate,
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
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
        };
        let mut parent_view = build_parent_view_with_bulletin_commitment(
            &manifest,
            &[build_log_descriptor(
                &manifest.transparency_log_id,
                &log_keypair,
            )],
            policy,
            GuardianWitnessEpochSeed {
                epoch: manifest.epoch,
                seed: [102u8; 32],
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
        parent_view.state.insert(
            aft_canonical_order_abort_key(header.height),
            codec::to_bytes_canonical(&CanonicalOrderAbort {
                height: header.height,
                reason: CanonicalOrderAbortReason::InvalidProofBinding,
                details: "published canonical abort dominates a proof-binding failure".into(),
                bulletin_commitment_hash: [103u8; 32],
                bulletin_availability_certificate_hash: [104u8; 32],
                bulletin_close_hash: [106u8; 32],
                canonical_order_certificate_hash: [105u8; 32],
            })
            .unwrap(),
        );

        let err = engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("canonical order abort already dominates slot"));
    }

    #[tokio::test]
    async fn asymptote_rejects_canonical_order_certificate_without_publication_frontier() {
        let (mut engine, mut header, manifest, preimage, _, log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;

        let bulletin = BulletinCommitment {
            height: header.height,
            cutoff_timestamp_ms: 1_750_000_026,
            bulletin_root: [107u8; 32],
            entry_count: 3,
        };
        let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
        let template_certificate = CanonicalOrderCertificate {
            height: header.height,
            bulletin_commitment: bulletin.clone(),
            bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
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
        let bulletin_availability_certificate = build_bulletin_availability_certificate(
            &bulletin,
            &randomness_beacon,
            &public_inputs.ordered_transactions_root_hash,
            &public_inputs.resulting_state_root_hash,
        )
        .unwrap();
        header.canonical_order_certificate = Some(CanonicalOrderCertificate {
            bulletin_availability_certificate,
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
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
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
                seed: [108u8; 32],
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
        assert!(err.to_string().contains("requires a publication frontier"));
    }

    #[tokio::test]
    async fn asymptote_rejects_conflicting_published_publication_frontier() {
        let (mut engine, mut header, manifest, preimage, _, log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;

        let bulletin = BulletinCommitment {
            height: header.height,
            cutoff_timestamp_ms: 1_750_000_027,
            bulletin_root: [109u8; 32],
            entry_count: 3,
        };
        let randomness_beacon = derive_reference_ordering_randomness_beacon(&header).unwrap();
        let template_certificate = CanonicalOrderCertificate {
            height: header.height,
            bulletin_commitment: bulletin.clone(),
            bulletin_availability_certificate: BulletinAvailabilityCertificate::default(),
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
        let bulletin_availability_certificate = build_bulletin_availability_certificate(
            &bulletin,
            &randomness_beacon,
            &public_inputs.ordered_transactions_root_hash,
            &public_inputs.resulting_state_root_hash,
        )
        .unwrap();
        header.canonical_order_certificate = Some(CanonicalOrderCertificate {
            bulletin_availability_certificate,
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
        let frontier = build_publication_frontier(&header, None).unwrap();
        header.publication_frontier = Some(frontier.clone());

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
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
        };
        let mut parent_view = build_parent_view_with_bulletin_commitment(
            &manifest,
            &[build_log_descriptor(
                &manifest.transparency_log_id,
                &log_keypair,
            )],
            policy,
            GuardianWitnessEpochSeed {
                epoch: manifest.epoch,
                seed: [110u8; 32],
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
        let mut conflicting_frontier = frontier.clone();
        conflicting_frontier.view += 1;
        conflicting_frontier.bulletin_commitment_hash[0] ^= 0xFF;
        parent_view.state.insert(
            aft_publication_frontier_key(header.height),
            codec::to_bytes_canonical(&conflicting_frontier).unwrap(),
        );

        let err = engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("conflicts with the published same-slot frontier"));
    }

    #[tokio::test]
    async fn asymptote_accepts_abort_only_ordering_outcome_when_abort_is_published() {
        let (mut engine, header, manifest, preimage, _, log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;

        let bulletin = BulletinCommitment {
            height: header.height,
            cutoff_timestamp_ms: 1_750_000_031,
            bulletin_root: [111u8; 32],
            entry_count: 0,
        };
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
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
        };
        let mut parent_view = build_parent_view_with_bulletin_commitment(
            &manifest,
            &[build_log_descriptor(
                &manifest.transparency_log_id,
                &log_keypair,
            )],
            policy,
            GuardianWitnessEpochSeed {
                epoch: manifest.epoch,
                seed: [112u8; 32],
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
        parent_view.state.insert(
            aft_canonical_order_abort_key(header.height),
            codec::to_bytes_canonical(&CanonicalOrderAbort {
                height: header.height,
                reason: CanonicalOrderAbortReason::BulletinSurfaceMismatch,
                details:
                    "published canonical abort is the ordering outcome after a surface mismatch"
                        .into(),
                bulletin_commitment_hash: [113u8; 32],
                bulletin_availability_certificate_hash: [114u8; 32],
                bulletin_close_hash: [115u8; 32],
                canonical_order_certificate_hash: [116u8; 32],
            })
            .unwrap(),
        );

        engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn asymptote_rejects_abort_only_outcome_when_parent_state_coexists_with_positive_ordering_artifacts(
    ) {
        let (mut engine, header, manifest, preimage, _, log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;

        let bulletin = BulletinCommitment {
            height: header.height,
            cutoff_timestamp_ms: 1_750_000_041,
            bulletin_root: [121u8; 32],
            entry_count: 0,
        };
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
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
        };
        let mut parent_view = build_parent_view_with_bulletin_commitment(
            &manifest,
            &[build_log_descriptor(
                &manifest.transparency_log_id,
                &log_keypair,
            )],
            policy,
            GuardianWitnessEpochSeed {
                epoch: manifest.epoch,
                seed: [122u8; 32],
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
            bulletin.clone(),
        );
        let bulletin_availability_certificate = BulletinAvailabilityCertificate {
            height: header.height,
            bulletin_commitment_hash: [123u8; 32],
            recoverability_root: [124u8; 32],
        };
        parent_view.state.insert(
            aft_bulletin_availability_certificate_key(header.height),
            codec::to_bytes_canonical(&bulletin_availability_certificate).unwrap(),
        );
        let bulletin_close =
            build_canonical_bulletin_close(&bulletin, &bulletin_availability_certificate).unwrap();
        parent_view.state.insert(
            aft_canonical_bulletin_close_key(header.height),
            codec::to_bytes_canonical(&bulletin_close).unwrap(),
        );
        parent_view.state.insert(
            aft_canonical_order_abort_key(header.height),
            codec::to_bytes_canonical(&CanonicalOrderAbort {
                height: header.height,
                reason: CanonicalOrderAbortReason::MissingOrderCertificate,
                details: "abort should not coexist with positive ordering artifacts".into(),
                bulletin_commitment_hash: [125u8; 32],
                bulletin_availability_certificate_hash: [126u8; 32],
                bulletin_close_hash: [127u8; 32],
                canonical_order_certificate_hash: [0u8; 32],
            })
            .unwrap(),
        );

        let err = engine
            .verify_guardianized_certificate(&header, &preimage, &parent_view)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("canonical order abort coexists with positive published ordering artifacts"));
    }

    #[tokio::test]
    async fn asymptote_accepts_matching_published_canonical_collapse_object() {
        let (mut engine, header, manifest, _preimage, _, log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;

        let bulletin = BulletinCommitment {
            height: header.height,
            cutoff_timestamp_ms: 1_750_000_051,
            bulletin_root: [131u8; 32],
            entry_count: 0,
        };
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
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
        };
        let mut parent_view = build_parent_view_with_bulletin_commitment(
            &manifest,
            &[build_log_descriptor(
                &manifest.transparency_log_id,
                &log_keypair,
            )],
            policy,
            GuardianWitnessEpochSeed {
                epoch: manifest.epoch,
                seed: [132u8; 32],
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
        let previous =
            test_canonical_collapse_object(header.height - 1, None, [210u8; 32], [211u8; 32]);
        parent_view.state.insert(
            aft_canonical_collapse_object_key(previous.height),
            codec::to_bytes_canonical(&previous).unwrap(),
        );
        let collapse =
            derive_canonical_collapse_object_with_previous(&header, &[], Some(&previous)).unwrap();
        parent_view.state.insert(
            aft_canonical_collapse_object_key(header.height),
            codec::to_bytes_canonical(&collapse).unwrap(),
        );

        engine
            .verify_published_canonical_collapse_object(&header, &parent_view)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn asymptote_rejects_mismatched_published_canonical_collapse_object() {
        let (mut engine, header, manifest, _preimage, _, log_keypair) =
            build_case(&[(0, 0), (1, 1)]);
        engine.safety_mode = AftSafetyMode::Asymptote;

        let bulletin = BulletinCommitment {
            height: header.height,
            cutoff_timestamp_ms: 1_750_000_061,
            bulletin_root: [141u8; 32],
            entry_count: 0,
        };
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
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
        };
        let mut parent_view = build_parent_view_with_bulletin_commitment(
            &manifest,
            &[build_log_descriptor(
                &manifest.transparency_log_id,
                &log_keypair,
            )],
            policy,
            GuardianWitnessEpochSeed {
                epoch: manifest.epoch,
                seed: [142u8; 32],
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
        let previous =
            test_canonical_collapse_object(header.height - 1, None, [212u8; 32], [213u8; 32]);
        parent_view.state.insert(
            aft_canonical_collapse_object_key(previous.height),
            codec::to_bytes_canonical(&previous).unwrap(),
        );
        let mut collapse =
            derive_canonical_collapse_object_with_previous(&header, &[], Some(&previous)).unwrap();
        collapse.resulting_state_root_hash = [143u8; 32];
        parent_view.state.insert(
            aft_canonical_collapse_object_key(header.height),
            codec::to_bytes_canonical(&collapse).unwrap(),
        );

        let err = engine
            .verify_published_canonical_collapse_object(&header, &parent_view)
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("published canonical collapse object does not match"));
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
            observer_sealing_mode: AsymptoteObserverSealingMode::SampledCloseV1,
            observer_challenge_window_ms: 0,
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
            observer_transcripts: Vec::new(),
            observer_challenges: Vec::new(),
            observer_transcript_commitment: None,
            observer_challenge_commitment: None,
            observer_canonical_close: None,
            observer_canonical_abort: None,
            veto_proofs: vec![veto_proof],
            divergence_signals: Vec::new(),
            proof_signature: SignatureProof::default(),
        });
        sign_test_sealed_finality_proof(
            header.sealed_finality_proof.as_mut().unwrap(),
            &guardian_log_keypair,
        );

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

    #[test]
    fn asymptote_reset_does_not_promote_vote_only_quorum_candidate_for_committed_height() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        let block_hash = [19u8; 32];
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

        assert!(engine.highest_qc.height < 5);
        assert!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::take_pending_quorum_certificates(
                &mut engine,
            )
            .is_empty()
        );
    }

    #[test]
    fn reset_promotes_recovered_header_for_committed_height() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let recovered_header = RecoveredCanonicalHeaderEntry {
            height: 5,
            view: 2,
            canonical_block_commitment_hash: [0x45u8; 32],
            parent_block_commitment_hash: [0x34u8; 32],
            transactions_root_hash: [0x23u8; 32],
            resulting_state_root_hash: [0x13u8; 32],
            previous_canonical_collapse_commitment_hash: [0x12u8; 32],
        };

        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_consensus_header(
            &mut engine,
            &recovered_header,
        ));

        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

        assert_eq!(engine.highest_qc.height, 5);
        assert_eq!(engine.highest_qc.view, recovered_header.view);
        assert_eq!(
            engine.highest_qc.block_hash,
            recovered_header.canonical_block_commitment_hash
        );
    }

    #[test]
    fn synthetic_parent_qc_uses_recovered_header_hint() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let recovered_header = RecoveredCanonicalHeaderEntry {
            height: 4,
            view: 7,
            canonical_block_commitment_hash: [0x56u8; 32],
            parent_block_commitment_hash: [0x46u8; 32],
            transactions_root_hash: [0x36u8; 32],
            resulting_state_root_hash: [0x26u8; 32],
            previous_canonical_collapse_commitment_hash: [0x26u8; 32],
        };

        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_consensus_header(
            &mut engine,
            &recovered_header,
        ));

        let parent_qc = engine
            .synthetic_parent_qc_for_height(5)
            .expect("recovered parent QC hint");
        assert_eq!(parent_qc.height, 4);
        assert_eq!(parent_qc.view, recovered_header.view);
        assert_eq!(
            parent_qc.block_hash,
            recovered_header.canonical_block_commitment_hash
        );
    }

    #[test]
    fn recovered_header_for_quorum_certificate_returns_restart_hint() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let recovered_header = RecoveredCanonicalHeaderEntry {
            height: 6,
            view: 3,
            canonical_block_commitment_hash: [0x66u8; 32],
            parent_block_commitment_hash: [0x56u8; 32],
            transactions_root_hash: [0x46u8; 32],
            resulting_state_root_hash: [0x36u8; 32],
            previous_canonical_collapse_commitment_hash: [0x26u8; 32],
        };

        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_consensus_header(
            &mut engine,
            &recovered_header,
        ));

        let recovered_qc = recovered_header.synthetic_quorum_certificate();
        let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_consensus_header_for_quorum_certificate(
            &engine,
            &recovered_qc,
        )
        .expect("matching recovered header hint");
        assert_eq!(resolved, recovered_header);
    }

    #[test]
    fn recovered_certified_header_for_quorum_certificate_returns_restart_entry() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let previous_header = RecoveredCanonicalHeaderEntry {
            height: 5,
            view: 2,
            canonical_block_commitment_hash: [0x55u8; 32],
            parent_block_commitment_hash: [0x45u8; 32],
            transactions_root_hash: [0x35u8; 32],
            resulting_state_root_hash: [0x25u8; 32],
            previous_canonical_collapse_commitment_hash: [0x15u8; 32],
        };
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_consensus_header(
            &mut engine,
            &previous_header,
        ));

        let recovered_entry = RecoveredCertifiedHeaderEntry {
            header: RecoveredCanonicalHeaderEntry {
                height: 6,
                view: 3,
                canonical_block_commitment_hash: [0x66u8; 32],
                parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
                transactions_root_hash: [0x46u8; 32],
                resulting_state_root_hash: [0x36u8; 32],
                previous_canonical_collapse_commitment_hash: [0x26u8; 32],
            },
            certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
            certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
        };

        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_certified_header(
            &mut engine,
            &recovered_entry,
        ));

        let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_certified_header_for_quorum_certificate(
            &engine,
            &recovered_entry.certified_quorum_certificate(),
        )
        .expect("matching recovered certified header hint");
        assert_eq!(resolved, recovered_entry);
    }

    #[test]
    fn observe_recovered_certified_header_rejects_conflicting_parent_state_root() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let previous_header = RecoveredCanonicalHeaderEntry {
            height: 7,
            view: 4,
            canonical_block_commitment_hash: [0x77u8; 32],
            parent_block_commitment_hash: [0x67u8; 32],
            transactions_root_hash: [0x57u8; 32],
            resulting_state_root_hash: [0x47u8; 32],
            previous_canonical_collapse_commitment_hash: [0x37u8; 32],
        };
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_consensus_header(
            &mut engine,
            &previous_header,
        ));

        let conflicting_entry = RecoveredCertifiedHeaderEntry {
            header: RecoveredCanonicalHeaderEntry {
                height: 8,
                view: 5,
                canonical_block_commitment_hash: [0x88u8; 32],
                parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
                transactions_root_hash: [0x68u8; 32],
                resulting_state_root_hash: [0x58u8; 32],
                previous_canonical_collapse_commitment_hash: [0x48u8; 32],
            },
            certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
            certified_parent_resulting_state_root_hash: [0xffu8; 32],
        };

        assert!(!<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_certified_header(
            &mut engine,
            &conflicting_entry,
        ));
    }

    #[test]
    fn header_for_quorum_certificate_returns_recovered_restart_header() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let previous_header = RecoveredCanonicalHeaderEntry {
            height: 6,
            view: 2,
            canonical_block_commitment_hash: [0x61u8; 32],
            parent_block_commitment_hash: [0x51u8; 32],
            transactions_root_hash: [0x41u8; 32],
            resulting_state_root_hash: [0x31u8; 32],
            previous_canonical_collapse_commitment_hash: [0x21u8; 32],
        };
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_consensus_header(
            &mut engine,
            &previous_header,
        ));

        let certified_entry = RecoveredCertifiedHeaderEntry {
            header: RecoveredCanonicalHeaderEntry {
                height: 7,
                view: 3,
                canonical_block_commitment_hash: [0x71u8; 32],
                parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
                transactions_root_hash: [0x51u8; 32],
                resulting_state_root_hash: [0x41u8; 32],
                previous_canonical_collapse_commitment_hash: [0x31u8; 32],
            },
            certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
            certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
        };
        let payload = RecoverableSlotPayloadV5 {
            height: 7,
            view: 3,
            producer_account_id: AccountId([0x72u8; 32]),
            block_commitment_hash: certified_entry.header.canonical_block_commitment_hash,
            parent_block_hash: certified_entry.header.parent_block_commitment_hash,
            canonical_order_certificate: CanonicalOrderCertificate {
                height: 7,
                bulletin_commitment: BulletinCommitment {
                    height: 7,
                    cutoff_timestamp_ms: 1_760_000_777_000,
                    bulletin_root: [0x73u8; 32],
                    entry_count: 0,
                },
                bulletin_availability_certificate: BulletinAvailabilityCertificate {
                    height: 7,
                    bulletin_commitment_hash: [0x74u8; 32],
                    recoverability_root: [0x75u8; 32],
                },
                randomness_beacon: [0x76u8; 32],
                ordered_transactions_root_hash: certified_entry.header.transactions_root_hash,
                resulting_state_root_hash: certified_entry.header.resulting_state_root_hash,
                proof: CanonicalOrderProof::default(),
                omission_proofs: Vec::new(),
            },
            ordered_transaction_bytes: Vec::new(),
            canonical_order_publication_bundle_bytes: Vec::new(),
            canonical_bulletin_close_bytes: Vec::new(),
            canonical_bulletin_availability_certificate_bytes: Vec::new(),
            bulletin_surface_entries: Vec::new(),
        };
        let restart_entry = recovered_restart_block_header_entry(&payload, &certified_entry)
            .expect("restart entry");

        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_restart_block_header(
            &mut engine,
            &restart_entry,
        ));

        let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::header_for_quorum_certificate(
            &engine,
            &restart_entry.certified_quorum_certificate(),
        )
        .expect("matching recovered restart header");
        assert_eq!(resolved, restart_entry.header);
    }

    #[test]
    fn observe_recovered_restart_block_header_rejects_conflicting_parent_qc() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let previous_header = RecoveredCanonicalHeaderEntry {
            height: 8,
            view: 4,
            canonical_block_commitment_hash: [0x81u8; 32],
            parent_block_commitment_hash: [0x71u8; 32],
            transactions_root_hash: [0x61u8; 32],
            resulting_state_root_hash: [0x51u8; 32],
            previous_canonical_collapse_commitment_hash: [0x41u8; 32],
        };
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_consensus_header(
            &mut engine,
            &previous_header,
        ));

        let certified_entry = RecoveredCertifiedHeaderEntry {
            header: RecoveredCanonicalHeaderEntry {
                height: 9,
                view: 5,
                canonical_block_commitment_hash: [0x91u8; 32],
                parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
                transactions_root_hash: [0x71u8; 32],
                resulting_state_root_hash: [0x61u8; 32],
                previous_canonical_collapse_commitment_hash: [0x51u8; 32],
            },
            certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
            certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
        };
        let payload = RecoverableSlotPayloadV5 {
            height: 9,
            view: 5,
            producer_account_id: AccountId([0x92u8; 32]),
            block_commitment_hash: certified_entry.header.canonical_block_commitment_hash,
            parent_block_hash: certified_entry.header.parent_block_commitment_hash,
            canonical_order_certificate: CanonicalOrderCertificate {
                height: 9,
                bulletin_commitment: BulletinCommitment {
                    height: 9,
                    cutoff_timestamp_ms: 1_760_000_999_000,
                    bulletin_root: [0x93u8; 32],
                    entry_count: 0,
                },
                bulletin_availability_certificate: BulletinAvailabilityCertificate {
                    height: 9,
                    bulletin_commitment_hash: [0x94u8; 32],
                    recoverability_root: [0x95u8; 32],
                },
                randomness_beacon: [0x96u8; 32],
                ordered_transactions_root_hash: certified_entry.header.transactions_root_hash,
                resulting_state_root_hash: certified_entry.header.resulting_state_root_hash,
                proof: CanonicalOrderProof::default(),
                omission_proofs: Vec::new(),
            },
            ordered_transaction_bytes: Vec::new(),
            canonical_order_publication_bundle_bytes: Vec::new(),
            canonical_bulletin_close_bytes: Vec::new(),
            canonical_bulletin_availability_certificate_bytes: Vec::new(),
            bulletin_surface_entries: Vec::new(),
        };
        let mut restart_entry = recovered_restart_block_header_entry(&payload, &certified_entry)
            .expect("restart entry");
        restart_entry.header.parent_qc.block_hash[0] ^= 0xFF;

        assert!(!<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_restart_block_header(
            &mut engine,
            &restart_entry,
        ));
    }

    #[test]
    fn aft_recovered_trait_paths_match_legacy_wrappers() {
        let previous_header = RecoveredCanonicalHeaderEntry {
            height: 5,
            view: 2,
            canonical_block_commitment_hash: [0x51u8; 32],
            parent_block_commitment_hash: [0x41u8; 32],
            transactions_root_hash: [0x31u8; 32],
            resulting_state_root_hash: [0x21u8; 32],
            previous_canonical_collapse_commitment_hash: [0x11u8; 32],
        };
        let certified_entry = RecoveredCertifiedHeaderEntry {
            header: RecoveredCanonicalHeaderEntry {
                height: 6,
                view: 3,
                canonical_block_commitment_hash: [0x61u8; 32],
                parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
                transactions_root_hash: [0x41u8; 32],
                resulting_state_root_hash: [0x31u8; 32],
                previous_canonical_collapse_commitment_hash: [0x21u8; 32],
            },
            certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
            certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
        };
        let restart_entry = sample_recovered_restart_entry(
            &certified_entry.header,
            certified_entry.certified_quorum_certificate(),
            certified_entry.header.resulting_state_root_hash,
            7,
            4,
            0x71,
            0x72,
            0x73,
            0x74,
            0x75,
            0x76,
        );

        let mut legacy_engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let mut aft_engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);

        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_consensus_header(
            &mut legacy_engine,
            &previous_header,
        ));
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_certified_header(
            &mut legacy_engine,
            &certified_entry,
        ));
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_restart_block_header(
            &mut legacy_engine,
            &restart_entry,
        ));

        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_aft_recovered_consensus_header(
            &mut aft_engine,
            &previous_header,
        ));
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_aft_recovered_certified_header(
            &mut aft_engine,
            &certified_entry,
        ));
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_aft_recovered_restart_header(
            &mut aft_engine,
            &restart_entry,
        ));

        assert_eq!(
            legacy_engine.recovered_headers,
            aft_engine.recovered_headers
        );
        assert_eq!(
            legacy_engine.recovered_certified_headers,
            aft_engine.recovered_certified_headers
        );
        assert_eq!(
            legacy_engine.recovered_restart_headers,
            aft_engine.recovered_restart_headers
        );

        let recovered_qc = previous_header.synthetic_quorum_certificate();
        let certified_qc = certified_entry.certified_quorum_certificate();
        let restart_qc = restart_entry.certified_quorum_certificate();
        assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_consensus_header_for_quorum_certificate(
                &legacy_engine,
                &recovered_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_consensus_header_for_quorum_certificate(
                &aft_engine,
                &recovered_qc,
            )
        );
        assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_certified_header_for_quorum_certificate(
                &legacy_engine,
                &certified_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_certified_header_for_quorum_certificate(
                &aft_engine,
                &certified_qc,
            )
        );
        assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_restart_block_header_for_quorum_certificate(
                &legacy_engine,
                &restart_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_restart_header_for_quorum_certificate(
                &aft_engine,
                &restart_qc,
            )
        );
    }

    #[test]
    fn observe_aft_recovered_state_surface_matches_manual_header_seeding() {
        let previous_header = RecoveredCanonicalHeaderEntry {
            height: 5,
            view: 2,
            canonical_block_commitment_hash: [0x51u8; 32],
            parent_block_commitment_hash: [0x41u8; 32],
            transactions_root_hash: [0x31u8; 32],
            resulting_state_root_hash: [0x21u8; 32],
            previous_canonical_collapse_commitment_hash: [0x11u8; 32],
        };
        let certified_entry = RecoveredCertifiedHeaderEntry {
            header: RecoveredCanonicalHeaderEntry {
                height: 6,
                view: 3,
                canonical_block_commitment_hash: [0x61u8; 32],
                parent_block_commitment_hash: previous_header.canonical_block_commitment_hash,
                transactions_root_hash: [0x41u8; 32],
                resulting_state_root_hash: [0x31u8; 32],
                previous_canonical_collapse_commitment_hash: [0x21u8; 32],
            },
            certified_parent_quorum_certificate: previous_header.synthetic_quorum_certificate(),
            certified_parent_resulting_state_root_hash: previous_header.resulting_state_root_hash,
        };
        let restart_entry = sample_recovered_restart_entry(
            &certified_entry.header,
            certified_entry.certified_quorum_certificate(),
            certified_entry.header.resulting_state_root_hash,
            7,
            4,
            0x71,
            0x72,
            0x73,
            0x74,
            0x75,
            0x76,
        );
        let surface = AftRecoveredStateSurface {
            replay_prefix: Vec::new(),
            consensus_headers: vec![previous_header.clone()],
            certified_headers: vec![certified_entry.clone()],
            restart_headers: vec![restart_entry.clone()],
            historical_continuation: None,
        };

        let mut manual_engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let mut surface_engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);

        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_aft_recovered_consensus_header(
            &mut manual_engine,
            &previous_header,
        ));
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_aft_recovered_certified_header(
            &mut manual_engine,
            &certified_entry,
        ));
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_aft_recovered_restart_header(
            &mut manual_engine,
            &restart_entry,
        ));

        let stats = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_aft_recovered_state_surface(&mut surface_engine, &surface);

        assert_eq!(stats.accepted_consensus_headers, 1);
        assert_eq!(stats.accepted_certified_headers, 1);
        assert_eq!(stats.accepted_restart_headers, 1);
        assert!(stats.accepted_any());

        assert_eq!(
            manual_engine.recovered_headers,
            surface_engine.recovered_headers
        );
        assert_eq!(
            manual_engine.recovered_certified_headers,
            surface_engine.recovered_certified_headers
        );
        assert_eq!(
            manual_engine.recovered_restart_headers,
            surface_engine.recovered_restart_headers
        );

        let recovered_qc = previous_header.synthetic_quorum_certificate();
        let certified_qc = certified_entry.certified_quorum_certificate();
        let restart_qc = restart_entry.certified_quorum_certificate();
        assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_consensus_header_for_quorum_certificate(
                &manual_engine,
                &recovered_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_consensus_header_for_quorum_certificate(
                &surface_engine,
                &recovered_qc,
            )
        );
        assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_certified_header_for_quorum_certificate(
                &manual_engine,
                &certified_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_certified_header_for_quorum_certificate(
                &surface_engine,
                &certified_qc,
            )
        );
        assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_restart_header_for_quorum_certificate(
                &manual_engine,
                &restart_qc,
            ),
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::aft_recovered_restart_header_for_quorum_certificate(
                &surface_engine,
                &restart_qc,
            )
        );
    }

    #[test]
    fn recovered_restart_block_header_for_quorum_certificate_returns_later_step_entry() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let previous_header = RecoveredCanonicalHeaderEntry {
            height: 10,
            view: 5,
            canonical_block_commitment_hash: [0xA1u8; 32],
            parent_block_commitment_hash: [0x91u8; 32],
            transactions_root_hash: [0x81u8; 32],
            resulting_state_root_hash: [0x71u8; 32],
            previous_canonical_collapse_commitment_hash: [0x61u8; 32],
        };
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_consensus_header(
            &mut engine,
            &previous_header,
        ));

        let step_one = sample_recovered_restart_entry(
            &previous_header,
            previous_header.synthetic_quorum_certificate(),
            previous_header.resulting_state_root_hash,
            11,
            6,
            0xA2,
            0x82,
            0x72,
            0x62,
            0xB2,
            0xC2,
        );
        let step_two = sample_recovered_restart_entry(
            &step_one.certified_header.header,
            step_one.certified_quorum_certificate(),
            step_one.certified_header.header.resulting_state_root_hash,
            12,
            7,
            0xA3,
            0x83,
            0x73,
            0x63,
            0xB3,
            0xC3,
        );
        let step_three = sample_recovered_restart_entry(
            &step_two.certified_header.header,
            step_two.certified_quorum_certificate(),
            step_two.certified_header.header.resulting_state_root_hash,
            13,
            8,
            0xA4,
            0x84,
            0x74,
            0x64,
            0xB4,
            0xC4,
        );

        for entry in [&step_one, &step_two, &step_three] {
            assert!(<GuardianMajorityEngine as ConsensusEngine<
                ChainTransaction,
            >>::observe_recovered_restart_block_header(
                &mut engine, entry,
            ));
        }

        let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_restart_block_header_for_quorum_certificate(
            &engine,
            &step_three.certified_quorum_certificate(),
        )
        .expect("later-step recovered restart entry");
        assert_eq!(resolved, step_three);

        let resolved_header = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::header_for_quorum_certificate(
            &engine,
            &step_three.certified_quorum_certificate(),
        )
        .expect("later-step recovered restart header");
        assert_eq!(resolved_header, step_three.header);
    }

    #[test]
    fn recovered_restart_block_header_for_quorum_certificate_returns_fourth_step_entry() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let previous_header = RecoveredCanonicalHeaderEntry {
            height: 20,
            view: 9,
            canonical_block_commitment_hash: [0xB1u8; 32],
            parent_block_commitment_hash: [0xA1u8; 32],
            transactions_root_hash: [0x91u8; 32],
            resulting_state_root_hash: [0x81u8; 32],
            previous_canonical_collapse_commitment_hash: [0x71u8; 32],
        };
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_consensus_header(
            &mut engine,
            &previous_header,
        ));

        let step_one = sample_recovered_restart_entry(
            &previous_header,
            previous_header.synthetic_quorum_certificate(),
            previous_header.resulting_state_root_hash,
            21,
            10,
            0xB2,
            0x92,
            0x82,
            0x72,
            0xC2,
            0xD2,
        );
        let step_two = sample_recovered_restart_entry(
            &step_one.certified_header.header,
            step_one.certified_quorum_certificate(),
            step_one.certified_header.header.resulting_state_root_hash,
            22,
            11,
            0xB3,
            0x93,
            0x83,
            0x73,
            0xC3,
            0xD3,
        );
        let step_three = sample_recovered_restart_entry(
            &step_two.certified_header.header,
            step_two.certified_quorum_certificate(),
            step_two.certified_header.header.resulting_state_root_hash,
            23,
            12,
            0xB4,
            0x94,
            0x84,
            0x74,
            0xC4,
            0xD4,
        );
        let step_four = sample_recovered_restart_entry(
            &step_three.certified_header.header,
            step_three.certified_quorum_certificate(),
            step_three.certified_header.header.resulting_state_root_hash,
            24,
            13,
            0xB5,
            0x95,
            0x85,
            0x75,
            0xC5,
            0xD5,
        );

        for entry in [&step_one, &step_two, &step_three, &step_four] {
            assert!(<GuardianMajorityEngine as ConsensusEngine<
                ChainTransaction,
            >>::observe_recovered_restart_block_header(
                &mut engine, entry,
            ));
        }

        let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_restart_block_header_for_quorum_certificate(
            &engine,
            &step_four.certified_quorum_certificate(),
        )
        .expect("fourth-step recovered restart entry");
        assert_eq!(resolved, step_four);

        let resolved_header = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::header_for_quorum_certificate(
            &engine,
            &step_four.certified_quorum_certificate(),
        )
        .expect("fourth-step recovered restart header");
        assert_eq!(resolved_header, step_four.header);
    }

    #[test]
    fn recovered_restart_block_header_for_quorum_certificate_returns_fifth_step_entry() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let previous_header = RecoveredCanonicalHeaderEntry {
            height: 30,
            view: 14,
            canonical_block_commitment_hash: [0xC1u8; 32],
            parent_block_commitment_hash: [0xB1u8; 32],
            transactions_root_hash: [0xA1u8; 32],
            resulting_state_root_hash: [0x91u8; 32],
            previous_canonical_collapse_commitment_hash: [0x81u8; 32],
        };
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_consensus_header(
            &mut engine,
            &previous_header,
        ));

        let branch = sample_recovered_restart_entry_branch(&previous_header, 15, 5, 0xD1);
        for entry in &branch {
            assert!(<GuardianMajorityEngine as ConsensusEngine<
                ChainTransaction,
            >>::observe_recovered_restart_block_header(
                &mut engine, entry,
            ));
        }

        let tail = branch.last().expect("fifth-step branch tail");
        let resolved = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::recovered_restart_block_header_for_quorum_certificate(
            &engine,
            &tail.certified_quorum_certificate(),
        )
        .expect("fifth-step recovered restart entry");
        assert_eq!(resolved, *tail);

        let resolved_header = <GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::header_for_quorum_certificate(
            &engine,
            &tail.certified_quorum_certificate(),
        )
        .expect("fifth-step recovered restart header");
        assert_eq!(resolved_header, tail.header);
    }

    #[test]
    fn retain_recovered_ancestry_ranges_prunes_restart_caches_outside_keep_ranges() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let previous_header = RecoveredCanonicalHeaderEntry {
            height: 40,
            view: 19,
            canonical_block_commitment_hash: [0xD1u8; 32],
            parent_block_commitment_hash: [0xC1u8; 32],
            transactions_root_hash: [0xB1u8; 32],
            resulting_state_root_hash: [0xA1u8; 32],
            previous_canonical_collapse_commitment_hash: [0x91u8; 32],
        };
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_consensus_header(
            &mut engine,
            &previous_header,
        ));

        let branch = sample_recovered_restart_entry_branch(&previous_header, 20, 5, 0xE1);
        for entry in &branch {
            assert!(<GuardianMajorityEngine as ConsensusEngine<
                ChainTransaction,
            >>::observe_recovered_restart_block_header(
                &mut engine, entry,
            ));
        }

        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::retain_recovered_ancestry_ranges(
            &mut engine,
            &[(42, 43), (45, 45)],
        );

        let mut recovered_header_heights =
            engine.recovered_headers.keys().copied().collect::<Vec<_>>();
        let mut recovered_certified_heights = engine
            .recovered_certified_headers
            .keys()
            .copied()
            .collect::<Vec<_>>();
        let mut recovered_restart_heights = engine
            .recovered_restart_headers
            .keys()
            .copied()
            .collect::<Vec<_>>();
        recovered_header_heights.sort_unstable();
        recovered_certified_heights.sort_unstable();
        recovered_restart_heights.sort_unstable();

        assert_eq!(recovered_header_heights, vec![42, 43, 45]);
        assert_eq!(recovered_certified_heights, vec![42, 43, 45]);
        assert_eq!(recovered_restart_heights, vec![42, 43, 45]);
    }

    #[test]
    fn observe_recovered_consensus_header_rejects_conflicting_parent_link() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
        let previous_header = RecoveredCanonicalHeaderEntry {
            height: 4,
            view: 1,
            canonical_block_commitment_hash: [0x61u8; 32],
            parent_block_commitment_hash: [0x51u8; 32],
            transactions_root_hash: [0x41u8; 32],
            resulting_state_root_hash: [0x31u8; 32],
            previous_canonical_collapse_commitment_hash: [0x31u8; 32],
        };
        let conflicting_child = RecoveredCanonicalHeaderEntry {
            height: 5,
            view: 2,
            canonical_block_commitment_hash: [0x62u8; 32],
            parent_block_commitment_hash: [0x99u8; 32],
            transactions_root_hash: [0x42u8; 32],
            resulting_state_root_hash: [0x32u8; 32],
            previous_canonical_collapse_commitment_hash: [0x32u8; 32],
        };

        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_consensus_header(
            &mut engine,
            &previous_header,
        ));
        assert!(!<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_recovered_consensus_header(
            &mut engine,
            &conflicting_child,
        ));
        assert!(!engine.recovered_headers.contains_key(&5));
    }

    #[test]
    fn asymptote_reset_promotes_committed_header_for_committed_height() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        let previous_collapse = test_canonical_collapse_object(4, None, [44u8; 32], [45u8; 32]);
        engine
            .committed_collapses
            .insert(previous_collapse.height, previous_collapse.clone());
        let mut committed_header = build_progress_parent_header(5, 0);
        link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
        let committed_collapse = derive_canonical_collapse_object_with_previous(
            &committed_header,
            &[],
            Some(&previous_collapse),
        )
        .unwrap();
        let committed_hash = to_root_hash(&committed_header.hash().unwrap()).unwrap();
        engine
            .committed_headers
            .insert(committed_header.height, committed_header);
        engine
            .committed_collapses
            .insert(committed_collapse.height, committed_collapse);

        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

        assert_eq!(engine.highest_qc.height, 5);
        assert_eq!(engine.highest_qc.block_hash, committed_hash);
        assert_eq!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::take_pending_quorum_certificates(
                &mut engine,
            )
            .len(),
            1
        );
    }

    #[test]
    fn asymptote_observe_committed_block_ignores_mismatched_collapse_object() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        let previous_collapse = test_canonical_collapse_object(4, None, [46u8; 32], [47u8; 32]);
        engine
            .committed_collapses
            .insert(previous_collapse.height, previous_collapse.clone());
        let mut committed_header = build_progress_parent_header(5, 0);
        link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
        let mut collapse = derive_canonical_collapse_object_with_previous(
            &committed_header,
            &[],
            Some(&previous_collapse),
        )
        .unwrap();
        collapse.resulting_state_root_hash[0] ^= 0xFF;

        let accepted =
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
                &mut engine,
                &committed_header,
                Some(&collapse),
            );

        assert!(!accepted);
        assert!(!engine
            .committed_headers
            .contains_key(&committed_header.height));

        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

        assert!(engine.highest_qc.height < 5);
    }

    #[test]
    fn asymptote_observe_committed_block_with_matching_collapse_enables_reset_promotion() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        let previous_collapse = test_canonical_collapse_object(4, None, [48u8; 32], [49u8; 32]);
        engine
            .committed_collapses
            .insert(previous_collapse.height, previous_collapse.clone());
        let mut committed_header = build_progress_parent_header(5, 0);
        link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
        let committed_hash = to_root_hash(&committed_header.hash().unwrap()).unwrap();
        let collapse = derive_canonical_collapse_object_with_previous(
            &committed_header,
            &[],
            Some(&previous_collapse),
        )
        .unwrap();

        let accepted =
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
                &mut engine,
                &committed_header,
                Some(&collapse),
            );

        assert!(accepted);
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

        assert_eq!(engine.highest_qc.height, 5);
        assert_eq!(engine.highest_qc.block_hash, committed_hash);
    }

    #[test]
    fn asymptote_observe_committed_block_with_matching_succinct_collapse_enables_reset_promotion() {
        let _guard = continuity_env_lock().lock().expect("continuity env lock");
        let previous_env = std::env::var("IOI_AFT_CONTINUITY_PROOF_SYSTEM").ok();
        std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", "succinct-sp1-v1");

        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        let previous_collapse = test_canonical_collapse_object(4, None, [0x31u8; 32], [0x32u8; 32]);
        engine
            .committed_collapses
            .insert(previous_collapse.height, previous_collapse.clone());
        let mut committed_header = build_progress_parent_header(5, 0);
        link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
        let committed_hash = to_root_hash(&committed_header.hash().unwrap()).unwrap();
        let committed_collapse = derive_canonical_collapse_object_with_previous(
            &committed_header,
            &[],
            Some(&previous_collapse),
        )
        .unwrap();

        let accepted =
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
                &mut engine,
                &committed_header,
                Some(&committed_collapse),
            );

        assert!(accepted);
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::reset(&mut engine, 5);

        assert_eq!(engine.highest_qc.height, 5);
        assert_eq!(engine.highest_qc.block_hash, committed_hash);

        if let Some(value) = previous_env {
            std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", value);
        } else {
            std::env::remove_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM");
        }
    }

    #[test]
    fn asymptote_observe_committed_block_rejects_corrupted_local_succinct_predecessor_chain() {
        let _guard = continuity_env_lock().lock().expect("continuity env lock");
        let previous_env = std::env::var("IOI_AFT_CONTINUITY_PROOF_SYSTEM").ok();
        std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", "succinct-sp1-v1");

        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        let previous_collapse = test_canonical_collapse_object(4, None, [0x41u8; 32], [0x42u8; 32]);
        let mut stored_previous = previous_collapse.clone();
        stored_previous.continuity_recursive_proof.proof_bytes[0] ^= 0xFF;
        engine
            .committed_collapses
            .insert(stored_previous.height, stored_previous);
        let mut committed_header = build_progress_parent_header(5, 0);
        link_header_to_previous_collapse(&mut committed_header, &previous_collapse);
        let committed_collapse = derive_canonical_collapse_object_with_previous(
            &committed_header,
            &[],
            Some(&previous_collapse),
        )
        .unwrap();

        let accepted =
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::observe_committed_block(
                &mut engine,
                &committed_header,
                Some(&committed_collapse),
            );

        assert!(!accepted);

        if let Some(value) = previous_env {
            std::env::set_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM", value);
        } else {
            std::env::remove_var("IOI_AFT_CONTINUITY_PROOF_SYSTEM");
        }
    }

    #[tokio::test]
    async fn asymptote_handle_quorum_certificate_does_not_advance_without_local_header() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        engine.remember_validator_count(1, 3);
        let qc = QuorumCertificate {
            height: 1,
            view: 0,
            block_hash: [44u8; 32],
            signatures: vec![
                (AccountId([1u8; 32]), vec![1u8]),
                (AccountId([2u8; 32]), vec![2u8]),
            ],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };

        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
            &mut engine,
            qc,
        )
        .await
        .unwrap();

        assert_eq!(engine.highest_qc.height, 0);
        assert!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::take_pending_quorum_certificates(
                &mut engine,
            )
            .is_empty()
        );
        assert!(engine.safety.next_ready_commit().is_none());
    }

    #[tokio::test]
    async fn asymptote_handle_quorum_certificate_advances_with_local_header() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        engine.remember_validator_count(1, 3);
        let header = build_progress_parent_header(1, 0);
        let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
        engine
            .seen_headers
            .entry((header.height, header.view))
            .or_default()
            .insert(block_hash, header);
        let qc = QuorumCertificate {
            height: 1,
            view: 0,
            block_hash,
            signatures: vec![
                (AccountId([1u8; 32]), vec![1u8]),
                (AccountId([2u8; 32]), vec![2u8]),
            ],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };

        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
            &mut engine,
            qc.clone(),
        )
        .await
        .unwrap();

        assert_eq!(engine.highest_qc.height, qc.height);
        assert_eq!(engine.highest_qc.block_hash, qc.block_hash);
        assert!(engine.safety.next_ready_commit().is_none());
    }

    #[tokio::test]
    async fn asymptote_handle_quorum_certificate_does_not_advance_without_previous_anchor() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        engine.remember_validator_count(2, 3);

        let previous_collapse = test_canonical_collapse_object(1, None, [60u8; 32], [61u8; 32]);
        let mut header = build_progress_parent_header(2, 0);
        link_header_to_previous_collapse(&mut header, &previous_collapse);
        let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
        engine
            .seen_headers
            .entry((header.height, header.view))
            .or_default()
            .insert(block_hash, header);

        let qc = QuorumCertificate {
            height: 2,
            view: 0,
            block_hash,
            signatures: vec![
                (AccountId([1u8; 32]), vec![1u8]),
                (AccountId([2u8; 32]), vec![2u8]),
            ],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };

        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
            &mut engine,
            qc,
        )
        .await
        .unwrap();

        assert_eq!(engine.highest_qc.height, 0);
    }

    #[tokio::test]
    async fn asymptote_handle_quorum_certificate_does_not_advance_without_carried_previous_collapse_certificate(
    ) {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        engine.remember_validator_count(2, 3);

        let previous_collapse = test_canonical_collapse_object(1, None, [70u8; 32], [71u8; 32]);
        engine
            .committed_collapses
            .insert(previous_collapse.height, previous_collapse.clone());

        let mut header = build_progress_parent_header(2, 0);
        link_header_to_previous_collapse(&mut header, &previous_collapse);
        header.canonical_collapse_extension_certificate = None;
        let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
        engine
            .seen_headers
            .entry((header.height, header.view))
            .or_default()
            .insert(block_hash, header);

        let qc = QuorumCertificate {
            height: 2,
            view: 0,
            block_hash,
            signatures: vec![
                (AccountId([1u8; 32]), vec![1u8]),
                (AccountId([2u8; 32]), vec![2u8]),
            ],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };

        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
            &mut engine,
            qc,
        )
        .await
        .unwrap();

        assert!(engine.highest_qc.height < 2);
    }

    #[tokio::test]
    async fn asymptote_handle_quorum_certificate_does_not_advance_with_mismatched_local_previous_collapse(
    ) {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        engine.remember_validator_count(3, 3);

        let grandparent_collapse = test_canonical_collapse_object(1, None, [72u8; 32], [73u8; 32]);
        let previous_collapse =
            test_canonical_collapse_object(2, Some(&grandparent_collapse), [74u8; 32], [75u8; 32]);
        engine
            .committed_collapses
            .insert(grandparent_collapse.height, grandparent_collapse.clone());
        engine
            .committed_collapses
            .insert(previous_collapse.height, previous_collapse.clone());

        let mut header = build_progress_parent_header(3, 0);
        link_header_to_previous_collapse(&mut header, &previous_collapse);
        let mut wrong_certificate =
            extension_certificate_from_predecessor(&previous_collapse, header.height);
        wrong_certificate.predecessor_recursive_proof_hash[0] ^= 0xFF;
        header.previous_canonical_collapse_commitment_hash =
            canonical_collapse_commitment_hash_from_object(&previous_collapse).unwrap();
        header.canonical_collapse_extension_certificate = Some(wrong_certificate);
        let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
        engine
            .seen_headers
            .entry((header.height, header.view))
            .or_default()
            .insert(block_hash, header);

        let qc = QuorumCertificate {
            height: 3,
            view: 0,
            block_hash,
            signatures: vec![
                (AccountId([1u8; 32]), vec![1u8]),
                (AccountId([2u8; 32]), vec![2u8]),
            ],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };

        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
            &mut engine,
            qc,
        )
        .await
        .unwrap();

        assert!(engine.highest_qc.height < 3);
    }

    #[tokio::test]
    async fn asymptote_handle_quorum_certificate_advances_with_recursive_proof_backed_predecessor()
    {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        engine.remember_validator_count(3, 3);

        let grandparent_collapse = test_canonical_collapse_object(1, None, [76u8; 32], [77u8; 32]);
        let previous_collapse =
            test_canonical_collapse_object(2, Some(&grandparent_collapse), [78u8; 32], [79u8; 32]);
        engine
            .committed_collapses
            .insert(grandparent_collapse.height, grandparent_collapse.clone());
        engine
            .committed_collapses
            .insert(previous_collapse.height, previous_collapse.clone());

        let mut header = build_progress_parent_header(3, 0);
        link_header_to_collapse_chain(
            &mut header,
            &[previous_collapse.clone(), grandparent_collapse.clone()],
        );
        let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
        engine
            .seen_headers
            .entry((header.height, header.view))
            .or_default()
            .insert(block_hash, header);

        let qc = QuorumCertificate {
            height: 3,
            view: 0,
            block_hash,
            signatures: vec![
                (AccountId([1u8; 32]), vec![1u8]),
                (AccountId([2u8; 32]), vec![2u8]),
            ],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };

        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
            &mut engine,
            qc.clone(),
        )
        .await
        .unwrap();

        assert_eq!(engine.highest_qc.height, qc.height);
        assert_eq!(engine.highest_qc.block_hash, qc.block_hash);
    }

    #[tokio::test]
    async fn asymptote_handle_quorum_certificate_advances_with_valid_succinct_predecessor_proof() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        engine.remember_validator_count(3, 3);

        let grandparent_collapse = test_canonical_collapse_object(1, None, [80u8; 32], [81u8; 32]);
        let mut previous_collapse =
            test_canonical_collapse_object(2, Some(&grandparent_collapse), [82u8; 32], [83u8; 32]);
        bind_succinct_mock_continuity(&mut previous_collapse);
        engine
            .committed_collapses
            .insert(grandparent_collapse.height, grandparent_collapse.clone());
        engine
            .committed_collapses
            .insert(previous_collapse.height, previous_collapse.clone());

        let mut header = build_progress_parent_header(3, 0);
        link_header_to_previous_collapse(&mut header, &previous_collapse);
        let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
        engine
            .seen_headers
            .entry((header.height, header.view))
            .or_default()
            .insert(block_hash, header);

        let qc = QuorumCertificate {
            height: 3,
            view: 0,
            block_hash,
            signatures: vec![
                (AccountId([1u8; 32]), vec![1u8]),
                (AccountId([2u8; 32]), vec![2u8]),
            ],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };

        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
            &mut engine,
            qc.clone(),
        )
        .await
        .unwrap();

        assert_eq!(engine.highest_qc.height, qc.height);
        assert_eq!(engine.highest_qc.block_hash, qc.block_hash);
    }

    #[tokio::test]
    async fn asymptote_handle_quorum_certificate_rejects_invalid_succinct_predecessor_proof() {
        let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
        engine.remember_validator_count(3, 3);

        let grandparent_collapse = test_canonical_collapse_object(1, None, [84u8; 32], [85u8; 32]);
        let mut previous_collapse =
            test_canonical_collapse_object(2, Some(&grandparent_collapse), [86u8; 32], [87u8; 32]);
        bind_succinct_mock_continuity(&mut previous_collapse);
        previous_collapse
            .continuity_recursive_proof
            .proof_bytes
            .reverse();
        engine
            .committed_collapses
            .insert(grandparent_collapse.height, grandparent_collapse.clone());
        engine
            .committed_collapses
            .insert(previous_collapse.height, previous_collapse.clone());

        let mut header = build_progress_parent_header(3, 0);
        header.previous_canonical_collapse_commitment_hash =
            canonical_collapse_commitment_hash_from_object(&previous_collapse).unwrap();
        header.canonical_collapse_extension_certificate =
            Some(CanonicalCollapseExtensionCertificate {
                predecessor_commitment: canonical_collapse_commitment(&previous_collapse),
                predecessor_recursive_proof_hash: canonical_collapse_recursive_proof_hash(
                    &previous_collapse.continuity_recursive_proof,
                )
                .unwrap(),
            });
        header.parent_state_root = StateRoot(previous_collapse.resulting_state_root_hash.to_vec());
        let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
        engine
            .seen_headers
            .entry((header.height, header.view))
            .or_default()
            .insert(block_hash, header);

        let qc = QuorumCertificate {
            height: 3,
            view: 0,
            block_hash,
            signatures: vec![
                (AccountId([1u8; 32]), vec![1u8]),
                (AccountId([2u8; 32]), vec![2u8]),
            ],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };

        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
            &mut engine,
            qc,
        )
        .await
        .unwrap();

        assert!(engine.highest_qc.height < 3);
    }
}
