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
mod collapse_verification;
mod engine;
mod qc_state;
mod recovery_cache;
mod runtime;
#[cfg(test)]
mod tests;

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
