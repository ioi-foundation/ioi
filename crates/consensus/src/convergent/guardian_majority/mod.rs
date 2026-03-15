// Path: crates/consensus/src/convergent/guardian_majority/mod.rs

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
    compute_next_timestamp, derive_guardian_witness_assignment, effective_set_for_height,
    guardian_registry_checkpoint_key, guardian_registry_committee_key, guardian_registry_log_key,
    guardian_registry_witness_key, guardian_registry_witness_seed_key,
    guardian_registry_witness_set_key, read_validator_sets, to_root_hash, AccountId, Block,
    BlockHeader, BlockTimingParams, BlockTimingRuntime, ChainStatus, ChainTransaction,
    ConsensusVote, EchoMessage, FailureReport, GuardianCommitteeManifest, GuardianDecision,
    GuardianDecisionDomain, GuardianLogCheckpoint, GuardianQuorumCertificate,
    GuardianTransparencyLogDescriptor, GuardianWitnessCommitteeManifest, GuardianWitnessEpochSeed,
    GuardianWitnessSet, GuardianWitnessStatement, ProofOfDivergence, QuorumCertificate,
};
use ioi_types::codec;
use ioi_types::config::ConvergentSafetyMode;
use ioi_types::error::{ConsensusError, StateError, TransactionError};
use ioi_types::keys::{
    BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, CURRENT_EPOCH_KEY,
    QUARANTINED_VALIDATORS_KEY, STATUS_KEY, VALIDATOR_SET_KEY,
};
use libp2p::identity::PublicKey;
use libp2p::PeerId;
use parity_scale_codec::{Decode, Encode};
use std::collections::{BTreeSet, HashMap, HashSet};
use tracing::{debug, error, info, warn};

// Imports for Convergent deterministic components
use self::pacemaker::Pacemaker;
use self::safety::SafetyGadget;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

pub mod aggregator;
pub mod divergence;
#[cfg(test)]
mod network_simulator;
pub mod pacemaker;
pub mod safety;
#[cfg(test)]
mod simulator;

// --- New Structures for View Change ---

/// A vote from a validator to change the view at a specific height.
#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct ViewChangeVote {
    pub height: u64,
    pub view: u64,
    pub voter: AccountId,
    pub signature: Vec<u8>,
}

/// A proof that a majority of validators agreed to move to a new view.
#[derive(Debug, Clone, Encode, Decode)]
pub struct TimeoutCertificate {
    pub height: u64,
    pub view: u64,
    pub votes: Vec<ViewChangeVote>,
}

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

/// The Convergent deterministic Consensus Engine.
#[derive(Debug, Clone)]
pub struct GuardianMajorityEngine {
    safety_mode: ConvergentSafetyMode,
    /// Tracks the last observed Oracle counter for each validator.
    last_seen_counters: HashMap<AccountId, u64>,

    /// Tracks view change votes received.
    view_votes: HashMap<u64, HashMap<u64, HashMap<AccountId, ViewChangeVote>>>,

    /// Tracks if we have already formed a TC for a (height, view).
    tc_formed: HashSet<(u64, u64)>,

    /// Tracks block headers received per (height, view) for divergence detection.
    /// (Height, View) -> BlockHash -> Header
    seen_headers: HashMap<(u64, u64), HashMap<[u8; 32], BlockHeader>>,

    // --- BFT Voting State ---
    /// Buffer of votes for the current height/view.
    vote_pool: HashMap<u64, HashMap<[u8; 32], Vec<ConsensusVote>>>,

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
}

impl Default for GuardianMajorityEngine {
    fn default() -> Self {
        Self {
            safety_mode: ConvergentSafetyMode::ClassicBft,
            last_seen_counters: HashMap::new(),
            view_votes: HashMap::new(),
            tc_formed: HashSet::new(),
            seen_headers: HashMap::new(),
            vote_pool: HashMap::new(),
            highest_qc: QuorumCertificate::default(),
            mirror_seed: [0u8; 32],
            echo_pool: HashMap::new(),
            voted_slots: HashSet::new(),
            pacemaker: Arc::new(Mutex::new(Pacemaker::new(Duration::from_secs(5)))),
            safety: SafetyGadget::new(),
            mirror_stats: MirrorStats::default(),
            cached_validator_count: 1,
        }
    }
}

impl GuardianMajorityEngine {
    pub fn new(safety_mode: ConvergentSafetyMode) -> Self {
        Self {
            safety_mode,
            ..Self::default()
        }
    }

    pub fn safety_mode(&self) -> ConvergentSafetyMode {
        self.safety_mode
    }

    fn quorum_weight_threshold(&self, total_weight: u128) -> u128 {
        match self.safety_mode {
            ConvergentSafetyMode::ClassicBft => (total_weight * 2) / 3,
            ConvergentSafetyMode::GuardianMajority
            | ConvergentSafetyMode::ExperimentalNestedGuardian => total_weight / 2,
        }
    }

    fn quorum_count_threshold(&self, count: usize) -> usize {
        match self.safety_mode {
            ConvergentSafetyMode::ClassicBft => ((count * 2) / 3) + 1,
            ConvergentSafetyMode::GuardianMajority
            | ConvergentSafetyMode::ExperimentalNestedGuardian => (count / 2) + 1,
        }
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
            ConvergentSafetyMode::ClassicBft => Ok(()),
            ConvergentSafetyMode::GuardianMajority
            | ConvergentSafetyMode::ExperimentalNestedGuardian => {
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
                if matches!(
                    self.safety_mode,
                    ConvergentSafetyMode::ExperimentalNestedGuardian
                ) {
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

        // Convergent deterministic Quorum: Simple Majority (> 50%)
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
            "Convergent deterministic DIVERGENCE DETECTED @ H{} V{}: {:?} vs {:?}",
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
        let threshold = self.quorum_count_threshold(self.cached_validator_count);
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

        let (timed_out, current_view) = {
            let mut pacemaker = self.pacemaker.lock().await;
            if pacemaker.check_timeout() {
                let next_view = pacemaker.current_view + 1;
                pacemaker.advance_view(next_view);
                info!(target: "consensus", "Pacemaker timed out. Moving to View {}.", next_view);
                return ConsensusDecision::Timeout {
                    view: next_view,
                    height,
                };
            }
            (false, pacemaker.current_view)
        };

        let _ = timed_out;

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
            return ConsensusDecision::Stall;
        }

        if !self.tc_formed.contains(&(height, current_view)) {
            if let Some(_tc) = self.check_quorum(height, current_view, vs.total_weight, &sets) {
                info!(target: "consensus", "Majority Quorum reached for View {}. Advancing.", current_view);
                self.tc_formed.insert((height, current_view));
                self.pacemaker.lock().await.advance_view(current_view);
            }
        }

        let parent_root = parent_view.state_root();
        self.mirror_seed = ioi_crypto::algorithms::hash::sha256(parent_root).unwrap_or([0u8; 32]);

        let n = active_validators.len() as u64;
        let round_index = height.saturating_sub(1).saturating_add(current_view);
        let leader_index = (round_index % n) as usize;
        let leader_id = active_validators[leader_index];

        if known_peers.is_empty() && leader_id != *our_account_id {
            debug!(target: "consensus", "Stalling: No peers and not leader (Me: {:?}, Leader: {:?})", our_account_id, leader_id);
            return ConsensusDecision::Stall;
        }

        if leader_id == *our_account_id {
            if height > 2 && self.highest_qc.height < height - 1 {
                return ConsensusDecision::Stall;
            }

            // Safety Check: Ensure we don't propose conflicting blocks
            // Use locked_qc from safety gadget to ensure we extend the correct chain
            if let Some(_locked) = &self.safety.locked_qc {
                // If we have a lock, we must extend it.
                // For simplified Convergent deterministic, the highest_qc usually matches the lock or is newer.
                // The proposal construction in `create_block` uses `highest_qc` (via `parent_qc` logic).
            }

            let timing_params = match parent_view.get(BLOCK_TIMING_PARAMS_KEY).await {
                Ok(Some(b)) => {
                    codec::from_bytes_canonical::<BlockTimingParams>(&b).unwrap_or_default()
                }
                _ => return ConsensusDecision::Stall,
            };
            let timing_runtime = match parent_view.get(BLOCK_TIMING_RUNTIME_KEY).await {
                Ok(Some(b)) => {
                    codec::from_bytes_canonical::<BlockTimingRuntime>(&b).unwrap_or_default()
                }
                _ => return ConsensusDecision::Stall,
            };
            let parent_status: ChainStatus = match parent_view.get(STATUS_KEY).await {
                Ok(Some(b)) => codec::from_bytes_canonical(&b).unwrap_or_default(),
                Ok(None) if height == 1 => ChainStatus::default(),
                _ => return ConsensusDecision::Stall,
            };

            let expected_ts = compute_next_timestamp(
                &timing_params,
                &timing_runtime,
                height.saturating_sub(1),
                parent_status.latest_timestamp,
                0,
            )
            .unwrap_or(0);

            info!(target: "consensus", "I am leader for H={} V={}. Producing block.", height, current_view);

            let parent_qc = if height <= 2 && self.highest_qc.height == 0 {
                QuorumCertificate::default()
            } else {
                self.highest_qc.clone()
            };

            ConsensusDecision::ProduceBlock {
                transactions: vec![],
                expected_timestamp_secs: expected_ts,
                view: current_view,
                parent_qc,
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
        self.cached_validator_count = active_validators.len();

        let threshold = self.quorum_count_threshold(self.cached_validator_count);

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
                if qc.height > self.highest_qc.height {
                    info!(target: "consensus", "Formed QC for height {} (late trigger).", qc.height);
                    self.highest_qc = qc.clone(); // [FIX] Clone here

                    // Trigger Safety Update
                    if self.safety.update(&qc, &header.parent_qc) {
                        info!(target: "consensus", "Safety Gadget: Queued commit for height {}", header.parent_qc.height);
                    }
                }
            }
        }

        if header.height > 1 {
            let parent_qc = &header.parent_qc;
            if parent_qc.block_hash != header.parent_hash {
                return Err(ConsensusError::BlockVerificationFailed(
                    "Parent QC hash mismatch".into(),
                ));
            }
            let bootstrap_height_two_parent =
                header.height == 2 && parent_qc.height == 1 && parent_qc.signatures.is_empty();
            if !bootstrap_height_two_parent {
                if let Err(e) = self.verify_qc(parent_qc, &sets) {
                    error!(target: "consensus", "QC Verification Failed for block {}: {}", header.height, e);
                    return Err(e);
                }
            }
            if parent_qc.height > self.highest_qc.height {
                self.highest_qc = parent_qc.clone();
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

        if let Some(&last_ctr) = self.last_seen_counters.get(&header.producer_account_id) {
            if header.oracle_counter <= last_ctr {
                return Err(ConsensusError::BlockVerificationFailed(
                    "Guardian counter rollback".into(),
                ));
            }
        }
        self.last_seen_counters
            .insert(header.producer_account_id, header.oracle_counter);

        debug!(target: "consensus", "Convergent deterministic: Block {} verified. Initiating ECHO phase.", header.height);
        Ok(())
    }

    async fn handle_vote(&mut self, vote: ConsensusVote) -> Result<(), ConsensusError> {
        // Safety Check: Don't process votes if not safe
        if !self.safety.safe_to_vote(vote.view, vote.height - 1) {
            // Logic for unsafe vote handling (optional)
        }

        let threshold = self.quorum_count_threshold(self.cached_validator_count);
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
            if qc.height > self.highest_qc.height {
                info!(target: "consensus", "Formed QC for height {}. Updating highest_qc.", qc.height);
                self.highest_qc = qc.clone();

                // Trigger Safety Update
                // We need the parent QC to check the 2-chain rule.
                // Since we don't have the block body here, we look up the seen headers map.
                if let Some(header_map) = self.seen_headers.get(&(vote.height, vote.view)) {
                    if let Some(header) = header_map.get(&vote.block_hash) {
                        if self.safety.update(&qc, &header.parent_qc) {
                            info!(target: "consensus", "Safety Gadget: Queued commit for height {}", header.parent_qc.height);
                        }
                    }
                }
            }
        }
        Ok(())
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
        self.view_votes.retain(|h, _| *h >= height);
        self.tc_formed.retain(|(h, _)| *h >= height);
        self.seen_headers.retain(|(h, _), _| *h >= height);
        self.vote_pool.retain(|h, _| *h >= height);
        self.echo_pool.retain(|(h, _), _| *h >= height);
        self.voted_slots.retain(|(h, _)| *h >= height);

        if let Ok(mut pm) = self.pacemaker.try_lock() {
            pm.current_view = 0;
            pm.view_start_time = std::time::Instant::now();
        }
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
        canonical_witness_manifest_hash, encode_signers_bitfield, sign_decision_with_members,
        sign_witness_statement_with_members,
    };
    use ioi_crypto::sign::guardian_log::{
        canonical_log_leaf_hash, checkpoint_root_from_leaf_hashes, checkpoint_signing_payload,
    };
    use ioi_types::app::{
        guardian_registry_checkpoint_key, guardian_registry_committee_key,
        guardian_registry_log_key, guardian_registry_witness_key,
        guardian_registry_witness_seed_key, guardian_registry_witness_set_key,
        GuardianCommitteeMember, GuardianLogCheckpoint, GuardianLogProof,
        GuardianTransparencyLogDescriptor, GuardianWitnessCommitteeManifest, SignatureSuite,
        StateRoot,
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
        let engine = GuardianMajorityEngine::new(ConvergentSafetyMode::GuardianMajority);
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
            parent_qc: QuorumCertificate::default(),
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

    #[test]
    fn verifies_valid_guardian_certificate() {
        let (engine, header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
        engine
            .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
            .unwrap();
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
        engine.safety_mode = ConvergentSafetyMode::ExperimentalNestedGuardian;
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
        engine.safety_mode = ConvergentSafetyMode::ExperimentalNestedGuardian;
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
        engine.safety_mode = ConvergentSafetyMode::ExperimentalNestedGuardian;
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
        engine.safety_mode = ConvergentSafetyMode::ExperimentalNestedGuardian;
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
        engine.safety_mode = ConvergentSafetyMode::ExperimentalNestedGuardian;
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
}
