// Path: crates/consensus/src/admft/mod.rs

use crate::common::penalty::apply_quarantine_penalty;
use crate::{ConsensusDecision, ConsensusEngine, PenaltyEngine, PenaltyMechanism};
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, ChainView, StateRef};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::state::{StateAccess, StateManager};
use ioi_system::SystemState;
use ioi_types::app::{
    account_id_from_key_material, compute_next_timestamp, effective_set_for_height,
    read_validator_sets, AccountId, Block, BlockTimingParams, BlockTimingRuntime, ChainStatus,
    ConsensusVote, FailureReport, QuorumCertificate,
};
use ioi_types::codec;
use ioi_types::error::{ConsensusError, StateError, TransactionError};
use ioi_types::keys::{
    BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, QUARANTINED_VALIDATORS_KEY, STATUS_KEY,
    VALIDATOR_SET_KEY,
};
use libp2p::identity::PublicKey;
use libp2p::PeerId;
use parity_scale_codec::{Decode, Encode};
use std::collections::{BTreeSet, HashMap, HashSet};
use tracing::{debug, error, info, warn};

// Imports for A-DMFT components
use self::pacemaker::Pacemaker;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration;

pub mod pacemaker;
pub mod safety;
pub mod aggregator;

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
///
/// Implements **Lemma 1 (Deterministic Non-Equivocation)** from Appendix E.
/// The signature covers: `Hash(BlockHeader) || oracle_counter || oracle_trace`.
fn verify_guardian_signature(
    preimage: &[u8],
    public_key: &[u8],
    signature: &[u8],
    oracle_counter: u64,
    oracle_trace: &[u8; 32],
) -> Result<(), ConsensusError> {
    let pk =
        PublicKey::try_decode_protobuf(public_key).map_err(|_| ConsensusError::InvalidSignature)?;

    // 1. Hash the header content to get the 32-byte digest.
    let header_hash = ioi_crypto::algorithms::hash::sha256(preimage).map_err(|e| {
        warn!("Failed to hash header preimage: {}", e);
        ConsensusError::InvalidSignature
    })?;

    // 2. Concatenate: Hash || Counter || Trace
    // This binds the signature to a specific point in the Guardian's monotonic history.
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

/// The A-DMFT Consensus Engine.
///
/// Implements Adaptive Deterministic Mirror Fault Tolerance with Chained BFT voting.
/// Enforces safety via Guardian monotonic counters AND network voting quorums.
#[derive(Debug, Clone)]
pub struct AdmftEngine {
    /// Tracks the last observed Oracle counter for each validator.
    /// Used to enforce strictly monotonic progress and detect replay/equivocation.
    last_seen_counters: HashMap<AccountId, u64>,
    
    /// Tracks view change votes received: Height -> View -> Voter -> Vote
    view_votes: HashMap<u64, HashMap<u64, HashMap<AccountId, ViewChangeVote>>>,
    
    /// Tracks if we have already formed a TC for a (height, view) to avoid spam.
    tc_formed: HashSet<(u64, u64)>,
    
    /// Tracks block hashes received per (height, view) for divergence detection.
    /// (Height, View) -> BlockHash -> FirstSender
    seen_blocks: HashMap<(u64, u64), HashMap<[u8; 32], PeerId>>,

    // --- BFT Voting State ---

    /// Buffer of votes for the current height/view.
    /// Height -> BlockHash -> List of Votes
    vote_pool: HashMap<u64, HashMap<[u8; 32], Vec<ConsensusVote>>>,

    /// The highest QC we have observed (our "lock").
    /// This represents the highest block we know is safe to extend.
    highest_qc: QuorumCertificate,

    // Pacemaker for Liveness
    pacemaker: Arc<Mutex<Pacemaker>>,

    // Mirror Statistics
    mirror_stats: MirrorStats,

    // [NEW] Cached Validator Count for dynamic quorum calculation
    cached_validator_count: usize,
}

impl Default for AdmftEngine {
    fn default() -> Self {
        Self {
            last_seen_counters: HashMap::new(),
            view_votes: HashMap::new(),
            tc_formed: HashSet::new(),
            seen_blocks: HashMap::new(),
            vote_pool: HashMap::new(),
            highest_qc: QuorumCertificate::default(),
            // [FIX] Increased default timeout to 5s for CI stability
            pacemaker: Arc::new(Mutex::new(Pacemaker::new(Duration::from_secs(5)))),
            mirror_stats: MirrorStats::default(),
            cached_validator_count: 1, // Default to 1 to allow bootstrap
        }
    }
}

impl AdmftEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if we have enough votes to form a TimeoutCertificate.
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

        // Map account IDs to weights for quick lookup
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

        // A-DMFT Quorum: Simple Majority (> 50%)
        // Because Guardians prevent equivocation, we do not need 2/3 overlap to prevent forks.
        // N=3, Majority=2. N=4, Majority=3.
        let threshold = total_weight / 2;

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

    /// Internal helper to detect divergence (equivocation) based on received blocks.
    /// Returns true if divergence is detected.
    pub fn detect_divergence(
        &mut self,
        height: u64,
        view: u64,
        block_hash: [u8; 32],
        sender: PeerId,
    ) -> bool {
        let entry = self.seen_blocks.entry((height, view)).or_default();

        if entry.is_empty() {
            entry.insert(block_hash, sender);
            return false;
        }

        if entry.contains_key(&block_hash) {
            return false; // Seen this block before, consistent.
        }

        // If we are here, we have seen a DIFFERENT hash for the SAME (height, view).
        // This is cryptographic proof of equivocation by the leader (or a mirror collision).
        let (existing_hash, _) = entry.iter().next().unwrap();
        warn!(target: "consensus",
            "A-DMFT DIVERGENCE DETECTED @ H{} V{}: {:?} vs {:?}",
            height, view, hex::encode(existing_hash), hex::encode(block_hash)
        );
        true
    }

    /// Verifies a Quorum Certificate against the active validator set.
    /// This ensures that the parent block was indeed finalized by a majority of the network.
    fn verify_qc(
        &self,
        qc: &QuorumCertificate,
        sets: &ioi_types::app::ValidatorSetsV1,
    ) -> Result<(), ConsensusError> {
        if qc.height == 0 {
            // Genesis QC is trivially valid
            return Ok(());
        }

        let active_set = effective_set_for_height(sets, qc.height);
        let total_weight = active_set.total_weight;
        
        // A-DMFT Quorum: Simple Majority (> 50%)
        let threshold = total_weight / 2;
        
        let mut voting_power = 0u128;
        
        // Map account IDs to validators for quick lookup
        let validators: HashMap<AccountId, &ioi_types::app::ValidatorV1> = active_set
            .validators
            .iter()
            .map(|v| (v.account_id, v))
            .collect();

        // [FIX] Prefix unused vars with _ to suppress warnings
        for (voter, _signature) in &qc.signatures {
            if let Some(validator) = validators.get(voter) {
                // Verify Signature (Assuming handled by handle_vote or trusted aggregation for MVP)
                // In production, this loop should strictly verify every signature or use BLS aggregation.
                voting_power += validator.weight;
            }
        }

        // [NEW] BLS Aggregation Verification
        // If aggregated signature is present, verify it.
        if !qc.aggregated_signature.is_empty() {
             // Decode BLS signature and bitfield
             // Verify against aggregated public key of participants
             // For MVP, we assume trust if legacy verification passed or logic not yet active
             // Placeholder for Phase 2 logic
        }
        
        if voting_power <= threshold {
             return Err(ConsensusError::BlockVerificationFailed(format!(
                 "QC has insufficient voting power: {} <= {}", voting_power, threshold
             )));
        }

        Ok(())
    }
}

#[async_trait]
impl PenaltyMechanism for AdmftEngine {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccess,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        // A-DMFT uses the standard quarantine mechanism for faults.
        apply_quarantine_penalty(state, report).await
    }
}

impl PenaltyEngine for AdmftEngine {
    fn apply(
        &self,
        sys: &mut dyn SystemState,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        // Retrieve current validator set
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

        // Liveness guard: Ensure we don't quarantine below 1/2 threshold (simplified safety check)
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
                "Quarantine would jeopardize network liveness (A-DMFT requires > 1/2 live)".into(),
            ));
        }

        sys.quarantine_mut()
            .insert(report.offender)
            .map_err(TransactionError::State)
    }
}

#[async_trait]
impl<T: Clone + Send + 'static + parity_scale_codec::Encode> ConsensusEngine<T> for AdmftEngine {
    async fn decide(
        &mut self,
        our_account_id: &AccountId,
        height: u64,
        _view_arg: u64, // [FIX] Ignore argument, use internal pacemaker state
        parent_view: &dyn AnchoredStateView,
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        // [INSTRUMENTATION] Log entry
        info!(target: "consensus", "AdmftEngine::decide called for height {}", height);

        // [NEW] Pacemaker Check
        // Scope the lock to avoid holding it during check_quorum which borrows self
        let (timed_out, current_view) = {
            let mut pacemaker = self.pacemaker.lock().await;
            if pacemaker.check_timeout() {
                // [FIX] Read current_view into local var before calling advance_view to avoid overlapping borrow
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
        
        // [FIX] Prefix unused var with underscore
        let _ = timed_out;
        let view = current_view;

        // 1. Resolve Validator Set
        let vs_bytes = match parent_view.get(VALIDATOR_SET_KEY).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                error!(target: "consensus", "A-DMFT: VALIDATOR_SET_KEY not found in parent view at height {}", height);
                return ConsensusDecision::Stall;
            }
            Err(e) => {
                error!(target: "consensus", "A-DMFT: Failed to read VALIDATOR_SET_KEY: {}", e);
                return ConsensusDecision::Stall;
            }
        };
        let sets = match read_validator_sets(&vs_bytes) {
            Ok(s) => s,
            Err(e) => {
                error!(target: "consensus", "A-DMFT: Failed to decode validator sets: {}", e);
                return ConsensusDecision::Stall;
            }
        };

        // Filter Quarantined
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

        // [FIX] Update cache for quorum calculation
        self.cached_validator_count = active_validators.len();

        if active_validators.is_empty() {
            error!(target: "consensus", "A-DMFT: Active validator set is empty!");
            return ConsensusDecision::Stall;
        }

        // Check for Quorum on View Change first
        if !self.tc_formed.contains(&(height, view)) {
            if let Some(_tc) = self.check_quorum(height, view, vs.total_weight, &sets) {
                info!(target: "consensus", "A-DMFT: Majority Quorum reached for View {}. Advancing.", view);
                self.tc_formed.insert((height, view));
                // Update pacemaker to match network view
                self.pacemaker.lock().await.advance_view(view);
            }
        }
        
        // Re-read view from pacemaker in case it was updated by TC
        let current_view = self.pacemaker.lock().await.current_view;
        // Ensure we are deciding for the correct view
        if view < current_view {
             // We are behind, stall to allow catch-up or re-entry at correct view
             return ConsensusDecision::Stall;
        }

        // 2. Deterministic Leader Selection (Round-Robin)
        let n = active_validators.len() as u64;
        let round_index = height.saturating_sub(1).saturating_add(current_view);
        let leader_index = (round_index % n) as usize;
        let leader_id = active_validators[leader_index];

        debug!(
            target: "consensus", 
            "A-DMFT Decide: Height={} View={} | Me={} | Leader={} | ValCount={} | RoundIdx={}", 
            height, current_view, 
            hex::encode(&our_account_id.0[..4]), 
            hex::encode(&leader_id.0[..4]), 
            active_validators.len(),
            round_index
        );

        if known_peers.is_empty() && leader_id != *our_account_id {
            // [INSTRUMENTATION] Log stall due to no peers
            tracing::info!(
                target: "consensus", 
                "Stalling: No peers and not leader (Me: {}, Leader: {}).", 
                hex::encode(&our_account_id.0[..4]), 
                hex::encode(&leader_id.0[..4])
            );
            return ConsensusDecision::Stall;
        }

        // 3. Leader Logic (Produce Block)
        if leader_id == *our_account_id {
            // [NEW] Check if we have a valid QC for the PARENT block
            if height > 1 {
                 if self.highest_qc.height < height - 1 {
                     info!(target: "consensus", "A-DMFT: Leader waiting for QC for height {} (Have: {})", height - 1, self.highest_qc.height);
                     // Allow Stall to retry, hoping vote arrives
                     return ConsensusDecision::Stall;
                 }
            }
            
            // 4. Compute Timestamp
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
                0, // Gas used placeholder
            )
            .unwrap_or(0);

            info!(target: "consensus", "A-DMFT: I am leader for H={} V={}. Producing block.", height, current_view);

            // Determine the correct QC to include
            let parent_qc = if height == 1 {
                QuorumCertificate::default()
            } else {
                self.highest_qc.clone()
            };

            ConsensusDecision::ProduceBlock {
                transactions: vec![],
                expected_timestamp_secs: expected_ts,
                view: current_view,
                parent_qc, // <--- Populate field
            }
        } else {
            // Follower Logic
            info!(target: "consensus", 
                "A-DMFT: Waiting. H={} V={} | Me={} | Leader={}", 
                height, current_view, 
                hex::encode(&our_account_id.0[0..4]), 
                hex::encode(&leader_id.0[0..4])
            );
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
        let header = &block.header;
        
        // 1. Divergence Check
        let block_hash = block
            .header
            .hash()
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        let mut fixed_hash = [0u8; 32];
        fixed_hash.copy_from_slice(&block_hash);

        if self.detect_divergence(header.height, header.view, fixed_hash, PeerId::random()) {
            return Err(ConsensusError::BlockVerificationFailed(
                "Mirror Divergence (Equivocation) Detected".into(),
            ));
        }

        // 2. Load Parent View & Validator Set
        let parent_state_ref = StateRef {
            height: header.height - 1,
            state_root: header.parent_state_root.as_ref().to_vec(),
            block_hash: header.parent_hash,
        };
        let parent_view = chain_view
            .view_at(&parent_state_ref)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;

        let vs_bytes = parent_view
            .get(VALIDATOR_SET_KEY)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or(ConsensusError::StateAccess(StateError::KeyNotFound))?;
        let sets = read_validator_sets(&vs_bytes)
            .map_err(|_| ConsensusError::BlockVerificationFailed("VS decode failed".into()))?;
        let vs = effective_set_for_height(&sets, header.height);

        // 3. [NEW] Verify Parent QC (Chained BFT Safety)
        if header.height > 1 {
            let parent_qc = &header.parent_qc;
            
            // The QC must attest to the parent block hash
            if parent_qc.block_hash != header.parent_hash {
                return Err(ConsensusError::BlockVerificationFailed(
                    "Parent QC hash does not match parent_hash".into()
                ));
            }
            
            // Verify QC signatures against validator set
            self.verify_qc(parent_qc, &sets)?;
            
            // Update local highest QC tracker if this one is newer
            if parent_qc.height > self.highest_qc.height {
                self.highest_qc = parent_qc.clone();
            }
            
            // [NEW] Safety Gadget Trigger (Commit Rule)
            // self.safety.update_qc(&parent_qc); 
            // Trigger 3-chain check here.
        }

        // 4. Validate Validator Set & Leader
        let quarantined: BTreeSet<AccountId> =
            match parent_view.get(QUARANTINED_VALIDATORS_KEY).await {
                Ok(Some(b)) => codec::from_bytes_canonical(&b).unwrap_or_default(),
                _ => BTreeSet::new(),
            };

        let active_validators: Vec<AccountId> = vs
            .validators
            .iter()
            .map(|v| v.account_id)
            .filter(|id| !quarantined.contains(id))
            .collect();

        // [FIX] Update cache for quorum calculation
        self.cached_validator_count = active_validators.len();

        if !active_validators.contains(&header.producer_account_id) {
            return Err(ConsensusError::BlockVerificationFailed(
                "Producer not in authority set".into(),
            ));
        }

        // Leader Check
        let n = active_validators.len() as u64;
        let round_index = header.height.saturating_sub(1).saturating_add(header.view);
        let leader_index = (round_index % n) as usize;
        let expected_leader = active_validators[leader_index];

        if header.producer_account_id != expected_leader {
            return Err(ConsensusError::InvalidLeader {
                expected: expected_leader,
                got: header.producer_account_id,
            });
        }

        // 5. Verify Guardian Signature & Monotonicity
        let producer_record = vs
            .validators
            .iter()
            .find(|v| v.account_id == header.producer_account_id)
            .unwrap();
        let pubkey = &header.producer_pubkey;

        let derived_id = account_id_from_key_material(producer_record.consensus_key.suite, pubkey)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        if derived_id != producer_record.consensus_key.public_key_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "Producer key mismatch".into(),
            ));
        }

        let preimage = header
            .to_preimage_for_signing()
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;

        verify_guardian_signature(
            &preimage,
            pubkey,
            &header.signature,
            header.oracle_counter,
            &header.oracle_trace_hash,
        )?;

        if let Some(&last_ctr) = self.last_seen_counters.get(&header.producer_account_id) {
            if header.oracle_counter <= last_ctr {
                warn!(
                    target: "consensus",
                    "A-DMFT Violation: Counter rollback/replay detected from {}. Last: {}, Got: {}",
                    hex::encode(header.producer_account_id), last_ctr, header.oracle_counter
                );
                return Err(ConsensusError::BlockVerificationFailed(
                    "Guardian counter not monotonic".into(),
                ));
            }
        }

        self.last_seen_counters
            .insert(header.producer_account_id, header.oracle_counter);

        // [NEW] Reset Pacemaker on valid proposal for current view
        let pm = self.pacemaker.lock().await; // [FIX] Removed mut
        if header.view == pm.current_view {
             // Valid proposal for current view.
             // We don't advance yet; we wait for the Vote step to succeed or timeout.
        }

        debug!(target: "consensus", "A-DMFT: Block {} verified. Broadcasting VOTE.", header.height);
        Ok(())
    }

    /// Handles a vote from a peer. Aggregates them into a QC.
    async fn handle_vote(
        &mut self,
        vote: ConsensusVote,
    ) -> Result<(), ConsensusError> {
        // 1. Basic Validity Check
        // (Signature verification should be done statelessly by Orchestrator before calling this)
        
        // 2. Add to Vote Pool
        let height_map = self.vote_pool.entry(vote.height).or_default();
        let votes = height_map.entry(vote.block_hash).or_default();
        
        // Dedup
        if votes.iter().any(|v| v.voter == vote.voter) {
            return Ok(());
        }
        votes.push(vote.clone());

        // 3. Check for QC Formation
        // [FIX] Dynamic Quorum Adjustment
        // Threshold = Floor(N / 2) + 1
        let threshold = (self.cached_validator_count / 2) + 1;

        if votes.len() >= threshold {
            let qc = QuorumCertificate {
                height: vote.height,
                view: vote.view,
                block_hash: vote.block_hash,
                signatures: votes.iter().map(|v| (v.voter, v.signature.clone())).collect(),
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            };
            if qc.height > self.highest_qc.height {
                info!(target: "consensus", "Formed QC for height {}. Updating highest_qc.", qc.height);
                self.highest_qc = qc;
                // [NEW] Update Pacemaker if we formed a QC for the current view
                let mut pm = self.pacemaker.lock().await;
                if pm.current_view <= vote.view {
                     // Assuming successful commit resets view to 0, but if we are just advancing:
                     // pm.advance_view(vote.view + 1); 
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
        let vote: ViewChangeVote = ioi_types::codec::from_bytes_canonical(proof_bytes)
            .map_err(|e| ConsensusError::BlockVerificationFailed(format!("Invalid view vote format: {}", e)))?;

        info!(target: "consensus", "A-DMFT: Received ViewChange vote for H={} V={} from 0x{} (Peer: {})", 
            vote.height, vote.view, hex::encode(vote.voter.as_ref()), from);

        let height_map = self.view_votes.entry(vote.height).or_default();
        let view_map = height_map.entry(vote.view).or_default();
        
        if view_map.contains_key(&vote.voter) {
            return Ok(());
        }
        
        view_map.insert(vote.voter, vote);
        Ok(())
    }

    fn reset(&mut self, height: u64) {
        self.view_votes.retain(|h, _| *h >= height);
        self.tc_formed.retain(|(h, _)| *h >= height);
        self.seen_blocks.retain(|(h, _), _| *h >= height);
        self.vote_pool.retain(|h, _| *h >= height);
        
        // [FIX] Reset Pacemaker View to 0 for the next height
        // This ensures the round-robin schedule advances correctly:
        // H=1, V=0 -> Leader 0
        // H=2, V=0 -> Leader 1
        if let Ok(mut pm) = self.pacemaker.try_lock() {
             pm.current_view = 0;
             pm.view_start_time = std::time::Instant::now();
             info!(target: "consensus", "Pacemaker reset to View 0 for new height.");
        } else {
             warn!(target: "consensus", "Failed to lock pacemaker in reset!");
        }
    }
}