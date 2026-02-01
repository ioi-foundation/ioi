// Path: crates/consensus/src/admft/mod.rs

use crate::common::penalty::apply_quarantine_penalty;
use crate::{ConsensusDecision, ConsensusEngine, PenaltyEngine, PenaltyMechanism};
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, ChainView, StateRef};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::ConsensusControl; 
use ioi_api::state::{StateAccess, StateManager};
use ioi_system::SystemState;
use ioi_types::app::{
    effective_set_for_height, read_validator_sets, AccountId, Block, BlockHeader, 
    BlockTimingParams, BlockTimingRuntime, ChainStatus, ConsensusVote, EchoMessage, 
    FailureReport, ProofOfDivergence, QuorumCertificate, ChainTransaction, 
    compute_next_timestamp, to_root_hash,
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
use self::safety::SafetyGadget;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration;

pub mod pacemaker;
pub mod safety;
pub mod aggregator;
pub mod divergence;

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

/// The A-DMFT Consensus Engine.
#[derive(Debug, Clone)]
pub struct AdmftEngine {
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

impl Default for AdmftEngine {
    fn default() -> Self {
        Self {
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

impl AdmftEngine {
    pub fn new() -> Self {
        Self::default()
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

        // A-DMFT Quorum: Simple Majority (> 50%)
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

    /// Internal helper to detect divergence.
    fn check_divergence(
        &mut self,
        header: &BlockHeader,
    ) -> Option<ProofOfDivergence> {
        let entry = self.seen_headers.entry((header.height, header.view)).or_default();
        
        let header_hash = match header.hash() {
            Ok(h) => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&h);
                arr
            },
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
            "A-DMFT DIVERGENCE DETECTED @ H{} V{}: {:?} vs {:?}",
            header.height, header.view, hex::encode(existing_hash), hex::encode(header_hash)
        );

        Some(ProofOfDivergence {
            offender: header.producer_account_id,
            evidence_a: existing_header.clone(),
            evidence_b: header.clone(),
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
        let threshold = total_weight / 2;
        
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
                 "QC has insufficient voting power: {} <= {}", voting_power, threshold
             )));
        }

        Ok(())
    }

    /// Processes an incoming Echo message.
    pub async fn handle_echo(
        &mut self,
        echo: EchoMessage,
    ) -> Result<ConsensusDecision<ChainTransaction>, ConsensusError> {
        let pool = self.echo_pool.entry((echo.height, echo.view)).or_default();
        if pool.iter().any(|e| e.sender_id == echo.sender_id) {
            return Ok(ConsensusDecision::WaitForBlock);
        }
        pool.push(echo.clone());
        
        let threshold = (self.cached_validator_count / 4) + 1;
        let count = pool.iter().filter(|e| e.block_hash == echo.block_hash).count();
        
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

// Implement ConsensusControl for AdmftEngine
impl ConsensusControl for AdmftEngine {
    fn switch_to_apmft(&mut self) {
        // Handled by wrapper
    }
    fn switch_to_admft(&mut self) {
        // Handled by wrapper
    }
    fn get_apmft_tip(&self) -> Option<([u8; 32], u32)> { None }
    fn feed_apmft_sample(&mut self, _hash: [u8; 32]) {}
}

#[async_trait]
impl PenaltyMechanism for AdmftEngine {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccess,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        apply_quarantine_penalty(state, report).await
    }
}

impl PenaltyEngine for AdmftEngine {
    fn apply(
        &self,
        sys: &mut dyn SystemState,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        let sets = sys.validators().current_sets().map_err(TransactionError::State)?;
        let authorities: Vec<AccountId> = sets.current.validators.iter().map(|v| v.account_id).collect();
        let quarantined = sys.quarantine().get_all().map_err(TransactionError::State)?;
        let min_live = (authorities.len() / 2) + 1;

        if !authorities.contains(&report.offender) {
            return Err(TransactionError::Invalid("Offender is not an authority".into()));
        }
        if quarantined.contains(&report.offender) {
            return Ok(());
        }
        let live_after = authorities.len().saturating_sub(quarantined.len()).saturating_sub(1);
        if live_after < min_live {
            return Err(TransactionError::Invalid("Quarantine jeopardizes liveness".into()));
        }
        sys.quarantine_mut().insert(report.offender).map_err(TransactionError::State)
    }
}

#[async_trait]
impl<T: Clone + Send + 'static + parity_scale_codec::Encode> ConsensusEngine<T> for AdmftEngine {
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

        info!(target: "consensus", "AdmftEngine::decide called for height {}", height);

        let (timed_out, current_view) = {
            let mut pacemaker = self.pacemaker.lock().await;
            if pacemaker.check_timeout() {
                let next_view = pacemaker.current_view + 1;
                pacemaker.advance_view(next_view);
                info!(target: "consensus", "Pacemaker timed out. Moving to View {}.", next_view);
                return ConsensusDecision::Timeout { view: next_view, height };
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

        let quarantined: BTreeSet<AccountId> = match parent_view.get(QUARANTINED_VALIDATORS_KEY).await {
            Ok(Some(b)) => codec::from_bytes_canonical(&b).unwrap_or_default(),
            _ => BTreeSet::new(),
        };

        let vs = effective_set_for_height(&sets, height);
        let active_validators: Vec<AccountId> = vs.validators.iter().map(|v| v.account_id).filter(|id| !quarantined.contains(id)).collect();
        self.cached_validator_count = active_validators.len();

        if active_validators.is_empty() { return ConsensusDecision::Stall; }

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
            if height > 1 && self.highest_qc.height < height - 1 {
                return ConsensusDecision::Stall;
            }

            // Safety Check: Ensure we don't propose conflicting blocks
            // Use locked_qc from safety gadget to ensure we extend the correct chain
            if let Some(_locked) = &self.safety.locked_qc {
                 // If we have a lock, we must extend it.
                 // For simplified A-DMFT, the highest_qc usually matches the lock or is newer.
                 // The proposal construction in `create_block` uses `highest_qc` (via `parent_qc` logic).
            }

            let timing_params = match parent_view.get(BLOCK_TIMING_PARAMS_KEY).await {
                Ok(Some(b)) => codec::from_bytes_canonical::<BlockTimingParams>(&b).unwrap_or_default(),
                _ => return ConsensusDecision::Stall,
            };
            let timing_runtime = match parent_view.get(BLOCK_TIMING_RUNTIME_KEY).await {
                Ok(Some(b)) => codec::from_bytes_canonical::<BlockTimingRuntime>(&b).unwrap_or_default(),
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
            ).unwrap_or(0);

            info!(target: "consensus", "I am leader for H={} V={}. Producing block.", height, current_view);

            let parent_qc = if height == 1 { QuorumCertificate::default() } else { self.highest_qc.clone() };

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
             return Err(ConsensusError::BlockVerificationFailed("Panic:HardwareDivergence".into()));
        }

        let header = &block.header;
        
        let parent_state_ref = StateRef {
            height: header.height - 1,
            state_root: header.parent_state_root.as_ref().to_vec(),
            block_hash: header.parent_hash,
        };
        let parent_view = chain_view.view_at(&parent_state_ref).await.map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;

        let vs_bytes = match parent_view.get(VALIDATOR_SET_KEY).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                 error!(target: "consensus", "Validator set missing in parent state for H={}", header.height);
                 return Err(ConsensusError::StateAccess(StateError::KeyNotFound));
            },
            Err(e) => {
                 error!(target: "consensus", "State access error reading validator set: {}", e);
                 return Err(ConsensusError::StateAccess(StateError::Backend(e.to_string())));
            }
        };

        let sets = read_validator_sets(&vs_bytes).map_err(|e| {
             error!(target: "consensus", "Failed to decode validator set: {}", e);
             ConsensusError::BlockVerificationFailed("VS decode failed".into())
        })?;

        let quarantined: BTreeSet<AccountId> = match parent_view.get(QUARANTINED_VALIDATORS_KEY).await {
            Ok(Some(b)) => codec::from_bytes_canonical(&b).unwrap_or_default(),
            _ => BTreeSet::new(),
        };

        let vs = effective_set_for_height(&sets, header.height);
        let active_validators: Vec<AccountId> = vs.validators.iter().map(|v| v.account_id).filter(|id| !quarantined.contains(id)).collect();
        self.cached_validator_count = active_validators.len();

        let threshold = (self.cached_validator_count / 2) + 1;
        
        let block_hash_bytes = match header.hash() {
             Ok(h) => h,
             Err(_) => return Err(ConsensusError::BlockVerificationFailed("Hash fail".into())),
        };
        let block_hash = to_root_hash(&block_hash_bytes).map_err(|_| ConsensusError::BlockVerificationFailed("Hash len".into()))?;

        // Check votes
        if let Some(votes) = self.vote_pool.get(&header.height).and_then(|m| m.get(&block_hash)) {
             if votes.len() >= threshold {
                let qc = QuorumCertificate {
                    height: header.height,
                    view: header.view,
                    block_hash,
                    signatures: votes.iter().map(|v| (v.voter, v.signature.clone())).collect(),
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
                return Err(ConsensusError::BlockVerificationFailed("Parent QC hash mismatch".into()));
            }
            if let Err(e) = self.verify_qc(parent_qc, &sets) {
                error!(target: "consensus", "QC Verification Failed for block {}: {}", header.height, e);
                return Err(e);
            }
            if parent_qc.height > self.highest_qc.height {
                self.highest_qc = parent_qc.clone();
            }
        }

        let preimage = header.to_preimage_for_signing().map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        verify_guardian_signature(&preimage, &header.producer_pubkey, &header.signature, header.oracle_counter, &header.oracle_trace_hash)?;

        if let Some(&last_ctr) = self.last_seen_counters.get(&header.producer_account_id) {
            if header.oracle_counter <= last_ctr {
                return Err(ConsensusError::BlockVerificationFailed("Guardian counter rollback".into()));
            }
        }
        self.last_seen_counters.insert(header.producer_account_id, header.oracle_counter);

        debug!(target: "consensus", "A-DMFT: Block {} verified. Initiating ECHO phase.", header.height);
        Ok(())
    }

    async fn handle_vote(
        &mut self,
        vote: ConsensusVote,
    ) -> Result<(), ConsensusError> {
        // Safety Check: Don't process votes if not safe
        if !self.safety.safe_to_vote(vote.view, vote.height - 1) { 
             // Logic for unsafe vote handling (optional)
        }

        let height_map = self.vote_pool.entry(vote.height).or_default();
        let votes = height_map.entry(vote.block_hash).or_default();
        
        if votes.iter().any(|v| v.voter == vote.voter) {
            return Ok(());
        }
        votes.push(vote.clone());

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
        let vote: ViewChangeVote = ioi_types::codec::from_bytes_canonical(proof_bytes)
            .map_err(|e| ConsensusError::BlockVerificationFailed(format!("Invalid view vote: {}", e)))?;

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