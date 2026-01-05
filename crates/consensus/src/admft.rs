// Path: crates/consensus/src/admft.rs

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
    FailureReport, SignatureSuite,
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
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use tracing::{debug, error, info, warn};

// --- New Structures for View Change ---

/// A vote from a validator to change the view at a specific height.
#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct ViewChangeVote {
    pub height: u64,
    pub view: u64,
    pub voter: AccountId,
    pub signature: Vec<u8>,
}

/// A proof that 2f+1 validators agreed to move to a new view.
#[derive(Debug, Clone, Encode, Decode)]
pub struct TimeoutCertificate {
    pub height: u64,
    pub view: u64,
    pub votes: Vec<ViewChangeVote>,
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
/// Implements Adaptive Deterministic Mirror Fault Tolerance.
/// Enforces safety via Guardian monotonic counters (n > 2f safety).
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
}

impl Default for AdmftEngine {
    fn default() -> Self {
        Self {
            last_seen_counters: HashMap::new(),
            view_votes: HashMap::new(),
            tc_formed: HashSet::new(),
            seen_blocks: HashMap::new(),
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
        let active_set = ioi_types::app::effective_set_for_height(sets, height);

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

        // BFT Quorum: > 2/3 of total weight
        let threshold = (total_weight * 2) / 3;

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
        view: u64,
        parent_view: &dyn AnchoredStateView,
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        // 1. Resolve Validator Set
        let vs_bytes = match parent_view.get(VALIDATOR_SET_KEY).await {
            Ok(Some(b)) => b,
            _ => return ConsensusDecision::Stall,
        };
        let sets = match read_validator_sets(&vs_bytes) {
            Ok(s) => s,
            Err(_) => return ConsensusDecision::Stall,
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

        if active_validators.is_empty() {
            return ConsensusDecision::Stall;
        }

        // Check for Quorum on View Change first
        if !self.tc_formed.contains(&(height, view)) {
            if let Some(_tc) = self.check_quorum(height, view, vs.total_weight, &sets) {
                info!(target: "consensus", "A-DMFT: Quorum reached for View {}. Advancing.", view);
                self.tc_formed.insert((height, view));
                // In a full impl, we'd attach the TC to the proposal.
                // For now, we signal readiness to proceed in the new view.
            }
        }

        // 2. Deterministic Leader Selection (Round-Robin for now, weighted in future)
        // A-DMFT uses linear views. Leader depends on view number.
        // Round index = (Height + View)
        let n = active_validators.len() as u64;
        let round_index = height.saturating_sub(1).saturating_add(view);
        let leader_index = (round_index % n) as usize;
        let leader_id = active_validators[leader_index];

        // Liveness Guard: If we have no peers and aren't the leader, we stall to avoid empty loops
        if known_peers.is_empty() && leader_id != *our_account_id {
            return ConsensusDecision::Stall;
        }

        if leader_id == *our_account_id {
            // 3. Compute Deterministic Timestamp
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

            info!(target: "consensus", "A-DMFT: I am leader for H={} V={}. Producing block.", height, view);

            ConsensusDecision::ProduceBlock {
                transactions: vec![],
                expected_timestamp_secs: expected_ts,
                view,
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
        let header = &block.header;

        // NEW: Divergence Detection Integration
        // We use a dummy PeerId here because the specific peer isn't critical for the logic
        // inside the engine, just the fact that *someone* sent it.
        // The orchestrator handles peer banning.
        let block_hash = block
            .header
            .hash()
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        let mut fixed_hash = [0u8; 32];
        fixed_hash.copy_from_slice(&block_hash);

        // Note: In real usage, the Orchestrator should call a dedicated method to inject the PeerId.
        // For standard handle_block_proposal, we just check against history.
        if self.detect_divergence(header.height, header.view, fixed_hash, PeerId::random()) {
            return Err(ConsensusError::BlockVerificationFailed(
                "Mirror Divergence (Equivocation) Detected".into(),
            ));
        }

        // 1. Load Parent View
        let parent_state_ref = StateRef {
            height: header.height - 1,
            state_root: header.parent_state_root.as_ref().to_vec(),
            block_hash: header.parent_hash,
        };
        let parent_view = chain_view
            .view_at(&parent_state_ref)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;

        // 2. Validate Validator Set & Leader
        let vs_bytes = parent_view
            .get(VALIDATOR_SET_KEY)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or(ConsensusError::StateAccess(StateError::KeyNotFound))?;
        let sets = read_validator_sets(&vs_bytes)
            .map_err(|_| ConsensusError::BlockVerificationFailed("VS decode failed".into()))?;
        let vs = effective_set_for_height(&sets, header.height);

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

        // 3. Verify Guardian Signature & Monotonicity (The Core of A-DMFT)
        let producer_record = vs
            .validators
            .iter()
            .find(|v| v.account_id == header.producer_account_id)
            .unwrap();
        let pubkey = &header.producer_pubkey;

        // Verify Key Match
        let derived_id = account_id_from_key_material(producer_record.consensus_key.suite, pubkey)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        if derived_id != producer_record.consensus_key.public_key_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "Producer key mismatch".into(),
            ));
        }

        // Verify Signature with Oracle Counter
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

        // 4. Enforce Monotonicity (A-DMFT Invariant)
        // If we have seen a counter >= current from this peer, they are equivocating or replaying.
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

        // Update local tracking
        self.last_seen_counters
            .insert(header.producer_account_id, header.oracle_counter);

        debug!(target: "consensus", "A-DMFT: Block {} verified. Oracle counter: {}", header.height, header.oracle_counter);

        Ok(())
    }

    async fn handle_view_change(
        &mut self,
        from: PeerId,
        height: u64,
        new_view: u64,
    ) -> Result<(), ConsensusError> {
        // In a real implementation, we would verify the signature on the ViewChange message here.
        // For Phase 1, we assume the networking layer has validated the peer identity.

        // We map PeerID to AccountID using the validator set is technically required,
        // but for this implementation we simulate the vote structure.

        // Placeholder: We need the actual Vote struct passed in, but the trait signature
        // in api/consensus/mod.rs only gives us PeerId/height/view.
        // Ideally, we'd update the trait to pass the opaque message bytes.
        // For now, we log the event to confirm the hook is active.

        info!(target: "consensus", "Received ViewChange to V={} @ H={} from {}", new_view, height, from);

        // To implement actual TC formation, we would:
        // 1. Decode the vote from the network message (requires trait change or side-channel).
        // 2. self.view_votes.entry(height).entry(view).insert(voter, vote);
        // 3. Check quorum (done in decide()).

        Ok(())
    }

    fn reset(&mut self, height: u64) {
        // Prune memory for old heights
        self.view_votes.retain(|h, _| *h >= height);
        self.tc_formed.retain(|(h, _)| *h >= height);
        self.seen_blocks.retain(|(h, _), _| *h >= height);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{
        AccountId, ActiveKeyRecord, SignatureSuite, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    };
    use rand::RngCore;

    fn mock_account_id(byte: u8) -> AccountId {
        let mut arr = [0u8; 32];
        arr[0] = byte;
        AccountId(arr)
    }

    fn mock_vote(height: u64, view: u64, voter: AccountId) -> ViewChangeVote {
        ViewChangeVote {
            height,
            view,
            voter,
            signature: vec![0xAA, 0xBB], // Dummy sig
        }
    }

    #[test]
    fn test_detect_divergence() {
        let mut engine = AdmftEngine::new();
        let h = 100;
        let v = 0;
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        // First block seen
        assert!(!engine.detect_divergence(h, v, hash1, peer1));

        // Same block, same peer -> OK
        assert!(!engine.detect_divergence(h, v, hash1, peer1));

        // Same block, different peer -> OK
        assert!(!engine.detect_divergence(h, v, hash1, peer2));

        // Different block, same height/view -> Divergence!
        assert!(engine.detect_divergence(h, v, hash2, peer2));
    }

    #[test]
    fn test_check_quorum() {
        let mut engine = AdmftEngine::new();
        let h = 10;
        let v = 2;

        let acc1 = mock_account_id(1);
        let acc2 = mock_account_id(2);
        let acc3 = mock_account_id(3);
        let acc4 = mock_account_id(4);

        // Setup Validator Set: 4 validators, weight 1 each. Total = 4.
        // Threshold > 2/3 * 4 = 2.66 -> Needs 3 votes.
        let validators = vec![
            ValidatorV1 {
                account_id: acc1,
                weight: 1,
                consensus_key: ActiveKeyRecord::default(),
            },
            ValidatorV1 {
                account_id: acc2,
                weight: 1,
                consensus_key: ActiveKeyRecord::default(),
            },
            ValidatorV1 {
                account_id: acc3,
                weight: 1,
                consensus_key: ActiveKeyRecord::default(),
            },
            ValidatorV1 {
                account_id: acc4,
                weight: 1,
                consensus_key: ActiveKeyRecord::default(),
            },
        ];
        let sets = ValidatorSetsV1 {
            current: ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: 4,
                validators,
            },
            next: None,
        };

        // Inject votes manually into internal state for testing
        let height_map = engine.view_votes.entry(h).or_default();
        let view_map = height_map.entry(v).or_default();

        // 1. Vote from Acc1 -> Total 1 (Wait)
        view_map.insert(acc1, mock_vote(h, v, acc1));
        assert!(engine.check_quorum(h, v, 4, &sets).is_none());

        // 2. Vote from Acc2 -> Total 2 (Wait, 2 < 2.66)
        view_map.insert(acc2, mock_vote(h, v, acc2));
        assert!(engine.check_quorum(h, v, 4, &sets).is_none());

        // 3. Vote from Acc3 -> Total 3 (Pass, 3 > 2.66)
        view_map.insert(acc3, mock_vote(h, v, acc3));
        let tc = engine.check_quorum(h, v, 4, &sets);
        assert!(tc.is_some());
        assert_eq!(tc.unwrap().votes.len(), 3);
    }
}
