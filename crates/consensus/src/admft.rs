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
use std::collections::{BTreeSet, HashMap, HashSet};
use tracing::{debug, error, info, warn};

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
}

impl Default for AdmftEngine {
    fn default() -> Self {
        Self {
            last_seen_counters: HashMap::new(),
        }
    }
}

impl AdmftEngine {
    pub fn new() -> Self {
        Self::default()
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
        _known_peers: &HashSet<PeerId>,
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

        // 2. Deterministic Leader Selection (Round-Robin for now, weighted in future)
        // A-DMFT uses linear views. Leader depends on view number.
        // Round index = (Height + View)
        let n = active_validators.len() as u64;
        let round_index = height.saturating_sub(1).saturating_add(view);
        let leader_index = (round_index % n) as usize;

        let leader_id = active_validators[leader_index];

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
        _from: PeerId,
        _height: u64,
        _new_view: u64,
    ) -> Result<(), ConsensusError> {
        // In full implementation, this handles TC (TimeoutCertificates).
        Ok(())
    }

    fn reset(&mut self, _height: u64) {
        // Prune old counter tracking if needed, or keep for long-range safety.
    }
}
