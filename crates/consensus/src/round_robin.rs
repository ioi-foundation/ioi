// Path: crates/consensus/src/round_robin.rs
//! An implementation of the `ConsensusEngine` trait that uses a simple, deterministic
//! round-robin leader election schedule. This engine extracts the logic that was
//! previously hardcoded in the `OrchestrationContainer`.

use crate::{ConsensusDecision, ConsensusEngine, PenaltyMechanism};
use async_trait::async_trait;
use depin_sdk_api::chain::{ChainView, StateView};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::consensus::ChainStateReader;
use depin_sdk_api::state::{StateAccessor, StateManager};
use depin_sdk_types::app::{read_validator_sets, AccountId, Block, FailureReport};
use depin_sdk_types::error::{ConsensusError, CoreError, StateError, TransactionError};
use depin_sdk_types::keys::{QUARANTINED_VALIDATORS_KEY, VALIDATOR_SET_KEY};
use libp2p::PeerId;
use std::collections::{BTreeSet, HashMap, HashSet};
use tokio::time::{Duration, Instant};

// Re-use helpers from PoA
use crate::proof_of_authority::{hash_key, verify_signature};

/// Checks if a sufficient number of validators (quorum) are connected.
fn has_quorum(
    validator_set: &[AccountId],
    known_peers: &HashSet<PeerId>,
    _local_peer_id: &PeerId, // This is harder to check now without a state view
) -> bool {
    if validator_set.is_empty() {
        return true; // Genesis case or no validators defined, allow progress.
    }
    // A real implementation would need a way to map AccountId back to PeerId to check liveness.
    // For now, we'll assume quorum is met if we have any known peers.
    let connected_validators = known_peers.len() + 1; // +1 for self

    // Simple majority quorum
    let quorum_size = (validator_set.len() / 2) + 1;
    let has_quorum = connected_validators >= quorum_size;
    if !has_quorum {
        log::warn!(
            "Quorum check failed: see {}/{} of validator set (quorum is {}).",
            connected_validators,
            validator_set.len(),
            quorum_size
        );
    }
    has_quorum
}

/// A consensus engine implementing a round-robin BFT-style leader rotation.
#[derive(Debug, Clone)]
pub struct RoundRobinBftEngine {
    /// Internal state for tracking timeouts for view changes.
    /// Key: (height, view), Value: time we started waiting in this view.
    view_start_times: HashMap<(u64, u64), Instant>,
    /// The duration to wait for a leader's block before proposing a view change.
    view_timeout: Duration,
    /// A map from block height to the current consensus view number.
    current_views: HashMap<u64, u64>,
    /// Stores votes for view changes. Key: (height, new_view), Value: Set of voters.
    view_change_votes: HashMap<(u64, u64), HashSet<PeerId>>,
    /// Caches the validator set for a given height, as seen in the last `decide` call.
    validator_set_cache: HashMap<u64, Vec<AccountId>>,
}

impl RoundRobinBftEngine {
    /// Creates a new `RoundRobinBftEngine` with a specified view timeout.
    pub fn new(view_timeout: Duration) -> Self {
        Self {
            view_start_times: HashMap::new(),
            view_timeout,
            current_views: HashMap::new(),
            view_change_votes: HashMap::new(),
            validator_set_cache: HashMap::new(),
        }
    }

    /// Checks if the timeout for the current view has been exceeded.
    fn has_timed_out(&mut self, height: u64, view: u64) -> bool {
        let now = Instant::now();
        let start_time = self.view_start_times.entry((height, view)).or_insert(now);

        if now.duration_since(*start_time) > self.view_timeout {
            // To prevent spamming view change proposals, reset the timer for this view.
            self.view_start_times.insert((height, view), now);
            true
        } else {
            false
        }
    }
}

impl Default for RoundRobinBftEngine {
    fn default() -> Self {
        // This default is used when the feature is enabled but no config is provided.
        Self::new(Duration::from_secs(20))
    }
}

#[async_trait]
impl PenaltyMechanism for RoundRobinBftEngine {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccessor,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        const MIN_LIVE_AUTHORITIES: usize = 2;

        let authorities_bytes = state.get(VALIDATOR_SET_KEY)?.ok_or_else(|| {
            TransactionError::State(StateError::KeyNotFound(
                "Authority set not found in state".into(),
            ))
        })?;
        let authorities: Vec<AccountId> = read_validator_sets(&authorities_bytes)?
            .current
            .validators
            .into_iter()
            .map(|v| v.account_id)
            .collect();

        let quarantined: BTreeSet<AccountId> = state
            .get(QUARANTINED_VALIDATORS_KEY)?
            .map(|b| {
                depin_sdk_types::codec::from_bytes_canonical(&b).map_err(StateError::InvalidValue)
            })
            .transpose()?
            .unwrap_or_default();

        if !quarantined.contains(&report.offender)
            && (authorities.len() - quarantined.len() - 1) < MIN_LIVE_AUTHORITIES
        {
            return Err(TransactionError::Invalid(
                "Quarantine would jeopardize network liveness".into(),
            ));
        }

        let mut new_quarantined = quarantined;
        if new_quarantined.insert(report.offender) {
            state.insert(
                QUARANTINED_VALIDATORS_KEY,
                &depin_sdk_types::codec::to_bytes_canonical(&new_quarantined),
            )?;
        }
        Ok(())
    }
}

#[async_trait]
impl<T: Clone + Send + 'static> ConsensusEngine<T> for RoundRobinBftEngine {
    async fn get_validator_data(
        &self,
        _state_reader: &dyn ChainStateReader,
    ) -> Result<Vec<Vec<u8>>, ConsensusError> {
        Ok(vec![]) // Placeholder
    }

    async fn decide(
        &mut self,
        our_account_id: &AccountId,
        height: u64,
        _view: u64, // The view is managed internally by this engine.
        parent_view: &dyn StateView,
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        let vs_bytes = match parent_view.get(VALIDATOR_SET_KEY).await {
            Ok(Some(bytes)) => bytes,
            _ => return ConsensusDecision::Stall,
        };
        let sets = match read_validator_sets(&vs_bytes) {
            Ok(s) => s,
            Err(_) => return ConsensusDecision::Stall,
        };
        let validator_data: Vec<_> = sets
            .current
            .validators
            .into_iter()
            .map(|v| v.account_id)
            .collect();

        self.validator_set_cache
            .entry(height)
            .or_insert_with(|| validator_data.to_vec());

        let view = *self.current_views.entry(height).or_insert(0);

        if validator_data.is_empty() {
            return if height == 1 {
                ConsensusDecision::ProduceBlock(vec![])
            } else {
                ConsensusDecision::Stall
            };
        }

        // This is a placeholder for a real implementation that would map AccountId -> PeerId
        let local_peer_id = PeerId::random();
        let leader_index = ((height + view) % validator_data.len() as u64) as usize;
        let designated_leader = &validator_data[leader_index];

        if designated_leader == our_account_id {
            self.view_start_times.remove(&(height, view));
            if has_quorum(&validator_data, known_peers, &local_peer_id) {
                ConsensusDecision::ProduceBlock(vec![])
            } else {
                ConsensusDecision::WaitForBlock
            }
        } else if self.has_timed_out(height, view) {
            ConsensusDecision::ProposeViewChange
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

        // FIX: Handle the Result from to_anchor()
        let parent_state_anchor = header
            .parent_state_root
            .to_anchor()
            .map_err(|e| ConsensusError::StateAccess(StateError::InvalidValue(e.to_string())))?;
        let parent_view = chain_view
            .view_at(&parent_state_anchor)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;

        let vs_bytes = parent_view
            .get(VALIDATOR_SET_KEY)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::StateAccess(StateError::KeyNotFound("ValidatorSet".into()))
            })?;
        let sets = read_validator_sets(&vs_bytes)
            .map_err(|e| ConsensusError::StateAccess(StateError::InvalidValue(e.to_string())))?;
        let validator_set: Vec<_> = sets
            .current
            .validators
            .into_iter()
            .map(|v| v.account_id)
            .collect();

        if validator_set.is_empty() {
            return Err(ConsensusError::BlockVerificationFailed(
                "Cannot validate block, validator set is empty".to_string(),
            ));
        }

        let active_key = parent_view
            .active_consensus_key(&header.producer_account_id)
            .await
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed("Producer has no active key".into())
            })?;

        let pubkey = &header.producer_pubkey;
        // FIX: Handle the Result from hash_key()
        let derived_hash = hash_key(active_key.suite, pubkey)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        if derived_hash != active_key.pubkey_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "Public key in header does not match its hash".into(),
            ));
        }

        let preimage = header.to_preimage_for_signing();
        verify_signature(&preimage, pubkey, active_key.suite, &header.signature)?;

        let view = *self.current_views.entry(header.height).or_insert(0);
        let leader_index = ((header.height + view) % validator_set.len() as u64) as usize;
        let expected_leader = &validator_set[leader_index];

        if &header.producer_account_id != expected_leader {
            return Err(ConsensusError::InvalidLeader {
                expected: *expected_leader,
                got: header.producer_account_id,
            });
        }

        log::info!(
            "Block proposal from valid leader {:?} for (h:{}, v:{}) verified.",
            header.producer_account_id,
            header.height,
            view
        );

        ConsensusEngine::<T>::reset(self, header.height);
        Ok(())
    }

    async fn handle_view_change(
        &mut self,
        from: PeerId,
        height: u64,
        new_view: u64,
    ) -> Result<(), ConsensusError> {
        let current_view = *self.current_views.entry(height).or_insert(0);

        if new_view <= current_view {
            return Ok(());
        }

        log::info!(
            "Received view change vote from {:?} for height {}, new view {}.",
            from,
            height,
            new_view
        );

        let voters = self
            .view_change_votes
            .entry((height, new_view))
            .or_default();
        voters.insert(from);

        if let Some(validator_set) = self.validator_set_cache.get(&height) {
            let quorum_size = (validator_set.len() / 2) + 1;
            if voters.len() >= quorum_size {
                log::info!(
                    "View change quorum reached for (h:{}, v:{}). Updating local view.",
                    height,
                    new_view
                );
                self.current_views.insert(height, new_view);
                self.view_start_times
                    .retain(|(h, v), _| *h != height || *v >= new_view);
                self.view_change_votes
                    .retain(|(h, v), _| *h != height || *v >= new_view);
            }
        } else {
            log::warn!(
                "Received view change vote for height {} but have no validator set cached.",
                height
            );
        }

        Ok(())
    }

    fn reset(&mut self, height: u64) {
        self.view_start_times.retain(|(h, _), _| *h != height);
        self.current_views.remove(&height);
        self.view_change_votes.retain(|(h, _), _| *h != height);
        self.validator_set_cache.remove(&height);
        log::debug!("Consensus engine state reset for height {}.", height);
    }
}
