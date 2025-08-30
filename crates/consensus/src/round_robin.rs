// Path: crates/consensus/src/round_robin.rs
//! An implementation of the `ConsensusEngine` trait that uses a simple, deterministic
//! round-robin leader election schedule. This engine extracts the logic that was
//! previously hardcoded in the `OrchestrationContainer`.

use crate::{ConsensusDecision, ConsensusEngine, PenaltyMechanism};
use async_trait::async_trait;
use depin_sdk_api::consensus::ChainStateReader;
use depin_sdk_api::state::StateAccessor;
use depin_sdk_types::app::{AccountId, Block, FailureReport};
use depin_sdk_types::error::{ConsensusError, StateError, TransactionError};
use depin_sdk_types::keys::{AUTHORITY_SET_KEY, QUARANTINED_VALIDATORS_KEY};
use libp2p::identity::PublicKey;
use libp2p::PeerId;
use std::collections::{BTreeSet, HashMap, HashSet};
use tokio::time::{Duration, Instant};

/// Checks if a sufficient number of validators (quorum) are connected.
fn has_quorum(
    validator_set: &[Vec<u8>],
    known_peers: &HashSet<PeerId>,
    local_peer_id: &PeerId,
) -> bool {
    if validator_set.is_empty() {
        return true; // Genesis case or no validators defined, allow progress.
    }
    let mut connected_validators = 0;
    for peer_bytes in validator_set {
        if let Ok(peer_id) = PeerId::from_bytes(peer_bytes) {
            if &peer_id == local_peer_id || known_peers.contains(&peer_id) {
                connected_validators += 1;
            }
        }
    }
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
    validator_set_cache: HashMap<u64, Vec<Vec<u8>>>,
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
        const MIN_LIVE_AUTHORITIES: usize = 3;

        let authorities_bytes = state.get(AUTHORITY_SET_KEY)?.ok_or_else(|| {
            TransactionError::State(StateError::KeyNotFound(
                "Authority set not found in state".into(),
            ))
        })?;
        let authorities: Vec<Vec<u8>> = serde_json::from_slice(&authorities_bytes)?;

        let quarantined: BTreeSet<AccountId> = state
            .get(QUARANTINED_VALIDATORS_KEY)?
            .map(|b| {
                depin_sdk_types::codec::from_bytes_canonical(&b)
                    .map_err(|e| StateError::InvalidValue(e))
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
        state_reader: &dyn ChainStateReader,
    ) -> Result<Vec<Vec<u8>>, ConsensusError> {
        state_reader
            .get_authority_set()
            .await
            .map_err(|e| ConsensusError::ClientError(e.to_string()))
    }

    async fn decide(
        &mut self,
        local_public_key: &PublicKey,
        height: u64,
        _view: u64, // The view is managed internally by this engine.
        validator_data: &[Vec<u8>],
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        self.validator_set_cache
            .entry(height)
            .or_insert_with(|| validator_data.to_vec());

        let view = *self.current_views.entry(height).or_insert(0);

        if validator_data.is_empty() {
            return ConsensusDecision::ProduceBlock(vec![]);
        }

        let local_peer_id = local_public_key.to_peer_id();
        let leader_index = ((height + view) % validator_data.len() as u64) as usize;
        let designated_leader = &validator_data[leader_index];

        if designated_leader == &local_peer_id.to_bytes() {
            self.view_start_times.remove(&(height, view));
            if has_quorum(validator_data, known_peers, &local_peer_id) {
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

    async fn handle_block_proposal(
        &mut self,
        block: Block<T>,
        state_reader: &dyn ChainStateReader,
    ) -> Result<(), ConsensusError> {
        let height = block.header.height;
        let producer_pubkey =
            PublicKey::try_decode_protobuf(&block.header.producer).map_err(|e| {
                ConsensusError::BlockVerificationFailed(format!(
                    "Failed to decode producer public key: {}",
                    e
                ))
            })?;
        let header_hash = block.header.hash();
        if !producer_pubkey.verify(&header_hash, &block.header.signature) {
            return Err(ConsensusError::InvalidSignature);
        }

        let validator_set = state_reader.get_authority_set().await.map_err(|e| {
            ConsensusError::ClientError(format!("Could not get validator set: {}", e))
        })?;
        if validator_set.is_empty() {
            return Err(ConsensusError::BlockVerificationFailed(
                "Cannot validate block, validator set is empty".to_string(),
            ));
        }

        let view = *self.current_views.entry(height).or_insert(0);
        let leader_index = ((height + view) % validator_set.len() as u64) as usize;
        let expected_leader_bytes = &validator_set[leader_index];
        let got = producer_pubkey.to_peer_id();

        if &got.to_bytes() != expected_leader_bytes {
            let expected = PeerId::from_bytes(expected_leader_bytes).map_err(|e| {
                ConsensusError::BlockVerificationFailed(format!(
                    "Could not decode expected leader PeerId: {}",
                    e
                ))
            })?;
            return Err(ConsensusError::InvalidLeader { expected, got });
        }

        log::info!(
            "Block proposal from valid leader {} for (h:{}, v:{}) verified.",
            got,
            height,
            view
        );

        ConsensusEngine::<T>::reset(self, height);
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
