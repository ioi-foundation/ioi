// Path: crates/consensus/src/round_robin.rs
//! An implementation of the `ConsensusEngine` trait that uses a simple, deterministic
//! round-robin leader election schedule. This engine extracts the logic that was
//! previously hardcoded in the `OrchestrationContainer`.

use crate::{ConsensusDecision, ConsensusEngine};
use async_trait::async_trait;
use depin_sdk_api::chain::AppChain;
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::WorkloadContainer;
use depin_sdk_types::app::Block;
use libp2p::identity::PublicKey;
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
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
    /// Creates a new `RoundRobinBftEngine` with default settings.
    pub fn new() -> Self {
        Self {
            view_start_times: HashMap::new(),
            // This timeout should be longer than the block production interval.
            view_timeout: Duration::from_secs(20),
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
        Self::new()
    }
}

#[async_trait]
impl<T: Clone + Send + 'static> ConsensusEngine<T> for RoundRobinBftEngine {
    async fn decide(
        &mut self,
        local_peer_id: &PeerId,
        height: u64,
        _view: u64, // The view is managed internally by this engine.
        validator_set: &[Vec<u8>],
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        // Cache the validator set for this height so `handle_view_change` can use it for quorum checks.
        self.validator_set_cache
            .entry(height)
            .or_insert_with(|| validator_set.to_vec());

        // Use our own state for the current view, as this engine manages view changes internally.
        let view = *self.current_views.entry(height).or_insert(0);

        if validator_set.is_empty() {
            return ConsensusDecision::ProduceBlock(vec![]);
        }

        let leader_index = ((height + view) % validator_set.len() as u64) as usize;
        let designated_leader = &validator_set[leader_index];

        if designated_leader == &local_peer_id.to_bytes() {
            self.view_start_times.remove(&(height, view));
            if has_quorum(validator_set, known_peers, local_peer_id) {
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

    async fn handle_block_proposal<CS, TM, ST>(
        &mut self,
        block: Block<T>,
        chain: &mut (dyn AppChain<CS, TM, ST> + Send + Sync),
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), String>
    where
        CS: CommitmentScheme + Send + Sync,
        TM: TransactionModel<CommitmentScheme = CS> + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
            + Send
            + Sync
            + 'static
            + Debug,
        CS::Commitment: Send + Sync + Debug,
    {
        let height = block.header.height;
        // 1. Basic structural validation
        if height != chain.status().height + 1 {
            return Err(format!(
                "Invalid block height. Expected {}, got {}",
                chain.status().height + 1,
                height
            ));
        }

        // 2. Verify Producer Signature
        let producer_pubkey = PublicKey::try_decode_protobuf(&block.header.producer)
            .map_err(|e| format!("Failed to decode producer public key: {}", e))?;
        let header_hash = block.header.hash_for_signing();
        if !producer_pubkey.verify(&header_hash, &block.header.signature) {
            return Err("Invalid block signature".to_string());
        }

        // 3. Verify Producer is the leader for the current view at this height
        let validator_set = chain
            .get_validator_set(workload)
            .await
            .map_err(|e| format!("Could not get validator set: {}", e))?;
        if validator_set.is_empty() {
            return Err("Cannot validate block, validator set is empty".to_string());
        }

        let view = *self.current_views.entry(height).or_insert(0);
        let leader_index = ((height + view) % validator_set.len() as u64) as usize;
        let expected_leader_bytes = &validator_set[leader_index];
        let producer_peer_id = producer_pubkey.to_peer_id();

        if &producer_peer_id.to_bytes() != expected_leader_bytes {
            return Err(format!(
                "Block producer {} is not the designated leader for height {} view {}.",
                producer_peer_id, height, view
            ));
        }

        log::info!(
            "Block proposal from valid leader {} for (h:{}, v:{}) verified.",
            producer_peer_id,
            height,
            view
        );

        // A valid block proposal means a leader was successful. Reset our internal state
        // for that height to prevent outdated timers from causing a spurious view change.
        ConsensusEngine::<T>::reset(self, height);
        Ok(())
    }

    async fn handle_view_change(
        &mut self,
        from: PeerId,
        height: u64,
        new_view: u64,
    ) -> Result<(), String> {
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
        // Remove all state related to the given height. This is called after a block
        // is successfully committed, ensuring a clean slate for the next round.
        self.view_start_times.retain(|(h, _), _| *h != height);
        self.current_views.remove(&height);
        self.view_change_votes.retain(|(h, _), _| *h != height);
        self.validator_set_cache.remove(&height);
        log::debug!("Consensus engine state reset for height {}.", height);
    }
}
