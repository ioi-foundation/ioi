// Path: crates/consensus/src/round_robin.rs
//! An implementation of the `ConsensusEngine` trait that uses a simple, deterministic
//! round-robin leader election schedule. This engine extracts the logic that was
//! previously hardcoded in the `OrchestrationContainer`.

use crate::{ConsensusDecision, ConsensusEngine};
use async_trait::async_trait;
use depin_sdk_core::app::Block;
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
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
}

impl RoundRobinBftEngine {
    /// Creates a new `RoundRobinBftEngine` with default settings.
    pub fn new() -> Self {
        Self {
            view_start_times: HashMap::new(),
            // This timeout should be longer than the block production interval.
            // Since the interval is 10s, a 20s timeout allows for one missed block.
            view_timeout: Duration::from_secs(20),
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
        view: u64,
        validator_set: &[Vec<u8>],
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        if validator_set.is_empty() {
            // Genesis case: the first node is the leader.
            return ConsensusDecision::ProduceBlock(vec![]);
        }

        let leader_index = ((height + view) % validator_set.len() as u64) as usize;
        let designated_leader = &validator_set[leader_index];

        if designated_leader == &local_peer_id.to_bytes() {
            // We are the leader. Clear any timeout state we might have had as a follower.
            self.view_start_times.remove(&(height, view));

            if has_quorum(validator_set, known_peers, local_peer_id) {
                ConsensusDecision::ProduceBlock(vec![])
            } else {
                ConsensusDecision::WaitForBlock // Wait for more peers to achieve quorum.
            }
        } else {
            // We are a follower. Check if we've timed out waiting for the leader.
            if self.has_timed_out(height, view) {
                ConsensusDecision::ProposeViewChange
            } else {
                ConsensusDecision::WaitForBlock
            }
        }
    }

    async fn handle_block_proposal(&mut self, _block: Block<T>) -> Result<(), String> {
        // For this simple engine, block validation is handled by the chain logic itself.
        Ok(())
    }

    async fn handle_view_change(
        &mut self,
        _from: PeerId,
        _height: u64,
        _new_view: u64,
    ) -> Result<(), String> {
        // The OrchestrationContainer handles vote aggregation. The engine itself
        // doesn't need to do anything with individual view change messages in this model.
        Ok(())
    }

    fn reset(&mut self, height: u64) {
        // Remove all view timeout entries related to the given height.
        self.view_start_times.retain(|(h, _), _| *h != height);
        log::debug!("Consensus engine state reset for height {}.", height);
    }
}
