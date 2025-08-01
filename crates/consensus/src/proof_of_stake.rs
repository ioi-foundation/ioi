// File: crates/consensus/src/proof_of_stake.rs

use crate::{ConsensusDecision, ConsensusEngine};
use async_trait::async_trait;
use depin_sdk_core::app::Block;
use depin_sdk_crypto::algorithms::hash::sha256;
use libp2p::PeerId;
use std::collections::{BTreeMap, HashSet};

// CORRECTION: The key for the stakes map must be a string for JSON compatibility.
pub type PublicKey = String;
pub type StakeAmount = u64;

/// A Proof of Stake consensus engine that uses a deterministic, stake-weighted
/// lottery to select a block producer for each round.
pub struct ProofOfStakeEngine {}

impl ProofOfStakeEngine {
    pub fn new() -> Self {
        Self {}
    }

    /// Selects a leader from a map of stakers.
    /// The selection is deterministic based on the height and total stake.
    fn select_leader(
        &self,
        height: u64,
        stakers: &BTreeMap<PublicKey, StakeAmount>,
    ) -> Option<PublicKey> {
        if stakers.is_empty() {
            return None;
        }

        let total_stake = stakers.values().sum::<StakeAmount>();
        if total_stake == 0 {
            // If total stake is zero, fall back to the first staker to avoid division by zero.
            return stakers.keys().next().cloned();
        }

        // Create a deterministic "winning ticket" number for this height.
        let seed = height.to_le_bytes();
        let hash = sha256(seed);
        let winning_ticket = u64::from_le_bytes(hash[0..8].try_into().unwrap()) % total_stake;

        // Find which staker "owns" the winning ticket.
        let mut cumulative_stake = 0;
        for (validator_pk_b58, stake) in stakers {
            cumulative_stake += stake;
            if winning_ticket < cumulative_stake {
                return Some(validator_pk_b58.clone());
            }
        }
        
        // Fallback in case of rounding errors, though it should not be reached.
        stakers.keys().last().cloned()
    }
}

#[async_trait]
impl<T: Clone + Send + 'static> ConsensusEngine<T> for ProofOfStakeEngine {
    async fn decide(
        &mut self,
        local_peer_id: &PeerId,
        height: u64,
        _view: u64,
        // For PoS, this `validator_set` parameter is interpreted as the *staked validators*.
        // The OrchestrationContainer will be responsible for fetching and passing this data.
        staked_validators: &[Vec<u8>],
        _known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        // The staked_validators list is assumed to be a serialized BTreeMap for this PoS engine.
        let stakers: BTreeMap<PublicKey, StakeAmount> =
            serde_json::from_slice(staked_validators.get(0).unwrap_or(&vec![]))
                .unwrap_or_default();

        if stakers.is_empty() {
            log::warn!("PoS `decide` called with no staked validators.");
            return ConsensusDecision::WaitForBlock;
        }

        let local_pk_b58 = local_peer_id.to_base58();
        if !stakers.contains_key(&local_pk_b58) {
            log::trace!("Not a staker, waiting for block.");
            return ConsensusDecision::WaitForBlock;
        }

        let designated_leader = self.select_leader(height, &stakers);

        if designated_leader.as_deref() == Some(local_pk_b58.as_str()) {
            log::info!("Consensus decision: Produce block for height {}.", height);
            ConsensusDecision::ProduceBlock(vec![])
        } else {
            ConsensusDecision::WaitForBlock
        }
    }

    async fn handle_block_proposal(&mut self, _block: Block<T>) -> Result<(), String> {
        // Validation logic is handled by the chain.
        Ok(())
    }
    
    async fn handle_view_change(
        &mut self,
        _from: PeerId,
        _height: u64,
        _new_view: u64,
    ) -> Result<(), String> {
        Ok(())
    }
    
    fn reset(&mut self, _height: u64) {
        // No height-specific state to reset in this simple implementation.
    }
}