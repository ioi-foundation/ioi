// Path: crates/consensus/src/proof_of_stake.rs
use crate::{ConsensusDecision, ConsensusEngine};
use async_trait::async_trait;
use bs58;
use depin_sdk_api::chain::{AppChain, StakeAmount};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::WorkloadContainer;
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_types::app::Block;
use libp2p::identity::PublicKey as Libp2pPublicKey;
use libp2p::PeerId;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Debug;
use std::str::FromStr;

pub struct ProofOfStakeEngine {}

impl Default for ProofOfStakeEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofOfStakeEngine {
    pub fn new() -> Self {
        Self {}
    }

    fn select_leader(
        &self,
        height: u64,
        stakers: &BTreeMap<Vec<u8>, StakeAmount>,
    ) -> Option<Vec<u8>> {
        let active_stakers_iter = stakers.iter().filter(|(_, stake)| **stake > 0);

        let total_stake: u64 = active_stakers_iter.clone().map(|(_, stake)| *stake).sum();

        if total_stake == 0 {
            return None;
        }

        let seed = height.to_le_bytes();
        let hash = sha256(seed);
        let winning_ticket = u64::from_le_bytes(hash[0..8].try_into().unwrap()) % total_stake;

        let mut cumulative_stake = 0;
        for (validator_pk_bytes, stake) in active_stakers_iter.clone() {
            cumulative_stake += *stake;
            if winning_ticket < cumulative_stake {
                return Some(validator_pk_bytes.clone());
            }
        }

        active_stakers_iter.last().map(|(key, _)| key.clone())
    }
}

#[async_trait]
impl<T: Clone + Send + 'static> ConsensusEngine<T> for ProofOfStakeEngine {
    async fn decide(
        &mut self,
        local_peer_id: &PeerId,
        height: u64,
        _view: u64,
        staked_validators: &[Vec<u8>],
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        // --- ENHANCED LOGGING ---
        log::info!(
            "[PoS Engine] Decide called for height {}. Received staker data blob size: {} bytes.",
            height,
            staked_validators.get(0).map_or(0, |v| v.len())
        );
        // --- END LOGGING ---

        let empty_vec = vec![];
        let staker_bytes = staked_validators.first().unwrap_or(&empty_vec);

        let stakers: BTreeMap<Vec<u8>, StakeAmount> =
            if let Ok(m) = serde_json::from_slice::<BTreeMap<String, u64>>(staker_bytes) {
                // SAFER: parse as PeerId, then use .to_bytes() for exact canonical bytes
                m.into_iter()
                    .filter(|(_, v)| *v > 0)
                    .filter_map(|(k, v)| PeerId::from_str(&k).ok().map(|pid| (pid.to_bytes(), v)))
                    .collect()
            } else if let Ok(m) = serde_json::from_slice::<BTreeMap<Vec<u8>, u64>>(staker_bytes) {
                m.into_iter().filter(|(_, v)| *v > 0).collect()
            } else {
                if !staker_bytes.is_empty() {
                    log::error!(
                        "[PoS] failed to decode staker map ({} bytes)",
                        staker_bytes.len()
                    );
                }
                BTreeMap::new()
            };

        let local_b58 = local_peer_id.to_base58();
        let decoded_b58: Vec<String> = stakers
            .keys()
            .map(|k| bs58::encode(k).into_string())
            .collect();
        log::info!(
            "[PoS] height={} local={} stakers={:?}",
            height,
            local_b58,
            decoded_b58
        );

        let designated_bytes = match self.select_leader(height, &stakers) {
            Some(winner_bytes) => {
                log::info!(
                    "[PoS] leader@{} = {}",
                    height,
                    bs58::encode(&winner_bytes).into_string()
                );
                winner_bytes
            }
            None => {
                // Fallback when total stake == 0: pick lowest PeerId deterministically to prevent stall.
                let mut everyone = known_peers.iter().cloned().collect::<Vec<_>>();
                if !everyone.contains(local_peer_id) {
                    everyone.push(*local_peer_id);
                }
                everyone.sort();
                let fallback_leader = everyone.first().cloned().unwrap_or(*local_peer_id);
                let fallback_bytes = fallback_leader.to_bytes();
                log::warn!(
                    "[PoS] zero/empty stake at height {}, fallback leader={}",
                    height,
                    fallback_leader.to_base58()
                );
                fallback_bytes
            }
        };

        if designated_bytes.as_slice() == local_peer_id.to_bytes().as_slice() {
            ConsensusDecision::ProduceBlock(vec![])
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
        if block.header.height != chain.status().height + 1 {
            return Err(format!(
                "Invalid block height. Expected {}, got {}",
                chain.status().height + 1,
                block.header.height
            ));
        }

        let producer_pubkey = Libp2pPublicKey::try_decode_protobuf(&block.header.producer)
            .map_err(|e| format!("Failed to decode producer public key: {}", e))?;
        let header_hash = block.header.hash();
        if !producer_pubkey.verify(&header_hash, &block.header.signature) {
            return Err("Invalid block signature".to_string());
        }

        let stakers_string_map = chain
            .get_staked_validators(workload)
            .await
            .map_err(|e| format!("Could not get staked validators: {}", e))?;
        if stakers_string_map.is_empty() {
            return Err("Cannot validate block, no stakers found".to_string());
        }

        // --- FIX: Use robust PeerId parsing for verification, matching the producer side ---
        let stakers: BTreeMap<Vec<u8>, u64> = stakers_string_map
            .into_iter()
            .filter_map(|(k, v)| PeerId::from_str(&k).ok().map(|pid| (pid.to_bytes(), v)))
            .collect();

        let expected_leader_bytes = self
            .select_leader(block.header.height, &stakers)
            .ok_or("Leader selection failed for received block")?;

        let producer_peer_id_bytes = producer_pubkey.to_peer_id().to_bytes();

        if producer_peer_id_bytes != expected_leader_bytes {
            return Err(format!(
                "Block producer {} is not the designated PoS leader for height {}. Expected {}.",
                producer_pubkey.to_peer_id(),
                block.header.height,
                bs58::encode(&expected_leader_bytes).into_string()
            ));
        }

        log::info!(
            "Block proposal from valid PoS leader {} verified.",
            producer_pubkey.to_peer_id()
        );
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

    fn reset(&mut self, _height: u64) {}
}
