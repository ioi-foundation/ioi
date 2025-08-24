// Path: crates/consensus/src/proof_of_stake.rs
use crate::{ConsensusDecision, ConsensusEngine};
use async_trait::async_trait;
use depin_sdk_api::chain::{AppChain, StakeAmount};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_client::WorkloadClient;
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_types::app::Block;
use libp2p::identity::PublicKey as Libp2pPublicKey;
use libp2p::PeerId;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;

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
        let mut active_stakers_iter = stakers.iter().filter(|(_, stake)| **stake > 0);
        let total_stake: u64 = active_stakers_iter.clone().map(|(_, stake)| *stake).sum();

        if total_stake == 0 {
            return None;
        }

        let seed = height.to_le_bytes();
        let hash = sha256(&seed);
        let winning_ticket = u64::from_le_bytes(hash[0..8].try_into().unwrap()) % total_stake;

        let mut cumulative_stake = 0;
        for (validator_pk_bytes, stake) in active_stakers_iter.clone() {
            cumulative_stake += *stake;
            if winning_ticket < cumulative_stake {
                return Some(validator_pk_bytes.clone());
            }
        }
        active_stakers_iter.next_back().map(|(key, _)| key.clone())
    }
}

#[async_trait]
impl<T: Clone + Send + 'static> ConsensusEngine<T> for ProofOfStakeEngine {
    async fn get_validator_data(
        &self,
        workload_client: &Arc<WorkloadClient>,
    ) -> Result<Vec<Vec<u8>>, String> {
        let staker_map = workload_client
            .get_next_staked_validators()
            .await
            .map_err(|e| e.to_string())?;
        let serialized_map =
            serde_json::to_vec(&staker_map).map_err(|e| format!("Serialization failed: {}", e))?;
        Ok(vec![serialized_map])
    }

    async fn decide(
        &mut self,
        local_peer_id: &PeerId,
        height: u64,
        _view: u64,
        validator_data: &[Vec<u8>],
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        let empty_vec = vec![];
        let staker_bytes = validator_data.first().unwrap_or(&empty_vec);

        let stakers_string_map: BTreeMap<String, StakeAmount> =
            serde_json::from_slice(staker_bytes).unwrap_or_default();

        let stakers: BTreeMap<Vec<u8>, StakeAmount> = stakers_string_map
            .into_iter()
            .filter(|(_, v)| *v > 0)
            .filter_map(|(k, v)| PeerId::from_str(&k).ok().map(|pid| (pid.to_bytes(), v)))
            .collect();

        let local_b58 = local_peer_id.to_base58();
        let decoded_b58: Vec<String> = stakers
            .keys()
            .filter_map(|k| PeerId::from_bytes(k).ok().map(|p| p.to_base58()))
            .collect();
        log::info!(
            "[PoS] height={} local={} stakers={:?}",
            height,
            local_b58,
            decoded_b58
        );

        let designated_bytes = match self.select_leader(height, &stakers) {
            Some(winner_bytes) => {
                let winner_peer_id = PeerId::from_bytes(&winner_bytes)
                    .map(|p| p.to_base58())
                    .unwrap_or_else(|_| "unknown".to_string());
                log::info!("[PoS] leader@{} = {}", height, winner_peer_id);
                winner_bytes
            }
            None => {
                let mut everyone: Vec<_> = known_peers.iter().cloned().collect();
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

        if designated_bytes == local_peer_id.to_bytes() {
            ConsensusDecision::ProduceBlock(vec![])
        } else {
            ConsensusDecision::WaitForBlock
        }
    }

    async fn handle_block_proposal<CS, TM, ST>(
        &mut self,
        block: Block<T>,
        _chain: &mut (dyn AppChain<CS, TM, ST> + Send + Sync),
        workload_client: &Arc<WorkloadClient>,
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
        let producer_pubkey = Libp2pPublicKey::try_decode_protobuf(&block.header.producer)
            .map_err(|e| format!("Failed to decode producer public key: {}", e))?;
        let header_hash = block.header.hash();
        if !producer_pubkey.verify(&header_hash, &block.header.signature) {
            return Err("Invalid block signature".to_string());
        }

        let stakers_string_map = workload_client
            .get_next_staked_validators()
            .await
            .map_err(|e| format!("Could not get staked validators: {}", e))?;

        if stakers_string_map.is_empty() {
            return Err("Cannot validate block, no stakers found".to_string());
        }

        let stakers: BTreeMap<Vec<u8>, u64> = stakers_string_map
            .into_iter()
            .filter_map(|(k, v)| PeerId::from_str(&k).ok().map(|pid| (pid.to_bytes(), v)))
            .collect();

        let expected_leader_bytes = self
            .select_leader(block.header.height, &stakers)
            .ok_or("Leader selection failed for received block")?;

        let producer_peer_id = producer_pubkey.to_peer_id();

        if producer_peer_id.to_bytes() != expected_leader_bytes {
            let expected_leader_peer_id = PeerId::from_bytes(&expected_leader_bytes)
                .map(|p| p.to_base58())
                .unwrap_or_else(|_| "unknown".to_string());
            return Err(format!(
                "Block producer {} is not the designated PoS leader for height {}. Expected {}.",
                producer_peer_id, block.header.height, expected_leader_peer_id
            ));
        }

        log::info!(
            "Block proposal from valid PoS leader {} verified.",
            producer_peer_id
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
