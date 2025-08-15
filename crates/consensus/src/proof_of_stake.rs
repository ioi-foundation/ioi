// Path: crates/consensus/src/proof_of_stake.rs
use crate::{ConsensusDecision, ConsensusEngine};
use async_trait::async_trait;
use depin_sdk_api::chain::{AppChain, PublicKey, StakeAmount};
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
        stakers: &BTreeMap<PublicKey, StakeAmount>,
    ) -> Option<PublicKey> {
        if stakers.is_empty() {
            return None;
        }

        let total_stake = stakers.values().sum::<StakeAmount>();
        if total_stake == 0 {
            return stakers.keys().next().cloned();
        }

        let seed = height.to_le_bytes();
        let hash = sha256(seed);
        let winning_ticket = u64::from_le_bytes(hash[0..8].try_into().unwrap()) % total_stake;

        let mut cumulative_stake = 0;
        for (validator_pk_b58, stake) in stakers {
            cumulative_stake += stake;
            if winning_ticket < cumulative_stake {
                return Some(validator_pk_b58.clone());
            }
        }

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
        staked_validators: &[Vec<u8>],
        _known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        let stakers: BTreeMap<PublicKey, StakeAmount> =
            serde_json::from_slice(staked_validators.first().unwrap_or(&vec![]))
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

        let stakers = chain
            .get_staked_validators(workload)
            .await
            .map_err(|e| format!("Could not get staked validators: {}", e))?;
        if stakers.is_empty() {
            return Err("Cannot validate block, no stakers found".to_string());
        }

        let expected_leader_b58 = self
            .select_leader(block.header.height, &stakers)
            .ok_or("Leader selection failed for received block")?;

        let producer_peer_id_b58 = producer_pubkey.to_peer_id().to_base58();

        if producer_peer_id_b58 != expected_leader_b58 {
            return Err(format!(
                "Block producer {} is not the designated PoS leader for height {}. Expected {}.",
                producer_peer_id_b58, block.header.height, expected_leader_b58
            ));
        }

        log::info!(
            "Block proposal from valid PoS leader {} verified.",
            producer_peer_id_b58
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
