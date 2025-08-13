// Path: crates/consensus/src/proof_of_authority.rs
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
use std::collections::HashSet;
use std::fmt::Debug;

pub struct ProofOfAuthorityEngine {}

impl Default for ProofOfAuthorityEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofOfAuthorityEngine {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl<T: Clone + Send + 'static> ConsensusEngine<T> for ProofOfAuthorityEngine {
    async fn decide(
        &mut self,
        local_peer_id: &PeerId,
        height: u64,
        view: u64,
        // For PoA, this `validator_set` parameter is interpreted as the *authority set*.
        authority_set: &[Vec<u8>],
        _known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        if authority_set.is_empty() {
            // Genesis node or misconfiguration. The first node produces.
            return ConsensusDecision::ProduceBlock(vec![]);
        }

        let leader_index = ((height + view) % authority_set.len() as u64) as usize;

        // This check is safe because we return early if authority_set is empty.
        let designated_leader = &authority_set[leader_index];

        if designated_leader == &local_peer_id.to_bytes() {
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
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static + Debug,
        CS::Commitment: Send + Sync + Debug,
    {
        // 1. Basic structural validation
        if block.header.height != chain.status().height + 1 {
            return Err(format!(
                "Invalid block height. Expected {}, got {}",
                chain.status().height + 1,
                block.header.height
            ));
        }

        // 2. Verify Producer Signature
        let producer_pubkey = PublicKey::try_decode_protobuf(&block.header.producer)
            .map_err(|e| format!("Failed to decode producer public key: {}", e))?;
        let header_hash = block.header.hash_for_signing();
        if !producer_pubkey.verify(&header_hash, &block.header.signature) {
            return Err("Invalid block signature".to_string());
        }

        // 3. Verify Producer is a valid authority for this height
        let authority_set = chain.get_authority_set(workload).await
            .map_err(|e| format!("Could not get authority set: {}", e))?;
        if authority_set.is_empty() {
            return Err("Cannot validate block, authority set is empty".to_string());
        }
        
        // For PoA, the view is implicitly 0 as we don't handle view changes.
        let leader_index = (block.header.height % authority_set.len() as u64) as usize;
        let expected_leader_bytes = &authority_set[leader_index];
        let producer_peer_id = producer_pubkey.to_peer_id();

        if &producer_peer_id.to_bytes() != expected_leader_bytes {
            return Err(format!(
                "Block producer is not the designated leader for height {}",
                block.header.height
            ));
        }

        log::info!("Block proposal from valid authority {} verified.", producer_peer_id);
        Ok(())
    }

    async fn handle_view_change(
        &mut self,
        _from: PeerId,
        _height: u64,
        _new_view: u64,
    ) -> Result<(), String> {
        // This Proof-of-Authority engine is not a BFT-style protocol and does not
        // have a concept of view changes based on peer votes. Leader failure is
        // handled by the orchestrator by waiting for the next block slot, which
        // will have a different leader based on the deterministic rotation.
        Ok(())
    }

    fn reset(&mut self, _height: u64) {
        // This engine is stateless, so there is no round-specific state to clear.
    }
}