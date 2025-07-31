// In: crates/consensus/src/proof_of_authority.rs

use crate::{ConsensusDecision, ConsensusEngine};
use async_trait::async_trait;
use depin_sdk_core::app::Block;
use libp2p::PeerId;
use std::collections::HashSet;

pub struct ProofOfAuthorityEngine {}

impl ProofOfAuthorityEngine {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl<T: Send + 'static> ConsensusEngine<T> for ProofOfAuthorityEngine {
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
        let designated_leader = &authority_set[leader_index];

        if designated_leader == &local_peer_id.to_bytes() {
            ConsensusDecision::ProduceBlock(vec![])
        } else {
            ConsensusDecision::WaitForBlock
        }
    }

    async fn handle_block_proposal(&mut self, _block: Block<T>) -> Result<(), String> { Ok(()) }
    async fn handle_view_change(&mut self, _from: PeerId, _height: u64, _new_view: u64) -> Result<(), String> { Ok(()) }
    fn reset(&mut self, _height: u64) {} // Stateless engine, nothing to reset.
}