// Path: crates/consensus/src/proof_of_authority.rs
use crate::{ConsensusDecision, ConsensusEngine, PenaltyMechanism};
use async_trait::async_trait;
use depin_sdk_api::consensus::ChainStateReader;
use depin_sdk_api::state::StateAccessor;
use depin_sdk_types::app::{AccountId, Block, FailureReport};
use depin_sdk_types::error::{ConsensusError, StateError, TransactionError};
use depin_sdk_types::keys::{AUTHORITY_SET_KEY, QUARANTINED_VALIDATORS_KEY};
use libp2p::identity::PublicKey;
use libp2p::PeerId;
use std::collections::{BTreeSet, HashSet};

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
impl PenaltyMechanism for ProofOfAuthorityEngine {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccessor, // CHANGED: Receive StateAccessor directly
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
impl<T: Clone + Send + 'static> ConsensusEngine<T> for ProofOfAuthorityEngine {
    async fn get_validator_data(
        &self,
        state_reader: &dyn ChainStateReader,
    ) -> Result<Vec<Vec<u8>>, ConsensusError> {
        state_reader
            .get_authority_set()
            .await
            .map_err(|e| ConsensusError::ClientError(e))
    }

    async fn decide(
        &mut self,
        local_public_key: &PublicKey,
        height: u64,
        view: u64,
        validator_data: &[Vec<u8>],
        _known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        if validator_data.is_empty() {
            return ConsensusDecision::ProduceBlock(vec![]);
        }

        let local_peer_id_bytes = local_public_key.to_peer_id().to_bytes();
        let leader_index = ((height + view) % validator_data.len() as u64) as usize;
        let designated_leader_bytes = &validator_data[leader_index];

        if designated_leader_bytes == &local_peer_id_bytes {
            ConsensusDecision::ProduceBlock(vec![])
        } else {
            ConsensusDecision::WaitForBlock
        }
    }

    async fn handle_block_proposal(
        &mut self,
        block: Block<T>,
        state_reader: &dyn ChainStateReader,
    ) -> Result<(), ConsensusError> {
        let producer_pubkey =
            PublicKey::try_decode_protobuf(&block.header.producer).map_err(|e| {
                ConsensusError::BlockVerificationFailed(format!("Invalid producer key: {}", e))
            })?;
        let header_hash = block.header.hash();
        if !producer_pubkey.verify(&header_hash, &block.header.signature) {
            return Err(ConsensusError::InvalidSignature);
        }

        let authority_set = state_reader
            .get_authority_set()
            .await
            .map_err(|e| ConsensusError::ClientError(e))?;
        if authority_set.is_empty() {
            return Err(ConsensusError::BlockVerificationFailed(
                "Authority set is empty".to_string(),
            ));
        }

        let leader_index = (block.header.height % authority_set.len() as u64) as usize;
        let expected_leader_bytes = &authority_set[leader_index];
        let producer_peer_id = producer_pubkey.to_peer_id();

        if producer_peer_id.to_bytes() != *expected_leader_bytes {
            let expected = PeerId::from_bytes(expected_leader_bytes).map_err(|e| {
                ConsensusError::BlockVerificationFailed(format!("Invalid authority peerid: {}", e))
            })?;
            return Err(ConsensusError::InvalidLeader {
                expected,
                got: producer_peer_id,
            });
        }

        log::info!(
            "Block proposal from valid authority {} verified.",
            producer_peer_id
        );
        Ok(())
    }

    async fn handle_view_change(
        &mut self,
        _from: PeerId,
        _height: u64,
        _new_view: u64,
    ) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn reset(&mut self, _height: u64) {}
}
