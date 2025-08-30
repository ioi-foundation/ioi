// Path: crates/consensus/src/proof_of_stake.rs
use crate::ConsensusEngine;
use async_trait::async_trait;
use depin_sdk_api::chain::StakeAmount;
use depin_sdk_api::consensus::{ChainStateReader, ConsensusDecision, PenaltyMechanism};
use depin_sdk_api::state::StateAccessor;
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_types::app::{AccountId, Block, FailureReport};
use depin_sdk_types::codec;
use depin_sdk_types::error::{ConsensusError, StateError, TransactionError};
use depin_sdk_types::keys::STAKES_KEY_NEXT;
use libp2p::identity::PublicKey as Libp2pPublicKey;
use libp2p::PeerId;
use std::collections::{BTreeMap, HashSet};
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

    /// Selects a deterministic leader for a given block height based on stake weight.
    fn select_leader(
        &self,
        height: u64,
        stakers: &BTreeMap<AccountId, StakeAmount>,
    ) -> Option<AccountId> {
        let active_stakers: Vec<_> = stakers.iter().filter(|(_, stake)| **stake > 0).collect();
        if active_stakers.is_empty() {
            return None;
        }

        let total_stake: u128 = active_stakers
            .iter()
            .map(|(_, stake)| **stake as u128)
            .sum();
        if total_stake == 0 {
            return None;
        }

        let seed = height.to_le_bytes();
        let hash = sha256(&seed);
        let winning_ticket = u128::from_le_bytes(hash[0..16].try_into().unwrap()) % total_stake;

        let mut cumulative_stake: u128 = 0;
        for (validator_account_id, stake) in active_stakers {
            cumulative_stake += *stake as u128;
            if winning_ticket < cumulative_stake {
                return Some(*validator_account_id);
            }
        }
        None
    }
}

#[async_trait]
impl PenaltyMechanism for ProofOfStakeEngine {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccessor, // CHANGED: Receive StateAccessor directly
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        const PENALTY_PERCENTAGE: u8 = 10;

        let stakes_bytes = state.get(STAKES_KEY_NEXT)?.ok_or_else(|| {
            TransactionError::State(StateError::KeyNotFound("STAKES_KEY_NEXT missing".into()))
        })?;

        let mut stakes: BTreeMap<AccountId, u64> = codec::from_bytes_canonical(&stakes_bytes)?;

        if let Some(stake) = stakes.get_mut(&report.offender) {
            let slash_amount = (((*stake as u128) * (PENALTY_PERCENTAGE as u128)) / 100u128) as u64;
            *stake = stake.saturating_sub(slash_amount);
            state.insert(STAKES_KEY_NEXT, &codec::to_bytes_canonical(&stakes))?;
        } else {
            return Err(TransactionError::Invalid(format!(
                "Unknown validator to slash: {:?}",
                report.offender
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl<T: Clone + Send + 'static> ConsensusEngine<T> for ProofOfStakeEngine {
    async fn get_validator_data(
        &self,
        state_reader: &dyn ChainStateReader,
    ) -> Result<Vec<Vec<u8>>, ConsensusError> {
        let staker_map = state_reader
            .get_next_staked_validators()
            .await
            .map_err(|e| ConsensusError::ClientError(e.to_string()))?;

        let stakes_account_id_map: BTreeMap<AccountId, u64> = staker_map
            .into_iter()
            .filter_map(|(key_hex, stake)| {
                hex::decode(key_hex).ok().and_then(|bytes| {
                    if bytes.len() == 32 {
                        Some((AccountId(bytes.try_into().unwrap()), stake))
                    } else {
                        None
                    }
                })
            })
            .collect();

        let serialized_map = codec::to_bytes_canonical(&stakes_account_id_map);
        Ok(vec![serialized_map])
    }

    async fn decide(
        &mut self,
        local_public_key: &Libp2pPublicKey,
        height: u64,
        _view: u64,
        validator_data: &[Vec<u8>],
        _known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        let empty_vec = vec![];
        let staker_bytes = validator_data.first().unwrap_or(&empty_vec);

        let stakers: BTreeMap<AccountId, StakeAmount> =
            codec::from_bytes_canonical(staker_bytes).unwrap_or_default();

        let our_account_id = depin_sdk_types::app::account_id_from_pubkey(local_public_key);

        if !stakers.contains_key(&our_account_id) {
            return ConsensusDecision::WaitForBlock;
        }

        if let Some(leader_account_id) = self.select_leader(height, &stakers) {
            log::info!(
                "[PoS] Leader for height {}: {}",
                height,
                hex::encode(leader_account_id.0)
            );
            if leader_account_id == our_account_id {
                ConsensusDecision::ProduceBlock(vec![])
            } else {
                ConsensusDecision::WaitForBlock
            }
        } else {
            log::warn!(
                "[PoS] No leader could be elected for height {}. Waiting.",
                height
            );
            ConsensusDecision::WaitForBlock
        }
    }

    async fn handle_block_proposal(
        &mut self,
        block: Block<T>,
        state_reader: &dyn ChainStateReader,
    ) -> Result<(), ConsensusError> {
        let producer_pubkey = Libp2pPublicKey::try_decode_protobuf(&block.header.producer)
            .map_err(|e| {
                ConsensusError::BlockVerificationFailed(format!(
                    "Failed to decode producer public key: {}",
                    e
                ))
            })?;
        let header_hash = block.header.hash();
        if !producer_pubkey.verify(&header_hash, &block.header.signature) {
            return Err(ConsensusError::InvalidSignature);
        }

        let stakers_string_map = state_reader
            .get_next_staked_validators()
            .await
            .map_err(|e| {
                ConsensusError::ClientError(format!("Could not get staked validators: {}", e))
            })?;

        if stakers_string_map.is_empty() {
            return Err(ConsensusError::BlockVerificationFailed(
                "Cannot validate block, no stakers found".to_string(),
            ));
        }

        let stakers: BTreeMap<AccountId, u64> = stakers_string_map
            .into_iter()
            .filter_map(|(key_hex, stake)| {
                hex::decode(key_hex).ok().and_then(|bytes| {
                    if bytes.len() == 32 {
                        Some((AccountId(bytes.try_into().unwrap()), stake))
                    } else {
                        None
                    }
                })
            })
            .collect();

        let expected_leader_account_id = self.select_leader(block.header.height, &stakers).ok_or(
            ConsensusError::BlockVerificationFailed(
                "Leader selection failed for received block".to_string(),
            ),
        )?;

        let got_account_id = depin_sdk_types::app::account_id_from_pubkey(&producer_pubkey);

        if got_account_id != expected_leader_account_id {
            let expected_pk = state_reader
                .get_public_key_for_account(&expected_leader_account_id)
                .await
                .map_err(|e| {
                    ConsensusError::BlockVerificationFailed(format!(
                        "Could not get public key for expected leader: {}",
                        e
                    ))
                })?;

            return Err(ConsensusError::InvalidLeader {
                expected: expected_pk.to_peer_id(),
                got: producer_pubkey.to_peer_id(),
            });
        }

        log::info!(
            "Block proposal from valid PoS leader {:?} verified.",
            got_account_id
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
