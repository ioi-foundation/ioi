// Path: crates/consensus/src/proof_of_stake.rs
use crate::{ConsensusDecision, ConsensusEngine};
use async_trait::async_trait;
use depin_sdk_api::chain::{ChainView, StakeAmount, StateView};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::consensus::{ChainStateReader, PenaltyMechanism};
use depin_sdk_api::state::{StateAccessor, StateManager};
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_types::app::{AccountId, Block, FailureReport};
use depin_sdk_types::codec;
use depin_sdk_types::error::{ConsensusError, StateError, TransactionError};
use depin_sdk_types::keys::{STAKES_KEY_CURRENT, STAKES_KEY_NEXT};
use std::collections::{BTreeMap, HashSet};

// Re-use helpers from PoA
use crate::proof_of_authority::{hash_key, verify_signature};

#[derive(Debug, Clone)]
pub struct ProofOfStakeEngine {}

impl Default for ProofOfStakeEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads the stakes map that will be active for the next block from a given state view.
async fn read_stakes(
    view: &dyn StateView,
) -> Result<BTreeMap<AccountId, StakeAmount>, ConsensusError> {
    // --- FIX: Read from STAKES_KEY_NEXT, with a fallback to STAKES_KEY_CURRENT ---
    // The leader for the upcoming block (H) is determined by the state of stakes
    // at the end of the previous block (H-1), which is stored in the 'next' key.
    match view
        .get(STAKES_KEY_NEXT)
        .await
        .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
    {
        Some(bytes) => {
            let stakes: BTreeMap<AccountId, u64> = codec::from_bytes_canonical(&bytes)
                .map_err(|e| ConsensusError::StateAccess(StateError::InvalidValue(e)))?;
            Ok(stakes)
        }
        None => {
            // If NEXT is not found, fall back to CURRENT. This is important for the genesis block
            // where only CURRENT is initialized.
            match view
                .get(STAKES_KEY_CURRENT)
                .await
                .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            {
                Some(bytes) => {
                    let stakes: BTreeMap<AccountId, u64> = codec::from_bytes_canonical(&bytes)
                        .map_err(|e| ConsensusError::StateAccess(StateError::InvalidValue(e)))?;
                    Ok(stakes)
                }
                None => Ok(BTreeMap::new()),
            }
        }
    }
}

impl ProofOfStakeEngine {
    pub fn new() -> Self {
        Self {}
    }

    /// Selects a deterministic leader for a given block height based on stake weight.
    #[allow(dead_code)]
    fn select_leader(
        &self,
        height: u64,
        stakers: &BTreeMap<AccountId, StakeAmount>,
    ) -> Option<AccountId> {
        let mut active_stakers: Vec<_> = stakers.iter().filter(|(_, stake)| **stake > 0).collect();
        if active_stakers.is_empty() {
            return None;
        }

        // Explicitly sort by AccountId to guarantee deterministic iteration for leader selection.
        active_stakers.sort_by(|(a, _), (b, _)| a.as_ref().cmp(b.as_ref()));

        let total_stake: u128 = active_stakers
            .iter()
            .map(|(_, stake)| **stake as u128)
            .sum();
        if total_stake == 0 {
            return None;
        }

        let seed = height.to_le_bytes();
        let hash = sha256(seed);
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
        state: &mut dyn StateAccessor,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        const PENALTY_PERCENTAGE: u8 = 10;

        let base_stakes_bytes = state
            .get(STAKES_KEY_NEXT)?
            .or(state.get(STAKES_KEY_CURRENT)?);

        let mut stakes: BTreeMap<AccountId, u64> = match base_stakes_bytes {
            Some(bytes) => codec::from_bytes_canonical(&bytes)?,
            None => {
                return Err(TransactionError::State(StateError::KeyNotFound(
                    "No current or next stake map found".into(),
                )))
            }
        };

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
        _state_reader: &dyn ChainStateReader,
    ) -> Result<Vec<Vec<u8>>, ConsensusError> {
        // Placeholder, no longer used.
        Ok(vec![])
    }

    async fn decide(
        &mut self,
        our_account_id: &AccountId,
        height: u64,
        _view: u64,
        parent_view: &dyn StateView,
        _known_peers: &HashSet<libp2p::PeerId>,
    ) -> ConsensusDecision<T> {
        let stakes = match read_stakes(parent_view).await {
            Ok(s) => s,
            Err(_) => return ConsensusDecision::Stall,
        };

        if stakes.is_empty() {
            return if height == 1 {
                ConsensusDecision::ProduceBlock(vec![])
            } else {
                ConsensusDecision::Stall
            };
        }

        if let Some(leader_account_id) = self.select_leader(height, &stakes) {
            // --- FIX: The log message was using the Debug format for AccountId instead of hex.
            log::info!(
                "[PoS] Leader for height {}: AccountId(0x{})",
                height,
                hex::encode(leader_account_id.as_ref())
            );
            if leader_account_id == *our_account_id {
                ConsensusDecision::ProduceBlock(vec![])
            } else {
                ConsensusDecision::WaitForBlock
            }
        } else {
            ConsensusDecision::Stall
        }
    }

    async fn handle_block_proposal<CS, ST>(
        &mut self,
        block: Block<T>,
        chain_view: &dyn ChainView<CS, ST>,
    ) -> Result<(), ConsensusError>
    where
        CS: CommitmentScheme + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        let header = &block.header;

        let parent_view_box = chain_view
            .view_at(&header.parent_state_root)
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;
        let parent_view = parent_view_box.as_ref();

        let validator_set = parent_view
            .validator_set()
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;
        if validator_set
            .binary_search(&header.producer_account_id)
            .is_err()
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "Producer not in validator set".into(),
            ));
        }

        let active_key = parent_view
            .active_consensus_key(&header.producer_account_id)
            .await
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed("Producer has no active key".into())
            })?;

        if header.height < active_key.since_height {
            return Err(ConsensusError::BlockVerificationFailed(
                "Key not yet active at this height".into(),
            ));
        }

        if active_key.suite != header.producer_key_suite
            || active_key.pubkey_hash != header.producer_pubkey_hash
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "Header key material does not match active key record".into(),
            ));
        }

        let pubkey = &header.producer_pubkey;
        let derived_hash = hash_key(active_key.suite, pubkey);
        if derived_hash != active_key.pubkey_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "Public key in header does not match its hash".into(),
            ));
        }
        let preimage = header.to_preimage_for_signing();
        verify_signature(&preimage, pubkey, active_key.suite, &header.signature)?;

        let stakes = read_stakes(parent_view).await?;
        let expected_leader = self.select_leader(header.height, &stakes).ok_or_else(|| {
            ConsensusError::BlockVerificationFailed("Leader selection failed".to_string())
        })?;

        if header.producer_account_id != expected_leader {
            return Err(ConsensusError::InvalidLeader {
                expected: expected_leader,
                got: header.producer_account_id,
            });
        }

        log::info!(
            "Block proposal from valid PoS leader {:?} verified.",
            header.producer_account_id
        );
        Ok(())
    }

    async fn handle_view_change(
        &mut self,
        _from: libp2p::PeerId,
        _height: u64,
        _new_view: u64,
    ) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn reset(&mut self, _height: u64) {}
}
