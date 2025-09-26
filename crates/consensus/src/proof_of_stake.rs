// Path: crates/consensus/src/proof_of_stake.rs
use crate::{ConsensusDecision, ConsensusEngine, PenaltyMechanism};
use async_trait::async_trait;
use depin_sdk_api::chain::{ChainView, StateView};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::consensus::ChainStateReader;
use depin_sdk_api::state::{StateAccessor, StateManager};
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_types::app::{
    read_validator_sets, write_validator_sets, AccountId, Block, FailureReport, ValidatorSetV1,
    ValidatorSetsV1,
};
use depin_sdk_types::error::{ConsensusError, StateError, TransactionError};
use depin_sdk_types::keys::{STATUS_KEY, VALIDATOR_SET_KEY}; // Import STATUS_KEY
use std::collections::HashSet;

// Re-use helpers from PoA
use crate::proof_of_authority::{hash_key, verify_signature};

use hex;

/// A pure helper function to select the correct validator set for a given height.
/// It never mutates state.
fn effective_set_for_height(sets: &ValidatorSetsV1, h: u64) -> &ValidatorSetV1 {
    if let Some(next) = &sets.next {
        if h >= next.effective_from_height && !next.validators.is_empty() && next.total_weight > 0 {
            return next;
        }
    }
    &sets.current
}

// [+] DEBUGGING: Add a helper to log validator set details.
fn log_vs(label: &str, h: u64, sets: &ValidatorSetsV1) {
    let log_one = |name: &str, vs: &ValidatorSetV1| {
        log::info!(
            "[PoS Decide H={}] {}: eff_from={} members={} total_weight={}",
            h,
            name,
            vs.effective_from_height,
            vs.validators.len(),
            vs.total_weight
        );
        for v in vs.validators.iter().take(8) {
            log::info!(
                "  - acct=0x{} w={}",
                hex::encode(v.account_id.as_ref()),
                v.weight
            );
        }
    };
    log::info!("[PoS Decide H={}] --- {} DUMP ---", h, label.to_uppercase());
    log_one("current", &sets.current);
    if let Some(n) = &sets.next {
        log_one("next", n);
    }
}

#[derive(Debug, Clone)]
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
    fn select_leader(&self, height: u64, vs: &ValidatorSetV1) -> Option<AccountId> {
        if vs.validators.is_empty() || vs.total_weight == 0 {
            return None;
        }

        let seed = height.to_le_bytes();
        let hash = sha256(seed);
        let winning_ticket = u128::from_le_bytes(hash[0..16].try_into().unwrap()) % vs.total_weight;

        let mut cumulative_weight: u128 = 0;
        // The validator set is guaranteed to be sorted by account_id, ensuring determinism.
        for validator in &vs.validators {
            cumulative_weight += validator.weight;
            if winning_ticket < cumulative_weight {
                return Some(validator.account_id);
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
        const PENALTY_PERCENTAGE: u128 = 10; // Use u128 for calculations

        let blob_bytes = state.get(VALIDATOR_SET_KEY)?.ok_or_else(|| {
            TransactionError::State(StateError::KeyNotFound("ValidatorSet not found".into()))
        })?;

        let mut sets = read_validator_sets(&blob_bytes)?;
        let mut vs = sets.current; // Penalties apply to the current set
        let mut validator_found = false;

        for validator in &mut vs.validators {
            if validator.account_id == report.offender {
                let slash_amount = (validator.weight * PENALTY_PERCENTAGE) / 100;
                validator.weight = validator.weight.saturating_sub(slash_amount);
                validator_found = true;
                break;
            }
        }

        if !validator_found {
            return Err(TransactionError::Invalid(format!(
                "Unknown validator to slash: {:?}",
                report.offender
            )));
        }

        // FIX: Re-sort the validator set to maintain deterministic order after modification.
        // Failure to do so can cause a consensus fork.
        vs.validators
            .sort_by(|a, b| a.account_id.cmp(&b.account_id));
        vs.total_weight = vs.validators.iter().map(|v| v.weight).sum();
        sets.current = vs;
        state.insert(VALIDATOR_SET_KEY, &write_validator_sets(&sets))?;

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
        log::info!(
            "[PoS Decide H={}] Node 0x{} starting consensus tick. Parent anchor: 0x{}",
            height,
            hex::encode(&our_account_id.as_ref()[..4]), // Log a short prefix of our ID
            hex::encode(parent_view.state_anchor().as_ref())
        );

        let status_at_parent = parent_view.get(STATUS_KEY).await;
        log::info!(
            "[PoS Decide H={}] Probe STATUS_KEY at parent anchor {} -> ok={} present={}",
            height,
            hex::encode(parent_view.state_anchor().as_ref()),
            status_at_parent.is_ok(),
            status_at_parent
                .as_ref()
                .ok()
                .and_then(|opt| opt.as_ref())
                .is_some()
        );

        let maybe_vs_bytes = parent_view.get(VALIDATOR_SET_KEY).await;

        let vs_bytes = match maybe_vs_bytes {
            Ok(Some(bytes)) => {
                log::info!(
                    "[PoS Decide H={}] Successfully read validator set blob ({} bytes) via StateView.",
                    height,
                    bytes.len()
                );
                bytes
            }
            Ok(None) => {
                log::error!(
                    "[PoS Decide H={}] StateView reported None for VALIDATOR_SET_KEY at parent anchor {}. Stalling.",
                    height,
                    hex::encode(parent_view.state_anchor().as_ref())
                );
                return ConsensusDecision::Stall;
            }
            Err(e) => {
                log::error!(
                    "[PoS Decide H={}] StateView.get(VALIDATOR_SET_KEY) error: {}. Stalling.",
                    height,
                    e
                );
                return ConsensusDecision::Stall;
            }
        };

        let sets: ValidatorSetsV1 = match read_validator_sets(&vs_bytes) {
            Ok(s) => s,
            Err(e) => {
                log::error!(
                    "[PoS Decide H={}] Could not decode ValidatorSet blob: {}. Stalling.",
                    height,
                    e
                );
                return ConsensusDecision::Stall;
            }
        };
        // [+] DEBUGGING: Log the state of the validator set from the parent view.
        log_vs("parent_vs", height, &sets);
        let vs = effective_set_for_height(&sets, height);

        log::debug!(
            "[PoS Decide H={}] Using effective validator set with {} members and total weight {}",
            height,
            vs.validators.len(),
            vs.total_weight
        );

        if vs.validators.is_empty() {
            log::warn!(
                "[PoS Decide H={}] Validator set is empty. Stalling.",
                height
            );
            return ConsensusDecision::Stall;
        }

        if let Some(leader_account_id) = self.select_leader(height, vs) {
            log::info!(
                "[PoS Decide H={}] Selected leader: 0x{}. Our ID: 0x{}",
                height,
                hex::encode(leader_account_id.as_ref()),
                hex::encode(our_account_id.as_ref())
            );
            if leader_account_id == *our_account_id {
                log::info!(
                    "[PoS Decide H={}] DECISION: We are the leader. Will ProduceBlock.",
                    height
                );
                ConsensusDecision::ProduceBlock(vec![])
            } else {
                log::info!(
                    "[PoS Decide H={}] DECISION: We are not the leader. Will WaitForBlock.",
                    height
                );
                ConsensusDecision::WaitForBlock
            }
        } else {
            log::error!(
                "[PoS Decide H={}] Leader selection returned None. DECISION: Stalling.",
                height
            );
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
        let producer_short_id = hex::encode(&header.producer_account_id.as_ref()[..4]);

        log::info!(
            "[PoS Verify H={}] Received block proposal from 0x{}",
            header.height,
            producer_short_id
        );

        let parent_state_anchor = header
            .parent_state_root
            .to_anchor()
            .map_err(|e| ConsensusError::StateAccess(StateError::InvalidValue(e.to_string())))?;
        log::debug!(
            "[PoS Verify H={}] Obtaining parent view at anchor 0x{}",
            header.height,
            hex::encode(parent_state_anchor.as_ref())
        );
        let parent_view = chain_view
            .view_at(&parent_state_anchor)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;

        log::debug!(
            "[PoS Verify H={}] Reading validator set from parent view...",
            header.height
        );
        let vs_bytes = parent_view
            .get(VALIDATOR_SET_KEY)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::StateAccess(StateError::KeyNotFound("ValidatorSet".into()))
            })?;
        let sets: ValidatorSetsV1 = read_validator_sets(&vs_bytes)
            .map_err(|e| ConsensusError::StateAccess(StateError::InvalidValue(e.to_string())))?;
        let vs = effective_set_for_height(&sets, header.height);
        log::debug!(
            "[PoS Verify H={}] Validator set read successfully.",
            header.height
        );

        let v_entry = vs
            .validators
            .iter()
            .find(|v| v.account_id == header.producer_account_id)
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed("Producer not in validator set".into())
            })?;
        log::debug!(
            "[PoS Verify H={}] Producer 0x{} found in validator set.",
            header.height,
            producer_short_id
        );

        let active_key = &v_entry.consensus_key;

        log::info!(
            "[PoS Verify H={}] Producer acct=0x{} header.suite={:?} state.suite={:?} since={} hash.match.header={} hash.match.state={}",
            header.height,
            hex::encode(header.producer_account_id.as_ref()),
            header.producer_key_suite,
            active_key.suite,
            active_key.since_height,
            (hash_key(header.producer_key_suite, &header.producer_pubkey).map_or(false, |h| h == header.producer_pubkey_hash)),
            (active_key.pubkey_hash == hash_key(active_key.suite, &header.producer_pubkey).unwrap_or_default()),
        );

        if header.height < active_key.since_height {
            return Err(ConsensusError::BlockVerificationFailed(
                "Key not yet active at this height".into(),
            ));
        }
        if active_key.suite != header.producer_key_suite {
            return Err(ConsensusError::BlockVerificationFailed(
                "Header key suite does not match active key".into(),
            ));
        }

        let derived_hash = hash_key(active_key.suite, &header.producer_pubkey)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;

        if header.producer_pubkey_hash != derived_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "Header public key hash mismatch".into(),
            ));
        }
        if active_key.pubkey_hash != derived_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "State active key hash mismatch".into(),
            ));
        }

        let preimage = header.to_preimage_for_signing();
        verify_signature(
            &preimage,
            &header.producer_pubkey,
            active_key.suite,
            &header.signature,
        )?;
        log::debug!(
            "[PoS Verify H={}] Block signature verified successfully.",
            header.height
        );

        let expected_leader = self.select_leader(header.height, vs).ok_or_else(|| {
            ConsensusError::BlockVerificationFailed("Leader selection failed".to_string())
        })?;
        log::debug!(
            "[PoS Verify H={}] Expected leader is 0x{}",
            header.height,
            hex::encode(expected_leader.as_ref())
        );

        if header.producer_account_id != expected_leader {
            return Err(ConsensusError::InvalidLeader {
                expected: expected_leader,
                got: header.producer_account_id,
            });
        }

        log::info!(
            "[PoS Verify H={}] Block proposal from valid leader 0x{} verified.",
            header.height,
            producer_short_id
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