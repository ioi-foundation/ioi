// Path: crates/consensus/src/round_robin.rs

use crate::{ConsensusDecision, ConsensusEngine, PenaltyMechanism};
use async_trait::async_trait;
use depin_sdk_api::chain::{AnchoredStateView, ChainView};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::consensus::ChainStateReader;
use depin_sdk_api::state::{StateAccessor, StateManager};
use depin_sdk_types::app::{read_validator_sets, AccountId, Block, FailureReport};
use depin_sdk_types::error::{ConsensusError, StateError, TransactionError};
use depin_sdk_types::keys::{QUARANTINED_VALIDATORS_KEY, VALIDATOR_SET_KEY};
use libp2p::PeerId;
use std::collections::{BTreeSet, HashSet};
use std::time::{Duration, Instant};

// Re-use PoA helpers since this is also an authority-based model.
use crate::proof_of_authority::{hash_key, verify_signature};

#[derive(Debug, Clone)]
pub struct RoundRobinBftEngine {
    current_view: u64,
    view_timeout: Duration,
    last_tick: Instant,
}

impl RoundRobinBftEngine {
    pub fn new(view_timeout: Duration) -> Self {
        Self {
            current_view: 0,
            view_timeout,
            last_tick: Instant::now(),
        }
    }
}

#[async_trait]
impl PenaltyMechanism for RoundRobinBftEngine {
    // This penalty mechanism is identical to the one in PoA.
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccessor,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        const MIN_LIVE_AUTHORITIES: usize = 2;
        let authorities_bytes = state.get(VALIDATOR_SET_KEY)?.ok_or_else(|| {
            TransactionError::State(StateError::KeyNotFound(
                "Authority set not found in state".into(),
            ))
        })?;
        let sets = read_validator_sets(&authorities_bytes)?;
        let authorities: Vec<AccountId> = sets
            .current
            .validators
            .into_iter()
            .map(|v| v.account_id)
            .collect();
        if !authorities.contains(&report.offender) {
            return Err(TransactionError::Invalid(
                "Reported offender is not a current authority.".into(),
            ));
        }

        let quarantined: BTreeSet<AccountId> = state
            .get(QUARANTINED_VALIDATORS_KEY)?
            .map(|b| {
                depin_sdk_types::codec::from_bytes_canonical(&b).map_err(StateError::InvalidValue)
            })
            .transpose()?
            .unwrap_or_default();

        if !quarantined.contains(&report.offender) {
            let live_after = authorities
                .len()
                .saturating_sub(quarantined.len())
                .saturating_sub(1);
            if live_after < MIN_LIVE_AUTHORITIES {
                return Err(TransactionError::Invalid(
                    "Quarantine would jeopardize network liveness".into(),
                ));
            }
        }

        let mut new_quarantined = quarantined;
        if new_quarantined.insert(report.offender) {
            state.insert(
                QUARANTINED_VALIDATORS_KEY,
                &depin_sdk_types::codec::to_bytes_canonical(&new_quarantined),
            )?;
            log::info!(
                "[PoA penalty] Quarantined authority: 0x{} (set size = {})",
                hex::encode(report.offender.as_ref()),
                new_quarantined.len()
            );
        }
        Ok(())
    }
}

#[async_trait]
impl<T: Clone + Send + 'static> ConsensusEngine<T> for RoundRobinBftEngine {
    async fn get_validator_data(
        &self,
        _state_reader: &dyn ChainStateReader,
    ) -> Result<Vec<Vec<u8>>, ConsensusError> {
        Ok(vec![])
    }

    async fn decide(
        &mut self,
        our_account_id: &AccountId,
        height: u64,
        _view: u64,
        parent_view: &dyn AnchoredStateView,
        _known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        if self.last_tick.elapsed() > self.view_timeout {
            self.current_view += 1;
            self.last_tick = Instant::now();
            return ConsensusDecision::ProposeViewChange;
        }

        let vs_bytes = match parent_view.get(VALIDATOR_SET_KEY).await {
            Ok(Some(bytes)) => bytes,
            _ => return ConsensusDecision::Stall,
        };

        let sets = match read_validator_sets(&vs_bytes) {
            Ok(s) => s,
            _ => return ConsensusDecision::Stall,
        };
        let validator_set: Vec<_> = sets
            .current
            .validators
            .into_iter()
            .map(|v| v.account_id)
            .collect();

        if validator_set.is_empty() {
            return if height == 1 {
                ConsensusDecision::ProduceBlock(vec![])
            } else {
                ConsensusDecision::Stall
            };
        }

        let leader_index = ((height + self.current_view) % validator_set.len() as u64) as usize;
        if validator_set[leader_index] == *our_account_id {
            ConsensusDecision::ProduceBlock(vec![])
        } else {
            ConsensusDecision::WaitForBlock
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

        let parent_state_ref = depin_sdk_api::chain::StateRef {
            height: header.height - 1,
            state_root: header.parent_state_root.as_ref().try_into().map_err(|_| {
                ConsensusError::BlockVerificationFailed("Invalid parent state root".into())
            })?,
            block_hash: header.parent_hash,
        };

        let parent_view = chain_view
            .view_at(&parent_state_ref)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;

        let vs_bytes = parent_view
            .get(VALIDATOR_SET_KEY)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::StateAccess(StateError::KeyNotFound("ValidatorSet".into()))
            })?;
        let sets = read_validator_sets(&vs_bytes)
            .map_err(|e| ConsensusError::StateAccess(StateError::InvalidValue(e.to_string())))?;
        let validator_set: Vec<_> = sets
            .current
            .validators
            .into_iter()
            .map(|v| v.account_id)
            .collect();

        if validator_set
            .binary_search(&header.producer_account_id)
            .is_err()
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "Producer not in authority set".into(),
            ));
        }

        let pubkey = &header.producer_pubkey;
        let derived_hash = hash_key(header.producer_key_suite, pubkey)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        if header.producer_pubkey_hash != derived_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "Public key in header does not match its hash".into(),
            ));
        }

        let preimage = header.to_preimage_for_signing();
        verify_signature(
            &preimage,
            pubkey,
            header.producer_key_suite,
            &header.signature,
        )?;

        // For RoundRobin, leader depends on view. We can't verify this without knowing the remote peer's view.
        // A full BFT implementation would have votes that establish the view. For this simplified model,
        // we accept any valid authority's block.
        // A stricter check could be added if view numbers were part of the block header.

        Ok(())
    }

    async fn handle_view_change(
        &mut self,
        _from: PeerId,
        _height: u64,
        new_view: u64,
    ) -> Result<(), ConsensusError> {
        if new_view > self.current_view {
            self.current_view = new_view;
            self.last_tick = Instant::now();
        }
        Ok(())
    }

    fn reset(&mut self, _height: u64) {
        self.current_view = 0;
        self.last_tick = Instant::now();
    }
}
