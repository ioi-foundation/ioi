// Path: crates/consensus/src/round_robin.rs

use crate::{ConsensusDecision, ConsensusEngine, PenaltyMechanism};
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, ChainView};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::ChainStateReader;
use ioi_api::state::{StateAccess, StateManager};
use ioi_types::app::{
    compute_interval_from_parent_state, read_validator_sets, AccountId, Block, BlockTimingParams,
    BlockTimingRuntime, ChainStatus, FailureReport,
};
use ioi_types::codec;
use ioi_types::error::{ConsensusError, StateError, TransactionError};
use ioi_types::keys::{
    BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, QUARANTINED_VALIDATORS_KEY, STATUS_KEY,
    VALIDATOR_SET_KEY,
};
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
        state: &mut dyn StateAccess,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        const MIN_LIVE_AUTHORITIES: usize = 2;
        let authorities_bytes = state
            .get(VALIDATOR_SET_KEY)?
            .ok_or_else(|| TransactionError::State(StateError::KeyNotFound))?;
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
            .map(|b| ioi_types::codec::from_bytes_canonical(&b).map_err(StateError::InvalidValue))
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
                &ioi_types::codec::to_bytes_canonical(&new_quarantined)?,
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
impl<T: Clone + Send + 'static + parity_scale_codec::Encode> ConsensusEngine<T>
    for RoundRobinBftEngine
{
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

        // Consistent timestamp calculation for this engine.
        let expected_timestamp_secs = {
            let parent_ts = if height > 1 {
                let status_bytes = match parent_view.get(STATUS_KEY).await {
                    Ok(Some(b)) => b,
                    _ => return ConsensusDecision::Stall,
                };
                let parent_status: ChainStatus = match codec::from_bytes_canonical(&status_bytes) {
                    Ok(s) => s,
                    Err(_) => return ConsensusDecision::Stall,
                };
                parent_status.latest_timestamp
            } else {
                0
            };

            let timing_params_bytes = match parent_view.get(BLOCK_TIMING_PARAMS_KEY).await {
                Ok(Some(b)) => b,
                _ => return ConsensusDecision::Stall,
            };
            let timing_runtime_bytes = match parent_view.get(BLOCK_TIMING_RUNTIME_KEY).await {
                Ok(Some(b)) => b,
                _ => return ConsensusDecision::Stall,
            };
            let timing_params: BlockTimingParams =
                match codec::from_bytes_canonical(&timing_params_bytes) {
                    Ok(x) => x,
                    Err(_) => return ConsensusDecision::Stall,
                };
            let timing_runtime: BlockTimingRuntime =
                match codec::from_bytes_canonical(&timing_runtime_bytes) {
                    Ok(x) => x,
                    Err(_) => return ConsensusDecision::Stall,
                };
            let interval = compute_interval_from_parent_state(
                &timing_params,
                &timing_runtime,
                height.saturating_sub(1),
                0,
            );
            parent_ts + interval
        };

        if validator_set.is_empty() {
            return if height == 1 {
                ConsensusDecision::ProduceBlock {
                    transactions: vec![],
                    expected_timestamp_secs,
                }
            } else {
                ConsensusDecision::Stall
            };
        }

        let leader_index = ((height + self.current_view)
            .checked_rem(validator_set.len() as u64)
            .unwrap_or(0)) as usize;
        if let Some(leader) = validator_set.get(leader_index) {
            if *leader == *our_account_id {
                ConsensusDecision::ProduceBlock {
                    transactions: vec![],
                    expected_timestamp_secs,
                }
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

        let parent_state_ref = ioi_api::chain::StateRef {
            height: header.height - 1,
            state_root: header.parent_state_root.as_ref().to_vec(),
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
            .ok_or_else(|| ConsensusError::StateAccess(StateError::KeyNotFound))?;
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

        let preimage = header.to_preimage_for_signing().map_err(|e| {
            ConsensusError::BlockVerificationFailed(format!("Failed to create preimage: {}", e))
        })?;
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
