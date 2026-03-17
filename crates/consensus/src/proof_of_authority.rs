use crate::common::penalty::apply_quarantine_penalty;
use crate::common::signature::verify_signature;
use crate::{ConsensusDecision, ConsensusEngine, PenaltyEngine, PenaltyMechanism};
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, ChainView, StateRef};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::ConsensusControl;
use ioi_api::state::{StateAccess, StateManager};
use ioi_system::SystemState;
use ioi_types::app::{
    account_id_from_key_material, compute_next_timestamp, compute_next_timestamp_ms,
    effective_set_for_height, read_validator_sets, timestamp_millis_to_legacy_seconds, AccountId,
    Block, BlockTimingParams, BlockTimingRuntime, ChainStatus, ConsensusVote, FailureReport,
    QuorumCertificate, SignatureSuite,
};
use ioi_types::codec;
use ioi_types::error::{ConsensusError, CoreError, StateError, TransactionError};
use ioi_types::keys::{
    BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, QUARANTINED_VALIDATORS_KEY, STATUS_KEY,
    VALIDATOR_SET_KEY,
};
use libp2p::PeerId;
use std::collections::{BTreeSet, HashSet};
use tracing::warn;

/// Helper retained for compatibility with older authority-style engines.
#[allow(dead_code)]
pub(crate) fn hash_key(suite: SignatureSuite, pubkey: &[u8]) -> Result<[u8; 32], CoreError> {
    account_id_from_key_material(suite, pubkey).map_err(|e| CoreError::Custom(e.to_string()))
}

#[derive(Debug, Clone)]
pub struct ProofOfAuthorityEngine;

impl Default for ProofOfAuthorityEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofOfAuthorityEngine {
    pub fn new() -> Self {
        Self
    }
}

impl ConsensusControl for ProofOfAuthorityEngine {
    fn experimental_sample_tip(&self) -> Option<([u8; 32], u32)> {
        None
    }

    fn observe_experimental_sample(&mut self, _hash: [u8; 32]) {}
}

#[async_trait]
impl PenaltyMechanism for ProofOfAuthorityEngine {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccess,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        apply_quarantine_penalty(state, report).await
    }
}

impl PenaltyEngine for ProofOfAuthorityEngine {
    fn apply(
        &self,
        sys: &mut dyn SystemState,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        let sets = sys
            .validators()
            .current_sets()
            .map_err(TransactionError::State)?;
        let authorities: Vec<AccountId> = sets
            .current
            .validators
            .iter()
            .map(|v| v.account_id)
            .collect();

        let quarantined = sys
            .quarantine()
            .get_all()
            .map_err(TransactionError::State)?;

        let min_live = 2;

        if !authorities.contains(&report.offender) {
            return Err(TransactionError::Invalid(
                "Offender is not an authority".into(),
            ));
        }

        if quarantined.contains(&report.offender) {
            return Ok(());
        }

        let live_after = authorities
            .len()
            .saturating_sub(quarantined.len())
            .saturating_sub(1);

        if live_after < min_live {
            return Err(TransactionError::Invalid(
                "Quarantine would jeopardize network liveness".into(),
            ));
        }

        sys.quarantine_mut()
            .insert(report.offender)
            .map_err(TransactionError::State)
    }
}

#[async_trait]
impl<T: Clone + Send + 'static + parity_scale_codec::Encode> ConsensusEngine<T>
    for ProofOfAuthorityEngine
{
    async fn decide(
        &mut self,
        our_account_id: &AccountId,
        height: u64,
        view: u64,
        parent_view: &dyn AnchoredStateView,
        _known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        let vs_bytes = match parent_view.get(VALIDATOR_SET_KEY).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                log::warn!(
                    "[PoA Decide] VALIDATOR_SET_KEY not found in state at height {}. Stalling.",
                    height
                );
                return ConsensusDecision::Stall;
            }
            Err(e) => {
                log::error!(
                    "[PoA Decide] Failed to get validator set from state view: {}. Stalling.",
                    e
                );
                return ConsensusDecision::Stall;
            }
        };

        let sets = match read_validator_sets(&vs_bytes) {
            Ok(sets) => sets,
            Err(_) => return ConsensusDecision::Stall,
        };

        let quarantined: BTreeSet<AccountId> =
            match parent_view.get(QUARANTINED_VALIDATORS_KEY).await {
                Ok(Some(bytes)) => codec::from_bytes_canonical(&bytes).unwrap_or_default(),
                _ => BTreeSet::new(),
            };

        let vs = effective_set_for_height(&sets, height);
        let validator_set: Vec<_> = vs
            .validators
            .iter()
            .map(|v| v.account_id)
            .filter(|id| !quarantined.contains(id))
            .collect();

        let (expected_timestamp_secs, expected_timestamp_ms) = {
            let timing_params_bytes = match parent_view.get(BLOCK_TIMING_PARAMS_KEY).await {
                Ok(Some(bytes)) => bytes,
                _ => return ConsensusDecision::Stall,
            };
            let timing_runtime_bytes = match parent_view.get(BLOCK_TIMING_RUNTIME_KEY).await {
                Ok(Some(bytes)) => bytes,
                _ => return ConsensusDecision::Stall,
            };

            let timing_params: BlockTimingParams =
                match codec::from_bytes_canonical(&timing_params_bytes) {
                    Ok(value) => value,
                    Err(_) => return ConsensusDecision::Stall,
                };
            let timing_runtime: BlockTimingRuntime =
                match codec::from_bytes_canonical(&timing_runtime_bytes) {
                    Ok(value) => value,
                    Err(_) => return ConsensusDecision::Stall,
                };

            let parent_status: ChainStatus = match parent_view.get(STATUS_KEY).await {
                Ok(Some(status_bytes)) => match codec::from_bytes_canonical(&status_bytes) {
                    Ok(status) => status,
                    Err(_) => return ConsensusDecision::Stall,
                },
                Ok(None) if height == 1 => ChainStatus::default(),
                _ => return ConsensusDecision::Stall,
            };

            let parent_gas_used = match parent_view.gas_used().await {
                Ok(gas_used) => gas_used,
                Err(_) => return ConsensusDecision::Stall,
            };

            match compute_next_timestamp_ms(
                &timing_params,
                &timing_runtime,
                height.saturating_sub(1),
                parent_status.latest_timestamp_ms_or_legacy(),
                parent_gas_used,
            ) {
                Some(timestamp_ms) => (
                    timestamp_millis_to_legacy_seconds(timestamp_ms),
                    timestamp_ms,
                ),
                None => return ConsensusDecision::Stall,
            }
        };

        let validator_count = validator_set.len() as u64;
        if validator_count == 0 {
            log::error!(
                "[PoA Decide] The effective validator set for height {} is empty. Stalling.",
                height
            );
            return ConsensusDecision::Stall;
        }

        let round_index = height.saturating_sub(1).saturating_add(view);
        let leader_index = (round_index % validator_count) as usize;

        match validator_set.get(leader_index) {
            Some(leader) if *leader == *our_account_id => ConsensusDecision::ProduceBlock {
                transactions: vec![],
                expected_timestamp_secs,
                expected_timestamp_ms,
                view,
                parent_qc: QuorumCertificate::default(),
                timeout_certificate: None,
            },
            Some(_) => ConsensusDecision::WaitForBlock,
            None => ConsensusDecision::Stall,
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

        if header.height == 0 {
            return Err(ConsensusError::BlockVerificationFailed(
                "Cannot process a proposal for the genesis block.".into(),
            ));
        }

        let parent_state_ref = StateRef {
            height: header.height - 1,
            state_root: header.parent_state_root.as_ref().to_vec(),
            block_hash: header.parent_hash,
        };

        let parent_view = chain_view.view_at(&parent_state_ref).await.map_err(|e| {
            warn!(
                target: "consensus",
                "Failed to resolve parent view for block proposal: {}",
                e
            );
            ConsensusError::StateAccess(StateError::Backend(e.to_string()))
        })?;

        let timing_params_bytes = parent_view
            .get(BLOCK_TIMING_PARAMS_KEY)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed("BlockTimingParams not found".into())
            })?;
        let timing_runtime_bytes = parent_view
            .get(BLOCK_TIMING_RUNTIME_KEY)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed("BlockTimingRuntime not found".into())
            })?;

        let timing_params: BlockTimingParams = codec::from_bytes_canonical(&timing_params_bytes)
            .map_err(|_| {
                ConsensusError::BlockVerificationFailed("Decode BlockTimingParams failed".into())
            })?;
        let timing_runtime: BlockTimingRuntime = codec::from_bytes_canonical(&timing_runtime_bytes)
            .map_err(|_| {
                ConsensusError::BlockVerificationFailed("Decode BlockTimingRuntime failed".into())
            })?;

        let parent_status: ChainStatus = match parent_view.get(STATUS_KEY).await {
            Ok(Some(status_bytes)) => codec::from_bytes_canonical(&status_bytes).map_err(|_| {
                ConsensusError::BlockVerificationFailed("Decode ChainStatus failed".into())
            })?,
            Ok(None) if header.height == 1 => ChainStatus::default(),
            _ => {
                return Err(ConsensusError::BlockVerificationFailed(
                    "ChainStatus missing in parent state".into(),
                ));
            }
        };

        let parent_gas_used = parent_view
            .gas_used()
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;

        let expected_ts = compute_next_timestamp(
            &timing_params,
            &timing_runtime,
            header.height - 1,
            parent_status.latest_timestamp,
            parent_gas_used,
        )
        .ok_or_else(|| ConsensusError::BlockVerificationFailed("Timestamp overflow".into()))?;

        if header.timestamp != expected_ts {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "Invalid timestamp: got {}, expected {}",
                header.timestamp, expected_ts
            )));
        }

        let vs_bytes = parent_view
            .get(VALIDATOR_SET_KEY)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| ConsensusError::StateAccess(StateError::KeyNotFound))?;
        let sets = read_validator_sets(&vs_bytes)
            .map_err(|e| ConsensusError::StateAccess(StateError::InvalidValue(e.to_string())))?;

        let quarantined: BTreeSet<AccountId> =
            match parent_view.get(QUARANTINED_VALIDATORS_KEY).await {
                Ok(Some(bytes)) => codec::from_bytes_canonical(&bytes).unwrap_or_default(),
                _ => BTreeSet::new(),
            };

        let vs = effective_set_for_height(&sets, header.height);
        let validator_entry = vs
            .validators
            .binary_search_by_key(&header.producer_account_id, |v| v.account_id)
            .map_or(None, |idx| Some(&vs.validators[idx]))
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed("Producer not in authority set".into())
            })?;

        if quarantined.contains(&header.producer_account_id) {
            return Err(ConsensusError::BlockVerificationFailed(
                "Producer is quarantined".into(),
            ));
        }

        let active_key_record = &validator_entry.consensus_key;

        if header.height < active_key_record.since_height {
            return Err(ConsensusError::BlockVerificationFailed(
                "Validator key not yet active at this height".into(),
            ));
        }

        if header.producer_key_suite != active_key_record.suite {
            return Err(ConsensusError::BlockVerificationFailed(
                "Header key suite does not match authorized consensus key".into(),
            ));
        }

        let pubkey = &header.producer_pubkey;
        let derived_hash = account_id_from_key_material(active_key_record.suite, pubkey)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;

        if derived_hash != active_key_record.public_key_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "Public key in header does not match authorized consensus key hash".into(),
            ));
        }

        let preimage = header.to_preimage_for_signing().map_err(|e| {
            ConsensusError::BlockVerificationFailed(format!("Failed to create preimage: {}", e))
        })?;
        verify_signature(
            &preimage,
            pubkey,
            active_key_record.suite,
            &header.signature,
            header.oracle_counter,
            &header.oracle_trace_hash,
        )?;

        let active_validator_ids: Vec<_> = vs
            .validators
            .iter()
            .map(|v| v.account_id)
            .filter(|id| !quarantined.contains(id))
            .collect();

        let validator_count = active_validator_ids.len() as u64;
        if validator_count == 0 {
            return Err(ConsensusError::BlockVerificationFailed(
                "Block cannot be validated against an empty validator set.".into(),
            ));
        }

        let round_index = header.height.saturating_sub(1).saturating_add(header.view);
        let leader_index = (round_index % validator_count) as usize;
        let expected_leader =
            active_validator_ids
                .get(leader_index)
                .ok_or(ConsensusError::InvalidLeader {
                    expected: AccountId::default(),
                    got: header.producer_account_id,
                })?;

        if *expected_leader != header.producer_account_id {
            return Err(ConsensusError::InvalidLeader {
                expected: *expected_leader,
                got: header.producer_account_id,
            });
        }

        Ok(())
    }

    async fn handle_vote(&mut self, _vote: ConsensusVote) -> Result<(), ConsensusError> {
        Ok(())
    }

    async fn handle_view_change(
        &mut self,
        _from: PeerId,
        _proof_bytes: &[u8],
    ) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn reset(&mut self, _height: u64) {}
}
