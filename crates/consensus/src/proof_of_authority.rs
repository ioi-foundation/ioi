// Path: crates/consensus/src/proof_of_authority.rs
use crate::{ConsensusDecision, ConsensusEngine, PenaltyMechanism};
use async_trait::async_trait;
use ioi_types::app::{
    account_id_from_key_material, compute_interval_from_parent_state, read_validator_sets,
    AccountId, Block, BlockTimingParams, BlockTimingRuntime, ChainStatus, FailureReport,
    SignatureSuite, ValidatorSetV1, ValidatorSetsV1,
};
use ioi_types::codec;
use ioi_types::error::{ConsensusError, CoreError, StateError, TransactionError};
use ioi_types::keys::{
    BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, QUARANTINED_VALIDATORS_KEY, STATUS_KEY,
    VALIDATOR_SET_KEY,
};
use ioi_api::chain::{AnchoredStateView, ChainView};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::ChainStateReader;
use ioi_api::state::{StateAccessor, StateManager};
use libp2p::identity::PublicKey;
use libp2p::PeerId;
use std::collections::{BTreeSet, HashSet};
use tracing::warn;

/// A centralized helper for verifying cryptographic signatures.
pub(crate) fn verify_signature(
    message: &[u8],
    public_key: &[u8],
    _suite: SignatureSuite,
    signature: &[u8],
) -> Result<(), ConsensusError> {
    let pk = PublicKey::try_decode_protobuf(public_key)
        .map_err(|_e| ConsensusError::InvalidSignature)?;
    if pk.verify(message, signature) {
        Ok(())
    } else {
        Err(ConsensusError::InvalidSignature)
    }
}

/// A centralized helper to hash a public key.
pub(crate) fn hash_key(suite: SignatureSuite, pubkey: &[u8]) -> Result<[u8; 32], CoreError> {
    account_id_from_key_material(suite, pubkey).map_err(|e| CoreError::Custom(e.to_string()))
}

#[derive(Debug, Clone)]
pub struct ProofOfAuthorityEngine {}

/// Selects the validator set that is effective for the given height.
/// Mirrors the logic from the PoS engine for consistency.
fn effective_set_for_height(sets: &ValidatorSetsV1, h: u64) -> &ValidatorSetV1 {
    if let Some(next) = &sets.next {
        if h >= next.effective_from_height && !next.validators.is_empty() && next.total_weight > 0 {
            return next;
        }
    }
    &sets.current
}

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
        state: &mut dyn StateAccessor,
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
            .map(|b| {
                ioi_types::codec::from_bytes_canonical(&b).map_err(StateError::InvalidValue)
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
    for ProofOfAuthorityEngine
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
        view: u64,
        parent_view: &dyn AnchoredStateView, // REFACTORED: Now uses the AnchoredStateView trait.
        _known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        let vs_bytes_result = parent_view.get(VALIDATOR_SET_KEY).await;
        let vs_bytes = match vs_bytes_result {
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
            Ok(s) => s,
            Err(_) => return ConsensusDecision::Stall,
        };
        // FIX: Use the effective validator set for the target height.
        let vs = effective_set_for_height(&sets, height);
        let mut validator_set: Vec<_> = vs.validators.iter().map(|v| v.account_id).collect();
        // >>> Normalize order across nodes <<<
        validator_set.sort();

        if validator_set.is_empty() {
            return if height == 1 {
                ConsensusDecision::ProduceBlock(vec![])
            } else {
                ConsensusDecision::Stall
            };
        }

        let n = validator_set.len() as u64;
        // Height 1 -> index 0, Height 2 -> index 1, etc. (then add view)
        let round = height.saturating_sub(1).saturating_add(view);
        let leader_index = (round % n) as usize;

        if let Some(leader) = validator_set.get(leader_index) {
            if *leader == *our_account_id {
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

        // [+] GUARD: Prevent underflow for genesis block proposals
        if header.height == 0 {
            return Err(ConsensusError::BlockVerificationFailed(
                "Cannot process a proposal for the genesis block.".into(),
            ));
        }

        let parent_state_ref = ioi_api::chain::StateRef {
            height: header.height - 1,
            // [+] FIX: Use .to_vec() to support variable-length state roots.
            state_root: header.parent_state_root.as_ref().to_vec(),
            block_hash: header.parent_hash,
        };

        let parent_view = chain_view.view_at(&parent_state_ref).await.map_err(|e| {
            warn!(
                target: "consensus",
                "Failed to resolve parent view for block proposal: {}", e
            );
            ConsensusError::StateAccess(StateError::Backend(e.to_string()))
        })?;

        // [+] VERIFY TIMESTAMP (Deterministic from parent state)
        let timing_params_bytes = parent_view
            .get(BLOCK_TIMING_PARAMS_KEY)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;
        let timing_runtime_bytes = parent_view
            .get(BLOCK_TIMING_RUNTIME_KEY)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;

        let timing_params: BlockTimingParams =
            codec::from_bytes_canonical(&timing_params_bytes.ok_or_else(|| {
                ConsensusError::BlockVerificationFailed("BlockTimingParams not found".into())
            })?)
            .map_err(|_| {
                ConsensusError::BlockVerificationFailed("Decode BlockTimingParams failed".into())
            })?;
        let timing_runtime: BlockTimingRuntime =
            codec::from_bytes_canonical(&timing_runtime_bytes.ok_or_else(|| {
                ConsensusError::BlockVerificationFailed("BlockTimingRuntime not found".into())
            })?)
            .map_err(|_| {
                ConsensusError::BlockVerificationFailed("Decode BlockTimingRuntime failed".into())
            })?;

        // Parent timestamp from parent ChainStatus in state (deterministic and universal).
        let status_bytes = parent_view
            .get(STATUS_KEY)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "ChainStatus missing in parent state".into(),
                )
            })?;
        let parent_status: ChainStatus =
            codec::from_bytes_canonical(&status_bytes).map_err(|_| {
                ConsensusError::BlockVerificationFailed("Decode ChainStatus failed".into())
            })?;
        let parent_timestamp = parent_status.latest_timestamp;

        let parent_gas_used_placeholder = 0u64; // TODO: replace when gas_used is recorded.
        let parent_height = header.height - 1;
        let interval = compute_interval_from_parent_state(
            &timing_params,
            &timing_runtime,
            parent_height,
            parent_gas_used_placeholder,
        );
        let expected_ts = parent_timestamp
            .checked_add(interval)
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
        // [+] FIX: Use the effective validator set for the block being verified.
        let vs = effective_set_for_height(&sets, header.height);
        let mut validator_set: Vec<_> = vs.validators.iter().map(|v| v.account_id).collect();
        validator_set.sort();
        if validator_set
            .binary_search(&header.producer_account_id)
            .is_err()
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "Producer not in authority set".into(),
            ));
        }

        let active_key_suite;
        let active_key_hash;
        {
            const KEY_PREFIX: &[u8] = b"identity::key_record::";
            let key = [KEY_PREFIX, header.producer_account_id.as_ref()].concat();
            let bytes = parent_view
                .get(&key)
                .await
                .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed("Producer has no active key".into())
                })?;
            let record: ioi_types::app::ActiveKeyRecord =
                ioi_types::codec::from_bytes_canonical(&bytes).map_err(|e| {
                    ConsensusError::BlockVerificationFailed(format!(
                        "Failed to decode ActiveKeyRecord: {}",
                        e
                    ))
                })?;
            active_key_suite = record.suite;
            active_key_hash = record.public_key_hash;
        }

        let pubkey = &header.producer_pubkey;
        let derived_hash = hash_key(active_key_suite, pubkey)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        if derived_hash != active_key_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "Public key in header does not match its hash".into(),
            ));
        }
        let preimage = header.to_preimage_for_signing().map_err(|e| {
            ConsensusError::BlockVerificationFailed(format!("Failed to create preimage: {}", e))
        })?;
        verify_signature(&preimage, pubkey, active_key_suite, &header.signature)?;

        let n = validator_set.len() as u64;
        // Verify using the same schedule: Height 1 -> index 0
        let leader_index = (header.height.saturating_sub(1) % n) as usize;

        let expected_leader =
            validator_set
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
