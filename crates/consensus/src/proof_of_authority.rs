// Path: crates/consensus/src/proof_of_authority.rs
use crate::{ConsensusDecision, ConsensusEngine, PenaltyMechanism};
use async_trait::async_trait;
use depin_sdk_api::chain::{AnchoredStateView, ChainView};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::consensus::ChainStateReader;
use depin_sdk_api::state::{StateAccessor, StateManager};
use depin_sdk_types::app::{
    account_id_from_key_material, read_validator_sets, AccountId, Block, FailureReport,
    SignatureSuite,
};
use depin_sdk_types::error::{ConsensusError, CoreError, StateError, TransactionError};
use depin_sdk_types::keys::{QUARANTINED_VALIDATORS_KEY, VALIDATOR_SET_KEY};
use libp2p::identity::PublicKey;
use libp2p::PeerId;
use std::collections::{BTreeSet, HashSet};

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
                &depin_sdk_types::codec::to_bytes_canonical(&new_quarantined)?,
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

        let leader_index = ((height + view)
            .checked_rem(validator_set.len() as u64)
            .unwrap_or(0)) as usize;

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

        // The logic for fetching the ActiveKeyRecord from a view is now restored.
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
            let record: depin_sdk_types::app::ActiveKeyRecord =
                depin_sdk_types::codec::from_bytes_canonical(&bytes).map_err(|e| {
                    ConsensusError::BlockVerificationFailed(format!(
                        "Failed to decode ActiveKeyRecord: {}",
                        e
                    ))
                })?;
            active_key_suite = record.suite;
            active_key_hash = record.pubkey_hash;
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

        let leader_index = (header
            .height
            .checked_rem(validator_set.len() as u64)
            .unwrap_or(0)) as usize;

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
