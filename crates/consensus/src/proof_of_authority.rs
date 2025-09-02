// Path: crates/consensus/src/proof_of_authority.rs
use crate::{ConsensusDecision, ConsensusEngine, PenaltyMechanism};
use async_trait::async_trait;
use depin_sdk_api::chain::{ChainView, StateView};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::consensus::ChainStateReader;
use depin_sdk_api::state::{StateAccessor, StateManager};
use depin_sdk_types::app::{
    account_id_from_key_material, AccountId, Block, FailureReport, SignatureSuite,
};
use depin_sdk_types::error::{ConsensusError, StateError, TransactionError};
use depin_sdk_types::keys::{AUTHORITY_SET_KEY, QUARANTINED_VALIDATORS_KEY};
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
    // This is a simplified implementation for the guide. A real implementation
    // would use the depin-sdk-crypto crate.
    let pk = PublicKey::try_decode_protobuf(public_key)
        .map_err(|_e| ConsensusError::InvalidSignature)?;
    if pk.verify(message, signature) {
        Ok(())
    } else {
        Err(ConsensusError::InvalidSignature)
    }
}

/// A centralized helper to hash a public key.
pub(crate) fn hash_key(suite: SignatureSuite, pubkey: &[u8]) -> [u8; 32] {
    account_id_from_key_material(suite, pubkey).unwrap()
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
        // Allow quarantine as long as at least 2 authorities remain live.
        const MIN_LIVE_AUTHORITIES: usize = 2;

        // 1. Get the current authority set directly.
        let authorities_bytes = state.get(AUTHORITY_SET_KEY)?.ok_or_else(|| {
            TransactionError::State(StateError::KeyNotFound(
                "Authority set not found in state".into(),
            ))
        })?;
        let authorities: Vec<AccountId> =
            depin_sdk_types::codec::from_bytes_canonical(&authorities_bytes)?;

        // 2. Directly check if the offender from the report is in the authority set.
        if !authorities.contains(&report.offender) {
            return Err(TransactionError::Invalid(
                "Reported offender is not a current authority.".into(),
            ));
        }

        // 3. Load the current quarantine list.
        let quarantined: BTreeSet<AccountId> = state
            .get(QUARANTINED_VALIDATORS_KEY)?
            .map(|b| {
                depin_sdk_types::codec::from_bytes_canonical(&b).map_err(StateError::InvalidValue)
            })
            .transpose()?
            .unwrap_or_default();

        // 4. Check liveness guard.
        if !quarantined.contains(&report.offender) {
            let live_after = authorities
                .len()
                .saturating_sub(quarantined.len())
                .saturating_sub(1); // removing offender
            if live_after < MIN_LIVE_AUTHORITIES {
                return Err(TransactionError::Invalid(
                    "Quarantine would jeopardize network liveness".into(),
                ));
            }
        }

        // 5. Add the offender to the quarantine list and save it.
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
impl<T: Clone + Send + 'static> ConsensusEngine<T> for ProofOfAuthorityEngine {
    async fn get_validator_data(
        &self,
        _state_reader: &dyn ChainStateReader, // No longer used, logic moved to handle_block_proposal
    ) -> Result<Vec<Vec<u8>>, ConsensusError> {
        // This function is now a placeholder; the real logic uses StateView.
        // Returning an empty vec is safe as the new `decide` handles it.
        Ok(vec![])
    }

    async fn decide(
        &mut self,
        our_account_id: &AccountId, // Passed in from OrchestrationContainer
        height: u64,
        view: u64,
        parent_view: &dyn StateView, // Pass the parent state view for deterministic reads
        _known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        let validator_set = match parent_view.validator_set().await {
            Ok(vs) => vs,
            Err(_) => return ConsensusDecision::Stall,
        };
        debug_assert!(
            validator_set.windows(2).all(|w| w[0] < w[1]),
            "Validator set must be sorted"
        );

        if validator_set.is_empty() {
            // Stall consensus if no authorities are defined, except at genesis.
            return if height == 1 {
                ConsensusDecision::ProduceBlock(vec![])
            } else {
                ConsensusDecision::Stall
            };
        }
        let leader_index = ((height + view) % validator_set.len() as u64) as usize;
        if validator_set[leader_index] == *our_account_id {
            ConsensusDecision::ProduceBlock(vec![])
        } else {
            ConsensusDecision::WaitForBlock
        }
    }

    async fn handle_block_proposal<CS, ST>(
        &mut self,
        block: Block<T>,
        chain_view: &dyn ChainView<CS, ST>, // Method is now generic over CS and ST
    ) -> Result<(), ConsensusError>
    where
        CS: CommitmentScheme + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        let header = &block.header;

        // 1. Obtain a read-only view of the PARENT state.
        let parent_view = chain_view
            .view_at(&header.parent_state_root)
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;

        // 2. Membership Check (against parent state)
        let validator_set = parent_view
            .validator_set()
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;
        if validator_set
            .binary_search(&header.producer_account_id)
            .is_err()
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "Producer not in authority set".into(),
            ));
        }

        // 3. Active Key Record Check (against parent state)
        let active_key = parent_view
            .active_consensus_key(&header.producer_account_id)
            .await
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed("Producer has no active key".into())
            })?;

        // 4. Activation Height Gating
        if header.height < active_key.since_height {
            return Err(ConsensusError::BlockVerificationFailed(
                "Key not yet active at this height".into(),
            ));
        }

        // 5. Header Key Match Check
        if active_key.suite != header.producer_key_suite
            || active_key.pubkey_hash != header.producer_pubkey_hash
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "Header key material does not match active key record".into(),
            ));
        }

        // 6. Signature Verification
        let pubkey = &header.producer_pubkey;
        let derived_hash = hash_key(active_key.suite, pubkey);
        if derived_hash != active_key.pubkey_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "Public key in header does not match its hash".into(),
            ));
        }
        let preimage = header.to_preimage_for_signing();
        verify_signature(&preimage, pubkey, active_key.suite, &header.signature)?;

        // Ensure public key length is valid for its suite
        let expected_len = match active_key.suite {
            SignatureSuite::Ed25519 => 32, // Raw key length
            SignatureSuite::Dilithium2 => 1312,
        };
        // Libp2p keys are encoded, so we can't do a simple length check.
        // A better check would be to try decoding. For now, we'll simplify.
        if pubkey.len() != expected_len && active_key.suite == SignatureSuite::Dilithium2 {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "Malformed pubkey for suite {:?}",
                active_key.suite
            )));
        }

        // 7. Leadership Check (if applicable)...
        // This PoA implementation uses a simple round-robin schedule based on height.
        let leader_index = (header.height % validator_set.len() as u64) as usize;
        if validator_set[leader_index] != header.producer_account_id {
            return Err(ConsensusError::InvalidLeader {
                expected: validator_set[leader_index],
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
