// Path: crates/transaction_models/src/unified/mod.rs
use crate::utxo::{UTXOModel, UTXOTransactionProof};
use async_trait::async_trait;
use bs58;
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::WorkloadContainer;
use depin_sdk_api::vm::ExecutionContext;
use depin_sdk_types::app::{ApplicationTransaction, ChainTransaction, StateEntry, SystemPayload};
use depin_sdk_types::error::{StateError, TransactionError};
use depin_sdk_types::keys::{
    AUTHORITY_SET_KEY, GOVERNANCE_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX, GOVERNANCE_VOTE_KEY_PREFIX,
    ORACLE_DATA_PREFIX, ORACLE_PENDING_REQUEST_PREFIX, STAKES_KEY_CURRENT, STAKES_KEY_NEXT,
};
use libp2p::identity::PublicKey as Libp2pPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum UnifiedProof<P> {
    UTXO(UTXOTransactionProof<P>),
    Application,
    System,
}

#[derive(Clone, Debug)]
pub struct UnifiedTransactionModel<CS: CommitmentScheme + Clone> {
    utxo_model: UTXOModel<CS>,
}

impl<CS: CommitmentScheme + Clone> UnifiedTransactionModel<CS> {
    pub fn new(scheme: CS) -> Self {
        Self {
            utxo_model: UTXOModel::new(scheme),
        }
    }
}

#[async_trait]
impl<CS: CommitmentScheme + Clone + Send + Sync> TransactionModel for UnifiedTransactionModel<CS>
where
    <CS as CommitmentScheme>::Proof: Serialize + for<'de> Deserialize<'de> + Clone,
{
    type Transaction = ChainTransaction;
    type CommitmentScheme = CS;
    type Proof = UnifiedProof<CS::Proof>;

    fn create_coinbase_transaction(
        &self,
        block_height: u64,
        recipient: &[u8],
    ) -> Result<Self::Transaction, TransactionError> {
        let utxo_tx = self
            .utxo_model
            .create_coinbase_transaction(block_height, recipient)?;
        Ok(ChainTransaction::Application(ApplicationTransaction::UTXO(
            utxo_tx,
        )))
    }

    fn validate<S>(&self, tx: &Self::Transaction, state: &S) -> Result<(), TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match tx {
            ChainTransaction::Application(app_tx) => match app_tx {
                ApplicationTransaction::UTXO(utxo_tx) => self.utxo_model.validate(utxo_tx, state),
                ApplicationTransaction::DeployContract {
                    signer_pubkey,
                    signature,
                    ..
                }
                | ApplicationTransaction::CallContract {
                    signer_pubkey,
                    signature,
                    ..
                } => {
                    let payload = app_tx.to_signature_payload();
                    let pubkey =
                        Libp2pPublicKey::try_decode_protobuf(signer_pubkey).map_err(|_| {
                            TransactionError::Invalid("Invalid public key format".into())
                        })?;
                    if !pubkey.verify(&payload, signature) {
                        return Err(TransactionError::Invalid("Invalid signature".into()));
                    }
                    Ok(())
                }
            },
            ChainTransaction::System(_) => Ok(()),
        }
    }

    async fn apply<ST>(
        &self,
        tx: &Self::Transaction,
        workload: &WorkloadContainer<ST>,
        _block_height: u64,
    ) -> Result<(), TransactionError>
    where
        ST: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + Send
            + Sync
            + 'static,
    {
        match tx {
            ChainTransaction::Application(app_tx) => match app_tx {
                ApplicationTransaction::UTXO(utxo_tx) => {
                    self.utxo_model
                        .apply(utxo_tx, workload, _block_height)
                        .await
                }
                ApplicationTransaction::DeployContract {
                    code,
                    signer_pubkey,
                    ..
                } => {
                    let (address, state_delta) = workload
                        .deploy_contract(code.clone(), signer_pubkey.clone())
                        .await
                        .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                    if !state_delta.is_empty() {
                        let state_tree_arc = workload.state_tree();
                        let mut state = state_tree_arc.lock().await;
                        let versioned_delta: Vec<(Vec<u8>, Vec<u8>)> = state_delta
                            .into_iter()
                            .map(|(key, value)| {
                                let entry = StateEntry {
                                    value,
                                    block_height: _block_height,
                                };
                                (key, serde_json::to_vec(&entry).unwrap())
                            })
                            .collect();
                        state.batch_set(&versioned_delta)?;
                    }
                    log::info!(
                        "Applied contract deployment at address: {}",
                        hex::encode(&address)
                    );
                    Ok(())
                }
                ApplicationTransaction::CallContract {
                    address,
                    input_data,
                    gas_limit,
                    signer_pubkey,
                    ..
                } => {
                    let context = ExecutionContext {
                        caller: signer_pubkey.clone(),
                        block_height: _block_height,
                        gas_limit: *gas_limit,
                        contract_address: address.clone(),
                    };
                    let (_output, state_delta) = workload
                        .call_contract(address.clone(), input_data.clone(), context)
                        .await
                        .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                    if !state_delta.is_empty() {
                        let state_tree_arc = workload.state_tree();
                        let mut state = state_tree_arc.lock().await;
                        let versioned_delta: Vec<(Vec<u8>, Vec<u8>)> = state_delta
                            .into_iter()
                            .map(|(key, value)| {
                                let entry = StateEntry {
                                    value,
                                    block_height: _block_height,
                                };
                                (key, serde_json::to_vec(&entry).unwrap())
                            })
                            .collect();
                        state.batch_set(&versioned_delta)?;
                    }
                    Ok(())
                }
            },
            ChainTransaction::System(sys_tx) => {
                let state_tree_arc = workload.state_tree();
                let mut state = state_tree_arc.lock().await;
                let payload_bytes = serde_json::to_vec(&sys_tx.payload)
                    .map_err(|e| TransactionError::Serialization(e.to_string()))?;

                match &sys_tx.payload {
                    SystemPayload::UpdateAuthorities { new_authorities } => {
                        let gov_key_bs58_bytes = state.get(GOVERNANCE_KEY)?.ok_or_else(|| {
                            TransactionError::Invalid("Governance key not found in state".into())
                        })?;
                        let gov_key_bs58: String = serde_json::from_slice(&gov_key_bs58_bytes)
                            .map_err(|_| {
                                TransactionError::Invalid(
                                    "Failed to deserialize governance key".into(),
                                )
                            })?;

                        let gov_pk_bytes = bs58::decode(gov_key_bs58).into_vec().map_err(|_| {
                            TransactionError::Invalid("Invalid base58 for governance key".into())
                        })?;
                        let ed25519_pk =
                            libp2p::identity::ed25519::PublicKey::try_from_bytes(&gov_pk_bytes)
                                .map_err(|_| {
                                    TransactionError::Invalid(
                                        "Could not decode Ed25519 public key".into(),
                                    )
                                })?;
                        let pubkey = Libp2pPublicKey::from(ed25519_pk);

                        if !pubkey.verify(&payload_bytes, &sys_tx.signature) {
                            return Err(TransactionError::Invalid(
                                "Invalid governance signature".into(),
                            ));
                        }

                        let serialized = serde_json::to_vec(new_authorities).unwrap();
                        state.insert(AUTHORITY_SET_KEY, &serialized)?;
                        log::info!("Applied verified authority set update.");
                    }
                    SystemPayload::Stake { amount } => {
                        const ED25519_PUBKEY_LEN: usize = 32;
                        if sys_tx.signature.len() < ED25519_PUBKEY_LEN {
                            return Err(TransactionError::Invalid(
                                "Invalid signature format".into(),
                            ));
                        }
                        let (pubkey_bytes, sig_bytes) =
                            sys_tx.signature.split_at(ED25519_PUBKEY_LEN);
                        let ed25519_pk =
                            libp2p::identity::ed25519::PublicKey::try_from_bytes(pubkey_bytes)
                                .map_err(|_| {
                                    TransactionError::Invalid(
                                        "Could not decode ed25519 public key from signature".into(),
                                    )
                                })?;
                        let pubkey = Libp2pPublicKey::from(ed25519_pk);

                        if !pubkey.verify(&payload_bytes, sig_bytes) {
                            return Err(TransactionError::Invalid(
                                "Invalid signature for stake".into(),
                            ));
                        }

                        let validator_pk_b58 = pubkey.to_peer_id().to_base58();
                        let stakes_bytes = state
                            .get(STAKES_KEY_NEXT)?
                            .unwrap_or_else(|| b"{}".to_vec());
                        let mut stakes: BTreeMap<String, u64> =
                            serde_json::from_slice(&stakes_bytes).map_err(|e| {
                                TransactionError::State(StateError::InvalidValue(e.to_string()))
                            })?;
                        let current_stake = stakes.entry(validator_pk_b58.clone()).or_insert(0);
                        *current_stake = current_stake.checked_add(*amount).ok_or_else(|| {
                            TransactionError::Invalid("Stake amount overflow".to_string())
                        })?;
                        log::info!(
                            "Staged stake of {} for validator {}.",
                            amount,
                            validator_pk_b58
                        );
                        let new_stakes_bytes = serde_json::to_vec(&stakes).unwrap();
                        state.insert(STAKES_KEY_NEXT, &new_stakes_bytes)?;
                    }
                    SystemPayload::Unstake { amount } => {
                        const ED25519_PUBKEY_LEN: usize = 32;
                        if sys_tx.signature.len() < ED25519_PUBKEY_LEN {
                            return Err(TransactionError::Invalid(
                                "Invalid signature format".into(),
                            ));
                        }
                        let (pubkey_bytes, sig_bytes) =
                            sys_tx.signature.split_at(ED25519_PUBKEY_LEN);
                        let ed25519_pk =
                            libp2p::identity::ed25519::PublicKey::try_from_bytes(pubkey_bytes)
                                .map_err(|_| {
                                    TransactionError::Invalid(
                                        "Could not decode ed25519 public key from signature".into(),
                                    )
                                })?;
                        let pubkey = Libp2pPublicKey::from(ed25519_pk);

                        if !pubkey.verify(&payload_bytes, sig_bytes) {
                            return Err(TransactionError::Invalid(
                                "Invalid signature for unstake".into(),
                            ));
                        }

                        let validator_pk_b58 = pubkey.to_peer_id().to_base58();
                        let stakes_bytes = state
                            .get(STAKES_KEY_NEXT)?
                            .unwrap_or_else(|| b"{}".to_vec());
                        let mut stakes: BTreeMap<String, u64> =
                            serde_json::from_slice(&stakes_bytes).map_err(|e| {
                                TransactionError::State(StateError::InvalidValue(e.to_string()))
                            })?;
                        let current_stake = stakes.entry(validator_pk_b58.clone()).or_insert(0);
                        *current_stake = current_stake.saturating_sub(*amount);
                        log::info!(
                            "Staged unstake of {} for validator {}.",
                            amount,
                            validator_pk_b58
                        );
                        let new_stakes_bytes = serde_json::to_vec(&stakes).unwrap();
                        state.insert(STAKES_KEY_NEXT, &new_stakes_bytes)?;
                    }
                    SystemPayload::SwapModule { .. } => {
                        log::debug!("SwapModule transaction observed in UnifiedTransactionModel, taking no action as it is handled by the Chain.");
                    }
                    SystemPayload::Vote {
                        proposal_id,
                        option,
                    } => {
                        const ED25519_PUBKEY_LEN: usize = 32;
                        if sys_tx.signature.len() < ED25519_PUBKEY_LEN {
                            return Err(TransactionError::Invalid(
                                "Invalid signature format for vote".into(),
                            ));
                        }
                        let (pubkey_bytes, _sig_bytes) =
                            sys_tx.signature.split_at(ED25519_PUBKEY_LEN);

                        let proposal_key =
                            [GOVERNANCE_PROPOSAL_KEY_PREFIX, &proposal_id.to_le_bytes()].concat();
                        let proposal_bytes = state.get(&proposal_key)?.ok_or_else(|| {
                            TransactionError::Invalid("Proposal does not exist".into())
                        })?;
                        let proposal: serde_json::Value = serde_json::from_slice(&proposal_bytes)
                            .map_err(|_| {
                            TransactionError::Invalid("Failed to parse proposal".into())
                        })?;

                        if proposal["status"] != "VotingPeriod" {
                            return Err(TransactionError::Invalid(
                                "Proposal is not in voting period".into(),
                            ));
                        }
                        if _block_height > proposal["voting_end_height"].as_u64().unwrap_or(0) {
                            return Err(TransactionError::Invalid(
                                "Voting period has ended".into(),
                            ));
                        }

                        let ed25519_pk =
                            libp2p::identity::ed25519::PublicKey::try_from_bytes(pubkey_bytes)
                                .map_err(|_| {
                                    TransactionError::Invalid(
                                        "Could not decode ed25519 pubkey".into(),
                                    )
                                })?;
                        let voter_peer_id = Libp2pPublicKey::from(ed25519_pk).to_peer_id();
                        let voter_bs58 = voter_peer_id.to_base58();

                        let vote_key = [
                            GOVERNANCE_VOTE_KEY_PREFIX,
                            &proposal_id.to_le_bytes(),
                            b"::",
                            voter_bs58.as_bytes(),
                        ]
                        .concat();
                        let vote_bytes = serde_json::to_vec(option).unwrap();
                        state.insert(&vote_key, &vote_bytes)?;

                        log::info!("Applied vote for proposal {}.", proposal_id);
                    }
                    SystemPayload::RequestOracleData { url, request_id } => {
                        let key =
                            [ORACLE_PENDING_REQUEST_PREFIX, &request_id.to_le_bytes()].concat();
                        let entry = StateEntry {
                            value: serde_json::to_vec(url).unwrap(),
                            block_height: _block_height,
                        };
                        let value = serde_json::to_vec(&entry).unwrap();
                        state.insert(&key, &value)?;
                        log::info!("Applied oracle data request for id: {}", request_id);
                    }
                    SystemPayload::SubmitOracleData {
                        request_id,
                        final_value,
                        consensus_proof,
                    } => {
                        // This is the critical security verification step.

                        // 1. Verify the pending request exists and then delete it.
                        let pending_key =
                            [ORACLE_PENDING_REQUEST_PREFIX, &request_id.to_le_bytes()].concat();
                        if state.get(&pending_key)?.is_none() {
                            return Err(TransactionError::Invalid(
                                "Oracle request not found or already processed".into(),
                            ));
                        }

                        // 2. Fetch the current validator stakes for quorum verification.
                        let stakes_bytes = state.get(STAKES_KEY_CURRENT)?.ok_or_else(|| {
                            TransactionError::Invalid("Validator stakes not found in state".into())
                        })?;
                        let stakes: BTreeMap<String, u64> =
                            serde_json::from_slice(&stakes_bytes).unwrap_or_default();
                        if stakes.is_empty() {
                            return Err(TransactionError::Invalid(
                                "Validator stake set is empty".into(),
                            ));
                        }

                        // 3. Verify the signatures in the consensus proof.
                        let total_stake: u64 = stakes.values().sum();
                        let quorum_threshold = (total_stake * 2) / 3 + 1;
                        let mut attested_stake: u64 = 0;
                        let mut verified_signers = HashSet::new();

                        for attestation in &consensus_proof.attestations {
                            let payload_to_verify = serde_json::to_vec(&(
                                &attestation.request_id,
                                &attestation.value,
                                &attestation.timestamp,
                            ))
                            .unwrap();

                            let mut signer_pk_b58: Option<String> = None;

                            // Find which validator this signature belongs to.
                            for (pk_b58, _) in &stakes {
                                if let Ok(pk_bytes) = bs58::decode(pk_b58).into_vec() {
                                    if let Ok(pubkey) =
                                        Libp2pPublicKey::try_decode_protobuf(&pk_bytes)
                                    {
                                        if pubkey.verify(&payload_to_verify, &attestation.signature)
                                        {
                                            signer_pk_b58 = Some(pk_b58.clone());
                                            break;
                                        }
                                    }
                                }
                            }

                            if let Some(pk_b58) = signer_pk_b58 {
                                // Ensure we don't count the same validator's stake twice.
                                if verified_signers.insert(pk_b58.clone()) {
                                    attested_stake += stakes.get(&pk_b58).unwrap_or(&0);
                                }
                            } else {
                                return Err(TransactionError::Invalid(
                                    "Consensus proof contains an invalid or unknown signature"
                                        .into(),
                                ));
                            }
                        }

                        // 4. Check if the total stake of verified signers meets the quorum.
                        if attested_stake < quorum_threshold {
                            return Err(TransactionError::Invalid(format!(
                                "Oracle quorum not met. Attested stake: {}, Required: {}",
                                attested_stake, quorum_threshold
                            )));
                        }

                        // 5. All checks passed. Write the final data to the state.
                        state.delete(&pending_key)?;
                        let final_key = [ORACLE_DATA_PREFIX, &request_id.to_le_bytes()].concat();
                        state.insert(&final_key, final_value)?;

                        log::info!("Applied and verified oracle data for id: {}", request_id);
                    }
                }
                Ok(())
            }
        }
    }

    fn generate_proof<S>(
        &self,
        tx: &Self::Transaction,
        state: &S,
    ) -> Result<Self::Proof, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match tx {
            ChainTransaction::Application(ApplicationTransaction::UTXO(utxo_tx)) => self
                .utxo_model
                .generate_proof(utxo_tx, state)
                .map(UnifiedProof::UTXO),
            ChainTransaction::Application(_) => Ok(UnifiedProof::Application),
            ChainTransaction::System(_) => Ok(UnifiedProof::System),
        }
    }

    fn verify_proof<S>(&self, proof: &Self::Proof, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match proof {
            UnifiedProof::UTXO(utxo_proof) => self.utxo_model.verify_proof(utxo_proof, state),
            UnifiedProof::Application => Ok(true),
            UnifiedProof::System => Ok(true),
        }
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        serde_json::to_vec(tx).map_err(|e| TransactionError::Serialization(e.to_string()))
    }
    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        serde_json::from_slice(data).map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}
