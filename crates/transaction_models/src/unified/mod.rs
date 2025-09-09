// Path: crates/transaction_models/src/unified/mod.rs

use crate::utxo::{UTXOModel, UTXOTransactionProof};
use async_trait::async_trait;
use depin_sdk_api::chain::ChainView;
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::{StateAccessor, StateManager};
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::vm::ExecutionContext;
use depin_sdk_services::governance::GovernanceModule;
use depin_sdk_services::identity::IdentityHub;
use depin_sdk_types::app::{
    account_id_from_key_material, evidence_id, AccountId, ApplicationTransaction, ChainTransaction,
    StateEntry, SystemPayload,
};
use depin_sdk_types::codec;
use depin_sdk_types::config::ConsensusType;
use depin_sdk_types::error::{StateError, TransactionError};
use depin_sdk_types::keys::{
    ACCOUNT_ID_TO_PUBKEY_PREFIX, AUTHORITY_SET_KEY, EVIDENCE_REGISTRY_KEY,
    IBC_PROCESSED_RECEIPT_PREFIX, ORACLE_DATA_PREFIX, ORACLE_PENDING_REQUEST_PREFIX,
    STAKES_KEY_CURRENT, STAKES_KEY_NEXT,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    <CS as CommitmentScheme>::Proof: Serialize + for<'de> serde::Deserialize<'de> + Clone,
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

    fn validate_stateless(&self, _tx: &Self::Transaction) -> Result<(), TransactionError> {
        Ok(())
    }

    async fn apply_payload<ST, CV>(
        &self,
        chain_ref: &CV,
        state: &mut dyn StateAccessor,
        tx: &Self::Transaction,
        ctx: TxContext<'_>,
    ) -> Result<(), TransactionError>
    where
        ST: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + Send
            + Sync
            + 'static,
        CV: ChainView<Self::CommitmentScheme, ST> + Send + Sync + ?Sized,
    {
        match tx {
            ChainTransaction::Application(app_tx) => match app_tx {
                ApplicationTransaction::UTXO(utxo_tx) => {
                    self.utxo_model
                        .apply_payload(chain_ref, state, utxo_tx, ctx)
                        .await
                }
                ApplicationTransaction::DeployContract {
                    code,
                    signature_proof,
                    ..
                } => {
                    let workload = chain_ref.workload_container();
                    let (address, state_delta) = workload
                        .deploy_contract(code.clone(), signature_proof.public_key.clone())
                        .await
                        .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                    if !state_delta.is_empty() {
                        let versioned_delta: Vec<(Vec<u8>, Vec<u8>)> = state_delta
                            .into_iter()
                            .map(|(key, value)| {
                                let entry = StateEntry {
                                    value,
                                    block_height: ctx.block_height,
                                };
                                (key, serde_json::to_vec(&entry).unwrap())
                            })
                            .collect();
                        state.batch_set(&versioned_delta)?; // Writes to the overlay
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
                    signature_proof,
                    ..
                } => {
                    let workload = chain_ref.workload_container();
                    let exec_context = ExecutionContext {
                        caller: signature_proof.public_key.clone(),
                        block_height: ctx.block_height,
                        gas_limit: *gas_limit,
                        contract_address: address.clone(),
                    };
                    let (_output, state_delta) = workload
                        .call_contract(address.clone(), input_data.clone(), exec_context)
                        .await
                        .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                    if !state_delta.is_empty() {
                        let versioned_delta: Vec<(Vec<u8>, Vec<u8>)> = state_delta
                            .into_iter()
                            .map(|(key, value)| {
                                let entry = StateEntry {
                                    value,
                                    block_height: ctx.block_height,
                                };
                                (key, serde_json::to_vec(&entry).unwrap())
                            })
                            .collect();
                        state.batch_set(&versioned_delta)?; // Writes to the overlay
                    }
                    Ok(())
                }
            },
            ChainTransaction::System(sys_tx) => match sys_tx.payload.clone() {
                SystemPayload::Stake { public_key, amount } => {
                    // FIX: Add consensus-aware guard.
                    if chain_ref.consensus_type() != ConsensusType::ProofOfStake {
                        return Err(TransactionError::Unsupported(
                            "Stake operations are not supported on non-PoS chains".into(),
                        ));
                    }
                    let staker_account_id = sys_tx.header.account_id;

                    let derived_pk_hash =
                        account_id_from_key_material(sys_tx.signature_proof.suite, &public_key)?;
                    if staker_account_id.0 != derived_pk_hash {
                        return Err(TransactionError::Invalid(
                            "Public key in Stake payload does not match the signer's AccountId"
                                .to_string(),
                        ));
                    }
                    let pubkey_map_key =
                        [ACCOUNT_ID_TO_PUBKEY_PREFIX, staker_account_id.as_ref()].concat();
                    if state.get(&pubkey_map_key)?.is_none() {
                        state.insert(&pubkey_map_key, &public_key)?;
                    }

                    let base_stakes_bytes = state
                        .get(STAKES_KEY_NEXT)?
                        .or(state.get(STAKES_KEY_CURRENT)?);
                    let mut stakes: BTreeMap<AccountId, u64> = base_stakes_bytes
                        .as_ref()
                        .map(|b: &Vec<u8>| codec::from_bytes_canonical(b).unwrap_or_default())
                        .unwrap_or_default();
                    let current_stake = stakes.entry(staker_account_id).or_insert(0);
                    *current_stake = current_stake.saturating_add(amount);
                    let new_stakes_bytes = codec::to_bytes_canonical(&stakes);
                    state.insert(STAKES_KEY_NEXT, &new_stakes_bytes)?;
                    Ok(())
                }
                SystemPayload::Unstake { amount } => {
                    // FIX: Add consensus-aware guard.
                    if chain_ref.consensus_type() != ConsensusType::ProofOfStake {
                        return Err(TransactionError::Unsupported(
                            "Unstake operations are not supported on non-PoS chains".into(),
                        ));
                    }
                    let staker_account_id = sys_tx.header.account_id;
                    let base_stakes_bytes = state
                        .get(STAKES_KEY_NEXT)?
                        .or(state.get(STAKES_KEY_CURRENT)?);
                    let mut stakes: BTreeMap<AccountId, u64> = base_stakes_bytes
                        .as_ref()
                        .map(|b: &Vec<u8>| codec::from_bytes_canonical(b).unwrap_or_default())
                        .unwrap_or_default();
                    let current_stake = stakes.entry(staker_account_id).or_insert(0);
                    *current_stake = current_stake.saturating_sub(amount);
                    let new_stakes_bytes = codec::to_bytes_canonical(&stakes);
                    state.insert(STAKES_KEY_NEXT, &new_stakes_bytes)?;
                    Ok(())
                }
                SystemPayload::UpdateAuthorities {
                    mut new_authorities,
                } => {
                    new_authorities.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
                    new_authorities.dedup();
                    let bytes = codec::to_bytes_canonical(&new_authorities);
                    state.insert(AUTHORITY_SET_KEY, &bytes)?;
                    Ok(())
                }
                SystemPayload::ReportMisbehavior { report } => {
                    let reporter_id = &sys_tx.header.account_id;

                    match chain_ref.consensus_type() {
                        ConsensusType::ProofOfStake => {
                            let stakes_bytes = state.get(STAKES_KEY_CURRENT)?.ok_or_else(|| {
                                TransactionError::State(StateError::KeyNotFound(
                                    "Stakes map not found".into(),
                                ))
                            })?;
                            let stakes: BTreeMap<AccountId, u64> =
                                codec::from_bytes_canonical(&stakes_bytes)?;
                            if stakes.get(reporter_id).copied().unwrap_or(0) == 0 {
                                return Err(TransactionError::Invalid(
                                    "Reporter is not an active validator (no stake)".into(),
                                ));
                            }
                        }
                        ConsensusType::ProofOfAuthority => {
                            let authorities_bytes =
                                state.get(AUTHORITY_SET_KEY)?.ok_or_else(|| {
                                    TransactionError::State(StateError::KeyNotFound(
                                        "Authority set not found".into(),
                                    ))
                                })?;
                            let authorities: Vec<AccountId> =
                                codec::from_bytes_canonical(&authorities_bytes)?;

                            if !authorities.contains(reporter_id) {
                                return Err(TransactionError::Invalid(
                                    "Reporter is not an active authority".into(),
                                ));
                            }
                        }
                    }

                    let handled_evidence: BTreeSet<[u8; 32]> = state
                        .get(EVIDENCE_REGISTRY_KEY)?
                        .as_deref()
                        .map(|b| codec::from_bytes_canonical(b).unwrap_or_default())
                        .unwrap_or_default();

                    let mut new_handled_evidence = handled_evidence;
                    let id = evidence_id(&report);
                    if !new_handled_evidence.insert(id) {
                        return Err(TransactionError::Invalid(
                            "Duplicate evidence: this offense has already been penalized."
                                .to_string(),
                        ));
                    }
                    state.insert(
                        EVIDENCE_REGISTRY_KEY,
                        &codec::to_bytes_canonical(&new_handled_evidence),
                    )?;

                    let penalty_mechanism = chain_ref.get_penalty_mechanism();
                    match penalty_mechanism.apply_penalty(state, &report).await {
                        Ok(()) => Ok(()),
                        Err(e) => {
                            log::warn!("[Penalty] Report rejected: {}", e);
                            Err(e)
                        }
                    }
                }
                SystemPayload::VerifyForeignReceipt { receipt, proof: _ } => {
                    let receipt_key =
                        [IBC_PROCESSED_RECEIPT_PREFIX, &receipt.unique_leaf_id].concat();
                    if state.get(&receipt_key)?.is_some() {
                        return Err(TransactionError::Invalid(
                            "Foreign receipt has already been processed (replay attack)"
                                .to_string(),
                        ));
                    }
                    state.insert(&receipt_key, &[1])?;
                    log::info!(
                            "Foreign receipt processed successfully. Emitting local event for endpoint: {}",
                            receipt.endpoint_id
                        );
                    Ok(())
                }
                SystemPayload::SubmitOracleData {
                    request_id,
                    final_value,
                    consensus_proof,
                } => {
                    if consensus_proof.attestations.is_empty() {
                        return Err(TransactionError::Invalid("Oracle proof is empty".into()));
                    }
                    let pending_key =
                        [ORACLE_PENDING_REQUEST_PREFIX, &request_id.to_le_bytes()].concat();
                    let final_key = [ORACLE_DATA_PREFIX, &request_id.to_le_bytes()].concat();
                    let entry = StateEntry {
                        value: final_value.clone(),
                        block_height: ctx.block_height,
                    };
                    let entry_bytes = serde_json::to_vec(&entry)?;
                    state.delete(&pending_key)?;
                    state.insert(&final_key, &entry_bytes)?;
                    log::info!("Applied and verified oracle data for id: {}", request_id);
                    Ok(())
                }
                SystemPayload::RequestOracleData { url, request_id } => {
                    let request_key =
                        [ORACLE_PENDING_REQUEST_PREFIX, &request_id.to_le_bytes()].concat();
                    let url_bytes = serde_json::to_vec(&url)?;
                    let entry = StateEntry {
                        value: url_bytes,
                        block_height: ctx.block_height,
                    };
                    let entry_bytes = serde_json::to_vec(&entry)?;
                    state.insert(&request_key, &entry_bytes)?;
                    Ok(())
                }
                SystemPayload::Vote {
                    proposal_id,
                    option,
                } => {
                    let governance_module = GovernanceModule::default();
                    let voter_account_id = &sys_tx.header.account_id;
                    governance_module
                        .vote(
                            state,
                            proposal_id,
                            voter_account_id,
                            option,
                            ctx.block_height,
                        )
                        .map_err(TransactionError::Invalid)
                }
                SystemPayload::RotateKey(proof) => {
                    let identity_hub = ctx.services.get::<IdentityHub>().ok_or_else(|| {
                        TransactionError::Unsupported(
                            "IdentityHub service is not available".to_string(),
                        )
                    })?;
                    identity_hub
                        .rotate(state, &sys_tx.header.account_id, &proof, ctx.block_height)
                        .map_err(TransactionError::Invalid)
                }
                _ => Ok(()),
            },
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
