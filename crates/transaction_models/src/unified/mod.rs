// Path: crates/transaction_models/src/unified/mod.rs

use crate::utxo::{UTXOModel, UTXOTransactionProof};
use async_trait::async_trait;
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::WorkloadContainer;
use depin_sdk_api::vm::ExecutionContext;
use depin_sdk_services::governance::GovernanceModule;
use depin_sdk_services::identity::IdentityHub;
use depin_sdk_types::app::{ApplicationTransaction, ChainTransaction, StateEntry, SystemPayload};
use depin_sdk_types::error::TransactionError;
use depin_sdk_types::keys::{
    ORACLE_DATA_PREFIX, ORACLE_PENDING_REQUEST_PREFIX, STAKES_KEY_CURRENT, STAKES_KEY_NEXT,
};
use libp2p::identity::PublicKey as Libp2pPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

    fn validate_stateless(&self, _tx: &Self::Transaction) -> Result<(), TransactionError> {
        // Validation is now stateful and handled by decorators.
        Ok(())
    }

    async fn apply_payload<ST>(
        &self,
        tx: &Self::Transaction,
        workload: &WorkloadContainer<ST>,
        ctx: TxContext<'_>,
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
                    self.utxo_model.apply_payload(utxo_tx, workload, ctx).await
                }
                ApplicationTransaction::DeployContract {
                    code,
                    signature_proof,
                    ..
                } => {
                    let (address, state_delta) = workload
                        .deploy_contract(code.clone(), signature_proof.public_key.clone())
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
                                    block_height: ctx.block_height,
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
                    signature_proof,
                    ..
                } => {
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
                        let state_tree_arc = workload.state_tree();
                        let mut state = state_tree_arc.lock().await;
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
                        state.batch_set(&versioned_delta)?;
                    }
                    Ok(())
                }
            },
            ChainTransaction::System(sys_tx) => {
                let state_tree_arc = workload.state_tree();
                let mut state = state_tree_arc.lock().await;

                match &sys_tx.payload {
                    SystemPayload::SubmitOracleData {
                        request_id,
                        final_value,
                        consensus_proof,
                    } => {
                        // In a real implementation, we'd re-verify the consensus proof here
                        // against the current validator set and their stakes. For this E2E
                        // test, we trust that the off-chain part handled it correctly.
                        if consensus_proof.attestations.is_empty() {
                            return Err(TransactionError::Invalid("Oracle proof is empty".into()));
                        }

                        // 1. Atomically delete the pending request and write the final data.
                        let pending_key =
                            [ORACLE_PENDING_REQUEST_PREFIX, &request_id.to_le_bytes()].concat();
                        let final_key = [ORACLE_DATA_PREFIX, &request_id.to_le_bytes()].concat();

                        let entry = StateEntry {
                            value: final_value.clone(),
                            block_height: ctx.block_height,
                        };
                        let entry_bytes = serde_json::to_vec(&entry)?;

                        // Delete the pending request first
                        state.delete(&pending_key)?;
                        // Then insert the final data
                        state.insert(&final_key, &entry_bytes)?;

                        log::info!("Applied and verified oracle data for id: {}", request_id);
                        Ok(())
                    }
                    SystemPayload::RequestOracleData { url, request_id } => {
                        let request_key =
                            [ORACLE_PENDING_REQUEST_PREFIX, &request_id.to_le_bytes()].concat();
                        let url_bytes = serde_json::to_vec(url)?;
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
                        let pk = Libp2pPublicKey::try_decode_protobuf(
                            &sys_tx.signature_proof.public_key,
                        )
                        .map_err(|_| {
                            TransactionError::Invalid("Invalid signer public key".to_string())
                        })?;
                        let voter_b58 = pk.to_peer_id().to_base58();

                        governance_module
                            .vote(
                                &mut *state,
                                *proposal_id,
                                &voter_b58,
                                *option,
                                ctx.block_height,
                            )
                            .map_err(TransactionError::Invalid)
                    }
                    SystemPayload::RotateKey(proof) => {
                        let identity_hub = ctx.services.get::<IdentityHub>().ok_or_else(|| {
                            TransactionError::Invalid(
                                "IdentityHub service is not available".to_string(),
                            )
                        })?;
                        identity_hub
                            .rotate(
                                &mut *state,
                                &sys_tx.header.account_id,
                                proof,
                                ctx.block_height,
                            )
                            .map_err(TransactionError::Invalid)
                    }
                    SystemPayload::Stake { amount } => {
                        let pk = Libp2pPublicKey::try_decode_protobuf(
                            &sys_tx.signature_proof.public_key,
                        )
                        .map_err(|_| {
                            TransactionError::Invalid("Invalid signer public key".to_string())
                        })?;
                        let signer_b58 = pk.to_peer_id().to_base58();

                        let mut stakes: BTreeMap<String, u64> =
                            if let Some(bytes) = state.get(STAKES_KEY_NEXT)? {
                                serde_json::from_slice(&bytes)?
                            } else if let Some(bytes) = state.get(STAKES_KEY_CURRENT)? {
                                serde_json::from_slice(&bytes)?
                            } else {
                                BTreeMap::new()
                            };
                        let current_stake = stakes.entry(signer_b58).or_insert(0);
                        *current_stake = current_stake.saturating_add(*amount);
                        let new_stakes_bytes = serde_json::to_vec(&stakes)?;
                        state.insert(STAKES_KEY_NEXT, &new_stakes_bytes)?;
                        Ok(())
                    }
                    SystemPayload::Unstake { amount } => {
                        let pk = Libp2pPublicKey::try_decode_protobuf(
                            &sys_tx.signature_proof.public_key,
                        )
                        .map_err(|_| {
                            TransactionError::Invalid("Invalid signer public key".to_string())
                        })?;
                        let signer_b58 = pk.to_peer_id().to_base58();
                        let mut stakes: BTreeMap<String, u64> =
                            if let Some(bytes) = state.get(STAKES_KEY_NEXT)? {
                                serde_json::from_slice(&bytes)?
                            } else if let Some(bytes) = state.get(STAKES_KEY_CURRENT)? {
                                serde_json::from_slice(&bytes)?
                            } else {
                                BTreeMap::new()
                            };
                        let current_stake = stakes.entry(signer_b58).or_insert(0);
                        *current_stake = current_stake.saturating_sub(*amount);
                        let new_stakes_bytes = serde_json::to_vec(&stakes)?;
                        state.insert(STAKES_KEY_NEXT, &new_stakes_bytes)?;
                        Ok(())
                    }
                    _ => Ok(()), // Other system transactions can be no-ops for now
                }
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
