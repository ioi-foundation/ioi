// Path: crates/transaction_models/src/unified/mod.rs

use crate::utxo::{UTXOModel, UTXOTransactionProof};
use async_trait::async_trait;
use depin_sdk_api::chain::ChainView;
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::WorkloadContainer;
use depin_sdk_api::vm::ExecutionContext;
use depin_sdk_services::gas_escrow::{
    GasEscrowHandler, GasEscrowService, PenaltyError, SettlementOutcome,
};
use depin_sdk_services::governance::GovernanceModule;
use depin_sdk_services::identity::IdentityHub;
use depin_sdk_types::app::{
    account_id_from_pubkey, AccountId, ApplicationTransaction, ChainTransaction, StateEntry,
    SystemPayload,
};
use depin_sdk_types::error::{StateError, TransactionError};
use depin_sdk_types::keys::{
    IBC_PROCESSED_RECEIPT_PREFIX, ORACLE_DATA_PREFIX, ORACLE_PENDING_REQUEST_PREFIX,
    QUARANTINED_VALIDATORS_KEY, STAKES_KEY_CURRENT, STAKES_KEY_NEXT,
};
use libp2p::identity::PublicKey as Libp2pPublicKey;
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
        Ok(())
    }

    async fn apply_payload<ST>(
        &self,
        chain_ref: &(dyn ChainView<Self::CommitmentScheme, ST> + Send + Sync),
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
                    self.utxo_model
                        .apply_payload(chain_ref, utxo_tx, workload, ctx)
                        .await
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
                    SystemPayload::Stake { amount } => {
                        let pk = Libp2pPublicKey::try_decode_protobuf(
                            &sys_tx.signature_proof.public_key,
                        )
                        .map_err(|_| {
                            TransactionError::Invalid("Invalid signer public key".to_string())
                        })?;
                        let signer_b58 = pk.to_peer_id().to_base58();

                        let base_stakes_bytes = state
                            .get(STAKES_KEY_NEXT)?
                            .or(state.get(STAKES_KEY_CURRENT)?);

                        let mut stakes: BTreeMap<String, u64> =
                            if let Some(bytes) = base_stakes_bytes {
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

                        let base_stakes_bytes = state
                            .get(STAKES_KEY_NEXT)?
                            .or(state.get(STAKES_KEY_CURRENT)?);

                        let mut stakes: BTreeMap<String, u64> =
                            if let Some(bytes) = base_stakes_bytes {
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
                    SystemPayload::ReportMisbehavior { report } => {
                        let reporter_pk = Libp2pPublicKey::try_decode_protobuf(
                            &sys_tx.signature_proof.public_key,
                        )
                        .map_err(|e| {
                            TransactionError::Invalid(format!("Invalid reporter public key: {}", e))
                        })?;
                        let reporter_id = account_id_from_pubkey(&reporter_pk);

                        let validator_set_bytes: Vec<Vec<u8>> =
                            chain_ref.get_validator_set(workload).await.map_err(|e| {
                                TransactionError::State(StateError::Backend(e.to_string()))
                            })?;

                        let mut active_validators = BTreeSet::new();
                        for peer_bytes in validator_set_bytes {
                            if let Ok(pk) = Libp2pPublicKey::try_decode_protobuf(&peer_bytes) {
                                active_validators.insert(account_id_from_pubkey(&pk));
                            }
                        }

                        if !active_validators.contains(&reporter_id) {
                            return Err(TransactionError::Invalid(
                                "Reporter is not an active validator".into(),
                            ));
                        }

                        let penalty_percentage = 10;

                        if workload.config().consensus_type
                            == depin_sdk_types::config::ConsensusType::ProofOfAuthority
                        {
                            let min_live_authorities = 3;
                            let authorities_bytes =
                                chain_ref.get_authority_set(workload).await.map_err(|e| {
                                    TransactionError::State(StateError::Backend(e.to_string()))
                                })?;
                            let quarantined: BTreeSet<AccountId> = state
                                .get(QUARANTINED_VALIDATORS_KEY)?
                                .map(|b| {
                                    depin_sdk_types::codec::from_bytes_canonical(&b)
                                        .map_err(StateError::InvalidValue)
                                })
                                .transpose()?
                                .unwrap_or_default();

                            if !quarantined.contains(&report.offender)
                                && (authorities_bytes.len() - quarantined.len() - 1)
                                    < min_live_authorities
                            {
                                return Err(TransactionError::Invalid(
                                    "Quarantine would jeopardize network liveness".into(),
                                ));
                            }
                        }

                        let gas_escrow_service =
                            ctx.services.get::<GasEscrowService>().ok_or_else(|| {
                                TransactionError::Invalid("GasEscrowService not available".into())
                            })?;
                        let outcome = SettlementOutcome::Failure {
                            report: report.clone(),
                            penalty_percentage,
                        };
                        gas_escrow_service
                            .settle(&mut *state, &workload.config().consensus_type, outcome)
                            .map_err(|e: PenaltyError| TransactionError::Invalid(e.to_string()))?;

                        Ok(())
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
                    _ => Ok(()),
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
