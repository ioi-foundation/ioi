// Path: crates/transaction_models/src/protocol/mod.rs
use crate::utxo::UTXOModel;
use async_trait::async_trait;
use bs58;
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::WorkloadContainer;
use depin_sdk_api::vm::ExecutionContext;
use depin_sdk_types::app::{
    ApplicationTransaction, ProtocolTransaction, StateEntry, SystemPayload,
};
use depin_sdk_types::error::TransactionError;
use depin_sdk_types::keys::{AUTHORITY_SET_KEY, GOVERNANCE_KEY};
use libp2p::identity::PublicKey as Libp2pPublicKey;

/// A unified transaction model that handles all `ProtocolTransaction` variants.
#[derive(Clone, Debug)]
pub struct ProtocolModel<CS: CommitmentScheme + Clone> {
    utxo_model: UTXOModel<CS>,
}

impl<CS: CommitmentScheme + Clone> ProtocolModel<CS> {
    pub fn new(scheme: CS) -> Self {
        Self {
            utxo_model: UTXOModel::new(scheme),
        }
    }
}

#[async_trait]
impl<CS: CommitmentScheme + Clone + Send + Sync> TransactionModel for ProtocolModel<CS> {
    type Transaction = ProtocolTransaction;
    type CommitmentScheme = CS;
    type Proof = (); // Proofs are not yet implemented for this model.

    fn create_coinbase_transaction(
        &self,
        block_height: u64,
        recipient: &[u8],
    ) -> Result<Self::Transaction, TransactionError> {
        let utxo_tx = self
            .utxo_model
            .create_coinbase_transaction(block_height, recipient)?;
        Ok(ProtocolTransaction::Application(
            ApplicationTransaction::UTXO(utxo_tx),
        ))
    }

    fn validate<S>(&self, tx: &Self::Transaction, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match tx {
            ProtocolTransaction::Application(app_tx) => match app_tx {
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
                    Ok(true)
                }
            },
            ProtocolTransaction::System(_) => {
                // Defer more complex validation (like checking governance key) to the async `apply` method.
                Ok(true)
            }
        }
    }

    async fn apply<ST>(
        &self,
        tx: &Self::Transaction,
        workload: &WorkloadContainer<ST>,
        block_height: u64,
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
            ProtocolTransaction::Application(app_tx) => match app_tx {
                ApplicationTransaction::UTXO(utxo_tx) => {
                    self.utxo_model.apply(utxo_tx, workload, block_height).await
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
                                    block_height,
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
                        block_height,
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
                                    block_height,
                                };
                                (key, serde_json::to_vec(&entry).unwrap())
                            })
                            .collect();
                        state.batch_set(&versioned_delta)?;
                    }
                    Ok(())
                }
            },
            ProtocolTransaction::System(sys_tx) => {
                // 1. Fetch governance key from state
                let state_tree_arc = workload.state_tree();
                let mut state = state_tree_arc.lock().await;
                let gov_key_bs58_bytes = state.get(GOVERNANCE_KEY)?.ok_or_else(|| {
                    TransactionError::Invalid("Governance key not found in state".into())
                })?;
                let gov_key_bs58: String =
                    serde_json::from_slice(&gov_key_bs58_bytes).map_err(|_| {
                        TransactionError::Invalid("Failed to deserialize governance key".into())
                    })?;

                // 2. Decode public key
                let gov_pk_bytes = bs58::decode(gov_key_bs58).into_vec().map_err(|_| {
                    TransactionError::Invalid("Invalid base58 for governance key".into())
                })?;
                let ed25519_pk =
                    libp2p::identity::ed25519::PublicKey::try_from_bytes(&gov_pk_bytes).map_err(
                        |_| TransactionError::Invalid("Could not decode Ed25519 public key".into()),
                    )?;
                let pubkey = Libp2pPublicKey::from(ed25519_pk);

                // 3. Verify signature
                let payload_bytes = serde_json::to_vec(&sys_tx.payload)
                    .map_err(|e| TransactionError::Serialization(e.to_string()))?;
                if !pubkey.verify(&payload_bytes, &sys_tx.signature) {
                    return Err(TransactionError::Invalid(
                        "Invalid governance signature".into(),
                    ));
                }

                // 4. Apply state change
                match &sys_tx.payload {
                    SystemPayload::UpdateAuthorities { new_authorities } => {
                        let serialized = serde_json::to_vec(new_authorities).unwrap();
                        state.insert(AUTHORITY_SET_KEY, &serialized)?;
                        log::info!("Applied verified authority set update.");
                    }
                    _ => {
                        return Err(TransactionError::Invalid(
                            "Unsupported system transaction".into(),
                        ))
                    }
                }
                Ok(())
            }
        }
    }

    fn generate_proof<S>(
        &self,
        _tx: &Self::Transaction,
        _state: &S,
    ) -> Result<Self::Proof, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        Ok(())
    }
    fn verify_proof<S>(&self, _proof: &Self::Proof, _state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        Ok(true)
    }
    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        serde_json::to_vec(tx).map_err(|e| TransactionError::Serialization(e.to_string()))
    }
    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        serde_json::from_slice(data).map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}
