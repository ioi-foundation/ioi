// Path: crates/tx/src/utxo/mod.rs
use async_trait::async_trait;
use ioi_api::commitment::CommitmentScheme;
use ioi_api::state::{ProofProvider, StateAccess, StateManager};
use ioi_api::transaction::context::TxContext;
use ioi_api::transaction::TransactionModel;
use ioi_types::app::Membership;
pub use ioi_types::app::{Input, Output, UTXOTransaction};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub struct InputProof<P> {
    pub utxo_key: Vec<u8>,
    pub utxo_value: Vec<u8>,
    pub inclusion_proof: P,
}

#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub struct UTXOTransactionProof<P> {
    pub input_proofs: Vec<InputProof<P>>,
}

#[derive(Debug, Clone, Default)]
pub struct UTXOConfig {
    pub max_inputs: usize,
    pub max_outputs: usize,
}

pub trait UTXOOperations {
    fn create_utxo_key(&self, tx_hash: &[u8], index: u32) -> Vec<u8>;
}

#[derive(Debug, Clone)]
pub struct UTXOModel<CS: CommitmentScheme> {
    config: UTXOConfig,
    _commitment_scheme: CS,
}

impl<CS: CommitmentScheme + Clone> UTXOModel<CS> {
    pub fn new(commitment_scheme: CS) -> Self {
        Self {
            config: UTXOConfig::default(),
            _commitment_scheme: commitment_scheme,
        }
    }
    pub fn with_config(commitment_scheme: CS, config: UTXOConfig) -> Self {
        Self {
            config,
            _commitment_scheme: commitment_scheme,
        }
    }
}

impl<CS: CommitmentScheme> UTXOOperations for UTXOModel<CS> {
    fn create_utxo_key(&self, tx_hash: &[u8], index: u32) -> Vec<u8> {
        let mut key = b"u".to_vec();
        key.extend_from_slice(tx_hash);
        key.extend_from_slice(&index.to_le_bytes());
        key
    }
}

#[async_trait]
impl<CS: CommitmentScheme + Clone + Send + Sync> TransactionModel for UTXOModel<CS>
where
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Encode + Decode + Debug,
{
    type Transaction = UTXOTransaction;
    type CommitmentScheme = CS;
    type Proof = UTXOTransactionProof<CS::Proof>;

    fn validate_stateless(&self, tx: &Self::Transaction) -> Result<(), TransactionError> {
        if self.config.max_inputs > 0 && tx.inputs.len() > self.config.max_inputs {
            return Err(TransactionError::InvalidInput(
                "Too many inputs".to_string(),
            ));
        }
        if self.config.max_outputs > 0 && tx.outputs.len() > self.config.max_outputs {
            return Err(TransactionError::InvalidOutput(
                "Too many outputs".to_string(),
            ));
        }
        Ok(())
    }

    async fn apply_payload<ST, CV>(
        &self,
        chain: &CV,
        state: &mut dyn StateAccess,
        tx: &Self::Transaction,
        _ctx: &mut TxContext<'_>,
    ) -> Result<(Self::Proof, u64), TransactionError>
    where
        ST: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ProofProvider
            + Send
            + Sync
            + 'static,
        CV: ioi_api::chain::ChainView<Self::CommitmentScheme, ST> + Send + Sync + ?Sized,
    {
        // 1) Stateful validation & read values from overlay
        if tx.inputs.is_empty() {
            if tx.outputs.is_empty() {
                return Err(TransactionError::InvalidOutput(
                    "Coinbase transaction must have outputs".to_string(),
                ));
            }
        } else {
            let mut total_input: u64 = 0;
            let mut materialized_inputs = Vec::with_capacity(tx.inputs.len());
            for input in &tx.inputs {
                let key = self.create_utxo_key(&input.tx_hash, input.output_index);
                let utxo_bytes = state.get(&key)?.ok_or_else(|| {
                    TransactionError::InvalidInput("Input UTXO not found".to_string())
                })?;
                let utxo: Output = codec::from_bytes_canonical(&utxo_bytes)
                    .map_err(|e| TransactionError::Deserialization(format!("UTXO error: {}", e)))?;
                total_input = total_input
                    .checked_add(utxo.value)
                    .ok_or_else(|| TransactionError::BalanceOverflow)?;
                materialized_inputs.push((key, utxo_bytes));
            }
            let total_output: u64 = tx.outputs.iter().map(|o| o.value).sum();
            if total_input < total_output {
                return Err(TransactionError::InsufficientFunds);
            }

            // 2) Generate anchored proofs BEFORE we touch overlay deletes
            let backend_arc = chain.workload_container().state_tree();
            let backend_guard = backend_arc.read().await;
            let backend = &*backend_guard;
            let pre_root = backend.root_commitment();

            let mut input_proofs = Vec::with_capacity(materialized_inputs.len());
            for (key, value) in &materialized_inputs {
                let (membership, inclusion_proof) = backend
                    .get_with_proof_at(&pre_root, key)
                    .map_err(TransactionError::State)?;
                match membership {
                    Membership::Present(_) => {
                        input_proofs.push(InputProof {
                            utxo_key: key.clone(),
                            utxo_value: value.clone(),
                            inclusion_proof,
                        });
                    }
                    Membership::Absent => {
                        return Err(TransactionError::InvalidInput(
                            "Input UTXO non-membership at pre-state".into(),
                        ));
                    }
                }
            }

            // 3) Apply overlay deletes/inserts
            for (key, _) in &materialized_inputs {
                state.delete(key)?;
            }
            let tx_hash = tx
                .hash()
                .map_err(|e| TransactionError::Invalid(e.to_string()))?;
            for (index, output) in tx.outputs.iter().enumerate() {
                let key = self.create_utxo_key(&tx_hash, index as u32);
                let value = codec::to_bytes_canonical(output)?;
                state.insert(&key, &value)?;
            }
            // TODO: Calculate actual gas usage
            return Ok((UTXOTransactionProof { input_proofs }, 0));
        }
        // This path is for coinbase, which has no inputs to prove.
        Ok((
            UTXOTransactionProof {
                input_proofs: vec![],
            },
            0,
        ))
    }

    fn create_coinbase_transaction(
        &self,
        _block_height: u64,
        recipient: &[u8],
    ) -> Result<Self::Transaction, TransactionError> {
        Ok(UTXOTransaction {
            inputs: vec![],
            outputs: vec![Output {
                value: 50,
                public_key: recipient.to_vec(),
            }],
        })
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        codec::to_bytes_canonical(tx).map_err(TransactionError::Serialization)
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        codec::from_bytes_canonical(data)
            .map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}
