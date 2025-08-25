// Path: crates/transaction_models/src/utxo/mod.rs
use async_trait::async_trait;
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::WorkloadContainer;
pub use depin_sdk_types::app::{Input, Output, UTXOTransaction};
use depin_sdk_types::error::TransactionError;
use serde::{Deserialize, Serialize}; // Add this line

// NEW: Define a structure to hold a proof for a single input UTXO.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputProof<P> {
    /// The state key of the UTXO being spent.
    pub utxo_key: Vec<u8>,
    /// The serialized `Output` data (the value) that is being proven.
    pub utxo_value: Vec<u8>,
    /// The cryptographic inclusion proof from the state manager.
    pub inclusion_proof: P,
}

// NEW: Define the complete proof structure for a UTXO transaction.
#[derive(Serialize, Deserialize, Debug, Clone)]
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
    // Add this bound so we can serialize the proof
    <CS as CommitmentScheme>::Proof: Serialize + for<'de> Deserialize<'de>,
{
    type Transaction = UTXOTransaction;
    type CommitmentScheme = CS;
    // UPDATE: Use our new generic proof structure.
    type Proof = UTXOTransactionProof<CS::Proof>;

    fn validate<S>(&self, tx: &Self::Transaction, state: &S) -> Result<(), TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        if tx.inputs.is_empty() {
            if tx.outputs.is_empty() {
                return Err(TransactionError::Invalid(
                    "Coinbase transaction must have outputs".to_string(),
                ));
            }
            return Ok(()); // Coinbase transaction
        }

        if self.config.max_inputs > 0 && tx.inputs.len() > self.config.max_inputs {
            return Err(TransactionError::Invalid("Too many inputs".to_string()));
        }
        if self.config.max_outputs > 0 && tx.outputs.len() > self.config.max_outputs {
            return Err(TransactionError::Invalid("Too many outputs".to_string()));
        }

        let mut total_input: u64 = 0;
        for input in &tx.inputs {
            let key = self.create_utxo_key(&input.tx_hash, input.output_index);
            let utxo_bytes = state
                .get(&key)?
                .ok_or_else(|| TransactionError::Invalid("Input UTXO not found".to_string()))?;
            let utxo: Output = serde_json::from_slice(&utxo_bytes)
                .map_err(|e| TransactionError::Invalid(format!("Deserialize error: {e}")))?;
            total_input = total_input
                .checked_add(utxo.value)
                .ok_or_else(|| TransactionError::Invalid("Input value overflow".to_string()))?;
        }

        let total_output: u64 = tx.outputs.iter().map(|o| o.value).sum();
        if total_input < total_output {
            return Err(TransactionError::Invalid("Insufficient funds".to_string()));
        }

        Ok(())
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
        let state_tree_arc = workload.state_tree();
        let mut state = state_tree_arc.lock().await;
        self.validate(tx, &*state)?;
        for input in &tx.inputs {
            let key = self.create_utxo_key(&input.tx_hash, input.output_index);
            state.delete(&key)?;
        }
        let tx_hash = tx.hash();
        for (index, output) in tx.outputs.iter().enumerate() {
            let key = self.create_utxo_key(&tx_hash, index as u32);
            let value = serde_json::to_vec(output)
                .map_err(|e| TransactionError::Serialization(e.to_string()))?;
            state.insert(&key, &value)?;
        }
        Ok(())
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

    // IMPLEMENT: generate_proof
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
        let mut input_proofs = Vec::with_capacity(tx.inputs.len());

        for input in &tx.inputs {
            // 1. Construct the state key for the input UTXO.
            let key = self.create_utxo_key(&input.tx_hash, input.output_index);

            // 2. Fetch the value (the `Output` struct) from the state. This is required for verification.
            let value = state.get(&key)?.ok_or_else(|| {
                TransactionError::Invalid("Input UTXO for proof generation not found".to_string())
            })?;

            // 3. Create the inclusion proof for that key-value pair.
            let inclusion_proof = state.create_proof(&key).ok_or_else(|| {
                TransactionError::Invalid("Failed to create inclusion proof for input".to_string())
            })?;

            input_proofs.push(InputProof {
                utxo_key: key,
                utxo_value: value,
                inclusion_proof,
            });
        }

        Ok(UTXOTransactionProof { input_proofs })
    }

    // IMPLEMENT: verify_proof
    fn verify_proof<S>(&self, proof: &Self::Proof, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        // 1. Get the state root we are verifying against.
        let root_commitment = state.root_commitment();

        // 2. Verify each input's inclusion proof against the root.
        for input_proof in &proof.input_proofs {
            let is_valid = state.verify_proof(
                // <-- FIX: Call verify_proof as a method on the state object
                &root_commitment,
                &input_proof.inclusion_proof,
                &input_proof.utxo_key,
                &input_proof.utxo_value,
            );

            if !is_valid {
                return Ok(false); // If any proof fails, the entire transaction proof is invalid.
            }
        }

        Ok(true)
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        serde_json::to_vec(tx).map_err(|e| TransactionError::Serialization(e.to_string()))
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        serde_json::from_slice(data).map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}
