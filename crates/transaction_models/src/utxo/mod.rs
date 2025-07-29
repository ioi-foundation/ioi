// Path: crates/transaction_models/src/utxo/mod.rs

use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::{StateError, TransactionError};
use depin_sdk_core::state::StateManager;
use depin_sdk_core::transaction::TransactionModel;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Default)]
pub struct UTXOConfig {
    pub max_inputs: usize,
    pub max_outputs: usize,
}

pub trait UTXOOperations {
    fn create_utxo_key(&self, tx_hash: &[u8], index: u32) -> Vec<u8>;
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Input {
    pub tx_hash: Vec<u8>,
    pub output_index: u32,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub value: u64,
    pub public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UTXOTransaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

impl UTXOTransaction {
    pub fn hash(&self) -> Vec<u8> {
        let serialized = serde_json::to_vec(self).unwrap();
        Sha256::digest(&serialized).to_vec()
    }
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

impl<CS: CommitmentScheme + Clone + Send + Sync> TransactionModel for UTXOModel<CS> {
    type Transaction = UTXOTransaction;
    type CommitmentScheme = CS;
    type Proof = ();

    fn validate<SM>(&self, tx: &Self::Transaction, state: &SM) -> Result<bool, TransactionError>
    where
        SM: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        // --- FIX: Add special validation logic for coinbase transactions ---
        // A coinbase transaction is the only valid transaction type with no inputs.
        if tx.inputs.is_empty() {
            // A valid coinbase should have at least one output to reward the miner.
            // More complex rules (e.g., exactly one output) could be added here.
            return Ok(!tx.outputs.is_empty());
        }
        // --- End Fix ---

        if tx.inputs.len() > self.config.max_inputs || tx.outputs.len() > self.config.max_outputs {
            return Ok(false);
        }

        let mut total_input: u64 = 0;
        for input in &tx.inputs {
            let key = self.create_utxo_key(&input.tx_hash, input.output_index);
            let utxo_bytes = state.get(&key)?.ok_or_else(|| {
                TransactionError::Invalid(format!("Input UTXO not found"))
            })?;
            let utxo: Output = serde_json::from_slice(&utxo_bytes)
                .map_err(|e| TransactionError::Invalid(format!("Deserialize error: {}", e)))?;
            total_input = total_input.checked_add(utxo.value)
                .ok_or_else(|| TransactionError::Invalid("Input value overflow".to_string()))?;
        }

        let total_output: u64 = tx.outputs.iter().map(|o| o.value).sum();
        if total_input < total_output {
            return Ok(false);
        }

        Ok(true)
    }

    fn apply<SM>(&self, tx: &Self::Transaction, state: &mut SM) -> Result<(), TransactionError>
    where
        SM: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        if !self.validate(tx, state)? {
            return Err(TransactionError::Invalid("Validation failed".to_string()));
        }
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
            outputs: vec![Output { value: 50, public_key: recipient.to_vec() }],
        })
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

    fn verify_proof<S>(
        &self,
        _proof: &Self::Proof,
        _state: &S,
    ) -> Result<bool, TransactionError>
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