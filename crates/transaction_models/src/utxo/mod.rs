//! UTXO-based transaction model implementation.

use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::TransactionError;
use depin_sdk_core::state::StateManager;
use depin_sdk_core::transaction::TransactionModel;
use std::any::Any;
use std::collections::HashMap;

/// UTXO transaction input
#[derive(Debug, Clone)]
pub struct UTXOInput {
    /// Previous transaction ID
    pub prev_txid: Vec<u8>,
    /// Output index in the previous transaction
    pub prev_index: u32,
    /// Signature unlocking the UTXO
    pub signature: Vec<u8>,
}

/// UTXO transaction output
#[derive(Debug, Clone)]
pub struct UTXOOutput {
    /// Value of the output
    pub value: u64,
    /// Locking script or public key hash
    pub lock_script: Vec<u8>,
}

/// UTXO transaction
#[derive(Debug, Clone)]
pub struct UTXOTransaction {
    /// Transaction ID
    pub txid: Vec<u8>,
    /// Inputs (references to previous transaction outputs)
    pub inputs: Vec<UTXOInput>,
    /// Outputs (new unspent transaction outputs)
    pub outputs: Vec<UTXOOutput>,
}

/// UTXO proof data
#[derive(Debug, Clone)]
pub struct UTXOProof {
    /// Proofs for transaction inputs
    pub input_proofs: Vec<Vec<u8>>,
    /// Additional data needed for verification
    pub metadata: HashMap<String, Vec<u8>>,
}

/// UTXO-specific operations
pub trait UTXOOperations {
    /// Create a key for a UTXO in the state store.
    ///
    /// # Arguments
    /// * `txid` - Transaction ID.
    /// * `index` - Output index.
    ///
    /// # Returns
    /// * `Ok(key)` - The generated key.
    /// * `Err(TransactionError)` - If key creation failed.
    fn create_utxo_key(&self, txid: &[u8], index: u32) -> Result<Vec<u8>, TransactionError>;
}

/// Configuration for the UTXO model
#[derive(Clone)]
pub struct UTXOConfig {
    /// Minimum confirmations required for spending
    pub min_confirmations: u32,
    /// Maximum number of inputs per transaction
    pub max_inputs: usize,
    /// Maximum number of outputs per transaction
    pub max_outputs: usize,
}

impl Default for UTXOConfig {
    fn default() -> Self {
        Self {
            min_confirmations: 1,
            max_inputs: 100,
            max_outputs: 100,
        }
    }
}

/// UTXO transaction model implementation
pub struct UTXOModel<CS: CommitmentScheme> {
    /// Model configuration
    config: UTXOConfig,
    /// The commitment scheme
    scheme: CS,
}

impl<CS: CommitmentScheme> UTXOModel<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Create a new UTXO model with default configuration.
    pub fn new(scheme: CS) -> Self {
        Self {
            config: UTXOConfig::default(),
            scheme,
        }
    }

    /// Create a new UTXO model with custom configuration.
    pub fn with_config(scheme: CS, config: UTXOConfig) -> Self {
        Self {
            config,
            scheme,
        }
    }

    /// Get model configuration.
    pub fn config(&self) -> &UTXOConfig {
        &self.config
    }

    /// Get the commitment scheme
    pub fn scheme(&self) -> &CS {
        &self.scheme
    }

    /// Helper method to get a UTXO from the state.
    fn get_utxo<S>(
        &self,
        state: &S,
        txid: &[u8],
        index: u32,
    ) -> Result<Option<UTXOOutput>, TransactionError>
    where
        S: StateManager<
            Commitment = CS::Commitment,
            Proof = CS::Proof,
        > + ?Sized,
    {
        let key = self.create_utxo_key(txid, index)?;
        let value = state
            .get(&key)
            .map_err(|e| TransactionError::StateAccessFailed(e.to_string()))?;

        match value {
            Some(data) => self.decode_utxo(&data),
            None => Ok(None),
        }
    }

    /// Helper method to decode a UTXO from bytes.
    fn decode_utxo(&self, data: &[u8]) -> Result<Option<UTXOOutput>, TransactionError> {
        if data.len() < 8 {
            return Err(TransactionError::SerializationError(
                "UTXO data too short".to_string(),
            ));
        }

        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(&data[0..8]);
        let value = u64::from_le_bytes(value_bytes);
        let lock_script = data[8..].to_vec();

        Ok(Some(UTXOOutput { value, lock_script }))
    }

    /// Helper method to encode a UTXO to bytes.
    fn encode_utxo(&self, output: &UTXOOutput) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + output.lock_script.len());
        data.extend_from_slice(&output.value.to_le_bytes());
        data.extend_from_slice(&output.lock_script);
        data
    }
    
    /// Convert raw bytes to the commitment scheme's value type
    fn to_value(&self, bytes: &[u8]) -> CS::Value {
        CS::Value::from(bytes.to_vec())
    }
}

impl<CS: CommitmentScheme> TransactionModel for UTXOModel<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type Transaction = UTXOTransaction;
    type Proof = UTXOProof;
    type CommitmentScheme = CS;

    fn validate<S>(&self, tx: &Self::Transaction, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
            Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
            Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
        > + ?Sized,
    {
        // Check transaction structure
        if tx.inputs.is_empty() {
            return Ok(false);
        }

        if tx.outputs.is_empty() {
            return Ok(false);
        }

        if tx.inputs.len() > self.config.max_inputs {
            return Ok(false);
        }

        if tx.outputs.len() > self.config.max_outputs {
            return Ok(false);
        }

        // Validate inputs exist and are unspent
        let mut total_input = 0u64;

        for input in &tx.inputs {
            let utxo = self.get_utxo(state, &input.prev_txid, input.prev_index)?;

            match utxo {
                Some(output) => {
                    // TODO: Validate signatures

                    // Add to total input
                    total_input = total_input.checked_add(output.value).ok_or_else(|| {
                        TransactionError::InvalidTransaction("Input value overflow".to_string())
                    })?;
                }
                None => return Ok(false), // Input UTXO not found
            }
        }

        // Calculate total output
        let mut total_output = 0u64;

        for output in &tx.outputs {
            total_output = total_output.checked_add(output.value).ok_or_else(|| {
                TransactionError::InvalidTransaction("Output value overflow".to_string())
            })?;
        }

        // Ensure total input >= total output
        if total_input < total_output {
            return Ok(false);
        }

        Ok(true)
    }

    fn apply<S>(&self, tx: &Self::Transaction, state: &mut S) -> Result<(), TransactionError>
    where
        S: StateManager<
            Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
            Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
        > + ?Sized,
    {
        // Validate transaction first
        if !self.validate(tx, state)? {
            return Err(TransactionError::InvalidTransaction(
                "Transaction validation failed".to_string(),
            ));
        }

        // Remove spent inputs
        for input in &tx.inputs {
            let key = self.create_utxo_key(&input.prev_txid, input.prev_index)?;
            state
                .delete(&key)
                .map_err(|e| TransactionError::StateAccessFailed(e.to_string()))?;
        }

        // Add new outputs
        for (i, output) in tx.outputs.iter().enumerate() {
            let key = self.create_utxo_key(&tx.txid, i as u32)?;
            let value = self.encode_utxo(output);

            state
                .set(&key, &value)
                .map_err(|e| TransactionError::StateAccessFailed(e.to_string()))?;
        }

        Ok(())
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
        let mut input_proofs = Vec::with_capacity(tx.inputs.len());

        for input in &tx.inputs {
            let key = self.create_utxo_key(&input.prev_txid, input.prev_index)?;

            // In a real implementation, we would create cryptographic proofs
            // For this example, we'll just get the raw UTXO data
            let utxo_data = state
                .get(&key)
                .map_err(|e| TransactionError::StateAccessFailed(e.to_string()))?
                .ok_or_else(|| {
                    TransactionError::InvalidInput("Referenced UTXO not found".to_string())
                })?;

            input_proofs.push(utxo_data);
        }

        Ok(UTXOProof {
            input_proofs,
            metadata: HashMap::new(),
        })
    }

    fn verify_proof<S>(&self, proof: &Self::Proof, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
            Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
            Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
        > + ?Sized,
    {
        // In a real implementation, this would verify cryptographic proofs
        // For this example, we'll just return true
        Ok(true)
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        // Simple manual serialization for demonstration
        let mut data = Vec::new();

        // Serialize txid
        data.extend_from_slice(&(tx.txid.len() as u32).to_le_bytes());
        data.extend_from_slice(&tx.txid);

        // Serialize inputs
        data.extend_from_slice(&(tx.inputs.len() as u32).to_le_bytes());
        for input in &tx.inputs {
            data.extend_from_slice(&(input.prev_txid.len() as u32).to_le_bytes());
            data.extend_from_slice(&input.prev_txid);
            data.extend_from_slice(&input.prev_index.to_le_bytes());
            data.extend_from_slice(&(input.signature.len() as u32).to_le_bytes());
            data.extend_from_slice(&input.signature);
        }

        // Serialize outputs
        data.extend_from_slice(&(tx.outputs.len() as u32).to_le_bytes());
        for output in &tx.outputs {
            data.extend_from_slice(&output.value.to_le_bytes());
            data.extend_from_slice(&(output.lock_script.len() as u32).to_le_bytes());
            data.extend_from_slice(&output.lock_script);
        }

        Ok(data)
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        if data.len() < 4 {
            return Err(TransactionError::SerializationError(
                "Data too short".to_string(),
            ));
        }

        let mut pos = 0;

        // Deserialize txid
        let txid_len = read_u32(&data[pos..pos + 4]) as usize;
        pos += 4;

        if pos + txid_len > data.len() {
            return Err(TransactionError::SerializationError(
                "Invalid txid length".to_string(),
            ));
        }

        let txid = data[pos..pos + txid_len].to_vec();
        pos += txid_len;

        // Deserialize inputs
        if pos + 4 > data.len() {
            return Err(TransactionError::SerializationError(
                "Invalid data format".to_string(),
            ));
        }

        let input_count = read_u32(&data[pos..pos + 4]) as usize;
        pos += 4;

        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            if pos + 4 > data.len() {
                return Err(TransactionError::SerializationError(
                    "Invalid data format".to_string(),
                ));
            }

            let prev_txid_len = read_u32(&data[pos..pos + 4]) as usize;
            pos += 4;

            if pos + prev_txid_len > data.len() {
                return Err(TransactionError::SerializationError(
                    "Invalid prev_txid length".to_string(),
                ));
            }

            let prev_txid = data[pos..pos + prev_txid_len].to_vec();
            pos += prev_txid_len;

            if pos + 4 > data.len() {
                return Err(TransactionError::SerializationError(
                    "Invalid data format".to_string(),
                ));
            }

            let prev_index = read_u32(&data[pos..pos + 4]);
            pos += 4;

            if pos + 4 > data.len() {
                return Err(TransactionError::SerializationError(
                    "Invalid data format".to_string(),
                ));
            }

            let signature_len = read_u32(&data[pos..pos + 4]) as usize;
            pos += 4;

            if pos + signature_len > data.len() {
                return Err(TransactionError::SerializationError(
                    "Invalid signature length".to_string(),
                ));
            }

            let signature = data[pos..pos + signature_len].to_vec();
            pos += signature_len;

            inputs.push(UTXOInput {
                prev_txid,
                prev_index,
                signature,
            });
        }

        // Deserialize outputs
        if pos + 4 > data.len() {
            return Err(TransactionError::SerializationError(
                "Invalid data format".to_string(),
            ));
        }

        let output_count = read_u32(&data[pos..pos + 4]) as usize;
        pos += 4;

        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            if pos + 8 > data.len() {
                return Err(TransactionError::SerializationError(
                    "Invalid data format".to_string(),
                ));
            }

            let mut value_bytes = [0u8; 8];
            value_bytes.copy_from_slice(&data[pos..pos + 8]);
            let value = u64::from_le_bytes(value_bytes);
            pos += 8;

            if pos + 4 > data.len() {
                return Err(TransactionError::SerializationError(
                    "Invalid data format".to_string(),
                ));
            }

            let lock_script_len = read_u32(&data[pos..pos + 4]) as usize;
            pos += 4;

            if pos + lock_script_len > data.len() {
                return Err(TransactionError::SerializationError(
                    "Invalid lock_script length".to_string(),
                ));
            }

            let lock_script = data[pos..pos + lock_script_len].to_vec();
            pos += lock_script_len;

            outputs.push(UTXOOutput { value, lock_script });
        }

        Ok(UTXOTransaction {
            txid,
            inputs,
            outputs,
        })
    }

    fn get_model_extensions(&self) -> Option<&dyn Any> {
        Some(self as &dyn Any)
    }
}

impl<CS: CommitmentScheme> UTXOOperations for UTXOModel<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    fn create_utxo_key(&self, txid: &[u8], index: u32) -> Result<Vec<u8>, TransactionError> {
        let mut key = Vec::with_capacity(txid.len() + 5);
        key.push(b'u'); // Prefix 'u' for UTXO
        key.extend_from_slice(txid);
        key.extend_from_slice(&index.to_le_bytes());
        Ok(key)
    }
}

/// Helper function to read a u32 from a byte slice
fn read_u32(data: &[u8]) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(data);
    u32::from_le_bytes(bytes)
}