// File: crates/core/src/transaction/mod.rs

use crate::commitment::CommitmentScheme;
use crate::error::TransactionError;
use crate::state::StateManager;
use std::any::Any;
use std::fmt::Debug;

/// Core transaction model trait that defines the interface for all transaction models.
///
/// This trait is intentionally model-agnostic, allowing for different implementations
/// (UTXO, account-based, hybrid, etc.) while providing a consistent interface.
pub trait TransactionModel {
    /// The transaction type for this model.
    type Transaction: Debug;

    /// The proof type for this model.
    type Proof;

    /// The commitment scheme used by this model.
    type CommitmentScheme: CommitmentScheme;

    /// Creates a "coinbase" or block reward transaction.
    ///
    /// This provides a generic way for a block producer (like the OrchestrationContainer)
    /// to create the first, special transaction in a block without needing to know the
    /// specific details of the transaction model.
    ///
    /// # Arguments
    /// * `block_height` - The height of the block this transaction will be in.
    /// * `recipient` - The public key or address of the block producer who should receive the reward.
    ///
    /// # Returns
    /// * `Ok(transaction)` - A valid coinbase transaction.
    /// * `Err(TransactionError)` - If the coinbase transaction could not be created.
    fn create_coinbase_transaction(
        &self,
        block_height: u64,
        recipient: &[u8],
    ) -> Result<Self::Transaction, TransactionError>;

    /// Validate a transaction against the current state.
    ///
    /// # Arguments
    /// * `tx` - The transaction to validate.
    /// * `state` - The state to validate against.
    ///
    /// # Returns
    /// * `Ok(true)` - If the transaction is valid.
    /// * `Ok(false)` - If the transaction is invalid.
    /// * `Err(TransactionError)` - If an error occurred during validation.
    fn validate<S>(&self, tx: &Self::Transaction, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized;

    /// Apply a transaction to the state.
    ///
    /// # Arguments
    /// * `tx` - The transaction to apply.
    /// * `state` - The state to modify.
    ///
    /// # Returns
    /// * `Ok(())` - If the transaction was successfully applied.
    /// * `Err(TransactionError)` - If an error occurred during application.
    fn apply<S>(&self, tx: &Self::Transaction, state: &mut S) -> Result<(), TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized;

    /// Generate a proof for a transaction.
    ///
    /// # Arguments
    /// * `tx` - The transaction to generate a proof for.
    /// * `state` - The state to generate the proof against.
    ///
    /// # Returns
    /// * `Ok(proof)` - If the proof was successfully generated.
    /// * `Err(TransactionError)` - If an error occurred during proof generation.
    fn generate_proof<S>(
        &self,
        tx: &Self::Transaction,
        state: &S,
    ) -> Result<Self::Proof, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized;

    /// Verify a proof for a transaction.
    ///
    /// # Arguments
    /// * `proof` - The proof to verify.
    /// * `state` - The state to verify against.
    ///
    /// # Returns
    /// * `Ok(true)` - If the proof is valid.
    /// * `Ok(false)` - If the proof is invalid.
    /// * `Err(TransactionError)` - If an error occurred during verification.
    fn verify_proof<S>(&self, proof: &Self::Proof, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized;

    /// Serialize a transaction to bytes.
    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError>;

    /// Deserialize bytes to a transaction.
    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError>;

    /// Optional extension point for model-specific functionality.
    fn get_model_extensions(&self) -> Option<&dyn Any> {
        None
    }
}

/// Registry for managing multiple transaction models at runtime.
#[derive(Default)]
pub struct TransactionModelRegistry {
    models: std::collections::HashMap<String, Box<dyn Any>>,
}

impl TransactionModelRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            models: std::collections::HashMap::new(),
        }
    }

    /// Register a transaction model.
    pub fn register<T: TransactionModel + 'static>(&mut self, name: &str, model: T) {
        self.models.insert(name.to_string(), Box::new(model));
    }

    /// Get a registered transaction model.
    pub fn get<T: 'static>(&self, name: &str) -> Option<&T> {
        self.models
            .get(name)
            .and_then(|model| model.downcast_ref::<T>())
    }

    /// Check if a model is registered.
    pub fn has_model(&self, name: &str) -> bool {
        self.models.contains_key(name)
    }
}