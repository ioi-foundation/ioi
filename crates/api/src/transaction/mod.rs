// Path: crates/api/src/transaction/mod.rs
//! Defines the core `TransactionModel` trait.

use crate::commitment::CommitmentScheme;
use crate::state::StateManager;
use crate::validator::WorkloadContainer;
use async_trait::async_trait;
use depin_sdk_types::error::TransactionError;
use std::any::Any;
use std::fmt::Debug;

/// The core trait that defines the interface for all transaction models.
#[async_trait]
pub trait TransactionModel: Send + Sync {
    /// The transaction type for this model.
    type Transaction: Debug + Send + Sync;
    /// The proof type for this model.
    type Proof;
    /// The commitment scheme used by this model.
    type CommitmentScheme: CommitmentScheme;

    /// Creates a "coinbase" or block reward transaction.
    fn create_coinbase_transaction(
        &self,
        block_height: u64,
        recipient: &[u8],
    ) -> Result<Self::Transaction, TransactionError>;
    /// Validates a transaction against the current state.
    fn validate<S>(&self, tx: &Self::Transaction, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized;
    /// Applies a transaction to the state.
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
            + 'static;
    /// Generates a proof for a transaction.
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
    /// Verifies a proof for a transaction.
    fn verify_proof<S>(&self, proof: &Self::Proof, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized;
    /// Serializes a transaction to bytes.
    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError>;
    /// Deserializes bytes to a transaction.
    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError>;
    /// Provides an optional extension point for model-specific functionality.
    fn get_model_extensions(&self) -> Option<&dyn Any> {
        None
    }
}