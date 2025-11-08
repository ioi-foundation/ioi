// Path: crates/api/src/transaction/mod.rs
//! Defines the core `TransactionModel` trait.

use crate::chain::ChainView;
use crate::commitment::CommitmentScheme;
use crate::state::{ProofProvider, StateAccess, StateManager};
use crate::transaction::context::TxContext;
use async_trait::async_trait;
use ioi_types::error::TransactionError;
use std::any::Any;
use std::fmt::Debug;

pub mod context;
pub mod decorator;

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

    /// Validates static properties of a transaction that do not require state access.
    fn validate_stateless(&self, tx: &Self::Transaction) -> Result<(), TransactionError>;

    /// Applies the core state transition logic of a transaction's payload.
    /// This is called *after* all `TxDecorator` handlers have passed.
    async fn apply_payload<ST, CV>(
        &self,
        chain: &CV,                    // ChainView for read-only context
        state: &mut dyn StateAccess, // The transactional state overlay for writes
        tx: &Self::Transaction,
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError>
    where
        ST: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + Send
            + Sync
            + 'static,
        CV: ChainView<Self::CommitmentScheme, ST> + Send + Sync + ?Sized;

    /// Generates a proof for a transaction.
    fn generate_proof<P>(
        &self,
        tx: &Self::Transaction,
        state: &P,
    ) -> Result<Self::Proof, TransactionError>
    where
        P: ProofProvider<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized;

    /// Verifies a proof for a transaction.
    fn verify_proof<P>(&self, proof: &Self::Proof, state: &P) -> Result<bool, TransactionError>
    where
        P: ProofProvider<
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