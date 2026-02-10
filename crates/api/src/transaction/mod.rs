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
    type Proof: Send + Sync + Debug;
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

    /// Applies the core state transition logic of a transaction's payload and returns a proof of the state that was read.
    /// This is called *after* all `TxDecorator` handlers have passed.
    ///
    /// Returns a tuple containing:
    /// 1. The cryptographic proof of the state read during execution.
    /// 2. The total gas consumed by the transaction execution.
    async fn apply_payload<ST, CV>(
        &self,
        chain: &CV,                  // ChainView for read-only context
        state: &mut dyn StateAccess, // The transactional state overlay for writes
        tx: &Self::Transaction,
        ctx: &mut TxContext<'_>,
    ) -> Result<(Self::Proof, u64), TransactionError>
    where
        ST: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ProofProvider
            + Send
            + Sync
            + 'static,
        CV: ChainView<Self::CommitmentScheme, ST> + Send + Sync + ?Sized;

    /// Serializes a transaction to bytes.
    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError>;

    /// Deserializes bytes to a transaction.
    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError>;

    /// Provides an optional extension point for model-specific functionality.
    fn get_model_extensions(&self) -> Option<&dyn Any> {
        None
    }
}
