// Path: crates/api/src/app/mod.rs

use crate::transaction::TransactionModel;

// Re-export all canonical app types from the `types` crate.
// This makes `ioi-types` the single source of truth for these data structures,
// eliminating the duplicate definitions that were here previously and resolving
// the deserialization bug.
pub use ioi_types::app::{
    ApplicationTransaction, Block, BlockHeader, ChainStatus, ChainTransaction, Input, Output,
    SystemPayload, SystemTransaction, UTXOTransaction,
};

/// A struct that holds the core, serializable state of a blockchain.
/// This is distinct from its logic, which is defined by the `ChainStateMachine` trait.
#[derive(Debug)]
pub struct ChainState<CS, TM: TransactionModel> {
    /// The cryptographic commitment scheme used by the chain.
    pub commitment_scheme: CS,
    /// The transaction model defining validation and application logic.
    pub transaction_model: TM,
    /// A unique identifier for the blockchain.
    pub chain_id: String,
    /// The current status of the chain.
    pub status: ChainStatus,
    /// A cache of recently processed blocks. Now uses the canonical type.
    pub recent_blocks: Vec<Block<ChainTransaction>>,
    /// The maximum number of recent blocks to keep in the cache.
    pub max_recent_blocks: usize,
}
