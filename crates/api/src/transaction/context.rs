// Path: crates/api/src/transaction/context.rs
//! Defines the stable context for transaction execution.
use crate::services::access::ServiceDirectory;
use depin_sdk_types::app::ChainId;

/// Provides stable, read-only context to transaction models during execution.
#[derive(Clone)]
pub struct TxContext<'a> {
    /// The current block height.
    pub block_height: u64,
    /// The unique identifier of the chain for replay protection.
    pub chain_id: ChainId,
    /// A read-only directory of available blockchain services.
    pub services: &'a ServiceDirectory,
    /// If true, the transaction is being simulated and should not have side effects.
    pub simulation: bool,
}