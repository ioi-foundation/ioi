// Path: crates/api/src/transaction/context.rs
//! Defines the stable context for transaction execution.

// [FIX] Removed ibc_primitives dependency to lighten the core build.
// use ibc_primitives::Timestamp;
use crate::services::access::ServiceDirectory;
use ioi_types::app::{AccountId, ChainId};

/// Provides stable, read-only context to transaction models and services during execution.
#[derive(Clone)]
pub struct TxContext<'a> {
    /// The current block height being processed.
    pub block_height: u64,
    /// The deterministic timestamp of the current block in **nanoseconds** since UNIX EPOCH.
    /// This replaces the heavy `ibc_primitives::Timestamp` dependency.
    pub block_timestamp: u64,
    /// The unique identifier of the chain for replay protection.
    pub chain_id: ChainId,
    /// The `AccountId` of the entity that signed the current transaction.
    /// This is the authoritative source for permission checks within services.
    pub signer_account_id: AccountId,
    /// A read-only directory of available blockchain services.
    pub services: &'a ServiceDirectory,
    /// If true, the transaction is being simulated (e.g., via `check_tx` or `query_contract`)
    /// and should not have permanent side effects.
    pub simulation: bool,
    /// If true, the call is initiated by the chain itself (e.g., end-block hook)
    /// and is permitted to call methods with `Internal` permission. For user-initiated
    /// transactions, this must always be `false`.
    pub is_internal: bool,
}
