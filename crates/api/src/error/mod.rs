// Path: crates/api/src/error/mod.rs
// Re-export all core error types from the central types crate.
pub use depin_sdk_types::error::{
    BlockError, ChainError, ConsensusError, CoreError, CryptoError, ErrorCode, GovernanceError,
    OracleError, RpcError, StateError, TransactionError, UpgradeError, ValidatorError, VmError,
};
pub use depin_sdk_types::Result;