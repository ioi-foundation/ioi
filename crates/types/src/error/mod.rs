// Path: crates/types/src/error/mod.rs
//! Core error types for the DePIN SDK.

use thiserror::Error;

/// Errors related to the state tree or state manager.
#[derive(Error, Debug)]
pub enum StateError {
    /// The requested key was not found in the state.
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    /// State validation failed.
    #[error("Validation failed: {0}")]
    Validation(String),
    /// Applying a state change failed.
    #[error("Apply failed: {0}")]
    Apply(String),
    /// An error occurred in the state backend.
    #[error("State backend error: {0}")]
    Backend(String),
    /// An error occurred while writing to the state.
    #[error("State write error: {0}")]
    WriteError(String),
    /// The provided value was invalid.
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

/// Errors related to transaction processing.
#[derive(Error, Debug)]
pub enum TransactionError {
    /// An error occurred during serialization.
    #[error("Serialization error: {0}")]
    Serialization(String),
    /// An error occurred during deserialization.
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    /// The transaction is invalid for a model-specific reason.
    #[error("Invalid transaction: {0}")]
    Invalid(String),
    /// An error occurred while interacting with the state.
    #[error("State error: {0}")]
    State(#[from] StateError),
}

/// Errors related to the virtual machine and contract execution.
#[derive(Error, Debug)]
pub enum VmError {
    /// The VM failed to initialize.
    #[error("VM initialization failed: {0}")]
    Initialization(String),
    /// The provided contract bytecode was invalid.
    #[error("Invalid bytecode: {0}")]
    InvalidBytecode(String),
    /// The contract execution trapped (e.g., out of gas, memory access error).
    #[error("Execution trapped (out of gas, memory access error, etc.): {0}")]
    ExecutionTrap(String),
    /// The requested function was not found in the contract.
    #[error("Function not found in contract: {0}")]
    FunctionNotFound(String),
    /// An error occurred in a host function call.
    #[error("Host function error: {0}")]
    HostError(String),
    /// A memory allocation or access error occurred within the VM.
    #[error("Memory allocation/access error in VM: {0}")]
    MemoryError(String),
}

/// Errors related to the validator and its containers.
#[derive(Error, Debug)]
pub enum ValidatorError {
    /// The container is already running.
    #[error("Container '{0}' is already running")]
    AlreadyRunning(String),
    /// An I/O error occurred.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// A configuration error occurred.
    #[error("Configuration error: {0}")]
    Config(String),
    /// A VM execution error occurred.
    #[error("VM execution error: {0}")]
    Vm(#[from] VmError),
    /// An error occurred while interacting with the state.
    #[error("State error: {0}")]
    State(#[from] StateError),
    /// A generic error occurred.
    #[error("Other error: {0}")]
    Other(String),
}

/// Errors related to blockchain-level processing.
#[derive(Debug, Error)]
pub enum ChainError {
    /// An error occurred during block processing.
    #[error("Block processing error: {0}")]
    Block(String),
    /// An error occurred during transaction processing.
    #[error("Transaction processing error: {0}")]
    Transaction(String),
    /// An error occurred while interacting with the state.
    #[error("State error: {0}")]
    State(#[from] StateError),
}

/// Implement the conversion from TransactionError to ChainError.
impl From<TransactionError> for ChainError {
    fn from(err: TransactionError) -> Self {
        ChainError::Transaction(err.to_string())
    }
}

/// General errors for core SDK services.
#[derive(Debug, Error)]
pub enum CoreError {
    /// The requested service was not found.
    #[error("Service not found: {0}")]
    ServiceNotFound(String),
    /// An error occurred during a service upgrade.
    #[error("Upgrade error: {0}")]
    UpgradeError(String),
    /// A custom, descriptive error.
    #[error("Custom error: {0}")]
    Custom(String),
}

/// Errors related to service upgrades.
#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    /// The proposed upgrade is invalid.
    #[error("Invalid upgrade: {0}")]
    InvalidUpgrade(String),
    /// State migration to the new service version failed.
    #[error("State migration failed: {0}")]
    MigrationFailed(String),
    /// The requested service was not found.
    #[error("Service not found")]
    ServiceNotFound,
    /// The service's health check failed.
    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),
    /// An operation on the service failed.
    #[error("Service operation failed: {0}")]
    OperationFailed(String),
}
