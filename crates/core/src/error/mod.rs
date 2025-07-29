// Path: crates/core/src/error/mod.rs

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StateError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Validation failed: {0}")]
    Validation(String),
    #[error("Apply failed: {0}")]
    Apply(String),
    #[error("State backend error: {0}")]
    Backend(String),
    // FIX: Add variants for errors that occur in state tree implementations.
    // The `WriteError` is used by `FileStateTree` when file I/O fails.
    // The `InvalidValue` is used by `VerkleTree` when a value can't be converted.
    #[error("State write error: {0}")]
    WriteError(String),
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    #[error("Invalid transaction: {0}")]
    Invalid(String),
    // FIX: Add a variant to wrap StateErrors, which will allow `?` to work.
    #[error("State error: {0}")]
    State(#[from] StateError),
}

#[derive(Error, Debug)]
pub enum ValidatorError {
    #[error("Container '{0}' is already running")]
    AlreadyRunning(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Service not found: {0}")]
    ServiceNotFound(String),
    #[error("Upgrade error: {0}")]
    UpgradeError(String),
    #[error("Custom error: {0}")]
    Custom(String),
}