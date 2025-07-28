//! Error types for the DePIN SDK Core.

use std::fmt;

/// Error type for transaction operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionError {
    /// Invalid transaction format or data
    InvalidTransaction(String),
    
    /// Failed to access or modify state
    StateAccessFailed(String),
    
    /// Invalid input referenced in transaction
    InvalidInput(String),
    
    /// Insufficient funds for transaction
    InsufficientFunds(String),
    
    /// Invalid signature
    InvalidSignature(String),
    
    /// Invalid nonce value
    InvalidNonce(String),
    
    /// Serialization or deserialization error
    SerializationError(String),
    
    /// Other transaction errors
    Other(String),
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionError::InvalidTransaction(msg) => write!(f, "Invalid transaction: {}", msg),
            TransactionError::StateAccessFailed(msg) => write!(f, "State access failed: {}", msg),
            TransactionError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            TransactionError::InsufficientFunds(msg) => write!(f, "Insufficient funds: {}", msg),
            TransactionError::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            TransactionError::InvalidNonce(msg) => write!(f, "Invalid nonce: {}", msg),
            TransactionError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            TransactionError::Other(msg) => write!(f, "Other error: {}", msg),
        }
    }
}

impl std::error::Error for TransactionError {}

/// Error type for state operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// Key not found in state
    KeyNotFound(String),
    
    /// Failed to read from storage
    ReadError(String),
    
    /// Failed to write to storage
    WriteError(String),
    
    /// Invalid key format
    InvalidKey(String),
    
    /// Invalid value format
    InvalidValue(String),
    
    /// Other state errors
    Other(String),
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::KeyNotFound(msg) => write!(f, "Key not found: {}", msg),
            StateError::ReadError(msg) => write!(f, "Read error: {}", msg),
            StateError::WriteError(msg) => write!(f, "Write error: {}", msg),
            StateError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            StateError::InvalidValue(msg) => write!(f, "Invalid value: {}", msg),
            StateError::Other(msg) => write!(f, "Other error: {}", msg),
        }
    }
}

impl std::error::Error for StateError {}

impl From<StateError> for TransactionError {
    fn from(error: StateError) -> Self {
        TransactionError::StateAccessFailed(error.to_string())
    }
}

/// Error type for validator operations.
#[derive(Debug, thiserror::Error)]
pub enum ValidatorError {
    #[error("Container operation failed: {0}")]
    Container(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Lifecycle error: {0}")]
    Lifecycle(String),
}


/// Core error type for the SDK
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("Service not found: {0}")]
    ServiceNotFound(String),
    
    #[error("Invalid block: {0}")]
    InvalidBlock(String),
    
    #[error("Consensus error: {0}")]
    ConsensusError(String),
    
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    #[error("Upgrade error: {0}")]
    UpgradeError(String),
    
    #[error("Custom error: {0}")]
    Custom(String),
}

/// Result type used throughout the SDK
pub type Result<T> = std::result::Result<T, CoreError>;