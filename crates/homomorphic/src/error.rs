use depin_sdk_core::commitment::HomomorphicOperation;
use std::error::Error;
use std::fmt;

/// Errors that can occur during homomorphic operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomomorphicError {
    /// Invalid point in a commitment
    InvalidPoint(String),
    /// Negative or zero scalar in scalar multiplication
    NegativeScalar,
    /// Position is out of bounds
    OutOfBounds(usize, usize),
    /// Operation not supported by the commitment scheme
    UnsupportedOperation(HomomorphicOperation),
    /// Proof verification failed
    VerificationFailure,
    /// Internal operation error
    InternalError(String),
    /// Invalid input for an operation
    InvalidInput(String),
    /// Custom error with message
    Custom(String),
}

impl fmt::Display for HomomorphicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HomomorphicError::InvalidPoint(details) => {
                write!(f, "Invalid point in commitment: {}", details)
            }
            HomomorphicError::NegativeScalar => {
                write!(f, "Scalar must be positive in scalar multiplication")
            }
            HomomorphicError::OutOfBounds(pos, max) => {
                write!(f, "Position {} out of bounds (max: {})", pos, max)
            }
            HomomorphicError::UnsupportedOperation(op) => {
                write!(f, "Operation not supported: {:?}", op)
            }
            HomomorphicError::VerificationFailure => write!(f, "Proof verification failed"),
            HomomorphicError::InternalError(details) => {
                write!(f, "Internal operation error: {}", details)
            }
            HomomorphicError::InvalidInput(details) => {
                write!(f, "Invalid input for operation: {}", details)
            }
            HomomorphicError::Custom(msg) => write!(f, "{}", msg),
        }
    }
}

impl Error for HomomorphicError {}

/// Convenience type for operation results
pub type HomomorphicResult<T> = Result<T, HomomorphicError>;

/// Convert string errors to HomomorphicError
impl From<String> for HomomorphicError {
    fn from(s: String) -> Self {
        HomomorphicError::Custom(s)
    }
}

/// Convert &str errors to HomomorphicError
impl From<&str> for HomomorphicError {
    fn from(s: &str) -> Self {
        HomomorphicError::Custom(s.to_string())
    }
}