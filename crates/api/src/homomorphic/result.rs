// Path: crates/api/src/homomorphic/result.rs
//! Definition of the OperationResult enum.

use std::any::Any;
use std::fmt;
use std::sync::Arc;

/// The result of a homomorphic operation execution.
pub enum OperationResult {
    /// The operation was successful, containing the resulting commitment.
    Success(Arc<dyn Any + Send + Sync>),

    /// The operation failed, containing an error message.
    Failure(String),

    /// The operation is not supported by the computation engine or commitment scheme.
    Unsupported,
}

impl fmt::Debug for OperationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success(_) => write!(f, "OperationResult::Success(..)"),
            Self::Failure(msg) => write!(f, "OperationResult::Failure({msg})"),
            Self::Unsupported => write!(f, "OperationResult::Unsupported"),
        }
    }
}

impl Clone for OperationResult {
    fn clone(&self) -> Self {
        match self {
            Self::Success(value) => Self::Success(Arc::clone(value)),
            Self::Failure(msg) => Self::Failure(msg.clone()),
            Self::Unsupported => Self::Unsupported,
        }
    }
}
