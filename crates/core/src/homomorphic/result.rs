//! Definition of the OperationResult enum

use std::any::Any;
use std::fmt;
use std::sync::Arc;

/// Result of a homomorphic operation
pub enum OperationResult {
    /// Successfully computed result
    Success(Arc<dyn Any + Send + Sync>),

    /// Operation failed
    Failure(String),

    /// Operation not supported
    Unsupported,
}

impl fmt::Debug for OperationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success(_) => write!(f, "OperationResult::Success(..)"),
            Self::Failure(msg) => write!(f, "OperationResult::Failure({})", msg),
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
