//! Definition of the CommitmentOperation enum

use std::any::Any;
use std::fmt;
use std::sync::Arc;

/// Type for operations on commitments
pub enum CommitmentOperation {
    /// Add two commitments
    Add {
        left: Arc<dyn Any + Send + Sync>,
        right: Arc<dyn Any + Send + Sync>,
    },

    /// Multiply a commitment by a scalar
    ScalarMultiply {
        commitment: Arc<dyn Any + Send + Sync>,
        scalar: i32,
    },

    /// Apply a custom operation
    Custom {
        operation_id: String,
        inputs: Vec<Arc<dyn Any + Send + Sync>>,
        parameters: Vec<u8>,
    },
}

impl fmt::Debug for CommitmentOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Add { .. } => write!(f, "CommitmentOperation::Add {{ .. }}"),
            Self::ScalarMultiply { scalar, .. } => {
                write!(
                    f,
                    "CommitmentOperation::ScalarMultiply {{ scalar: {}, .. }}",
                    scalar
                )
            }
            Self::Custom { operation_id, .. } => {
                write!(
                    f,
                    "CommitmentOperation::Custom {{ operation_id: {}, .. }}",
                    operation_id
                )
            }
        }
    }
}

impl Clone for CommitmentOperation {
    fn clone(&self) -> Self {
        match self {
            Self::Add { left, right } => Self::Add {
                left: Arc::clone(left),
                right: Arc::clone(right),
            },
            Self::ScalarMultiply { commitment, scalar } => Self::ScalarMultiply {
                commitment: Arc::clone(commitment),
                scalar: *scalar,
            },
            Self::Custom {
                operation_id,
                inputs,
                parameters,
            } => Self::Custom {
                operation_id: operation_id.clone(),
                inputs: inputs.iter().map(Arc::clone).collect(),
                parameters: parameters.clone(),
            },
        }
    }
}
