// Path: crates/api/src/homomorphic/operations.rs
//! Definition of the CommitmentOperation enum.

use std::any::Any;
use std::fmt;
use std::sync::Arc;

/// An enum representing a specific homomorphic operation to be performed.
/// This is used to pass type-erased operations to a computation engine.
pub enum CommitmentOperation {
    /// Represents the addition of two commitments.
    Add {
        /// The left-hand side of the addition.
        left: Arc<dyn Any + Send + Sync>,
        /// The right-hand side of the addition.
        right: Arc<dyn Any + Send + Sync>,
    },

    /// Represents the multiplication of a commitment by a scalar value.
    ScalarMultiply {
        /// The commitment to be multiplied.
        commitment: Arc<dyn Any + Send + Sync>,
        /// The scalar value.
        scalar: i32,
    },

    /// Represents a custom, scheme-specific operation.
    Custom {
        /// A unique string identifier for the custom operation.
        operation_id: String,
        /// A list of input commitments for the operation.
        inputs: Vec<Arc<dyn Any + Send + Sync>>,
        /// A byte slice for any additional parameters the operation requires.
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
                    "CommitmentOperation::ScalarMultiply {{ scalar: {scalar}, .. }}"
                )
            }
            Self::Custom { operation_id, .. } => {
                write!(
                    f,
                    "CommitmentOperation::Custom {{ operation_id: {operation_id}, .. }}"
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