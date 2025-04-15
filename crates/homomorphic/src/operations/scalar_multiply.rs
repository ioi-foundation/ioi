//! Implementation of scalar multiplication

use std::any::Any;
use depin_sdk_core::commitment::HomomorphicCommitmentScheme;
use depin_sdk_core::homomorphic::{CommitmentOperation, OperationResult};

/// Multiply a commitment by a scalar
pub fn scalar_multiply<C: HomomorphicCommitmentScheme>(
    scheme: &C,
    commitment: &C::Commitment,
    scalar: i32,
) -> Result<C::Commitment, String> {
    scheme.scalar_multiply(commitment, scalar)
}

/// Execute a scalar multiply operation
pub fn execute_scalar_multiply<C: HomomorphicCommitmentScheme>(
    scheme: &C,
    operation: &CommitmentOperation,
) -> OperationResult {
    match operation {
        CommitmentOperation::ScalarMultiply { commitment, scalar } => {
            // Try to downcast the boxed Any to the correct commitment type
            let commitment = match commitment.downcast_ref::<C::Commitment>() {
                Some(c) => c,
                None => return OperationResult::Failure("Commitment is not the correct type".to_string()),
            };
            
            // Perform the scalar multiplication
            match scheme.scalar_multiply(commitment, *scalar) {
                Ok(result) => OperationResult::Success(Box::new(result)),
                Err(e) => OperationResult::Failure(e),
            }
        },
        _ => OperationResult::Unsupported,
    }
}
