// Path: crates/homomorphic/src/operations/scalar_multiply/mod.rs
use crate::error::{HomomorphicError, HomomorphicResult};
use depin_sdk_api::commitment::HomomorphicCommitmentScheme;
use depin_sdk_api::homomorphic::{CommitmentOperation, OperationResult};
use std::sync::Arc;

/// Multiply a commitment by a scalar
pub fn scalar_multiply<C: HomomorphicCommitmentScheme>(
    scheme: &C,
    commitment: &C::Commitment,
    scalar: i32,
) -> HomomorphicResult<C::Commitment> {
    if scalar <= 0 {
        return Err(HomomorphicError::NegativeScalar);
    }

    scheme
        .scalar_multiply(commitment, scalar)
        .map_err(HomomorphicError::from)
}

/// Execute a scalar multiply operation
pub fn execute_scalar_multiply<C: HomomorphicCommitmentScheme>(
    scheme: &C,
    operation: &CommitmentOperation,
) -> OperationResult {
    match operation {
        CommitmentOperation::ScalarMultiply { commitment, scalar } => {
            // Try to downcast the Arc<dyn Any> to the correct commitment type
            let commitment = match commitment.downcast_ref::<C::Commitment>() {
                Some(c) => c,
                None => {
                    return OperationResult::Failure(
                        HomomorphicError::InvalidInput("Commitment is not the correct type".into())
                            .to_string(),
                    )
                }
            };

            // Perform the scalar multiplication
            match scalar_multiply(scheme, commitment, *scalar) {
                Ok(result) => OperationResult::Success(Arc::new(result)),
                Err(e) => OperationResult::Failure(e.to_string()),
            }
        }
        _ => OperationResult::Unsupported,
    }
}

#[cfg(test)]
mod tests;
