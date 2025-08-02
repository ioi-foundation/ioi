use crate::error::{HomomorphicError, HomomorphicResult};
use depin_sdk_api::commitment::HomomorphicCommitmentScheme;
use depin_sdk_api::homomorphic::{CommitmentOperation, OperationResult};
use std::sync::Arc;

/// Add two commitments
pub fn add<C: HomomorphicCommitmentScheme>(
    scheme: &C,
    left: &C::Commitment,
    right: &C::Commitment,
) -> HomomorphicResult<C::Commitment> {
    scheme.add(left, right).map_err(HomomorphicError::from)
}

/// Execute an add operation
pub fn execute_add<C: HomomorphicCommitmentScheme>(
    scheme: &C,
    operation: &CommitmentOperation,
) -> OperationResult {
    match operation {
        CommitmentOperation::Add { left, right } => {
            // Try to downcast the Arc<dyn Any> to the correct commitment type
            let left_commitment = match left.downcast_ref::<C::Commitment>() {
                Some(c) => c,
                None => {
                    return OperationResult::Failure(
                        HomomorphicError::InvalidInput(
                            "Left operand is not the correct commitment type".into(),
                        )
                        .to_string(),
                    )
                }
            };

            let right_commitment = match right.downcast_ref::<C::Commitment>() {
                Some(c) => c,
                None => {
                    return OperationResult::Failure(
                        HomomorphicError::InvalidInput(
                            "Right operand is not the correct commitment type".into(),
                        )
                        .to_string(),
                    )
                }
            };

            // Perform the addition
            match add(scheme, left_commitment, right_commitment) {
                Ok(result) => OperationResult::Success(Arc::new(result)),
                Err(e) => OperationResult::Failure(e.to_string()),
            }
        }
        _ => OperationResult::Unsupported,
    }
}
