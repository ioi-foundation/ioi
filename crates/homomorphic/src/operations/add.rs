//! Implementation of addition operations

use std::any::Any;
use depin_sdk_core::commitment::HomomorphicCommitmentScheme;
use depin_sdk_core::homomorphic::{CommitmentOperation, OperationResult};

/// Add two commitments
pub fn add<C: HomomorphicCommitmentScheme>(
    scheme: &C,
    left: &C::Commitment,
    right: &C::Commitment,
) -> Result<C::Commitment, String> {
    scheme.add(left, right)
}

/// Execute an add operation
pub fn execute_add<C: HomomorphicCommitmentScheme>(
    scheme: &C,
    operation: &CommitmentOperation,
) -> OperationResult {
    match operation {
        CommitmentOperation::Add { left, right } => {
            // Try to downcast the boxed Any to the correct commitment type
            let left_commitment = match left.downcast_ref::<C::Commitment>() {
                Some(c) => c,
                None => return OperationResult::Failure("Left operand is not the correct commitment type".to_string()),
            };
            
            let right_commitment = match right.downcast_ref::<C::Commitment>() {
                Some(c) => c,
                None => return OperationResult::Failure("Right operand is not the correct commitment type".to_string()),
            };
            
            // Perform the addition
            match scheme.add(left_commitment, right_commitment) {
                Ok(result) => OperationResult::Success(Box::new(result)),
                Err(e) => OperationResult::Failure(e),
            }
        },
        _ => OperationResult::Unsupported,
    }
}
