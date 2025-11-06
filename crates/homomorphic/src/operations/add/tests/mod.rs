// Path: crates/homomorphic/src/operations/add/tests/mod.rs
use super::*;
use crate::operations::{add, execute_add};
use ioi_state::primitives::pedersen::{PedersenCommitment, PedersenCommitmentScheme};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::homomorphic::CommitmentOperation;
use std::any::Any;
use std::sync::Arc;

#[test]
fn test_add_operation() {
    let scheme = PedersenCommitmentScheme::new(5).unwrap();

    // Create two commitments
    let value_a = b"value a";
    let value_b = b"value b";
    let commitment_a = scheme.commit(&[Some(value_a.to_vec())]).unwrap();
    let commitment_b = scheme.commit(&[Some(value_b.to_vec())]).unwrap();

    // Test direct add function
    let sum_result = add(&scheme, &commitment_a, &commitment_b);
    assert!(sum_result.is_ok());

    // Test execute_add with CommitmentOperation
    let left: Arc<dyn Any + Send + Sync> = Arc::new(commitment_a.clone());
    let right: Arc<dyn Any + Send + Sync> = Arc::new(commitment_b.clone());

    let operation = CommitmentOperation::Add { left, right };
    let result = execute_add(&scheme, &operation);

    match result {
        OperationResult::Success(result_arc) => {
            let sum = result_arc.downcast_ref::<PedersenCommitment>().unwrap();
            assert_ne!(sum.as_ref(), commitment_a.as_ref());
            assert_ne!(sum.as_ref(), commitment_b.as_ref());
        }
        _ => panic!("Operation failed or unsupported"),
    }
}

#[test]
fn test_add_invalid_input() {
    let scheme = PedersenCommitmentScheme::new(5).unwrap();

    // Create a valid commitment
    let value = b"test value";
    let commitment = scheme.commit(&[Some(value.to_vec())]).unwrap();

    // Create an invalid right operand
    let left: Arc<dyn Any + Send + Sync> = Arc::new(commitment);
    let right: Arc<dyn Any + Send + Sync> = Arc::new("not a commitment");

    let operation = CommitmentOperation::Add { left, right };
    let result = execute_add(&scheme, &operation);

    match result {
        OperationResult::Failure(error) => {
            assert!(error.contains("Right operand is not the correct commitment type"));
        }
        _ => panic!("Expected failure for invalid input"),
    }
}
