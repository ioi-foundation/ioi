// Path: crates/homomorphic/src/operations/scalar_multiply/tests/mod.rs
use super::*;
use crate::error::HomomorphicError;
use ioi_state::primitives::pedersen::{PedersenCommitment, PedersenCommitmentScheme};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::homomorphic::CommitmentOperation;
use std::any::Any;
use std::sync::Arc;

#[test]
fn test_scalar_multiply() {
    let scheme = PedersenCommitmentScheme::new(5).unwrap();

    // Create a commitment
    let value = b"test value";
    let commitment = scheme.commit(&[Some(value.to_vec())]).unwrap();

    // Test direct scalar_multiply function with valid scalar
    let scalar = 3;
    let product_result = scalar_multiply(&scheme, &commitment, scalar);
    assert!(product_result.is_ok());

    // Test with negative scalar
    let negative_result = scalar_multiply(&scheme, &commitment, -1);
    assert!(negative_result.is_err());
    assert!(matches!(
        negative_result.unwrap_err(),
        HomomorphicError::NegativeScalar
    ));
}

#[test]
fn test_execute_scalar_multiply() {
    let scheme = PedersenCommitmentScheme::new(5).unwrap();

    // Create a commitment
    let value = b"test value";
    let commitment = scheme.commit(&[Some(value.to_vec())]).unwrap();

    // Test execute_scalar_multiply with CommitmentOperation
    let commitment_arc: Arc<dyn Any + Send + Sync> = Arc::new(commitment.clone());
    let scalar = 3;

    let operation = CommitmentOperation::ScalarMultiply {
        commitment: commitment_arc,
        scalar,
    };

    let result = execute_scalar_multiply(&scheme, &operation);

    match result {
        OperationResult::Success(result_arc) => {
            let product = result_arc.downcast_ref::<PedersenCommitment>().unwrap();
            assert_ne!(product.as_ref(), commitment.as_ref());
        }
        _ => panic!("Operation failed or unsupported"),
    }
}

#[test]
fn test_scalar_multiply_invalid_input() {
    let scheme = PedersenCommitmentScheme::new(5).unwrap();

    // Create an invalid commitment
    let commitment_arc: Arc<dyn Any + Send + Sync> = Arc::new("not a commitment");
    let scalar = 3;

    let operation = CommitmentOperation::ScalarMultiply {
        commitment: commitment_arc,
        scalar,
    };

    let result = execute_scalar_multiply(&scheme, &operation);

    match result {
        OperationResult::Failure(error) => {
            assert!(error.contains("Commitment is not the correct type"));
        }
        _ => panic!("Expected failure for invalid input"),
    }
}

#[test]
fn test_scalar_multiply_negative_scalar() {
    let scheme = PedersenCommitmentScheme::new(5).unwrap();

    // Create a valid commitment
    let value = b"test value";
    let commitment = scheme.commit(&[Some(value.to_vec())]).unwrap();
    let commitment_arc: Arc<dyn Any + Send + Sync> = Arc::new(commitment);

    // Use a negative scalar
    let scalar = -1;

    let operation = CommitmentOperation::ScalarMultiply {
        commitment: commitment_arc,
        scalar,
    };

    let result = execute_scalar_multiply(&scheme, &operation);

    match result {
        OperationResult::Failure(error) => {
            assert!(error.contains("Scalar must be positive"));
        }
        _ => panic!("Expected failure for negative scalar"),
    }
}
