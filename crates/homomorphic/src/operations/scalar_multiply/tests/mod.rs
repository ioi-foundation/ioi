// Path: crates/homomorphic/src/operations/scalar_multiply/tests/mod.rs
use super::*;
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_commitment_schemes::elliptic_curve::{
    EllipticCurveCommitment, EllipticCurveCommitmentScheme,
};
use std::any::Any;

#[test]
fn test_scalar_multiply() {
    let scheme = EllipticCurveCommitmentScheme::new(5);

    // Create a commitment
    let value = b"test value";
    let commitment = scheme.commit(&[Some(value.to_vec())]);

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
    let scheme = EllipticCurveCommitmentScheme::new(5);

    // Create a commitment
    let value = b"test value";
    let commitment = scheme.commit(&[Some(value.to_vec())]);

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
            let product = result_arc
                .downcast_ref::<EllipticCurveCommitment>()
                .unwrap();
            assert_ne!(product.as_ref(), commitment.as_ref());
        }
        _ => panic!("Operation failed or unsupported"),
    }
}

#[test]
fn test_scalar_multiply_invalid_input() {
    let scheme = EllipticCurveCommitmentScheme::new(5);

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
    let scheme = EllipticCurveCommitmentScheme::new(5);

    // Create a valid commitment
    let value = b"test value";
    let commitment = scheme.commit(&[Some(value.to_vec())]);
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
