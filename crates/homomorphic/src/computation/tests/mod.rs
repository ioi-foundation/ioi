// Path: crates/homomorphic/src/computation/tests/mod.rs
use super::*;
use ioi_state::primitives::pedersen::{PedersenCommitment, PedersenCommitmentScheme};
use ioi_api::commitment::{CommitmentScheme, ProofContext, Selector};
use ioi_api::homomorphic::{CommitmentOperation, OperationResult};

use std::any::Any;

#[test]
fn test_computation_engine() {
    // Create a computation engine with Pedersen commitment scheme
    let scheme = PedersenCommitmentScheme::new(5).unwrap();
    let computation = HomomorphicComputation::new(scheme.clone());

    // Test add operation
    let value_a = b"value a";
    let value_b = b"value b";
    // NOTE: This commit is flawed as it doesn't return the blinding factor.
    // A real application would need a way to manage this.
    let commitment_a = scheme.commit(&[Some(value_a.to_vec())]).unwrap();
    let commitment_b = scheme.commit(&[Some(value_b.to_vec())]).unwrap();

    let left: Arc<dyn Any + Send + Sync> = Arc::new(commitment_a.clone());
    let right: Arc<dyn Any + Send + Sync> = Arc::new(commitment_b.clone());

    let add_op = CommitmentOperation::Add { left, right };
    let result = computation.execute(&add_op);

    match result {
        OperationResult::Success(result_arc) => {
            let sum = result_arc.downcast_ref::<PedersenCommitment>().unwrap();

            // Compute expected result directly
            let expected = scheme.add(&commitment_a, &commitment_b).unwrap();
            assert_eq!(sum.as_ref(), expected.as_ref());

            // Create a proof for the operation with a selector
            let selector = Selector::Position(0);
            let proof = computation
                .create_proof_with_selector(&add_op, sum, &selector)
                .unwrap();

            // Verify the proof with context
            let context = ProofContext::default();
            let verified = computation
                .verify_proof_with_context(&proof, &context)
                .unwrap();
            assert!(verified);
        }
        _ => panic!("Add operation failed or unsupported"),
    }

    // Test scalar multiply operation
    let commitment_arc: Arc<dyn Any + Send + Sync> = Arc::new(commitment_a.clone());
    let scalar = 3;

    let scalar_op = CommitmentOperation::ScalarMultiply {
        commitment: commitment_arc,
        scalar,
    };
    let result = computation.execute(&scalar_op);

    match result {
        OperationResult::Success(result_arc) => {
            let product = result_arc.downcast_ref::<PedersenCommitment>().unwrap();

            // Compute expected result directly
            let expected = scheme.scalar_multiply(&commitment_a, scalar).unwrap();
            assert_eq!(product.as_ref(), expected.as_ref());

            // Create a proof for the operation with a key selector
            let key = b"test_key".to_vec();
            let selector = Selector::Key(key);
            let proof = computation
                .create_proof_with_selector(&scalar_op, product, &selector)
                .unwrap();

            // Create a context with some data
            let mut context = ProofContext::default();
            context.add_data("test", vec![1, 2, 3]);

            // Verify the proof with context
            let verified = computation
                .verify_proof_with_context(&proof, &context)
                .unwrap();
            assert!(verified);
        }
        _ => panic!("Scalar multiply operation failed or unsupported"),
    }

    // Test combined operation and proof generation
    let key = b"combined_op_key".to_vec();
    let selector = Selector::Key(key);
    let (result, proof) = computation.apply_and_prove(&add_op, &selector).unwrap();

    // Verify the result and proof
    let verified = computation.verify_proof(&proof).unwrap();
    assert!(verified);

    // The result should match direct computation
    let expected = scheme.add(&commitment_a, &commitment_b).unwrap();
    assert_eq!(result.as_ref(), expected.as_ref());
}

#[test]
fn test_batch_operations() {
    // Create a computation engine with Pedersen commitment scheme
    let scheme = PedersenCommitmentScheme::new(5).unwrap();
    let computation = HomomorphicComputation::new(scheme.clone());

    // Create test commitments
    let value_a = b"value a";
    let value_b = b"value b";
    let commitment_a = scheme.commit(&[Some(value_a.to_vec())]).unwrap();
    let commitment_b = scheme.commit(&[Some(value_b.to_vec())]).unwrap();

    // Create a batch of operations with selectors
    let operations = vec![
        (
            CommitmentOperation::Add {
                left: Arc::new(commitment_a.clone()),
                right: Arc::new(commitment_b.clone()),
            },
            Selector::Position(0),
        ),
        (
            CommitmentOperation::ScalarMultiply {
                commitment: Arc::new(commitment_a.clone()),
                scalar: 3,
            },
            Selector::Key(b"test_key".to_vec()),
        ),
    ];

    // Apply batch and generate proofs
    let batch_results = computation.apply_batch_and_prove(&operations).unwrap();

    // Check the batch results
    assert_eq!(batch_results.len(), 2);

    // Verify all proofs
    for (_, proof) in &batch_results {
        let verified = computation.verify_proof(proof).unwrap();
        assert!(verified);
    }
}
