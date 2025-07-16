use depin_sdk_commitment_schemes::elliptical_curve::EllipticalCurveCommitmentScheme;
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::homomorphic::{CommitmentOperation, OperationResult};
use depin_sdk_homomorphic::{add, CompositeOperation, HomomorphicComputation, HomomorphicError};
use std::any::Any;
use std::sync::Arc;

fn main() {
    println!("Testing homomorphic operations...");

    // Create a Elliptical Curve commitment scheme
    let elliptical_curve = EllipticalCurveCommitmentScheme::new(5);

    // Create a homomorphic computation engine
    let computation = HomomorphicComputation::new(elliptical_curve.clone());

    // Register a custom operation
    let registry = computation.registry();
    registry
        .register("double", move |inputs, _params| {
            if inputs.is_empty() {
                return Err(HomomorphicError::InvalidInput("No inputs provided".into()));
            }

            // Try to downcast the input to the EllipticalCurve commitment type
            let commitment = inputs[0]
                .downcast_ref::<depin_sdk_commitment_schemes::elliptical_curve::EllipticalCurveCommitment>()
                .ok_or_else(|| {
                    HomomorphicError::InvalidInput("Input is not a EllipticalCurve commitment".into())
                })?;

            // Double the commitment (add it to itself)
            let result = add(&elliptical_curve, commitment, commitment)?;

            Ok(Arc::new(result))
        })
        .expect("Failed to register custom operation");

    // Test basic operations
    test_basic_operations(&computation);

    // Test custom operations
    test_custom_operations(&computation);

    // Test batch operations
    test_batch_operations(&computation);

    // Test composite operations
    test_composite_operations(&computation);

    // Test proofs
    test_homomorphic_proofs(&computation);

    println!("All tests completed successfully!");
}

fn test_basic_operations(computation: &HomomorphicComputation<EllipticalCurveCommitmentScheme>) {
    println!("\nTesting basic operations...");

    let scheme = computation.scheme();

    // Create two commitments
    let value_a = b"value a";
    let value_b = b"value b";
    let commitment_a = scheme.commit(&[Some(value_a.to_vec())]);
    let commitment_b = scheme.commit(&[Some(value_b.to_vec())]);

    println!("Created commitments A and B");

    // Test addition
    let left: Arc<dyn Any + Send + Sync> = Arc::new(commitment_a.clone());
    let right: Arc<dyn Any + Send + Sync> = Arc::new(commitment_b.clone());

    let add_op = CommitmentOperation::Add { left, right };
    let result = computation.execute(&add_op);

    match result {
        OperationResult::Success(_) => println!("Addition successful"),
        OperationResult::Failure(e) => panic!("Addition failed: {}", e),
        OperationResult::Unsupported => panic!("Addition operation not supported"),
    }

    // Test scalar multiplication
    let commitment_arc: Arc<dyn Any + Send + Sync> = Arc::new(commitment_a.clone());
    let scalar = 3;

    let scalar_op = CommitmentOperation::ScalarMultiply {
        commitment: commitment_arc,
        scalar,
    };
    let result = computation.execute(&scalar_op);

    match result {
        OperationResult::Success(_) => println!("Scalar multiplication successful"),
        OperationResult::Failure(e) => panic!("Scalar multiplication failed: {}", e),
        OperationResult::Unsupported => panic!("Scalar multiplication not supported"),
    }

    println!("Basic operations test passed");
}

fn test_custom_operations(computation: &HomomorphicComputation<EllipticalCurveCommitmentScheme>) {
    println!("\nTesting custom operations...");

    let scheme = computation.scheme();

    // Create a commitment
    let value = b"test value";
    let commitment = scheme.commit(&[Some(value.to_vec())]);

    // Call the custom "double" operation
    let inputs = vec![Arc::new(commitment.clone()) as Arc<dyn Any + Send + Sync>];

    let custom_op = CommitmentOperation::Custom {
        operation_id: "double".to_string(),
        inputs,
        parameters: vec![],
    };

    let result = computation.execute(&custom_op);

    match result {
        OperationResult::Success(_) => println!("Custom operation successful"),
        OperationResult::Failure(e) => panic!("Custom operation failed: {}", e),
        OperationResult::Unsupported => panic!("Custom operation not supported"),
    }

    // Try an unregistered custom operation
    let inputs = vec![Arc::new(commitment) as Arc<dyn Any + Send + Sync>];

    let custom_op = CommitmentOperation::Custom {
        operation_id: "unknown".to_string(),
        inputs,
        parameters: vec![],
    };

    let result = computation.execute(&custom_op);

    match result {
        OperationResult::Unsupported => println!("Correctly rejected unregistered operation"),
        OperationResult::Success(_) => panic!("Unregistered operation should not have succeeded"),
        OperationResult::Failure(_) => panic!("Expected Unsupported for unregistered operation"),
    }

    println!("Custom operations test passed");
}

fn test_batch_operations(computation: &HomomorphicComputation<EllipticalCurveCommitmentScheme>) {
    println!("\nTesting batch operations...");

    let scheme = computation.scheme();

    // Create commitments
    let value_a = b"value a";
    let value_b = b"value b";
    let commitment_a = scheme.commit(&[Some(value_a.to_vec())]);
    let commitment_b = scheme.commit(&[Some(value_b.to_vec())]);

    // Create a batch of operations
    let operations = vec![
        CommitmentOperation::Add {
            left: Arc::new(commitment_a.clone()),
            right: Arc::new(commitment_b.clone()),
        },
        CommitmentOperation::ScalarMultiply {
            commitment: Arc::new(commitment_a.clone()),
            scalar: 3,
        },
        CommitmentOperation::Custom {
            operation_id: "double".to_string(),
            inputs: vec![Arc::new(commitment_b.clone())],
            parameters: vec![],
        },
        CommitmentOperation::Custom {
            operation_id: "unknown".to_string(),
            inputs: vec![Arc::new(commitment_a)],
            parameters: vec![],
        },
    ];

    let batch_result = computation.execute_batch(&operations);

    println!("Batch execution results:");
    println!("  Total operations: {}", batch_result.results.len());
    println!("  Successful: {}", batch_result.success_count);
    println!("  Failed: {}", batch_result.failure_count);
    println!("  Unsupported: {}", batch_result.unsupported_count);
    println!("  Success rate: {:.1}%", batch_result.success_rate());

    println!("Batch operations test passed");
}

fn test_composite_operations(
    computation: &HomomorphicComputation<EllipticalCurveCommitmentScheme>,
) {
    println!("\nTesting composite operations...");

    let scheme = computation.scheme();

    // Create commitments
    let value_a = b"value a";
    let value_b = b"value b";
    let commitment_a = scheme.commit(&[Some(value_a.to_vec())]);
    let commitment_b = scheme.commit(&[Some(value_b.to_vec())]);

    // Register a test boolean operation that returns true
    let registry = computation.registry();
    registry
        .register("return_true", move |_, _| {
            Ok(Arc::new(true) as Arc<dyn Any + Send + Sync>)
        })
        .expect("Failed to register test operation");

    // Create a conditional operation
    let composite = CompositeOperation::Conditional {
        condition: Box::new(CommitmentOperation::Custom {
            operation_id: "return_true".to_string(),
            inputs: vec![],
            parameters: vec![],
        }),
        if_true: Box::new(CompositeOperation::Sequence(vec![
            CommitmentOperation::Add {
                left: Arc::new(commitment_a.clone()),
                right: Arc::new(commitment_b.clone()),
            },
            CommitmentOperation::ScalarMultiply {
                commitment: Arc::new(commitment_a),
                scalar: 3,
            },
        ])),
        if_false: Box::new(CompositeOperation::Single(CommitmentOperation::Custom {
            operation_id: "double".to_string(),
            inputs: vec![Arc::new(commitment_b)],
            parameters: vec![],
        })),
    };

    let result = computation.execute_composite(&composite);

    match result {
        Ok(OperationResult::Success(_)) => println!("Composite operation successful"),
        Ok(OperationResult::Failure(e)) => panic!("Composite operation failed: {}", e),
        Ok(OperationResult::Unsupported) => panic!("Composite operation not supported"),
        Err(e) => panic!("Composite operation error: {}", e),
    }

    println!("Composite operations test passed");
}

fn test_homomorphic_proofs(computation: &HomomorphicComputation<EllipticalCurveCommitmentScheme>) {
    println!("\nTesting homomorphic proofs...");

    let scheme = computation.scheme();

    // Create commitments
    let value_a = b"value a";
    let value_b = b"value b";
    let commitment_a = scheme.commit(&[Some(value_a.to_vec())]);
    let commitment_b = scheme.commit(&[Some(value_b.to_vec())]);

    // Execute an add operation
    let left: Arc<dyn Any + Send + Sync> = Arc::new(commitment_a.clone());
    let right: Arc<dyn Any + Send + Sync> = Arc::new(commitment_b.clone());

    let add_op = CommitmentOperation::Add { left, right };
    let result = computation.execute(&add_op);

    let sum = match result {
        OperationResult::Success(result_arc) => result_arc
            .downcast_ref::<depin_sdk_commitment_schemes::elliptical_curve::EllipticalCurveCommitment>()
            .expect("Failed to downcast result")
            .clone(),
        _ => panic!("Addition failed"),
    };

    // Create a proof for the addition
    let proof = computation
        .create_proof(&add_op, &sum)
        .expect("Failed to create proof");

    // Verify the proof
    let verified = computation
        .verify_proof(&proof)
        .expect("Failed to verify proof");

    if verified {
        println!("Proof verification successful");
    } else {
        panic!("Proof verification failed");
    }

    // Test scalar multiplication proof
    let commitment_arc: Arc<dyn Any + Send + Sync> = Arc::new(commitment_a.clone());
    let scalar = 3;

    let scalar_op = CommitmentOperation::ScalarMultiply {
        commitment: commitment_arc,
        scalar,
    };
    let result = computation.execute(&scalar_op);

    let product = match result {
        OperationResult::Success(result_arc) => result_arc
            .downcast_ref::<depin_sdk_commitment_schemes::elliptical_curve::EllipticalCurveCommitment>()
            .expect("Failed to downcast result")
            .clone(),
        _ => panic!("Scalar multiplication failed"),
    };

    // Create a proof for the scalar multiplication
    let proof = computation
        .create_proof(&scalar_op, &product)
        .expect("Failed to create proof");

    // Verify the proof
    let verified = computation
        .verify_proof(&proof)
        .expect("Failed to verify proof");

    if verified {
        println!("Scalar multiplication proof verification successful");
    } else {
        panic!("Scalar multiplication proof verification failed");
    }

    println!("Homomorphic proofs test passed");
}
