use super::*;

// Mock commitment for testing
#[derive(Debug, Clone)]
struct MockCommitment(i32);

#[test]
fn test_custom_operation_registry() {
    let registry = CustomOperationRegistry::new();

    // Register a custom operation
    registry
        .register("test_op", |inputs, _params| {
            if inputs.is_empty() {
                return Err(HomomorphicError::InvalidInput("No inputs provided".into()));
            }

            // Try to downcast the first input to MockCommitment
            let input = match inputs[0].downcast_ref::<MockCommitment>() {
                Some(c) => c,
                None => return Err(HomomorphicError::InvalidInput("Invalid input type".into())),
            };

            // Double the value
            let result = MockCommitment(input.0 * 2);

            Ok(Arc::new(result) as Arc<dyn Any + Send + Sync>)
        })
        .unwrap();

    // Check that the operation is registered
    assert!(registry.has_operation("test_op"));
    assert_eq!(registry.operation_count(), 1);
    assert_eq!(registry.list_operations(), vec!["test_op".to_string()]);

    // Test the custom operation
    let mock_commitment = MockCommitment(5);
    let inputs = vec![Arc::new(mock_commitment) as Arc<dyn Any + Send + Sync>];
    let parameters = vec![];

    let operation = CommitmentOperation::Custom {
        operation_id: "test_op".to_string(),
        inputs,
        parameters,
    };

    let result = execute_custom(&registry, &operation);

    match result {
        OperationResult::Success(result_arc) => {
            let result = result_arc.downcast_ref::<MockCommitment>().unwrap();
            assert_eq!(result.0, 10); // Should be doubled
        }
        _ => panic!("Operation failed or unsupported"),
    }

    // Test an unregistered operation
    let inputs = vec![Arc::new(MockCommitment(5)) as Arc<dyn Any + Send + Sync>];
    let parameters = vec![];

    let operation = CommitmentOperation::Custom {
        operation_id: "unknown_op".to_string(),
        inputs,
        parameters,
    };

    let result = execute_custom(&registry, &operation);

    match result {
        OperationResult::Unsupported => {} // This is expected
        _ => panic!("Expected unsupported for unknown operation"),
    }

    // Unregister the operation
    let unregistered = registry.unregister("test_op").unwrap();
    assert!(unregistered);
    assert_eq!(registry.operation_count(), 0);
}

#[test]
fn test_invalid_input_to_custom_operation() {
    let registry = CustomOperationRegistry::new();

    // Register a custom operation that expects a specific type
    registry
        .register("type_check", |inputs, _params| {
            if inputs.is_empty() {
                return Err(HomomorphicError::InvalidInput("No inputs provided".into()));
            }

            // Expect a MockCommitment
            if inputs[0].downcast_ref::<MockCommitment>().is_none() {
                return Err(HomomorphicError::InvalidInput(
                    "Expected MockCommitment".into(),
                ));
            }

            Ok(Arc::new(true) as Arc<dyn Any + Send + Sync>)
        })
        .unwrap();

    // Test with wrong input type
    let inputs = vec![Arc::new("not a commitment") as Arc<dyn Any + Send + Sync>];
    let parameters = vec![];

    let operation = CommitmentOperation::Custom {
        operation_id: "type_check".to_string(),
        inputs,
        parameters,
    };

    let result = execute_custom(&registry, &operation);

    match result {
        OperationResult::Failure(error) => {
            assert!(error.contains("Expected MockCommitment"));
        }
        _ => panic!("Expected failure for invalid input type"),
    }
}

#[test]
fn test_default_implementation() {
    // Test that Default creates a new empty registry
    let registry = CustomOperationRegistry::default();
    assert_eq!(registry.operation_count(), 0);
    assert!(registry.list_operations().is_empty());
}
