use super::*;
use depin_sdk_core::homomorphic::OperationResult;
use std::any::Any;

#[test]
fn test_batch_execution() {
    // Create a mock executor
    let executor = |op: &CommitmentOperation| match op {
        CommitmentOperation::Custom { operation_id, .. } => {
            if operation_id == "succeed" {
                OperationResult::Success(Arc::new(true))
            } else if operation_id == "fail" {
                OperationResult::Failure("Operation failed".into())
            } else {
                OperationResult::Unsupported
            }
        }
        _ => OperationResult::Unsupported,
    };

    // Create a batch of operations
    let operations = vec![
        CommitmentOperation::Custom {
            operation_id: "succeed".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
        CommitmentOperation::Custom {
            operation_id: "succeed".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
        CommitmentOperation::Custom {
            operation_id: "fail".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
        CommitmentOperation::Custom {
            operation_id: "unknown".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
    ];

    // Execute the batch
    let batch_result = execute_batch(&operations[..], executor);

    // Check the results
    assert_eq!(batch_result.results.len(), 4);
    assert_eq!(batch_result.success_count, 2);
    assert_eq!(batch_result.failure_count, 1);
    assert_eq!(batch_result.unsupported_count, 1);
    assert!(!batch_result.all_successful());
    assert_eq!(batch_result.success_rate(), 50.0);
}

#[test]
fn test_composite_sequence() {
    // Create a mock executor
    let executor = |op: &CommitmentOperation| match op {
        CommitmentOperation::Custom { operation_id, .. } => {
            if operation_id == "succeed" {
                OperationResult::Success(Arc::new(true))
            } else {
                OperationResult::Failure("Operation failed".into())
            }
        }
        _ => OperationResult::Unsupported,
    };

    // Create a sequence of operations
    let sequence = CompositeOperation::Sequence(vec![
        CommitmentOperation::Custom {
            operation_id: "succeed".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
        CommitmentOperation::Custom {
            operation_id: "succeed".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
    ]);

    // Execute the sequence
    let result = execute_composite(&sequence, executor).unwrap();

    match result {
        OperationResult::Success(_) => {} // Expected
        _ => panic!("Expected successful sequence execution"),
    }

    // Create a sequence with a failure
    let sequence_with_failure = CompositeOperation::Sequence(vec![
        CommitmentOperation::Custom {
            operation_id: "succeed".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
        CommitmentOperation::Custom {
            operation_id: "fail".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
    ]);

    // Execute the sequence with failure
    let result = execute_composite(&sequence_with_failure, executor).unwrap();

    match result {
        OperationResult::Failure(error) => {
            assert_eq!(error, "Operation failed");
        }
        _ => panic!("Expected failure in sequence execution"),
    }
}

#[test]
fn test_composite_conditional() {
    // Create a mock executor
    let executor = |op: &CommitmentOperation| match op {
        CommitmentOperation::Custom { operation_id, .. } => {
            if operation_id == "condition_true" {
                OperationResult::Success(Arc::new(true) as Arc<dyn Any + Send + Sync>)
            } else if operation_id == "condition_false" {
                OperationResult::Success(Arc::new(false) as Arc<dyn Any + Send + Sync>)
            } else if operation_id == "true_path" {
                OperationResult::Success(Arc::new("true_path_result") as Arc<dyn Any + Send + Sync>)
            } else if operation_id == "false_path" {
                OperationResult::Success(Arc::new("false_path_result") as Arc<dyn Any + Send + Sync>)
            } else {
                OperationResult::Unsupported
            }
        }
        _ => OperationResult::Unsupported,
    };

    // Create a conditional operation (true condition)
    let conditional_true = CompositeOperation::Conditional {
        condition: Box::new(CommitmentOperation::Custom {
            operation_id: "condition_true".to_string(),
            inputs: vec![],
            parameters: vec![],
        }),
        if_true: Box::new(CompositeOperation::Single(CommitmentOperation::Custom {
            operation_id: "true_path".to_string(),
            inputs: vec![],
            parameters: vec![],
        })),
        if_false: Box::new(CompositeOperation::Single(CommitmentOperation::Custom {
            operation_id: "false_path".to_string(),
            inputs: vec![],
            parameters: vec![],
        })),
    };

    // Execute the conditional (true path)
    let result = execute_composite(&conditional_true, executor).unwrap();

    match result {
        OperationResult::Success(result_arc) => {
            let result = result_arc.downcast_ref::<&str>().unwrap();
            assert_eq!(*result, "true_path_result");
        }
        _ => panic!("Expected successful conditional execution (true path)"),
    }

    // Create a conditional operation (false condition)
    let conditional_false = CompositeOperation::Conditional {
        condition: Box::new(CommitmentOperation::Custom {
            operation_id: "condition_false".to_string(),
            inputs: vec![],
            parameters: vec![],
        }),
        if_true: Box::new(CompositeOperation::Single(CommitmentOperation::Custom {
            operation_id: "true_path".to_string(),
            inputs: vec![],
            parameters: vec![],
        })),
        if_false: Box::new(CompositeOperation::Single(CommitmentOperation::Custom {
            operation_id: "false_path".to_string(),
            inputs: vec![],
            parameters: vec![],
        })),
    };

    // Execute the conditional (false path)
    let result = execute_composite(&conditional_false, executor).unwrap();

    match result {
        OperationResult::Success(result_arc) => {
            let result = result_arc.downcast_ref::<&str>().unwrap();
            assert_eq!(*result, "false_path_result");
        }
        _ => panic!("Expected successful conditional execution (false path)"),
    }
}
