use crate::error::{HomomorphicError, HomomorphicResult};
use depin_sdk_core::homomorphic::{CommitmentOperation, OperationResult};
use std::sync::Arc;

/// Composite operation for complex computations
#[derive(Debug, Clone)]
pub enum CompositeOperation {
    /// Execute operations in sequence
    Sequence(Vec<CommitmentOperation>),

    /// Execute operations in parallel
    Parallel(Vec<CommitmentOperation>),

    /// Conditional operation based on a boolean condition
    Conditional {
        /// Condition operation (expected to return a boolean)
        condition: Box<CommitmentOperation>,
        /// Operation to execute if condition is true
        if_true: Box<CompositeOperation>,
        /// Operation to execute if condition is false
        if_false: Box<CompositeOperation>,
    },

    /// Loop until a condition is met
    Loop {
        /// Maximum number of iterations
        max_iterations: usize,
        /// Condition operation (expected to return a boolean)
        condition: Box<CommitmentOperation>,
        /// Operation to execute in each iteration
        body: Box<CompositeOperation>,
    },

    /// Single operation
    Single(CommitmentOperation),
}

/// Result of a batch operation
#[derive(Debug, Clone)]
pub struct BatchResult {
    /// Results of individual operations
    pub results: Vec<OperationResult>,
    /// Number of successful operations
    pub success_count: usize,
    /// Number of failed operations
    pub failure_count: usize,
    /// Number of unsupported operations
    pub unsupported_count: usize,
}

impl BatchResult {
    /// Create a new empty batch result
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            success_count: 0,
            failure_count: 0,
            unsupported_count: 0,
        }
    }

    /// Add a result to the batch
    pub fn add_result(&mut self, result: OperationResult) {
        match &result {
            OperationResult::Success(_) => self.success_count += 1,
            OperationResult::Failure(_) => self.failure_count += 1,
            OperationResult::Unsupported => self.unsupported_count += 1,
        }

        self.results.push(result);
    }

    /// Check if all operations were successful
    pub fn all_successful(&self) -> bool {
        self.failure_count == 0 && self.unsupported_count == 0
    }

    /// Get the success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        if self.results.is_empty() {
            0.0
        } else {
            (self.success_count as f64) / (self.results.len() as f64) * 100.0
        }
    }
}

// Add Default implementation for BatchResult
impl Default for BatchResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Execute batch operations
pub fn execute_batch<F>(operations: &[CommitmentOperation], executor: F) -> BatchResult
where
    F: Fn(&CommitmentOperation) -> OperationResult,
{
    let mut result = BatchResult::new();

    for op in operations {
        let op_result = executor(op);
        result.add_result(op_result);
    }

    result
}

/// Execute a composite operation
pub fn execute_composite<F>(
    operation: &CompositeOperation,
    executor: F,
) -> HomomorphicResult<OperationResult>
where
    F: Fn(&CommitmentOperation) -> OperationResult + Copy,
{
    match operation {
        CompositeOperation::Sequence(ops) => {
            let mut last_result = OperationResult::Success(Arc::new(()));

            for op in ops {
                last_result = executor(op);

                // If any operation fails, return immediately
                if let OperationResult::Failure(_) = &last_result {
                    return Ok(last_result);
                }
            }

            Ok(last_result)
        }

        CompositeOperation::Parallel(ops) => {
            let batch = execute_batch(ops, executor);

            // If all operations are successful, return the last result
            if batch.all_successful() && !batch.results.is_empty() {
                if let Some(last) = batch.results.last() {
                    return Ok(last.clone());
                }
            } else if !batch.all_successful() {
                // Return the first failure
                for result in &batch.results {
                    if let OperationResult::Failure(_) = result {
                        return Ok(result.clone());
                    }
                }

                // If no failures but some unsupported, return unsupported
                return Ok(OperationResult::Unsupported);
            }

            // Empty batch
            Ok(OperationResult::Success(Arc::new(())))
        }

        CompositeOperation::Conditional {
            condition,
            if_true,
            if_false,
        } => {
            // Execute the condition
            let condition_result = executor(condition);

            match condition_result {
                OperationResult::Success(result) => {
                    // Try to downcast to bool
                    match result.downcast_ref::<bool>() {
                        Some(&true) => execute_composite(if_true, executor),
                        Some(&false) => execute_composite(if_false, executor),
                        None => Err(HomomorphicError::InvalidInput(
                            "Condition did not return a boolean value".into(),
                        )),
                    }
                }
                OperationResult::Failure(error) => Ok(OperationResult::Failure(format!(
                    "Condition failed: {error}"
                ))),
                OperationResult::Unsupported => Ok(OperationResult::Failure(
                    "Condition operation is unsupported".into(),
                )),
            }
        }

        CompositeOperation::Loop {
            max_iterations,
            condition,
            body,
        } => {
            let mut iterations = 0;

            loop {
                // Check maximum iterations
                if iterations >= *max_iterations {
                    return Ok(OperationResult::Success(Arc::new(iterations)));
                }

                // Evaluate condition
                let condition_result = executor(condition);

                match condition_result {
                    OperationResult::Success(result) => {
                        // Try to downcast to bool
                        match result.downcast_ref::<bool>() {
                            Some(&true) => {
                                // Continue loop, execute body
                                let body_result = execute_composite(body, executor)?;

                                // If body execution fails, propagate the error
                                if let OperationResult::Failure(_) = body_result {
                                    return Ok(body_result);
                                }

                                // Increment iteration count
                                iterations += 1;
                            }
                            Some(&false) => {
                                // Exit loop
                                return Ok(OperationResult::Success(Arc::new(iterations)));
                            }
                            None => {
                                return Err(HomomorphicError::InvalidInput(
                                    "Loop condition did not return a boolean value".into(),
                                ));
                            }
                        }
                    }
                    OperationResult::Failure(error) => {
                        return Ok(OperationResult::Failure(format!(
                            "Loop condition failed after {iterations} iterations: {error}"
                        )));
                    }
                    OperationResult::Unsupported => {
                        return Ok(OperationResult::Failure(
                            "Loop condition operation is unsupported".into(),
                        ));
                    }
                }
            }
        }

        CompositeOperation::Single(op) => Ok(executor(op)),
    }
}

#[cfg(test)]
mod tests;