// Path: crates/homomorphic/src/operations/custom/mod.rs
use crate::error::{HomomorphicError, HomomorphicResult};
use ioi_api::homomorphic::{CommitmentOperation, OperationResult};
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Type for custom operation handler
pub type CustomOperationHandler = Arc<
    dyn Fn(&[Arc<dyn Any + Send + Sync>], &[u8]) -> HomomorphicResult<Arc<dyn Any + Send + Sync>>
        + Send
        + Sync,
>;

/// Registry for custom operations
pub struct CustomOperationRegistry {
    /// Map of operation IDs to handlers
    pub(crate) handlers: RwLock<HashMap<String, CustomOperationHandler>>,
}

impl CustomOperationRegistry {
    /// Create a new custom operation registry
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a custom operation handler
    pub fn register<F>(&self, operation_id: &str, handler: F) -> HomomorphicResult<()>
    where
        F: Fn(
                &[Arc<dyn Any + Send + Sync>],
                &[u8],
            ) -> HomomorphicResult<Arc<dyn Any + Send + Sync>>
            + Send
            + Sync
            + 'static,
    {
        let mut handlers = self
            .handlers
            .write()
            .map_err(|_| HomomorphicError::InternalError("Failed to acquire write lock".into()))?;

        handlers.insert(operation_id.to_string(), Arc::new(handler));
        Ok(())
    }

    /// Unregister a custom operation handler
    pub fn unregister(&self, operation_id: &str) -> HomomorphicResult<bool> {
        let mut handlers = self
            .handlers
            .write()
            .map_err(|_| HomomorphicError::InternalError("Failed to acquire write lock".into()))?;

        Ok(handlers.remove(operation_id).is_some())
    }

    /// Check if a custom operation is registered
    pub fn has_operation(&self, operation_id: &str) -> bool {
        if let Ok(handlers) = self.handlers.read() {
            handlers.contains_key(operation_id)
        } else {
            false
        }
    }

    /// Get the number of registered operations
    pub fn operation_count(&self) -> usize {
        if let Ok(handlers) = self.handlers.read() {
            handlers.len()
        } else {
            0
        }
    }

    /// List all registered operation IDs
    pub fn list_operations(&self) -> Vec<String> {
        if let Ok(handlers) = self.handlers.read() {
            handlers.keys().cloned().collect()
        } else {
            Vec::new()
        }
    }
}

impl Default for CustomOperationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Execute a custom operation
pub fn execute_custom(
    registry: &CustomOperationRegistry,
    operation: &CommitmentOperation,
) -> OperationResult {
    match operation {
        CommitmentOperation::Custom {
            operation_id,
            inputs,
            parameters,
        } => {
            // Check if the operation is registered
            if !registry.has_operation(operation_id) {
                return OperationResult::Unsupported;
            }

            // Get the handler
            let handler = match registry.handlers.read() {
                Ok(handlers) => match handlers.get(operation_id) {
                    Some(h) => h.clone(),
                    None => return OperationResult::Unsupported,
                },
                Err(_) => {
                    return OperationResult::Failure(
                        HomomorphicError::InternalError("Failed to acquire read lock".into())
                            .to_string(),
                    )
                }
            };

            // Execute the handler - inputs are already Arc<dyn Any + Send + Sync>
            match handler(inputs, parameters) {
                Ok(result) => OperationResult::Success(result),
                Err(e) => OperationResult::Failure(e.to_string()),
            }
        }
        _ => OperationResult::Unsupported,
    }
}

#[cfg(test)]
mod tests;
