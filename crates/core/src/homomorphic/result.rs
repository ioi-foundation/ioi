//! Definition of the OperationResult enum

use std::any::Any;

/// Result of a homomorphic operation
pub enum OperationResult {
    /// Successfully computed result
    Success(Box<dyn Any>),
    
    /// Operation failed
    Failure(String),
    
    /// Operation not supported
    Unsupported,
}
