//! Definition of the CommitmentOperation enum

use std::any::Any;

/// Type for operations on commitments
pub enum CommitmentOperation {
    /// Add two commitments
    Add { 
        left: Box<dyn Any>, 
        right: Box<dyn Any>,
    },
    
    /// Multiply a commitment by a scalar
    ScalarMultiply { 
        commitment: Box<dyn Any>, 
        scalar: i32,
    },
    
    /// Apply a custom operation
    Custom {
        operation_id: String,
        inputs: Vec<Box<dyn Any>>,
        parameters: Vec<u8>,
    },
}
