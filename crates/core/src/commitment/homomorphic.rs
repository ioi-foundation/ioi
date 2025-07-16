// File: crates/core/src/commitment/homomorphic.rs

use crate::commitment::scheme::CommitmentScheme;

/// Type of homomorphic operation supported
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomomorphicOperation {
    /// Addition of two commitments
    Addition,
    /// Scalar multiplication
    ScalarMultiplication,
    /// Custom operation
    Custom(u32),
}

/// Extended trait for commitment schemes supporting homomorphic operations
pub trait HomomorphicCommitmentScheme: CommitmentScheme {
    /// Add two commitments
    fn add(&self, a: &Self::Commitment, b: &Self::Commitment) -> Result<Self::Commitment, String>;
    
    /// Multiply a commitment by a scalar
    fn scalar_multiply(&self, a: &Self::Commitment, scalar: i32) -> Result<Self::Commitment, String>;
    
    /// Check if this commitment scheme supports specific homomorphic operations
    fn supports_operation(&self, operation: HomomorphicOperation) -> bool;
}