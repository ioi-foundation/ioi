// Path: crates/api/src/commitment/homomorphic.rs
//! Defines the trait for commitment schemes supporting homomorphic operations.

use crate::commitment::scheme::CommitmentScheme;
use crate::error::CryptoError;

/// The type of homomorphic operation supported by a scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomomorphicOperation {
    /// Additive homomorphism.
    Addition,
    /// Scalar multiplication homomorphism.
    ScalarMultiplication,
    /// A custom, scheme-specific operation.
    Custom(u32),
}

/// An extended trait for commitment schemes that support homomorphic operations.
pub trait HomomorphicCommitmentScheme: CommitmentScheme {
    /// Performs homomorphic addition on two commitments.
    fn add(
        &self,
        a: &Self::Commitment,
        b: &Self::Commitment,
    ) -> Result<Self::Commitment, CryptoError>;

    /// Performs homomorphic scalar multiplication on a commitment.
    fn scalar_multiply(
        &self,
        a: &Self::Commitment,
        scalar: i32,
    ) -> Result<Self::Commitment, CryptoError>;

    /// Checks if this commitment scheme supports a specific homomorphic operation.
    fn supports_operation(&self, operation: HomomorphicOperation) -> bool;
}