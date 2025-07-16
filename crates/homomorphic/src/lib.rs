// homomorphic/src/lib.rs
//! # DePIN SDK Homomorphic Operations
//!
//! Implementation of homomorphic operations on commitments for the DePIN SDK.

pub mod computation;
pub mod error;
pub mod operations;
pub mod proof;

pub use depin_sdk_core::commitment::{
    CommitmentScheme, HomomorphicCommitmentScheme, HomomorphicOperation,
};
pub use depin_sdk_core::homomorphic::{CommitmentOperation, OperationResult};

// Re-export key components for easier access
pub use computation::HomomorphicComputation;
pub use error::{HomomorphicError, HomomorphicResult};
pub use operations::{
    add, execute_add, execute_batch, execute_composite, execute_custom, execute_scalar_multiply,
    scalar_multiply, BatchResult, CompositeOperation, CustomOperationRegistry,
};
pub use proof::{HomomorphicProof, ProofGenerator};
