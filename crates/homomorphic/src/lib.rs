// Path: crates/homomorphic/src/lib.rs
//! # IOI SDK Homomorphic Crate Lints
//!
//! This crate enforces a strict set of lints to ensure high-quality,
//! panic-free, and well-documented code. Panics are disallowed in non-test
//! code to promote robust error handling.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo,
        clippy::indexing_slicing
    )
)]

//! # IOI SDK Homomorphic Operations
//!
//! Implementation of homomorphic operations on commitments for the IOI SDK.

pub mod computation;
pub mod error;
pub mod operations;
pub mod proof;

pub use ioi_api::commitment::{
    CommitmentScheme, HomomorphicCommitmentScheme, HomomorphicOperation,
};
pub use ioi_api::homomorphic::{CommitmentOperation, OperationResult};

// Re-export key components for easier access
pub use computation::HomomorphicComputation;
pub use error::{HomomorphicError, HomomorphicResult};
pub use operations::{
    add, execute_add, execute_batch, execute_composite, execute_custom, execute_scalar_multiply,
    scalar_multiply, BatchResult, CompositeOperation, CustomOperationRegistry,
};
pub use proof::{HomomorphicProof, ProofGenerator};
