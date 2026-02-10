// Path: crates/commitment/src/lib.rs
//! # IOI Kernel Commitment Crate Lints
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
        clippy::indexing_slicing
    )
)]
//! # IOI Kernel Commitment
//!
//! This crate provides a unified interface and implementations for state commitments,
//! including both cryptographic primitives and the state trees that use them.

pub mod primitives;
pub mod tree;

/// A prelude for easily importing the most common types.
pub mod prelude {
    pub use crate::primitives::{
        hash::HashCommitmentScheme, kzg::KZGCommitmentScheme, pedersen::PedersenCommitmentScheme,
    };
    // NOTE: Removed FileStateTree and HashMapStateTree as per architectural recommendation.
    // These simple trees are not suitable for production as they lack robust, efficient
    // non-membership proofs required for light clients and interoperability.
    // Please use IAVLTree, SparseMerkleTree, or VerkleTree instead.
}
