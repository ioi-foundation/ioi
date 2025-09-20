// Path: crates/commitment/src/lib.rs

#![forbid(unsafe_code)]
//! # DePIN SDK Commitment
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

    // Re-export the core API trait, which now lives in the API crate
    pub use depin_sdk_api::state::StateCommitment;
}
