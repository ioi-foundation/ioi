//! # DePIN SDK State Trees
//!
//! Implementations of various state tree structures for the DePIN SDK.

pub mod hashmap;
pub mod iavl;
pub mod sparse_merkle;
pub mod verkle;

// Re-export concrete implementations for convenience
pub use hashmap::HashMapStateTree;
pub use iavl::IAVLTree;
pub use sparse_merkle::SparseMerkleTree;
pub use verkle::VerkleTree;

// Import core traits for use in the implementations
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::state::StateTree;
use std::any::Any;