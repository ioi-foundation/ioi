#![forbid(unsafe_code)]

//! # DePIN SDK State Trees
//!
//! Implementations of various state tree structures for the DePIN SDK.

pub mod file;
pub mod hashmap;
pub mod iavl;
pub mod sparse_merkle;
pub mod verkle;

// Re-export concrete implementations for convenience
pub use file::FileStateTree;
pub use hashmap::HashMapStateTree;
pub use iavl::IAVLTree;
pub use sparse_merkle::SparseMerkleTree;
pub use verkle::VerkleTree;
