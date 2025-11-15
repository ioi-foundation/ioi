// Path: crates/state/src/tree/iavl/mod.rs
//! IAVL (Immutable AVL) tree implementation with cryptographic security.
//! This module re-exports the public API from its constituent files.

mod encode;
mod indices;
mod node;
pub mod proof;
mod proof_builder;
mod store_proof;
mod tree;
pub mod verifier;

// Re-export public API to maintain stability for external consumers.
pub use self::proof::{ExistenceProof, IavlProof, InnerOp, LeafOp, NonExistenceProof, Side};
pub use self::tree::IAVLTree;