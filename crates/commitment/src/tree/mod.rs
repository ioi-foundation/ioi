// Path: crates/commitment/src/tree/mod.rs
#![forbid(unsafe_code)]
//! # State Commitment Tree
//!
//! This module exports the various stateful data structures that implement
//! the `StateCommitment` trait.

pub mod iavl;
pub mod sparse_merkle;
pub mod verkle;
