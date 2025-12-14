// Path: crates/commitment/src/tree/mod.rs
//! # IOI SDK State Tree Crate Lints
//!
//! This module enforces a strict set of lints to ensure high-quality,
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
//! # State Commitment Tree
//!
//! This module exports the various stateful data structures that implement
//! the `StateCommitment` trait.

pub mod iavl;
pub mod sparse_merkle;
pub mod verkle;

#[cfg(feature = "state-jellyfish")]
pub mod jellyfish;