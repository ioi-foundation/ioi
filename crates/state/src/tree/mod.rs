// Path: crates/state/src/tree/mod.rs
//! # IOI Kernel State Tree Crate Lints
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
#![allow(
    dead_code,
    clippy::borrow_deref_ref,
    clippy::get_first,
    clippy::indexing_slicing,
    clippy::map_entry,
    clippy::needless_borrows_for_generic_args,
    clippy::needless_return,
    clippy::only_used_in_recursion,
    clippy::type_complexity,
    clippy::unnecessary_sort_by,
    clippy::unwrap_used,
    clippy::useless_conversion
)]
//! # State Commitment Tree
//!
//! This module exports the various stateful data structures that implement
//! the `StateCommitment` trait.
//!
pub mod iavl;
pub mod sparse_merkle;
pub mod verkle;

#[cfg(feature = "state-jellyfish")]
pub mod jellyfish;

pub mod mhnsw;

// [NEW] Export Flat Store
pub mod flat;
