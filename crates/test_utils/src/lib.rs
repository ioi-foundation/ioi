// Path: crates/test_utils/src/lib.rs
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

//! # DePIN SDK Test Utilities
//!
//! Utilities for testing the DePIN SDK components.

pub mod agentic_mock;
pub mod assertions;
pub mod fixtures;
pub mod randomness;
