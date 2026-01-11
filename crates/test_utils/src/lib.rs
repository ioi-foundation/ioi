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

//! # IOI Kernel Test Utilities
//!
//! Utilities for testing the IOI Kernel components.

pub mod agentic_mock;
pub mod assertions;
pub mod fixtures;
pub mod randomness;
