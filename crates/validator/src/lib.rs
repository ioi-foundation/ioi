// Path: crates/validator/src/lib.rs
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing
    )
)]
#![deny(missing_docs)]

//! # IOI SDK Validator
//!
//! Validator implementation with container architecture for the IOI SDK.

pub mod common;
pub mod config;
pub mod metrics;
pub mod rpc;
pub mod standard;
