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

//! # IOI Kernel Validator
//!
//! Validator implementation with container architecture for the IOI Kernel.

/// Common components shared across validator types.
pub mod common;
/// Configuration structures for validator containers.
pub mod config;
/// The Agency Firewall (formerly ante handlers).
pub mod firewall;
/// Metrics collection and reporting.
pub mod metrics;
/// Standard validator implementations (Orchestration, Workload, Provider).
pub mod standard;