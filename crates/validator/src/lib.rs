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
/// Portable, domain-separated AuthorityGrantEnvelope v2 signing and verification.
pub mod portable_authority;
/// Portable receipt hash-chain checkpoints and offline proof verification.
pub mod portable_receipt_proof;
/// Standard validator implementations (Orchestration, Workload, Provider).
pub mod standard;
