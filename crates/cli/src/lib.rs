// Path: crates/cli/src/lib.rs
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

//! # IOI SDK CLI Library
//!
//! This library provides high-level APIs and helper functions to facilitate
//! testing and interaction with chains built on the IOI SDK.
//!
//! ## Architectural Boundary and Purpose
//!
//! **`cli` is designed to be the primary *external consumer* of the IOI SDK.**
//! Its purpose is to simulate the developer experience of someone building on,
//! or with, the SDK. To maintain this crucial role, this crate must adhere
//! to a strict architectural boundary:
//!
//! 1.  **Public API Only:** `cli` must **only** depend on the public APIs
//!     exposed by the other `ioi-*` library crates (e.g., `ioi-api`,
//!     `ioi-core`). It should never use `pub(crate)` visibility or other
//!     tricks to access internal implementation details.
//!
//! 2.  **No Core Logic:** `cli` should not contain any core protocol logic.
//!     Instead, it *composes* and *drives* the core libraries to achieve
//!     developer-focused outcomes (like running a test node or asserting state).
//!
//! 3.  **Simulates a User:** The workflows implemented here (spawning a node,
//!     submitting transactions, checking logs) are the same workflows a real
//!     user or developer would perform. This makes `cli` the first and most
//!     important user of the SDK, ensuring the public APIs are ergonomic and complete.
//!
//! By maintaining this boundary, we ensure that `cli` can one day be moved
//! into its own repository and depend on the SDK via `crates.io`, perfectly
//! mirroring the external developer's setup without requiring code changes.
//!
//! This crate contains modules for:
//! - `testing`: Helpers for writing integration and E2E tests.
//! - `builder`: (Future) Builder patterns for constructing nodes and chains in test environments.
//! - `client`: (Future) A lightweight client for interacting with a running node's RPC.

pub mod testing;

// Re-export core testing primitives for ergonomic top-level access.
// This allows tests to use `ioi_cli::TestCluster` directly.
pub use testing::cluster::{TestCluster, TestClusterBuilder};
pub use testing::genesis::GenesisBuilder;
pub use testing::validator::{TestValidator, ValidatorGuard};

// [FIX] Export build_test_artifacts so the CLI can use it
pub use testing::build::build_test_artifacts;

// Re-export helper functions for backward compatibility and convenience.
pub use testing::genesis::{add_genesis_identity, add_genesis_identity_custom};
pub use testing::rpc::{submit_transaction, submit_transaction_no_wait};
