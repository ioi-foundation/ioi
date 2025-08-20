// crates/forge/src/lib.rs

#![forbid(unsafe_code)]

//! # DePIN SDK Forge Library
//!
//! This library provides high-level APIs and helper functions to facilitate
//! testing and interaction with chains built on the DePIN SDK.
//!
//! ## Architectural Boundary and Purpose
//!
//! **`forge` is designed to be the primary *external consumer* of the DePIN SDK.**
//! Its purpose is to simulate the developer experience of someone building on,
//! or with, the SDK. To maintain this crucial role, this crate must adhere
//! to a strict architectural boundary:
//!
//! 1.  **Public API Only:** `forge` must **only** depend on the public APIs
//!     exposed by the other `depin-sdk-*` library crates (e.g., `depin-sdk-api`,
//!     `depin-sdk-core`). It should never use `pub(crate)` visibility or other
//!     tricks to access internal implementation details.
//!
//! 2.  **No Core Logic:** `forge` should not contain any core protocol logic.
//!     Instead, it *composes* and *drives* the core libraries to achieve
//!     developer-focused outcomes (like running a test node or asserting state).
//!
//! 3.  **Simulates a User:** The workflows implemented here (spawning a node,
//!     submitting transactions, checking logs) are the same workflows a real
//!     user or developer would perform. This makes `forge` the first and most
//!     important user of the SDK, ensuring the public APIs are ergonomic and complete.
//!
//! By maintaining this boundary, we ensure that `forge` can one day be moved
//! into its own repository and depend on the SDK via `crates.io`, perfectly
//! mirroring the external developer's setup without requiring code changes.
//!
//! This crate contains modules for:
//! - `testing`: Helpers for writing integration and E2E tests.
//! - `builder`: (Future) Builder patterns for constructing nodes and chains in test environments.
//! - `client`: (Future) A lightweight client for interacting with a running node's RPC.

pub mod testing;
