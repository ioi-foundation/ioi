// Path: crates/types/src/lib.rs
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # DePIN SDK Types
//!
//! This crate is the foundational library for the DePIN SDK, containing all core
//! data structures, error types, and configuration objects.
//!
//! ## Architectural Role
//!
//! As the base crate, `depin-sdk-types` has minimal dependencies and is itself a
//! dependency for almost every other crate in the workspace. This structure
//! prevents circular dependencies and provides a stable, canonical definition
//! for shared types like `Block`, `ChainTransaction`, `AccountId`, and various
//! error enums.

/// The maximum size in bytes for a value read from state during consensus.
pub const MAX_STATE_VALUE_BYTES: usize = 256 * 1024; // 256 KiB
/// The maximum size in bytes for a proof read from state during consensus.
pub const MAX_STATE_PROOF_BYTES: usize = 512 * 1024; // 512 KiB

/// A top-level, crate-wide `Result` type alias with a default error type.
#[must_use]
pub type Result<T, E = crate::error::CoreError> = std::result::Result<T, E>;

/// Core application-level data structures like `Block`, `Transaction`, and `AccountId`.
pub mod app;
/// The canonical, deterministic binary codec for consensus-critical state.
pub mod codec;
/// Core types for commitment schemes, such as `SchemeIdentifier`.
pub mod commitment;
/// Shared configuration structures (e.g., `WorkloadConfig`, `OrchestrationConfig`).
pub mod config;
/// A unified set of all error types used across the SDK.
pub mod error;
/// Core data structures for Universal Interoperability (IBC).
pub mod ibc;
/// Constants for well-known state keys used for accessing data in the state manager.
pub mod keys;
/// A prelude containing useful extension traits like `OptionExt`.
pub mod prelude;
/// Configuration structures for initial services like the Identity Hub.
pub mod service_configs;
