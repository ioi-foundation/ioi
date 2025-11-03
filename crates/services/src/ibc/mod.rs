// Path: crates/services/src/ibc/mod.rs
#![allow(clippy::module_inception)] // Allow the module name to match its parent directory

//! Implements the core IBC services, including light client verifiers,
//! a channel manager, and a registry to coordinate them.

/// Implements the IBC channel lifecycle (handshakes, packet ordering, timeouts).
pub mod channel;

/// Contains the adapter `IbcExecutionContext` that allows `ibc-rs` to interact
/// with the DePIN SDK's `StateAccessor`.
pub mod context;

/// Contains concrete, chain-specific implementations of the `InterchainVerifier` trait.
pub mod light_client;

/// Implements the `VerifierRegistry` for managing multiple light client instances
/// and dispatching all IBC messages.
pub mod registry;