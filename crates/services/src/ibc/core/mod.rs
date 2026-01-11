// Path: crates/services/src/ibc/core/mod.rs
//! Core IBC host machinery.

/// The adapter context that allows `ibc-rs` to interact with the IOI Kernel's `StateAccessor`.
pub mod context;

/// The `VerifierRegistry` for managing light clients and the main IBC message dispatcher.
pub mod registry;