// Path: crates/validator/src/standard/workload/mod.rs

//! Components specific to the Workload container.

/// The IPC server implementation for handling requests from the Orchestrator.
pub mod ipc;

/// Shared initialization and setup logic for Workload binaries.
pub mod setup;