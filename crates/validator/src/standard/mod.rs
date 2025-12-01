// Path: crates/validator/src/standard/mod.rs

//! Implements the standard validator architecture, separating concerns into
//! Orchestration, Workload, and Guardian containers.

/// The main logic for the Orchestration container, handling consensus and peer communication.
pub mod orchestration;

/// The logic for the Workload container, including the IPC server and setup routines.
pub mod workload;

// Publicly re-export the containers so they are visible to binaries.
pub use orchestration::Orchestrator;
// Re-export the IPC server from the new nested path for convenience
pub use workload::ipc::WorkloadIpcServer;