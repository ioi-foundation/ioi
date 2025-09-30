//! Implements the standard validator architecture, separating concerns into
//! Orchestration, Workload, and Guardian containers.

/// The main logic for the Orchestration container, handling consensus and peer communication.
pub mod orchestration;
/// The IPC server implementation for the Workload container.
pub mod workload_ipc_server;

// Publicly re-export the container so it's visible to binaries in the same crate.
pub use orchestration::OrchestrationContainer;
pub use workload_ipc_server::WorkloadIpcServer;
