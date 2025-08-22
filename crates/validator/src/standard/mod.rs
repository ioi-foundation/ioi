// Path: crates/validator/src/standard/mod.rs

pub mod orchestration;
pub mod workload_ipc_server;

// Publicly re-export the container so it's visible to binaries in the same crate.
pub use orchestration::OrchestrationContainer;
pub use workload_ipc_server::WorkloadIpcServer;
