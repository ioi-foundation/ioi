// Path: crates/validator/src/standard/mod.rs
//! Standard validator implementations.

/// The Orchestration container logic.
pub mod orchestration;
/// The Compute Provider logic.
pub mod provider;
/// The Workload container logic.
pub mod workload;

pub use orchestration::Orchestrator;
pub use workload::ipc::WorkloadIpcServer;
