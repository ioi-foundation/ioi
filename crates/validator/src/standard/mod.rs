// Path: crates/validator/src/standard/mod.rs
//! Standard validator implementations.

/// The Orchestration container logic.
pub mod orchestration;
/// The Workload container logic.
pub mod workload;
/// The Compute Provider logic.
pub mod provider;

pub use orchestration::Orchestrator;
pub use workload::ipc::WorkloadIpcServer;