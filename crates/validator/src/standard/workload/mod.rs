// Path: crates/validator/src/standard/workload/mod.rs

//! Components specific to the Workload container.

/// The IPC server implementation for handling requests from the Orchestrator.
pub mod ipc;

/// Shared initialization and setup logic for Workload binaries.
pub mod setup;

/// Logic for securely loading and verifying AI models (JIT Hydration).
pub mod hydration;

/// The high-level inference runtime orchestration.
pub mod runtime;

/// Workload runtime and hardware drivers.
pub mod drivers;

/// The Agentgres-admitted tip marker and its committed status (FU-N11-DURABLE-STATUS-1 D2a).
pub mod admitted_tip;

// FU-N11-DURABLE-STATUS-1 D2a RED-4: the ADMITTED INDEX adopt gate (T1), the ledger-bound
// publisher (T2), write-once through the publication (T5) and restart (T6), on the real workload
// handlers over loopback gRPC (workload/admitted_index_tests.rs).
#[cfg(test)]
mod admitted_index_tests;
