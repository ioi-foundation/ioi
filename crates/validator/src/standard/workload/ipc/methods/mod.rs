// Path: crates/validator/src/standard/workload_ipc_server/methods/mod.rs

//! This module defines the shared context for all RPC method handlers and
//! exports the individual method implementations from sub-modules.

use ioi_api::{commitment::CommitmentScheme, state::StateManager, validator::WorkloadContainer};
use ioi_execution::ExecutionMachine;
use std::sync::Arc;
use tokio::sync::Mutex;

// --- Sub-module declarations for each RPC method category ---
/// Methods related to chain state and block processing.
pub mod chain;
/// Methods related to smart contract deployment and execution.
pub mod contract;
/// Methods related to validator staking.
pub mod staking;
/// Methods for direct state queries and proof generation.
pub mod state;
/// Methods for system-level operations and status checks.
pub mod system;

/// The shared, read-only context available to all RPC method handlers.
///
/// It provides safe, concurrent access to the core components of the Workload container,
/// such as the `Chain` instance and the `WorkloadContainer` itself. This struct is generic
/// over the CommitmentScheme (CS) and StateManager (ST) to match the WorkloadIpcServer that creates it.
pub struct RpcContext<CS, ST>
where
    CS: CommitmentScheme + Clone,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>,
{
    /// A thread-safe handle to the core blockchain state machine.
    pub machine: Arc<Mutex<ExecutionMachine<CS, ST>>>,
    /// A thread-safe handle to the workload container, which manages the VM and state tree.
    pub workload: Arc<WorkloadContainer<ST>>,
}
