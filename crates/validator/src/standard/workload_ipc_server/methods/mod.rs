// Path: crates/validator/src/standard/workload_ipc_server/methods/mod.rs

//! This module defines the shared context for all RPC method handlers and
//! exports the individual method implementations from sub-modules.

use depin_sdk_api::{
    commitment::CommitmentScheme, state::StateManager, validator::WorkloadContainer,
};
use depin_sdk_chain::Chain;
use std::sync::Arc;
use tokio::sync::Mutex;

// --- Sub-module declarations for each RPC method category ---
pub mod chain;
pub mod contract;
pub mod staking;
pub mod state;
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
    pub chain: Arc<Mutex<Chain<CS, ST>>>,
    pub workload: Arc<WorkloadContainer<ST>>,
}
