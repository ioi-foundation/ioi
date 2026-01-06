// Path: crates/api/src/vm/mod.rs
//! Defines the core traits and types for virtual machines.
use crate::state::VmStateAccessor;
use async_trait::async_trait;
use ioi_types::error::VmError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

mod overlay;
pub use overlay::VmStateOverlay;

pub mod inference;
pub mod randomness; // [NEW]

/// A trait representing a sandboxed execution environment for smart contracts.
#[async_trait]
pub trait VirtualMachine: Send + Sync {
    /// Executes contract code within a sandboxed environment.
    ///
    /// # Arguments
    /// * `contract_bytecode`: The compiled WASM or EVM code.
    /// * `entrypoint`: The name of the function to call (e.g., "call").
    /// * `input_data`: The serialized arguments for the function call.
    /// * `state_accessor`: A mutable, dyn-safe handle for the VM to access state transactionally.
    async fn execute(
        &self,
        contract_bytecode: &[u8],
        entrypoint: &str,
        input_data: &[u8],
        state_accessor: &dyn VmStateAccessor,
        execution_context: ExecutionContext,
    ) -> Result<ExecutionOutput, VmError>;
}

/// Contains the results of a successful contract execution.
#[derive(Debug, Default, Serialize, Deserialize, Encode, Decode)]
pub struct ExecutionOutput {
    /// The amount of gas consumed by the execution.
    pub gas_used: u64,
    /// The data returned by the contract execution.
    pub return_data: Vec<u8>,
}

/// Provides contextual information to the smart contract during execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Encode, Decode)]
pub struct ExecutionContext {
    /// The address of the entity that initiated the contract call.
    pub caller: Vec<u8>,
    /// The current block height.
    pub block_height: u64,
    /// The gas limit for the execution.
    pub gas_limit: u64,
    /// The address of the contract being executed.
    pub contract_address: Vec<u8>,
}
