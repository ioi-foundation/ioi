// Path: crates/core/src/vm.rs
use crate::error::VmError;
use crate::state::VmStateAccessor;
use async_trait::async_trait;
use std::sync::Arc;

/// A trait representing a sandboxed execution environment for smart contracts.
#[async_trait]
pub trait VirtualMachine: Send + Sync {
    /// Executes contract code within a sandboxed environment.
    ///
    /// # Arguments
    /// * `contract_bytecode`: The compiled WASM or EVM code.
    /// * `entrypoint`: The name of the function to call (e.g., "call").
    /// * `input_data`: The serialized arguments for the function call.
    /// * `state_accessor`: A thread-safe, dyn-safe handle for the VM to access chain state.
    /// * `execution_context`: Contains metadata like the caller's address, block height, etc.
    async fn execute(
        &self,
        contract_bytecode: &[u8],
        entrypoint: &str,
        input_data: &[u8],
        state_accessor: Arc<dyn VmStateAccessor>,
        execution_context: ExecutionContext,
    ) -> Result<ExecutionOutput, VmError>;
}

/// Contains the results of a successful contract execution.
#[derive(Debug, Default)]
pub struct ExecutionOutput {
    pub gas_used: u64,
    pub return_data: Vec<u8>,
    // In a full implementation, this would also include logs/events emitted.
}

/// Provides contextual information to the smart contract during execution.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub caller: Vec<u8>,
    pub block_height: u64,
    pub gas_limit: u64,
}