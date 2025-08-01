// Path: crates/vm-wasm/src/lib.rs
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use depin_sdk_core::error::VmError;
use depin_sdk_core::state::VmStateAccessor;
use depin_sdk_core::vm::{ExecutionContext, ExecutionOutput, VirtualMachine};
use std::sync::Arc;
use wasmtime::*;

/// A Wasmtime-based virtual machine for executing WASM smart contracts.
pub struct WasmVm {
    engine: Engine,
}

impl Default for WasmVm {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmVm {
    pub fn new() -> Self {
        let mut config = Config::new();
        config.async_support(true);
        config.consume_fuel(true); // Enable gas metering
        Self {
            engine: Engine::new(&config).unwrap(),
        }
    }
}

/// This struct holds all host-side state accessible to the WASM module.
struct HostState {
    state_accessor: Arc<dyn VmStateAccessor>,
    context: ExecutionContext,
    memory: Option<Memory>,
}

/// Host Function: Write a key-value pair to the state tree.
async fn host_state_set(
    mut caller: Caller<'_, HostState>,
    key_ptr: u32,
    key_len: u32,
    value_ptr: u32,
    value_len: u32,
) -> Result<()> {
    let fuel = caller.get_fuel()?;
    caller.set_fuel(fuel.saturating_sub(1000))?;

    let memory = caller
        .data()
        .memory
        .ok_or_else(|| anyhow!("Memory not found"))?;

    let key = memory.data(&caller)[key_ptr as usize..(key_ptr + key_len) as usize].to_vec();
    let value = memory.data(&caller)[value_ptr as usize..(value_ptr + value_len) as usize].to_vec();

    let cost = (key.len() + value.len()) as u64 * 10;
    let fuel = caller.get_fuel()?;
    caller.set_fuel(fuel.saturating_sub(cost))?;

    caller
        .data()
        .state_accessor
        .insert(&key, &value)
        .await
        .map_err(|_| anyhow!("State write failed"))?;

    Ok(())
}

/// Host Function: Read a value by key from the state tree.
async fn host_state_get(
    mut caller: Caller<'_, HostState>,
    key_ptr: u32,
    key_len: u32,
    result_ptr: u32,
) -> Result<u32> {
    let fuel = caller.get_fuel()?;
    caller.set_fuel(fuel.saturating_sub(1000))?;

    let memory = caller
        .data()
        .memory
        .ok_or_else(|| anyhow!("Memory not found"))?;

    let key = memory.data(&caller)[key_ptr as usize..(key_ptr + key_len) as usize].to_vec();

    let cost = key.len() as u64 * 5;
    let fuel = caller.get_fuel()?;
    caller.set_fuel(fuel.saturating_sub(cost))?;

    let value = caller
        .data()
        .state_accessor
        .get(&key)
        .await
        .map_err(|_| anyhow!("State read failed"))?;

    if let Some(data) = value {
        let cost = data.len() as u64 * 5;
        let fuel = caller.get_fuel()?;
        caller.set_fuel(fuel.saturating_sub(cost))?;
        memory
            .write(&mut caller, result_ptr as usize, &data)
            .map_err(|e| anyhow!("Failed to write value to WASM memory: {}", e))?;
        Ok(data.len() as u32)
    } else {
        Ok(0)
    }
}

/// Host Function: Get the address of the contract caller.
async fn host_get_caller(mut caller: Caller<'_, HostState>, result_ptr: u32) -> Result<u32> {
    let fuel = caller.get_fuel()?;
    caller.set_fuel(fuel.saturating_sub(100))?;

    let memory = caller
        .data()
        .memory
        .ok_or_else(|| anyhow!("Memory not found"))?;

    let caller_addr = caller.data().context.caller.clone();

    memory
        .write(&mut caller, result_ptr as usize, &caller_addr)
        .map_err(|e| anyhow!("Failed to write caller to WASM memory: {}", e))?;
    Ok(caller_addr.len() as u32)
}

#[async_trait]
impl VirtualMachine for WasmVm {
    async fn execute(
        &self,
        contract_bytecode: &[u8],
        entrypoint: &str,
        input_data: &[u8],
        state_accessor: Arc<dyn VmStateAccessor>,
        execution_context: ExecutionContext,
    ) -> Result<ExecutionOutput, VmError> {
        let mut linker = Linker::new(&self.engine);

        linker
            .func_wrap4_async(
                "env",
                "state_set",
                |caller: Caller<'_, HostState>, p1: u32, p2: u32, p3: u32, p4: u32| {
                    Box::new(async move { host_state_set(caller, p1, p2, p3, p4).await })
                },
            )
            .map_err(|e| VmError::Initialization(e.to_string()))?;
        linker
            .func_wrap3_async(
                "env",
                "state_get",
                |caller: Caller<'_, HostState>, p1: u32, p2: u32, p3: u32| {
                    Box::new(async move { host_state_get(caller, p1, p2, p3).await })
                },
            )
            .map_err(|e| VmError::Initialization(e.to_string()))?;
        linker
            .func_wrap1_async(
                "env",
                "get_caller",
                |caller: Caller<'_, HostState>, p1: u32| {
                    Box::new(async move { host_get_caller(caller, p1).await })
                },
            )
            .map_err(|e| VmError::Initialization(e.to_string()))?;

        let host_state = HostState {
            state_accessor,
            context: execution_context.clone(),
            memory: None,
        };
        let mut store = Store::new(&self.engine, host_state);
        store
            .set_fuel(execution_context.gas_limit)
            .map_err(|e| VmError::Initialization(e.to_string()))?;

        let module = Module::new(&self.engine, contract_bytecode)
            .map_err(|e| VmError::InvalidBytecode(e.to_string()))?;
        let instance = linker
            .instantiate_async(&mut store, &module)
            .await
            .map_err(|e| VmError::Initialization(e.to_string()))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| VmError::Initialization("Memory export not found".to_string()))?;
        store.data_mut().memory = Some(memory);

        let allocate_func = instance
            .get_typed_func::<u32, u32>(&mut store, "allocate")
            .map_err(|e| VmError::FunctionNotFound(format!("'allocate': {e}")))?;
        let call_func = instance
            .get_typed_func::<(u32, u32), u64>(&mut store, entrypoint)
            .map_err(|e| VmError::FunctionNotFound(format!("'{entrypoint}': {e}")))?;

        let input_ptr = allocate_func
            .call_async(&mut store, input_data.len() as u32)
            .await
            .map_err(|e| VmError::ExecutionTrap(e.to_string()))?;
        memory
            .write(&mut store, input_ptr as usize, input_data)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let result_packed = call_func
            .call_async(&mut store, (input_ptr, input_data.len() as u32))
            .await
            .map_err(|e| VmError::ExecutionTrap(e.to_string()))?;

        let result_ptr = (result_packed >> 32) as u32;
        let result_len = result_packed as u32;
        let mut return_data = vec![0; result_len as usize];
        memory
            .read(&store, result_ptr as usize, &mut return_data)
            .map_err(|e| VmError::MemoryError(e.to_string()))?;

        let remaining_fuel = store
            .get_fuel()
            .map_err(|e| VmError::ExecutionTrap(e.to_string()))?;
        let gas_used = execution_context.gas_limit.saturating_sub(remaining_fuel);

        Ok(ExecutionOutput {
            gas_used,
            return_data,
        })
    }
}