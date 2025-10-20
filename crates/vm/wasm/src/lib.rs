// Path: crates/vm/wasm/src/lib.rs
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo,
        clippy::indexing_slicing
    )
)]

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use depin_sdk_api::runtime::{Runnable, Runtime, RuntimeError};
use depin_sdk_api::state::VmStateAccessor;
use depin_sdk_api::vm::{ExecutionContext, ExecutionOutput, VirtualMachine};
use depin_sdk_types::{config::VmFuelCosts, error::VmError};
use std::collections::HashSet;
use std::sync::Arc;
use wasmtime::*;

/// A Wasmtime-based runtime for WASM artifacts.
pub struct WasmRuntime {
    engine: Engine,
    fuel_costs: VmFuelCosts,
}

impl WasmRuntime {
    pub fn new(fuel_costs: VmFuelCosts) -> Result<Self, VmError> {
        let mut config = Config::new();
        config.async_support(true);
        config.consume_fuel(true);
        Ok(Self {
            engine: Engine::new(&config).map_err(|e| VmError::Initialization(e.to_string()))?,
            fuel_costs,
        })
    }
}

/// This struct holds all host-side state accessible to the WASM module.
struct HostState {
    state_accessor: Arc<dyn VmStateAccessor>,
    context: Option<ExecutionContext>,
    memory: Option<Memory>,
    fuel_costs: VmFuelCosts,
}

/// Centralized key namespacing to prevent inconsistencies.
fn get_namespaced_key(contract_address: &[u8], key: &[u8]) -> Vec<u8> {
    [contract_address, b"::", key].concat()
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
    caller.set_fuel(fuel.saturating_sub(caller.data().fuel_costs.base_cost))?;

    let memory = caller
        .data()
        .memory
        .ok_or_else(|| anyhow!("Memory not found"))?;

    let key_start = key_ptr as usize;
    let key_end = (key_ptr + key_len) as usize;
    let value_start = value_ptr as usize;
    let value_end = (value_ptr + value_len) as usize;

    let mem_data = memory.data(&caller);

    let contract_key = mem_data
        .get(key_start..key_end)
        .ok_or_else(|| anyhow!("host_state_set key read out of bounds"))?
        .to_vec();
    let value = mem_data
        .get(value_start..value_end)
        .ok_or_else(|| anyhow!("host_state_set value read out of bounds"))?
        .to_vec();

    let contract_address = caller
        .data()
        .context
        .as_ref()
        .ok_or_else(|| anyhow!("Context not set"))?
        .contract_address
        .clone();
    let namespaced_key = get_namespaced_key(&contract_address, &contract_key);

    let cost =
        (namespaced_key.len() + value.len()) as u64 * caller.data().fuel_costs.state_set_per_byte;
    let fuel = caller.get_fuel()?;
    caller.set_fuel(fuel.saturating_sub(cost))?;

    caller
        .data()
        .state_accessor
        .insert(&namespaced_key, &value)
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
    caller.set_fuel(fuel.saturating_sub(caller.data().fuel_costs.base_cost))?;

    let memory = caller
        .data()
        .memory
        .ok_or_else(|| anyhow!("Memory not found"))?;

    let key_start = key_ptr as usize;
    let key_end = (key_ptr + key_len) as usize;
    let contract_key = memory
        .data(&caller)
        .get(key_start..key_end)
        .ok_or_else(|| anyhow!("host_state_get key read out of bounds"))?
        .to_vec();

    let contract_address = caller
        .data()
        .context
        .as_ref()
        .ok_or_else(|| anyhow!("Context not set"))?
        .contract_address
        .clone();
    let namespaced_key = get_namespaced_key(&contract_address, &contract_key);

    let cost = namespaced_key.len() as u64 * caller.data().fuel_costs.state_get_per_byte;
    let fuel = caller.get_fuel()?;
    caller.set_fuel(fuel.saturating_sub(cost))?;

    let value = caller
        .data()
        .state_accessor
        .get(&namespaced_key)
        .await
        .map_err(|_| anyhow!("State read failed"))?;

    if let Some(data) = value {
        let cost = data.len() as u64 * caller.data().fuel_costs.state_get_per_byte;
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
    caller.set_fuel(fuel.saturating_sub(caller.data().fuel_costs.base_cost))?;

    let memory = caller
        .data()
        .memory
        .ok_or_else(|| anyhow!("Memory not found"))?;

    let caller_addr = caller
        .data()
        .context
        .as_ref()
        .ok_or_else(|| anyhow!("Context not set"))?
        .caller
        .clone();

    memory
        .write(&mut caller, result_ptr as usize, &caller_addr)
        .map_err(|e| anyhow!("Failed to write caller to WASM memory: {}", e))?;
    Ok(caller_addr.len() as u32)
}

/// Host Function: A single, unified entrypoint for host calls from WASM.
async fn host_call(
    mut caller: Caller<'_, HostState>,
    cap_ptr: u32,
    cap_len: u32,
    req_ptr: u32,
    req_len: u32,
    resp_out_ptr: u32,
) -> anyhow::Result<u32> {
    let memory = caller
        .data()
        .memory
        .ok_or_else(|| anyhow!("Memory not found in host state"))?;

    let cap_name = {
        let bytes = memory
            .data(&caller)
            .get(cap_ptr as usize..(cap_ptr + cap_len) as usize)
            .ok_or_else(|| anyhow!("Capability name pointer out of bounds"))?;
        std::str::from_utf8(bytes).map_err(|_| anyhow!("Capability name is not valid UTF-8"))?
    };

    let _req_bytes = memory
        .data(&caller)
        .get(req_ptr as usize..(req_ptr + req_len) as usize)
        .ok_or_else(|| anyhow!("Request pointer out of bounds"))?;

    let (status, resp_bytes) = match cap_name {
        // Dispatch to specific capability handlers
        _ => (1, Vec::new()), // 1 = Unknown Capability
    };

    // Write response back to WASM memory
    let allocate_func = caller
        .get_export("allocate")
        .and_then(|e| e.into_func())
        .and_then(|f| f.typed::<u32, u32>(&caller).ok())
        .ok_or_else(|| anyhow!("`allocate` function not found in module"))?;

    let resp_ptr = allocate_func
        .call_async(&mut caller, resp_bytes.len() as u32)
        .await
        .map_err(|e| anyhow!("WASM allocate failed for response: {}", e))?;

    memory
        .write(&mut caller, resp_ptr as usize, &resp_bytes)
        .map_err(|e| anyhow!("Failed to write response to WASM memory: {}", e))?;

    // Write the pointer and length back to the caller's output pointer
    let resp_meta = [
        resp_ptr.to_le_bytes(),
        (resp_bytes.len() as u32).to_le_bytes(),
    ]
    .concat();
    memory
        .write(&mut caller, resp_out_ptr as usize, &resp_meta)
        .map_err(|e| anyhow!("Failed to write response metadata to WASM memory: {}", e))?;

    Ok(status)
}

pub struct WasmRunnable {
    instance: Instance,
    store: Store<HostState>,
}

#[async_trait]
impl Runnable for WasmRunnable {
    async fn call(&mut self, entry: &str, req: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        // Replenish fuel before each call. Service calls are not metered like user
        // transactions, so we provide a large, fixed amount.
        self.store
            .set_fuel(u64::MAX)
            .map_err(|e| RuntimeError::CallFailed(format!("Failed to set fuel: {}", e)))?;

        let alloc = self
            .instance
            .get_typed_func::<u32, u32>(&mut self.store, "allocate")
            .map_err(|e| RuntimeError::EntrypointNotFound(format!("allocate: {}", e)))?;
        let func = self
            .instance
            .get_typed_func::<(u32, u32), u64>(&mut self.store, entry)
            .map_err(|_e| RuntimeError::EntrypointNotFound(entry.to_string()))?;
        let mem = self
            .instance
            .get_memory(&mut self.store, "memory")
            .ok_or_else(|| RuntimeError::LoadFailed("memory export missing".into()))?;

        // --- FIX START ---
        // Handle the edge case of an empty request buffer.
        // Calling `allocate(0)` can trap in some WASM runtimes or lead to null pointers.
        // By handling it here, we pass a canonical (ptr=0, len=0) for an empty slice,
        // which is a safe and standard FFI pattern.
        let (ptr, len) = if req.is_empty() {
            (0, 0)
        } else {
            let ptr = alloc
                .call_async(&mut self.store, req.len() as u32)
                .await
                .map_err(|e| RuntimeError::CallFailed(e.to_string()))?;
            mem.write(&mut self.store, ptr as usize, req)
                .map_err(|e| RuntimeError::CallFailed(e.to_string()))?;
            (ptr, req.len() as u32)
        };

        let packed = func
            .call_async(&mut self.store, (ptr, len)) // Use the derived ptr and len
            .await
            .map_err(|e| RuntimeError::CallFailed(e.to_string()))?;
        // --- FIX END ---

        let out_ptr = (packed >> 32) as u32;
        let out_len = (packed & 0xFFFF_FFFF) as u32;

        let mut out = vec![0; out_len as usize];
        mem.read(&self.store, out_ptr as usize, &mut out)
            .map_err(|e| RuntimeError::CallFailed(e.to_string()))?;
        Ok(out)
    }
}

#[async_trait]
impl VirtualMachine for WasmRuntime {
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
        linker
            .func_wrap5_async("env", "host_call", |c, p1, p2, p3, p4, p5| {
                Box::new(host_call(c, p1, p2, p3, p4, p5))
            })
            .map_err(|e| VmError::Initialization(e.to_string()))?;

        let host_state = HostState {
            state_accessor,
            context: Some(execution_context.clone()),
            memory: None,
            fuel_costs: self.fuel_costs.clone(),
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

#[async_trait]
impl Runtime for WasmRuntime {
    async fn load(&self, artifact: &[u8]) -> Result<Box<dyn Runnable>, RuntimeError> {
        let module = Module::new(&self.engine, artifact)
            .map_err(|e| RuntimeError::LoadFailed(e.to_string()))?;

        // 1. Check for prohibited imports
        if module.imports().next().is_some() {
            return Err(RuntimeError::LoadFailed(
                "WASM module must not have any imports".into(),
            ));
        }

        // 2. Verify all required exports are present
        let required_exports: HashSet<&str> = [
            "id",
            "abi_version",
            "state_schema",
            "prepare_upgrade",
            "complete_upgrade",
            // Capability-specific functions like "ante_handle" should not be checked here.
            // Their presence and version are determined by the service's manifest and dispatch logic.
        ]
        .iter()
        .cloned()
        .collect();

        let actual_exports: HashSet<&str> = module.exports().map(|e| e.name()).collect();

        if !required_exports.is_subset(&actual_exports) {
            return Err(RuntimeError::LoadFailed(format!(
                "WASM module is missing required ABI exports. Missing: {:?}",
                required_exports.difference(&actual_exports)
            )));
        }

        let host_state = HostState {
            state_accessor: Arc::new(NullStateAccessor), // A dummy accessor for setup
            context: None,
            memory: None,
            fuel_costs: self.fuel_costs.clone(),
        };
        let mut store = Store::new(&self.engine, host_state);
        // Add a large amount of initial fuel. Service calls are not metered in the same way
        // as user transactions, but fuel consumption must be enabled for the runtime.
        store
            .set_fuel(u64::MAX)
            .map_err(|e| RuntimeError::LoadFailed(format!("Failed to set initial fuel: {}", e)))?;

        let mut linker = Linker::new(&self.engine);
        linker
            .func_wrap5_async("env", "host_call", |c, p1, p2, p3, p4, p5| {
                Box::new(host_call(c, p1, p2, p3, p4, p5))
            })
            .unwrap();

        let instance = linker
            .instantiate_async(&mut store, &module)
            .await
            .map_err(|e| RuntimeError::LoadFailed(e.to_string()))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| RuntimeError::LoadFailed("Memory not found".into()))?;
        store.data_mut().memory = Some(memory);

        Ok(Box::new(WasmRunnable { instance, store }))
    }
}

struct NullStateAccessor;
#[async_trait]
impl VmStateAccessor for NullStateAccessor {
    async fn get(
        &self,
        _key: &[u8],
    ) -> Result<Option<Vec<u8>>, depin_sdk_types::error::StateError> {
        Ok(None)
    }
    async fn insert(
        &self,
        _key: &[u8],
        _value: &[u8],
    ) -> Result<(), depin_sdk_types::error::StateError> {
        Ok(())
    }
}
