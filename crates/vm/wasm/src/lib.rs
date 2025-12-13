// Path: crates/vm/wasm/src/lib.rs
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use async_trait::async_trait;
use ioi_api::state::VmStateAccessor;
use ioi_api::vm::{ExecutionContext, ExecutionOutput, VirtualMachine};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::{config::VmFuelCosts, error::VmError};
use std::collections::HashMap;
use std::sync::RwLock;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiView};

// Expose the new module
pub mod wasm_service;

// Generate Host traits from WIT
wasmtime::component::bindgen!({
    path: "../../types/wit/ioi.wit",
    world: "service",
    async: true
});

pub struct WasmRuntime {
    engine: Engine,
    fuel_costs: VmFuelCosts,
    component_cache: RwLock<HashMap<[u8; 32], Component>>,
}

impl WasmRuntime {
    pub fn new(fuel_costs: VmFuelCosts) -> Result<Self, VmError> {
        let mut config = Config::new();
        config.async_support(true);
        config.consume_fuel(true);
        config.wasm_component_model(true);

        Ok(Self {
            engine: Engine::new(&config).map_err(|e| VmError::Initialization(e.to_string()))?,
            fuel_costs,
            component_cache: RwLock::new(HashMap::new()),
        })
    }

    /// Returns a reference to the underlying Wasmtime Engine.
    /// This allows other components (like IBC light clients) to share the same engine
    /// for instantiation efficiency.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

struct HostState {
    state_accessor: SendSyncPtr<dyn VmStateAccessor>,
    context: ExecutionContext,
    table: ResourceTable,
    wasi_ctx: WasiCtx,
    _fuel_costs: VmFuelCosts,
}

impl WasiView for HostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi_ctx
    }
}

struct SendSyncPtr<T: ?Sized>(*const T);
unsafe impl<T: ?Sized> Send for SendSyncPtr<T> {}
unsafe impl<T: ?Sized> Sync for SendSyncPtr<T> {}

#[async_trait]
impl ioi::system::state::Host for HostState {
    // Remove wasmtime::Result wrapper
    async fn get(&mut self, key: Vec<u8>) -> Result<Option<Vec<u8>>, String> {
        let contract_addr = self.context.contract_address.clone();
        let ns_key = [contract_addr.as_slice(), b"::", key.as_slice()].concat();
        let accessor = unsafe { self.state_accessor.0.as_ref().unwrap() };

        match accessor.get(&ns_key).await {
            Ok(val) => Ok(val),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn set(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), String> {
        let contract_addr = self.context.contract_address.clone();
        let ns_key = [contract_addr.as_slice(), b"::", key.as_slice()].concat();
        let accessor = unsafe { self.state_accessor.0.as_ref().unwrap() };

        match accessor.insert(&ns_key, &value).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn delete(&mut self, key: Vec<u8>) -> Result<(), String> {
        let contract_addr = self.context.contract_address.clone();
        let ns_key = [contract_addr.as_slice(), b"::", key.as_slice()].concat();
        let accessor = unsafe { self.state_accessor.0.as_ref().unwrap() };

        match accessor.delete(&ns_key).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn prefix_scan(&mut self, prefix: Vec<u8>) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        let contract_addr = self.context.contract_address.clone();
        // The VM enforces isolation by prepending the contract address.
        // Format: {contract_addr}::{prefix}
        let ns_prefix = [contract_addr.as_slice(), b"::", prefix.as_slice()].concat();

        let accessor = unsafe { self.state_accessor.0.as_ref().unwrap() };

        match accessor.prefix_scan(&ns_prefix).await {
            Ok(results) => {
                // We must strip the namespace prefix so the guest sees keys relative to itself.
                let prefix_len = contract_addr.len() + 2; // len(addr) + len("::")

                let mapped_results = results
                    .into_iter()
                    .map(|(k, v)| {
                        // Safety check: key must start with the namespace prefix
                        if k.len() >= prefix_len {
                            (k[prefix_len..].to_vec(), v)
                        } else {
                            (k, v)
                        }
                    })
                    .collect();

                Ok(mapped_results)
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

#[async_trait]
impl ioi::system::context::Host for HostState {
    async fn get_caller(&mut self) -> Vec<u8> {
        self.context.caller.clone()
    }

    async fn block_height(&mut self) -> u64 {
        self.context.block_height
    }
}

#[async_trait]
impl ioi::system::host::Host for HostState {
    async fn call(&mut self, _capability: String, _request: Vec<u8>) -> Result<Vec<u8>, String> {
        Err("Host calls not implemented".to_string())
    }
}

#[async_trait]
impl VirtualMachine for WasmRuntime {
    async fn execute(
        &self,
        contract_bytecode: &[u8],
        entrypoint: &str,
        input_data: &[u8],
        state_accessor: &dyn VmStateAccessor,
        execution_context: ExecutionContext,
    ) -> Result<ExecutionOutput, VmError> {
        let bytecode_hash = sha256(contract_bytecode)
            .map_err(|e| VmError::Initialization(format!("Hashing failed: {}", e)))?;

        let component = {
            let read_guard = self.component_cache.read().unwrap();
            if let Some(comp) = read_guard.get(&bytecode_hash) {
                comp.clone()
            } else {
                drop(read_guard);
                let comp = Component::new(&self.engine, contract_bytecode)
                    .map_err(|e| VmError::InvalidBytecode(e.to_string()))?;

                let mut write_guard = self.component_cache.write().unwrap();
                write_guard.insert(bytecode_hash, comp.clone());
                comp
            }
        };

        let mut linker = Linker::new(&self.engine);

        Service::add_to_linker(&mut linker, |state: &mut HostState| state)
            .map_err(|e| VmError::Initialization(e.to_string()))?;

        wasmtime_wasi::add_to_linker_async(&mut linker)
            .map_err(|e| VmError::Initialization(e.to_string()))?;

        let state_accessor_static: &'static dyn VmStateAccessor =
            unsafe { std::mem::transmute(state_accessor) };

        let host_state = HostState {
            state_accessor: SendSyncPtr(state_accessor_static as *const _),
            context: execution_context.clone(),
            table: ResourceTable::new(),
            wasi_ctx: WasiCtxBuilder::new().build(),
            _fuel_costs: self.fuel_costs.clone(),
        };

        let mut store = Store::new(&self.engine, host_state);
        store
            .set_fuel(execution_context.gas_limit)
            .map_err(|e| VmError::Initialization(e.to_string()))?;

        let (service, _) = Service::instantiate_async(&mut store, &component, &linker)
            .await
            .map_err(|e| VmError::Initialization(e.to_string()))?;

        let return_data: Vec<u8> = match entrypoint {
            "manifest" => service
                .call_manifest(&mut store)
                .await
                .map(|s| s.into_bytes())
                .map_err(|e| VmError::ExecutionTrap(e.to_string()))?,

            "id" => service
                .call_id(&mut store)
                .await
                .map(|s| s.into_bytes())
                .map_err(|e| VmError::ExecutionTrap(e.to_string()))?,

            "abi-version" => service
                .call_abi_version(&mut store)
                .await
                .map(|v| v.to_le_bytes().to_vec())
                .map_err(|e| VmError::ExecutionTrap(e.to_string()))?,

            "state-schema" => service
                .call_state_schema(&mut store)
                .await
                .map(|s| s.into_bytes())
                .map_err(|e| VmError::ExecutionTrap(e.to_string()))?,

            "prepare-upgrade" => service
                .call_prepare_upgrade(&mut store, input_data)
                .await
                .map_err(|e| VmError::ExecutionTrap(e.to_string()))?,

            "complete-upgrade" => service
                .call_complete_upgrade(&mut store, input_data)
                .await
                .map_err(|e| VmError::ExecutionTrap(e.to_string()))?,

            method_name => {
                let res = service
                    .call_handle_service_call(&mut store, method_name, input_data)
                    .await
                    .map_err(|e| VmError::ExecutionTrap(e.to_string()))?;

                match res {
                    Ok(bytes) => bytes,
                    Err(contract_err) => return Err(VmError::ExecutionTrap(contract_err)),
                }
            }
        };

        let remaining = store.get_fuel().unwrap_or(0);
        let gas_used = execution_context.gas_limit.saturating_sub(remaining);

        Ok(ExecutionOutput {
            gas_used,
            return_data,
        })
    }
}