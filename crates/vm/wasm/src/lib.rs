// Path: crates/vm/wasm/src/lib.rs
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use async_trait::async_trait;
use ioi_api::state::VmStateAccessor;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent, MouseButton};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_api::vm::{ExecutionContext, ExecutionOutput, VirtualMachine};
use ioi_crypto::algorithms::hash::sha256;
use ioi_drivers::browser::BrowserDriver;
use ioi_types::app::agentic::InferenceOptions; // [FIX] Import InferenceOptions
use ioi_types::codec; // [FIX] Import codec for deserialization
use ioi_types::{config::VmFuelCosts, error::VmError};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
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

struct HostState {
    state_accessor: SendSyncPtr<dyn VmStateAccessor>,
    context: ExecutionContext,
    table: ResourceTable,
    wasi_ctx: WasiCtx,
    _fuel_costs: VmFuelCosts,
    inference: Option<Arc<dyn InferenceRuntime>>,
    gui_driver: Option<Arc<dyn GuiDriver>>,
    browser_driver: Option<Arc<BrowserDriver>>,
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

pub struct WasmRuntime {
    engine: Engine,
    fuel_costs: VmFuelCosts,
    component_cache: RwLock<HashMap<[u8; 32], Component>>,
    linker: Linker<HostState>,
    inference: RwLock<Option<Arc<dyn InferenceRuntime>>>,
    gui_driver: RwLock<Option<Arc<dyn GuiDriver>>>,
    browser_driver: RwLock<Option<Arc<BrowserDriver>>>,
}

impl WasmRuntime {
    pub fn new(fuel_costs: VmFuelCosts) -> Result<Self, VmError> {
        let mut config = Config::new();
        config.async_support(true);
        config.consume_fuel(true);
        config.wasm_component_model(true);

        let engine = Engine::new(&config).map_err(|e| VmError::Initialization(e.to_string()))?;

        let mut linker = Linker::new(&engine);

        Service::add_to_linker(&mut linker, |state: &mut HostState| state)
            .map_err(|e| VmError::Initialization(e.to_string()))?;

        wasmtime_wasi::add_to_linker_async(&mut linker)
            .map_err(|e| VmError::Initialization(e.to_string()))?;

        Ok(Self {
            engine,
            fuel_costs,
            component_cache: RwLock::new(HashMap::new()),
            linker,
            inference: RwLock::new(None),
            gui_driver: RwLock::new(None),
            browser_driver: RwLock::new(None),
        })
    }

    pub fn link_inference(&self, runtime: Arc<dyn InferenceRuntime>) {
        let mut guard = self.inference.write().unwrap();
        *guard = Some(runtime);
    }

    pub fn link_gui_driver(&self, driver: Arc<dyn GuiDriver>) {
        let mut guard = self.gui_driver.write().unwrap();
        *guard = Some(driver);
    }

    pub fn link_browser_driver(&self, driver: Arc<BrowserDriver>) {
        let mut guard = self.browser_driver.write().unwrap();
        *guard = Some(driver);
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

#[async_trait]
impl ioi::system::state::Host for HostState {
    async fn get(&mut self, key: Vec<u8>) -> Result<Option<Vec<u8>>, String> {
        let ns_key = if self.context.contract_address.len() == 32 {
            [
                self.context.contract_address.as_slice(),
                b"::",
                key.as_slice(),
            ]
            .concat()
        } else {
            key
        };
        let accessor = unsafe { self.state_accessor.0.as_ref().unwrap() };

        match accessor.get(&ns_key).await {
            Ok(val) => Ok(val),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn set(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), String> {
        let ns_key = if self.context.contract_address.len() == 32 {
            [
                self.context.contract_address.as_slice(),
                b"::",
                key.as_slice(),
            ]
            .concat()
        } else {
            key
        };
        let accessor = unsafe { self.state_accessor.0.as_ref().unwrap() };

        match accessor.insert(&ns_key, &value).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn delete(&mut self, key: Vec<u8>) -> Result<(), String> {
        let ns_key = if self.context.contract_address.len() == 32 {
            [
                self.context.contract_address.as_slice(),
                b"::",
                key.as_slice(),
            ]
            .concat()
        } else {
            key
        };
        let accessor = unsafe { self.state_accessor.0.as_ref().unwrap() };

        match accessor.delete(&ns_key).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn prefix_scan(&mut self, prefix: Vec<u8>) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        let is_contract = self.context.contract_address.len() == 32;
        let ns_prefix = if is_contract {
            [
                self.context.contract_address.as_slice(),
                b"::",
                prefix.as_slice(),
            ]
            .concat()
        } else {
            prefix
        };

        let accessor = unsafe { self.state_accessor.0.as_ref().unwrap() };

        match accessor.prefix_scan(&ns_prefix).await {
            Ok(results) => {
                if is_contract {
                    let prefix_len = self.context.contract_address.len() + 2;
                    let mapped_results = results
                        .into_iter()
                        .map(|(k, v)| {
                            if k.len() >= prefix_len {
                                (k[prefix_len..].to_vec(), v)
                            } else {
                                (k, v)
                            }
                        })
                        .collect();
                    Ok(mapped_results)
                } else {
                    Ok(results)
                }
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
impl ioi::system::inference::Host for HostState {
    async fn execute(
        &mut self,
        model_id: String,
        input_data: Vec<u8>,
        params: Vec<u8>, // [FIX] Use params argument
    ) -> Result<Vec<u8>, String> {
        let inference = self
            .inference
            .as_ref()
            .ok_or("Inference runtime not available")?;

        // Hash the model ID string to the expected 32-byte format
        let model_hash_bytes = sha256(model_id.as_bytes()).map_err(|e| e.to_string())?;
        let model_hash: [u8; 32] = model_hash_bytes
            .try_into()
            .map_err(|_| "Invalid model hash length")?;

        // [FIX] Deserialize options or use default
        let options: InferenceOptions = if params.is_empty() {
            InferenceOptions::default()
        } else {
            // Try to deserialize params as InferenceOptions
            codec::from_bytes_canonical(&params).unwrap_or_else(|_| InferenceOptions::default())
        };

        // Delegate to the IAL
        inference
            .execute_inference(model_hash, &input_data, options)
            .await
            .map_err(|e| e.to_string())
    }
}

#[async_trait]
impl ioi::system::host::Host for HostState {
    async fn call(&mut self, capability: String, request: Vec<u8>) -> Result<Vec<u8>, String> {
        match capability.as_str() {
            "gui" => {
                let driver = self.gui_driver.as_ref().ok_or("GUI driver not available")?;

                let req: Value = serde_json::from_slice(&request)
                    .map_err(|e| format!("Invalid GUI request JSON: {}", e))?;

                let action = req["action"].as_str().ok_or("Missing action field")?;

                match action {
                    "click" => {
                        let x = req["x"].as_u64().ok_or("Missing x")? as u32;
                        let y = req["y"].as_u64().ok_or("Missing y")? as u32;
                        let btn = match req["button"].as_str().unwrap_or("left") {
                            "right" => MouseButton::Right,
                            "middle" => MouseButton::Middle,
                            _ => MouseButton::Left,
                        };

                        driver
                            .inject_input(InputEvent::Click {
                                button: btn,
                                x,
                                y,
                                expected_visual_hash: None,
                            })
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok(vec![])
                    }
                    "type" => {
                        let text = req["text"].as_str().ok_or("Missing text")?;
                        driver
                            .inject_input(InputEvent::Type {
                                text: text.to_string(),
                            })
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok(vec![])
                    }
                    "screenshot" => {
                        let png_bytes = driver.capture_screen().await.map_err(|e| e.to_string())?;
                        Ok(png_bytes)
                    }
                    "tree" => {
                        let tree = driver.capture_tree().await.map_err(|e| e.to_string())?;
                        Ok(tree.into_bytes())
                    }
                    _ => Err(format!("Unknown GUI action: {}", action)),
                }
            }
            "browser" => {
                let driver = self
                    .browser_driver
                    .as_ref()
                    .ok_or("Browser driver not available")?;

                let req: Value = serde_json::from_slice(&request)
                    .map_err(|e| format!("Invalid Browser request JSON: {}", e))?;

                let action = req["action"].as_str().ok_or("Missing action field")?;

                match action {
                    "navigate" => {
                        let url = req["url"].as_str().ok_or("Missing url")?;
                        let content = driver
                            .navigate(url)
                            .await
                            .map_err(|e| e.to_string())?; // [FIX] Removed explicit type annotation
                        Ok(content.into_bytes())
                    }
                    "extract_dom" => {
                        let dom = driver
                            .extract_dom()
                            .await
                            .map_err(|e| e.to_string())?; // [FIX] Removed explicit type annotation
                        Ok(dom.into_bytes())
                    }
                    "click_selector" => {
                        let selector = req["selector"].as_str().ok_or("Missing selector")?;
                        driver
                            .click_selector(selector)
                            .await
                            .map_err(|e| e.to_string())?; // [FIX] Removed explicit type annotation
                        Ok(vec![])
                    }
                    _ => Err(format!("Unknown Browser action: {}", action)),
                }
            }
            _ => Err(format!("Capability '{}' not supported", capability)),
        }
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

        let linker = self.linker.clone();

        let state_accessor_static: &'static dyn VmStateAccessor =
            unsafe { std::mem::transmute(state_accessor) };

        let host_state = HostState {
            state_accessor: SendSyncPtr(state_accessor_static as *const _),
            context: execution_context.clone(),
            table: ResourceTable::new(),
            wasi_ctx: WasiCtxBuilder::new().build(),
            _fuel_costs: self.fuel_costs.clone(),
            inference: self.inference.read().unwrap().clone(),
            gui_driver: self.gui_driver.read().unwrap().clone(),
            browser_driver: self.browser_driver.read().unwrap().clone(),
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