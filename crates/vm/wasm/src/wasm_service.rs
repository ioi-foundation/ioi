// Path: crates/vm/wasm/src/wasm_service.rs

use async_trait::async_trait;
use ioi_api::{
    lifecycle::OnEndBlock,
    services::{BlockchainService, UpgradableService},
    state::StateAccess,
    transaction::{context::TxContext, decorator::TxDecorator},
};
use ioi_types::{
    app::ChainTransaction,
    codec::{from_bytes_canonical, to_bytes_canonical},
    error::{CoreError, StateError, TransactionError, UpgradeError},
    service_configs::Capabilities,
};
use parity_scale_codec::{Decode, Encode};
use std::any::Any;
use std::fmt::{self, Debug};
use std::sync::{Arc, Mutex};
use wasmtime::*;

#[derive(Encode, Decode)]
struct AnteHandleRequest {
    tx: ChainTransaction,
}
#[derive(Encode, Decode)]
struct AnteHandleResponse {
    result: Result<(), String>,
}

/// A wrapper that makes a WASM module behave like an `UpgradableService`.
pub struct WasmService {
    id: &'static str,
    abi_version: u32,
    state_schema: &'static str,
    instance: Instance,
    store: Mutex<Store<()>>,
    caps: Capabilities,
}

impl Debug for WasmService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WasmService")
            .field("id", &self.id)
            .field("abi_version", &self.abi_version)
            .field("state_schema", &self.state_schema)
            .field("capabilities", &self.caps)
            .finish()
    }
}

impl WasmService {
    /// Helper to call a WASM function that takes a byte slice and returns one.
    fn call_wasm_fn(&self, fn_name: &str, data: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| UpgradeError::OperationFailed("store lock poisoned".into()))?;
        let memory = self
            .instance
            .get_memory(&mut *store, "memory")
            .ok_or_else(|| {
                UpgradeError::InvalidUpgrade("WASM module must export 'memory'".to_string())
            })?;
        let allocate = self
            .instance
            .get_typed_func::<u32, u32>(&mut *store, "allocate")
            .map_err(|e| {
                UpgradeError::InvalidUpgrade(format!("'allocate' function not found: {}", e))
            })?;
        let wasm_fn = self
            .instance
            .get_typed_func::<(u32, u32), u64>(&mut *store, fn_name)
            .map_err(|e| {
                UpgradeError::InvalidUpgrade(format!("'{}' function not found: {}", fn_name, e))
            })?;

        let input_ptr = allocate
            .call(&mut *store, data.len() as u32)
            .map_err(|e| UpgradeError::OperationFailed(format!("WASM allocate failed: {}", e)))?;

        memory
            .write(&mut *store, input_ptr as usize, data)
            .map_err(|e| {
                UpgradeError::OperationFailed(format!("WASM memory write failed: {}", e))
            })?;

        let result_packed = wasm_fn
            .call(&mut *store, (input_ptr, data.len() as u32))
            .map_err(|e| {
                UpgradeError::OperationFailed(format!(
                    "WASM function call '{}' failed: {}",
                    fn_name, e
                ))
            })?;

        let result_ptr = (result_packed >> 32) as u32;
        let result_len = result_packed as u32;

        let mut result_buffer = vec![0u8; result_len as usize];
        memory
            .read(&*store, result_ptr as usize, &mut result_buffer)
            .map_err(|e| {
                UpgradeError::OperationFailed(format!("WASM memory read failed: {}", e))
            })?;

        Ok(result_buffer)
    }
}

impl BlockchainService for WasmService {
    fn id(&self) -> &'static str {
        self.id
    }
    fn abi_version(&self) -> u32 {
        self.abi_version
    }
    fn state_schema(&self) -> &'static str {
        self.state_schema
    }
    fn capabilities(&self) -> Capabilities {
        self.caps
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_tx_decorator(&self) -> Option<&dyn TxDecorator> {
        (self.caps.contains(Capabilities::TX_DECORATOR)).then_some(self)
    }
    fn as_on_end_block(&self) -> Option<&dyn OnEndBlock> {
        (self.caps.contains(Capabilities::ON_END_BLOCK)).then_some(self)
    }
}

#[async_trait]
impl TxDecorator for WasmService {
    async fn validate_ante(
        &self,
        _state: &dyn StateAccess,
        tx: &ChainTransaction,
        _ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        let req = AnteHandleRequest { tx: tx.clone() };
        let req_bytes = to_bytes_canonical(&req).map_err(TransactionError::Serialization)?;
        log::info!("[WasmService {}] Calling ante_validate in WASM", self.id());
        let resp_bytes = self
            .call_wasm_fn("ante_validate", &req_bytes)
            .map_err(|e| TransactionError::Invalid(format!("WASM ante_validate failed: {}", e)))?;
        let resp: AnteHandleResponse =
            from_bytes_canonical(&resp_bytes).map_err(TransactionError::Deserialization)?;
        resp.result.map_err(TransactionError::Invalid)
    }

    async fn write_ante(
        &self,
        _state: &mut dyn StateAccess,
        tx: &ChainTransaction,
        _ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        let req = AnteHandleRequest { tx: tx.clone() };
        let req_bytes = to_bytes_canonical(&req).map_err(TransactionError::Serialization)?;
        log::info!("[WasmService {}] Calling ante_write in WASM", self.id());
        let resp_bytes = self
            .call_wasm_fn("ante_write", &req_bytes)
            .map_err(|e| TransactionError::Invalid(format!("WASM ante_write failed: {}", e)))?;
        let resp: AnteHandleResponse =
            from_bytes_canonical(&resp_bytes).map_err(TransactionError::Deserialization)?;
        resp.result.map_err(TransactionError::Invalid)
    }
}

#[async_trait]
impl OnEndBlock for WasmService {
    async fn on_end_block(
        &self,
        _state: &mut dyn StateAccess,
        _ctx: &TxContext,
    ) -> Result<(), StateError> {
        log::info!(
            "[WasmService {}] OnEndBlock hook called (currently a no-op).",
            self.id()
        );
        Ok(())
    }
}

#[async_trait]
impl UpgradableService for WasmService {
    async fn prepare_upgrade(&self, new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        self.call_wasm_fn("prepare_upgrade", new_module_wasm)
    }

    async fn complete_upgrade(&self, snapshot: &[u8]) -> Result<(), UpgradeError> {
        self.call_wasm_fn("complete_upgrade", snapshot)?;
        Ok(())
    }
}

/// Creates a deterministically configured Wasmtime engine and a fueled store.
fn make_engine_and_store() -> Result<(Engine, Store<()>), CoreError> {
    let mut config = Config::new();
    config.async_support(true);
    config.consume_fuel(true);
    config.wasm_threads(false);
    config.wasm_simd(false);
    let engine = Engine::new(&config).map_err(|e| {
        CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
            "Wasmtime config error: {}",
            e
        )))
    })?;
    let mut store = Store::new(&engine, ());
    store.set_fuel(10_000_000_000).map_err(|e| {
        CoreError::Upgrade(UpgradeError::OperationFailed(format!(
            "Wasmtime fuel error: {}",
            e
        )))
    })?;
    Ok((engine, store))
}

/// The factory function that loads and instantiates a service from a WASM blob.
pub fn load_service_from_wasm(wasm_blob: &[u8]) -> Result<Arc<dyn UpgradableService>, CoreError> {
    log::info!(
        "Attempting to load service from WASM blob ({} bytes)...",
        wasm_blob.len()
    );

    let (engine, mut store) = make_engine_and_store()?;

    let module = Module::new(&engine, wasm_blob).map_err(|e| {
        CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
            "Failed to compile WASM: {e}"
        )))
    })?;

    let instance = Instance::new(&mut store, &module, &[]).map_err(|e| {
        CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
            "Failed to instantiate WASM: {e}"
        )))
    })?;

    let memory = instance.get_memory(&mut store, "memory").ok_or_else(|| {
        CoreError::Upgrade(UpgradeError::InvalidUpgrade(
            "WASM module must export 'memory'".to_string(),
        ))
    })?;

    let id_str = {
        let func = instance
            .get_typed_func::<(), u64>(&mut store, "id")
            .map_err(|e| {
                CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                    "WASM missing `id` export: {}",
                    e
                )))
            })?;
        let packed = func.call(&mut store, ()).map_err(|e| {
            CoreError::Upgrade(UpgradeError::OperationFailed(format!(
                "WASM `id` call failed: {}",
                e
            )))
        })?;
        let ptr = (packed >> 32) as u32;
        let len = packed as u32;
        let mut buffer = vec![0u8; len as usize];
        memory
            .read(&store, ptr as usize, &mut buffer)
            .map_err(|e| {
                CoreError::Upgrade(UpgradeError::OperationFailed(format!(
                    "WASM memory read failed for `id`: {}",
                    e
                )))
            })?;
        String::from_utf8(buffer).map_err(|e| {
            CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                "`id` result is not valid UTF-8: {}",
                e
            )))
        })?
    };
    let id: &'static str = Box::leak(id_str.into_boxed_str());

    let abi_version = {
        let func = instance
            .get_typed_func::<(), u32>(&mut store, "abi_version")
            .map_err(|e| {
                CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                    "WASM missing `abi_version` export: {e}"
                )))
            })?;
        func.call(&mut store, ()).map_err(|e| {
            CoreError::Upgrade(UpgradeError::OperationFailed(format!(
                "WASM `abi_version` call failed: {e}"
            )))
        })?
    };

    let state_schema_str = {
        let func = instance
            .get_typed_func::<(), u64>(&mut store, "state_schema")
            .map_err(|e| {
                CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                    "WASM missing `state_schema` export: {}",
                    e
                )))
            })?;
        let packed = func.call(&mut store, ()).map_err(|e| {
            CoreError::Upgrade(UpgradeError::OperationFailed(format!(
                "WASM `state_schema` call failed: {}",
                e
            )))
        })?;
        let ptr = (packed >> 32) as u32;
        let len = packed as u32;
        let mut buffer = vec![0u8; len as usize];
        memory
            .read(&store, ptr as usize, &mut buffer)
            .map_err(|e| {
                CoreError::Upgrade(UpgradeError::OperationFailed(format!(
                    "WASM memory read failed for `state_schema`: {}",
                    e
                )))
            })?;
        String::from_utf8(buffer).map_err(|e| {
            CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                "`state_schema` result is not valid UTF-8: {}",
                e
            )))
        })?
    };
    let state_schema: &'static str = Box::leak(state_schema_str.into_boxed_str());

    let manifest_str = {
        let func = instance
            .get_typed_func::<(), u64>(&mut store, "manifest")
            .map_err(|e| {
                CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                    "WASM missing `manifest` export: {}",
                    e
                )))
            })?;
        let packed = func.call(&mut store, ()).map_err(|e| {
            CoreError::Upgrade(UpgradeError::OperationFailed(format!(
                "WASM `manifest` call failed: {}",
                e
            )))
        })?;
        let ptr = (packed >> 32) as u32;
        let len = packed as u32;
        let mut buffer = vec![0u8; len as usize];
        memory
            .read(&store, ptr as usize, &mut buffer)
            .map_err(|e| {
                CoreError::Upgrade(UpgradeError::OperationFailed(format!(
                    "WASM memory read failed for `manifest`: {}",
                    e
                )))
            })?;
        String::from_utf8(buffer).map_err(|e| {
            CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
                "`manifest` result is not valid UTF-8: {}",
                e
            )))
        })?
    };

    #[derive(serde::Deserialize)]
    struct TempManifest {
        capabilities: Vec<String>,
    }
    let temp_manifest: TempManifest = toml::from_str(&manifest_str).map_err(|e| {
        CoreError::Upgrade(UpgradeError::InvalidUpgrade(format!(
            "Failed to parse manifest TOML: {}",
            e
        )))
    })?;
    let caps = Capabilities::from_strings(&temp_manifest.capabilities)?;

    log::info!(
        "Successfully loaded WASM service: id='{}', abi_version={}, state_schema='{}', caps={:?}",
        id,
        abi_version,
        state_schema,
        caps
    );

    Ok(Arc::new(WasmService {
        id,
        abi_version,
        state_schema,
        instance,
        store: Mutex::new(store),
        caps,
    }))
}
