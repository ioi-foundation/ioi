// Path: crates/chain/src/wasm_loader/mod.rs

use depin_sdk_api::impl_service_base;
use depin_sdk_api::services::{BlockchainService, ServiceType, UpgradableService};
use depin_sdk_types::error::{CoreError, UpgradeError};
use std::fmt::{self, Debug};
use std::sync::Arc;
use wasmtime::*;

/// A wrapper that makes a WASM module behave like an `UpgradableService`.
pub struct WasmService {
    service_type: ServiceType,
    instance: Instance,
    store: Store<()>,
}

impl Debug for WasmService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WasmService")
            .field("service_type", &self.service_type)
            .finish()
    }
}

impl WasmService {
    /// Helper to call a WASM function that takes a byte slice and returns one.
    fn call_wasm_fn(&mut self, fn_name: &str, data: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        // 1. Get exported functions from the WASM instance.
        let memory = self
            .instance
            .get_memory(&mut self.store, "memory")
            .ok_or_else(|| {
                UpgradeError::InvalidUpgrade("WASM module must export 'memory'".to_string())
            })?;
        let allocate = self
            .instance
            .get_typed_func::<u32, u32>(&mut self.store, "allocate")
            .map_err(|e| {
                UpgradeError::InvalidUpgrade(format!("'allocate' function not found: {}", e))
            })?;
        let wasm_fn = self
            .instance
            .get_typed_func::<(u32, u32), u64>(&mut self.store, fn_name)
            .map_err(|e| {
                UpgradeError::InvalidUpgrade(format!("'{}' function not found: {}", fn_name, e))
            })?;

        // 2. Allocate memory in the guest for the input data.
        let input_ptr = allocate
            .call(&mut self.store, data.len() as u32)
            .map_err(|e| UpgradeError::OperationFailed(format!("WASM allocate failed: {}", e)))?;

        // 3. Write the input data into the guest's memory.
        memory
            .write(&mut self.store, input_ptr as usize, data)
            .map_err(|e| {
                UpgradeError::OperationFailed(format!("WASM memory write failed: {}", e))
            })?;

        // 4. Call the target function.
        let result_packed = wasm_fn
            .call(&mut self.store, (input_ptr, data.len() as u32))
            .map_err(|e| {
                UpgradeError::OperationFailed(format!(
                    "WASM function call '{}' failed: {}",
                    fn_name, e
                ))
            })?;

        // 5. Unpack the pointer and length of the result from the u64 return value.
        let result_ptr = (result_packed >> 32) as u32;
        let result_len = result_packed as u32;

        // 6. Read the result data from the guest's memory.
        let mut result_buffer = vec![0u8; result_len as usize];
        memory
            .read(&self.store, result_ptr as usize, &mut result_buffer)
            .map_err(|e| {
                UpgradeError::OperationFailed(format!("WASM memory read failed: {}", e))
            })?;

        Ok(result_buffer)
    }
}

impl BlockchainService for WasmService {
    fn service_type(&self) -> ServiceType {
        self.service_type.clone()
    }
}

impl_service_base!(WasmService);

impl UpgradableService for WasmService {
    fn prepare_upgrade(&mut self, new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        self.call_wasm_fn("prepare_upgrade", new_module_wasm)
    }

    fn complete_upgrade(&mut self, snapshot: &[u8]) -> Result<(), UpgradeError> {
        self.call_wasm_fn("complete_upgrade", snapshot)?;
        Ok(())
    }
}

/// The factory function that replaces the placeholder.
pub fn load_service_from_wasm(wasm_blob: &[u8]) -> Result<Arc<dyn UpgradableService>, CoreError> {
    log::info!(
        "Attempting to load service from WASM blob ({} bytes)...",
        wasm_blob.len()
    );
    let engine = Engine::default();
    let mut store = Store::new(&engine, ());

    let module = Module::new(&engine, wasm_blob)
        .map_err(|e| CoreError::Upgrade(format!("Failed to compile WASM: {e}")))?;

    // The host does not provide any imports to the service. The service calls the host via FFI.
    let instance = Instance::new(&mut store, &module, &[])
        .map_err(|e| CoreError::Upgrade(format!("Failed to instantiate WASM: {e}")))?;

    // Call the `service_type` function to get the service identifier.
    let get_service_type_fn = instance
        .get_typed_func::<(), u64>(&mut store, "service_type")
        .map_err(|e| CoreError::Upgrade(format!("WASM missing `service_type` export: {e}")))?;

    let result_packed = get_service_type_fn
        .call(&mut store, ())
        .map_err(|e| CoreError::Upgrade(format!("WASM `service_type` call failed: {e}")))?;

    let result_ptr = (result_packed >> 32) as u32;
    let result_len = result_packed as u32;

    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| CoreError::Upgrade("WASM module must export 'memory'".to_string()))?;
    let mut type_buffer = vec![0u8; result_len as usize];
    memory
        .read(&store, result_ptr as usize, &mut type_buffer)
        .map_err(|e| {
            CoreError::Upgrade(format!("WASM memory read failed for service_type: {e}"))
        })?;
    let type_str = String::from_utf8(type_buffer)
        .map_err(|e| CoreError::Upgrade(format!("Service type is not valid UTF-8: {e}")))?;

    let service_type = ServiceType::Custom(type_str);
    log::info!(
        "Successfully loaded WASM service of type: {:?}",
        service_type
    );

    Ok(Arc::new(WasmService {
        service_type,
        instance,
        store,
    }))
}
