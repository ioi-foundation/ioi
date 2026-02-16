// Path: crates/validator/src/standard/workload/drivers/cpu.rs

//! CPU hardware driver implementation.

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::inference::{AcceleratorType, DeviceCapabilities, HardwareDriver, ModelHandle};
use ioi_types::error::VmError;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// A handle to a model loaded into system memory for CPU execution.
#[derive(Debug)]
struct CpuModelHandle {
    /// The unique 32-byte identifier for the model weights.
    id: [u8; 32],
}

impl ModelHandle for CpuModelHandle {
    fn id(&self) -> [u8; 32] {
        self.id
    }
}

/// A hardware driver that executes AI inference on the host CPU.
#[derive(Debug)]
pub struct CpuDriver {
    /// Registry of models currently resident in system memory.
    loaded_models: RwLock<HashMap<[u8; 32], Arc<CpuModelHandle>>>,
}

impl CpuDriver {
    /// Creates a new instance of the `CpuDriver`.
    pub fn new() -> Self {
        Self {
            loaded_models: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for CpuDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HardwareDriver for CpuDriver {
    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            accelerator_type: AcceleratorType::Cpu,
            vram_bytes: 0,
            compute_units: num_cpus::get() as u32,
            driver_version: "cpu-native".to_string(),
        }
    }

    async fn load_model(
        &self,
        model_id: [u8; 32],
        path: &Path,
        _config: &[u8],
    ) -> Result<Box<dyn ModelHandle>, VmError> {
        if !path.exists() {
            return Err(VmError::HostError(format!(
                "Model file does not exist: {}",
                path.display()
            )));
        }

        let handle = Arc::new(CpuModelHandle { id: model_id });
        let mut cache = self.loaded_models.write().unwrap();
        cache.insert(model_id, handle.clone());
        Ok(Box::new(CpuModelHandle { id: handle.id }))
    }

    async fn unload_model(&self, handle: Box<dyn ModelHandle>) -> Result<(), VmError> {
        let mut cache = self.loaded_models.write().unwrap();
        cache.remove(&handle.id());
        Ok(())
    }

    async fn is_model_loaded(&self, model_id: &[u8; 32]) -> bool {
        let cache = self.loaded_models.read().unwrap();
        cache.contains_key(model_id)
    }
}
