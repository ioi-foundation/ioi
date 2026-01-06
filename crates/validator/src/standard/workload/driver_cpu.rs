// Path: crates/validator/src/standard/workload/driver_cpu.rs

//! Implementation of the CPU-based hardware driver using the Candle ML framework.

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::inference::{AcceleratorType, DeviceCapabilities, HardwareDriver, ModelHandle};
use ioi_types::error::VmError;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

#[cfg(feature = "real-ai")]
use candle_core::quantized::gguf_file::Content;
#[cfg(feature = "real-ai")]
use candle_core::Device;
#[cfg(feature = "real-ai")]
use candle_transformers::models::quantized_llama::ModelWeights;

/// A handle to a model loaded into system memory for CPU execution.
#[derive(Debug)]
struct CpuModelHandle {
    /// The unique 32-byte identifier for the model weights.
    id: [u8; 32],
    /// The actual weights loaded and managed by the Candle framework.
    #[cfg(feature = "real-ai")]
    weights: Arc<ModelWeights>,
}

impl ModelHandle for CpuModelHandle {
    fn id(&self) -> [u8; 32] {
        self.id
    }
}

/// A hardware driver that executes AI inference on the host CPU.
/// This provides a universal fallback for nodes without dedicated GPU accelerators.
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
            vram_bytes: 0, // CPU uses shared system RAM
            compute_units: num_cpus::get() as u32,
            driver_version: "candle-cpu-0.3.3".to_string(),
        }
    }

    async fn load_model(
        &self,
        model_id: [u8; 32],
        path: &Path,
        _config: &[u8],
    ) -> Result<Box<dyn ModelHandle>, VmError> {
        #[cfg(feature = "real-ai")]
        {
            // 1. Open the GGUF file for metadata parsing
            let mut file_meta = std::fs::File::open(path)
                .map_err(|e| VmError::HostError(format!("Failed to open model file: {}", e)))?;

            // 2. Parse the GGUF header/content
            let content = Content::read(&mut file_meta)
                .map_err(|e| VmError::HostError(format!("Failed to read GGUF content: {}", e)))?;

            // 3. Open a separate handle for tensor data reading (allows independent seeking)
            let mut file_weights = std::fs::File::open(path).map_err(|e| {
                VmError::HostError(format!("Failed to open model file for weights: {}", e))
            })?;

            let device = Device::Cpu;

            // 4. Load the weights into system memory
            let weights = ModelWeights::from_gguf(content, &mut file_weights, &device)
                .map_err(|e| VmError::HostError(format!("Failed to load GGUF weights: {}", e)))?;

            let handle = Arc::new(CpuModelHandle {
                id: model_id,
                weights: Arc::new(weights),
            });

            let mut cache = self.loaded_models.write().unwrap();
            cache.insert(model_id, handle.clone());

            Ok(Box::new(CpuModelHandle {
                id: model_id,
                weights: handle.weights.clone(),
            }))
        }
        #[cfg(not(feature = "real-ai"))]
        {
            let _ = path; // Suppress unused warning
                          // Mock behavior for testing when real-ai feature is disabled
            let handle = Arc::new(CpuModelHandle { id: model_id });
            let mut cache = self.loaded_models.write().unwrap();
            cache.insert(model_id, handle.clone());
            Ok(Box::new(CpuModelHandle { id: model_id }))
        }
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
