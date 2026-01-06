// Path: crates/api/src/vm/inference/driver.rs

use async_trait::async_trait;
use ioi_types::error::VmError;
use std::fmt::Debug;
use std::path::Path;

/// The type of accelerator hardware available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceleratorType {
    Cpu,
    NvidiaCuda,
    AppleMetal,
    AmdRocm,
}

/// Capabilities reported by the hardware driver.
#[derive(Debug, Clone)]
pub struct DeviceCapabilities {
    pub accelerator_type: AcceleratorType,
    pub vram_bytes: u64,
    pub compute_units: u32,
    pub driver_version: String,
}

/// A handle to a loaded model on the device.
pub trait ModelHandle: Send + Sync {
    /// Returns the unique ID/Hash of the model this handle manages.
    fn id(&self) -> [u8; 32];
}

/// Abstraction for a hardware inference backend.
#[async_trait]
pub trait HardwareDriver: Send + Sync + Debug {
    /// Returns the capabilities of the underlying hardware.
    fn capabilities(&self) -> DeviceCapabilities;

    /// Loads a model from disk into device memory.
    ///
    /// # Arguments
    /// * `model_id` - Unique 32-byte hash/ID of the model.
    /// * `path` - Filesystem path to the weights.
    /// * `config` - Implementation-specific configuration (JSON bytes).
    async fn load_model(
        &self,
        model_id: [u8; 32],
        path: &Path,
        config: &[u8],
    ) -> Result<Box<dyn ModelHandle>, VmError>;

    /// Unloads a model to free VRAM.
    async fn unload_model(&self, handle: Box<dyn ModelHandle>) -> Result<(), VmError>;

    /// Checks if a model is currently loaded and "warm".
    async fn is_model_loaded(&self, model_id: &[u8; 32]) -> bool;
}
