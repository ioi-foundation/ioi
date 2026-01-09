// Path: crates/api/src/vm/inference/mod.rs

use async_trait::async_trait;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use std::path::Path;

pub mod driver;
pub mod http_adapter;
pub mod mock; // [NEW] Export the new module

pub use driver::{AcceleratorType, DeviceCapabilities, HardwareDriver, ModelHandle};
pub use http_adapter::HttpInferenceRuntime; // [NEW] Re-export for easier usage

/// A runtime capable of executing deterministic AI inference.
#[async_trait]
pub trait InferenceRuntime: Send + Sync {
    /// Executes a model against an input context with specific generation options.
    async fn execute_inference(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError>;

    /// Generates a vector embedding for a given text input.
    async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
        // Default implementation returns an empty vector or error if not supported.
        Err(VmError::HostError(
            "Embedding not supported by this runtime".into(),
        ))
    }

    /// Pre-loads a model into memory/VRAM to reduce latency for subsequent calls.
    async fn load_model(&self, model_hash: [u8; 32], path: &Path) -> Result<(), VmError>;

    /// Offloads a model from memory.
    async fn unload_model(&self, model_hash: [u8; 32]) -> Result<(), VmError>;
}
