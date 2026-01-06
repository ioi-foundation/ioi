// Path: crates/api/src/vm/inference/mod.rs

use async_trait::async_trait;
use ioi_types::error::VmError;
use std::path::Path;

pub mod driver;
pub mod mock; // [NEW]

pub use driver::{AcceleratorType, DeviceCapabilities, HardwareDriver, ModelHandle};

/// A runtime capable of executing deterministic AI inference.
///
/// Implementations (e.g., ONNX Runtime, Llama.cpp) must ensure:
/// 1. Fixed floating point modes (if supported).
/// 2. Fixed RNG seeds.
/// 3. Identical output across heterogeneous hardware (CPU vs GPU) if required by the consensus protocol.
#[async_trait]
pub trait InferenceRuntime: Send + Sync {
    /// Executes a model against an input context.
    ///
    /// # Arguments
    /// * `model_hash` - The SHA-256 identifier of the model snapshot.
    /// * `input_context` - The serialized input data (e.g., prompt tokens, embeddings).
    ///
    /// # Returns
    /// * `Vec<u8>` - The raw output tensor or text bytes.
    async fn execute_inference(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
    ) -> Result<Vec<u8>, VmError>;

    /// Pre-loads a model into memory/VRAM to reduce latency for subsequent calls.
    async fn load_model(&self, model_hash: [u8; 32], path: &Path) -> Result<(), VmError>;

    /// Offloads a model from memory.
    async fn unload_model(&self, model_hash: [u8; 32]) -> Result<(), VmError>;
}
