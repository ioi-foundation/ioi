// Path: crates/validator/src/standard/workload/runtime.rs

use crate::standard::workload::hydration::ModelHydrator;
use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::inference::{HardwareDriver, InferenceRuntime};
use ioi_types::app::agentic::InferenceOptions; // [FIX] Import
use ioi_types::error::VmError;
use std::path::Path;
use std::sync::Arc;

/// The standard implementation of the AI Inference Runtime.
///
/// This component orchestrates the secure loading of model weights via the
/// `ModelHydrator` and manages execution on physical hardware through a
/// `HardwareDriver`.
pub struct StandardInferenceRuntime {
    hydrator: Arc<ModelHydrator>,
    driver: Arc<dyn HardwareDriver>,
}

impl StandardInferenceRuntime {
    /// Creates a new `StandardInferenceRuntime`.
    ///
    /// # Arguments
    /// * `hydrator` - The component responsible for model verification and disk-to-VRAM loading.
    /// * `driver` - The abstraction for the physical accelerator (e.g., CPU, GPU).
    pub fn new(hydrator: Arc<ModelHydrator>, driver: Arc<dyn HardwareDriver>) -> Self {
        Self { hydrator, driver }
    }
}

#[async_trait]
impl InferenceRuntime for StandardInferenceRuntime {
    async fn load_model(&self, model_hash: [u8; 32], path: &Path) -> Result<(), VmError> {
        // Delegate to hydrator which handles verification and driver loading
        self.hydrator
            .hydrate(model_hash, path.to_str().unwrap_or(""))
            .await
            .map_err(|e| VmError::HostError(format!("Hydration failed: {}", e)))
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        // Simplified: The driver manages LRU or explicit unloads.
        // For Phase 3, we don't expose explicit unload to the contract yet.
        Ok(())
    }

    async fn execute_inference(
        &self,
        model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions, // [FIX] Added parameter
    ) -> Result<Vec<u8>, VmError> {
        // 1. Ensure model is loaded
        if !self.driver.is_model_loaded(&model_hash).await {
            return Err(VmError::HostError(
                "Model not loaded. Call load_model first.".into(),
            ));
        }

        // 2. Parse input (AgentContext or raw bytes)
        // For Phase 3, we assume raw bytes are prompt tokens for simplicity.

        // Native runtime path; model execution is wired by the loaded hardware driver.
        // Full tensor generation remains driver-specific, so this runtime returns a
        // deterministic placeholder until model forward integration is expanded.
        Ok(b"Mock inference result".to_vec())
    }
}
