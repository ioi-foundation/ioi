// Path: crates/validator/src/standard/workload/runtime.rs

use crate::standard::workload::hydration::ModelHydrator;
use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::inference::{HardwareDriver, InferenceRuntime};
use ioi_crypto::algorithms::hash::sha256;
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
        input_context: &[u8],
        _options: InferenceOptions, // [FIX] Added parameter
    ) -> Result<Vec<u8>, VmError> {
        // 1. Ensure model is loaded
        if !self.driver.is_model_loaded(&model_hash).await {
            return Err(VmError::HostError(
                "Model not loaded. Call load_model first.".into(),
            ));
        }

        let input_digest = sha256(input_context)
            .map_err(|e| VmError::HostError(format!("Input digest failed: {}", e)))?;

        let mut output = Vec::with_capacity(72);
        output.extend_from_slice(&model_hash);
        output.extend_from_slice(&input_digest);
        output.extend_from_slice(&(input_context.len() as u64).to_le_bytes());
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standard::workload::drivers::cpu::CpuDriver;

    #[tokio::test]
    async fn standard_runtime_executes_loaded_model_deterministically() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let model_bytes = b"deterministic-local-model";
        let model_hash = sha256(model_bytes).expect("model hash");
        let model_path = temp_dir
            .path()
            .join(format!("{}.bin", hex::encode(model_hash)));
        tokio::fs::write(&model_path, model_bytes)
            .await
            .expect("write model");

        let driver = Arc::new(CpuDriver::new());
        let hydrator = Arc::new(ModelHydrator::new(
            temp_dir.path().to_path_buf(),
            driver.clone(),
        ));
        let runtime = StandardInferenceRuntime::new(hydrator, driver);

        let unloaded = runtime
            .execute_inference(model_hash, b"input", InferenceOptions::default())
            .await;
        assert!(
            unloaded.is_err(),
            "unloaded model execution must fail closed"
        );

        let model_id = hex::encode(model_hash);
        runtime
            .load_model(model_hash, Path::new(&model_id))
            .await
            .expect("load model");

        let first = runtime
            .execute_inference(model_hash, b"input", InferenceOptions::default())
            .await
            .expect("first inference");
        let second = runtime
            .execute_inference(model_hash, b"input", InferenceOptions::default())
            .await
            .expect("second inference");

        assert_eq!(first, second);
        assert_eq!(&first[..32], &model_hash);
        assert_eq!(&first[32..64], &sha256(b"input").expect("input hash"));
        assert_eq!(
            u64::from_le_bytes(first[64..72].try_into().expect("length bytes")),
            5
        );
    }
}
