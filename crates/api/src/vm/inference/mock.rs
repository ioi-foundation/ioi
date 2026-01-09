// Path: crates/api/src/vm/inference/mock.rs

use crate::vm::inference::InferenceRuntime;
use async_trait::async_trait;
use ioi_types::app::agentic::InferenceOptions; // [UPDATED]
use ioi_types::error::VmError;
use std::path::Path;

/// A mock implementation of the InferenceRuntime for testing and development.
#[derive(Debug, Default, Clone)]
pub struct MockInferenceRuntime;

#[async_trait]
impl InferenceRuntime for MockInferenceRuntime {
    async fn execute_inference(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions, // [UPDATED] Add options parameter
    ) -> Result<Vec<u8>, VmError> {
        // Log the execution request
        log::info!(
            "MockInference: Executing on model {} with input len {}",
            hex::encode(model_hash),
            input_context.len()
        );

        // Return a deterministic response based on the input.
        let response = format!(
            r#"{{"status": "success", "processed_bytes": {}, "model": "{}"}}"#,
            input_context.len(),
            hex::encode(model_hash)
        );

        Ok(response.into_bytes())
    }

    async fn load_model(&self, model_hash: [u8; 32], path: &Path) -> Result<(), VmError> {
        if !path.exists() {
            return Err(VmError::HostError(format!(
                "MockInference: Model file not found at {:?}",
                path
            )));
        }
        log::info!(
            "MockInference: Loaded model {} from {:?}",
            hex::encode(model_hash),
            path
        );
        Ok(())
    }

    async fn unload_model(&self, model_hash: [u8; 32]) -> Result<(), VmError> {
        log::info!("MockInference: Unloaded model {}", hex::encode(model_hash));
        Ok(())
    }
}
