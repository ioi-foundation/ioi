// Path: crates/api/src/vm/inference/mock.rs

use crate::vm::inference::InferenceRuntime;
use async_trait::async_trait;
use ioi_types::app::agentic::InferenceOptions; // [UPDATED]
use ioi_types::error::VmError;
use std::path::Path;
// [NEW] Import for hashing
use dcrypt::algorithms::hash::{HashFunction, Sha256};

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

    // [NEW] Implement embed_text
    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        // Deterministic embedding: Hash the text, seed a PRNG (or just cycle the bytes),
        // and generate a float vector.
        // For testing stability, we map the 32-byte hash to a 384-dimensional vector (common small size).
        
        let digest = Sha256::digest(text.as_bytes())
            .map_err(|e| VmError::HostError(e.to_string()))?;
        
        let seed = digest.as_ref();
        let mut embedding = Vec::with_capacity(384);
        
        for i in 0..384 {
            // Simple chaotic mapping to get floats in [-1.0, 1.0]
            let byte = seed[i % 32];
            let modifier = (i * 7) as u8;
            let val = byte.wrapping_add(modifier);
            let float_val = (val as f32 / 255.0) * 2.0 - 1.0;
            embedding.push(float_val);
        }
        
        // Normalize vector
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in &mut embedding {
                *x /= norm;
            }
        }

        Ok(embedding)
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