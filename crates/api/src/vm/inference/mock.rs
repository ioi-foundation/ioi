// Path: crates/api/src/vm/inference/mock.rs

use crate::vm::inference::InferenceRuntime;
use async_trait::async_trait;
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use serde_json::json;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct MockInferenceRuntime;

#[async_trait]
impl InferenceRuntime for MockInferenceRuntime {
    async fn execute_inference(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        // Log the execution request
        log::info!(
            "MockInference: Executing on model {} with input len {}",
            hex::encode(model_hash),
            input_context.len()
        );

        let input_str = String::from_utf8_lossy(input_context);

        // [DEBUG]
        // println!("[MockBrain] Input: {}", input_str);

        // 1. Intent Resolver Logic (Control Plane)
        // Detect if this is a request to map Natural Language -> Transaction.
        // We look for keywords from the System Prompt or specific user intent triggers.
        if input_str.contains("intent resolver")
            || input_str.contains("User Input:")
            || input_str.contains("<user_intent>")
        {
            if input_str.contains("Analyze network traffic") || input_str.contains("example.com") {
                // Return Intent Plan JSON matching the schema expected by IntentResolver
                let mock_intent_json = json!({
                    "operation_id": "start_agent",
                    "params": {
                        "goal": "Analyze network traffic on example.com"
                    },
                    "gas_ceiling": 5000000
                });
                return Ok(mock_intent_json.to_string().into_bytes());
            }
        }

        // 2. Agent Execution Logic (Data Plane)
        // If not intent resolution, it's the agent loop asking for the next tool action.
        let response = if input_str.contains("browser")
            || (input_str.contains("network") && !input_str.contains("start_agent"))
            || input_str.contains("example.com")
        {
            json!({
                "name": "browser__navigate",
                "arguments": { "url": "https://example.com" }
            })
        } else if input_str.contains("click") {
            json!({
                "name": "gui__click",
                "arguments": { "x": 500, "y": 500, "button": "left" }
            })
        } else {
            // Default thought/action
            json!({
                "name": "sys__exec",
                "arguments": { "command": "echo", "args": ["Mock Brain Thinking..."] }
            })
        };

        Ok(response.to_string().into_bytes())
    }

    // [NEW] Implement embed_text
    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        // Deterministic embedding: Hash the text, seed a PRNG (or just cycle the bytes),
        // and generate a float vector.

        let digest =
            Sha256::digest(text.as_bytes()).map_err(|e| VmError::HostError(e.to_string()))?;

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
            // In mock mode, we don't strictly require the file to exist on disk unless testing hydration.
            // But we log it.
            log::warn!(
                "MockInference: Model file not found at {:?} (proceeding anyway for mock)",
                path
            );
        } else {
            log::info!(
                "MockInference: Loaded model {} from {:?}",
                hex::encode(model_hash),
                path
            );
        }
        Ok(())
    }

    async fn unload_model(&self, model_hash: [u8; 32]) -> Result<(), VmError> {
        log::info!("MockInference: Unloaded model {}", hex::encode(model_hash));
        Ok(())
    }
}
