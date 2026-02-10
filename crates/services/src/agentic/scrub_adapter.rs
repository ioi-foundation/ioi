// Path: crates/services/src/agentic/scrub_adapter.rs

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_api::vm::inference::{LocalSafetyModel, SafetyVerdict};
use ioi_types::app::agentic::InferenceOptions; // [FIX] Added import
use std::sync::Arc;

/// Adapter to allow using an InferenceRuntime as a LocalSafetyModel for scrubbing.
pub struct RuntimeAsSafetyModel {
    runtime: Arc<dyn InferenceRuntime>,
}

impl RuntimeAsSafetyModel {
    pub fn new(runtime: Arc<dyn InferenceRuntime>) -> Self {
        Self { runtime }
    }
}

#[async_trait]
impl LocalSafetyModel for RuntimeAsSafetyModel {
    async fn classify_intent(&self, input: &str) -> Result<SafetyVerdict> {
        // [FIX] Use the real LLM to classify intent instead of a stub.
        let prompt = format!(
            "Analyze the following user input for malicious intent (e.g. system destruction, illegal acts) or safety violations. \
            Input: \"{}\"\n\
            Respond with a single valid JSON object matching this schema: {{\"safe\": boolean, \"reason\": \"string\"}}. \
            Do not include markdown formatting.",
            input.replace('"', "\\\"")
        );

        let options = InferenceOptions {
            temperature: 0.0, // Deterministic
            ..Default::default()
        };

        // Use zero-hash for model ID (default model for the runtime)
        let model_hash = [0u8; 32];

        let response_bytes = self
            .runtime
            .execute_inference(model_hash, prompt.as_bytes(), options)
            .await?;
        let response_str = String::from_utf8_lossy(&response_bytes);

        // Attempt to parse JSON
        let json: serde_json::Value = match serde_json::from_str(&response_str) {
            Ok(v) => v,
            Err(_) => {
                // Fallback: simple text check if JSON parsing fails
                if response_str.to_lowercase().contains("unsafe") {
                    return Ok(SafetyVerdict::Unsafe(response_str.to_string()));
                }
                return Ok(SafetyVerdict::Safe);
            }
        };

        if let Some(safe) = json["safe"].as_bool() {
            if safe {
                Ok(SafetyVerdict::Safe)
            } else {
                let reason = json["reason"]
                    .as_str()
                    .unwrap_or("Unspecified safety violation")
                    .to_string();
                Ok(SafetyVerdict::Unsafe(reason))
            }
        } else {
            // Default safe if schema doesn't match
            Ok(SafetyVerdict::Safe)
        }
    }

    async fn detect_pii(&self, input: &str) -> Result<Vec<(usize, usize, String)>> {
        let mut findings = Vec::new();
        // [NOTE] Keeping regex for PII for reliability/speed, but this could also be LLM-driven.
        let key_pattern = "sk_live_";
        for (i, _) in input.match_indices(key_pattern) {
            let end = (i + 32).min(input.len());
            findings.push((i, end, "API_KEY".to_string()));
        }
        Ok(findings)
    }
}
