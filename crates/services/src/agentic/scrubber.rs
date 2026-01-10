// Path: crates/services/src/agentic/scrubber.rs

use anyhow::Result;
use dcrypt::algorithms::ByteSerializable; // Required for copy_from_slice
use ioi_api::vm::inference::LocalSafetyModel;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{RedactionEntry, RedactionMap, RedactionType};
use std::sync::Arc;

/// The Semantic Scrubber acts as the "Airlock" for data leaving the Orchestrator.
/// It uses the local safety model to identify and redact sensitive information.
pub struct SemanticScrubber {
    model: Arc<dyn LocalSafetyModel>,
}

impl SemanticScrubber {
    /// Creates a new `SemanticScrubber` backed by the given safety model.
    pub fn new(model: Arc<dyn LocalSafetyModel>) -> Self {
        Self { model }
    }

    /// Scrubs PII and Secrets from the input string.
    /// Returns the sanitized string and a map to reverse the process (rehydration).
    pub async fn scrub(&self, input: &str) -> Result<(String, RedactionMap)> {
        // 1. Detect PII using the local model
        let detections = self.model.detect_pii(input).await?;

        if detections.is_empty() {
            return Ok((input.to_string(), RedactionMap { entries: vec![] }));
        }

        // 2. Sort detections by position to handle replacements linearly
        let mut sorted_detections = detections;
        sorted_detections.sort_by_key(|k| k.0);

        let mut output = String::with_capacity(input.len());
        let mut redactions = Vec::new();
        let mut last_pos = 0;

        for (start, end, category) in sorted_detections {
            // Skip overlaps for simplicity in this version
            if start < last_pos {
                continue;
            }

            // Append safe text before the secret
            output.push_str(&input[last_pos..start]);

            // Extract the secret
            let secret_slice = &input[start..end];
            let secret_bytes = secret_slice.as_bytes();

            // Hash the secret for integrity verification later
            let hash = sha256(secret_bytes)?;
            let mut hash_arr = [0u8; 32];
            hash_arr.copy_from_slice(hash.as_ref());

            // Determine redaction type
            let r_type = if category == "API_KEY" {
                RedactionType::Secret
            } else {
                RedactionType::Pii
            };

            // Record the redaction
            // Note: Indices in RedactionEntry refer to the ORIGINAL input
            redactions.push(RedactionEntry {
                start_index: start as u32,
                end_index: end as u32,
                redaction_type: r_type,
                original_hash: hash_arr,
            });

            // Replace with placeholder token
            let placeholder = format!("<REDACTED:{}>", category);
            output.push_str(&placeholder);

            last_pos = end;
        }

        // Append remaining text
        if last_pos < input.len() {
            output.push_str(&input[last_pos..]);
        }

        Ok((
            output,
            RedactionMap {
                entries: redactions,
            },
        ))
    }
}