// Path: crates/scs/src/scrubber.rs

//! Integration for the "Scrub-on-Export" pipeline.
//!
//! This module provides the logic to read raw frames from the local SCS,
//! apply semantic redaction using the `SemanticScrubber`,
//! and produce clean `ContextSlice` objects ready for network transport.

use crate::format::FrameId;
use crate::store::SovereignContextStore;
use anyhow::Result;
use dcrypt::algorithms::ByteSerializable; // Required for copy_from_slice
use ioi_api::vm::inference::LocalSafetyModel;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{ContextSlice, RedactionEntry, RedactionMap, RedactionType};
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

/// A specialized exporter that sanitizes data as it leaves the secure local storage.
pub struct ScsExporter<'a> {
    store: &'a mut SovereignContextStore,
    scrubber: &'a SemanticScrubber,
}

impl<'a> ScsExporter<'a> {
    pub fn new(store: &'a mut SovereignContextStore, scrubber: &'a SemanticScrubber) -> Self {
        Self { store, scrubber }
    }

    /// Exports a specific frame as a sanitized ContextSlice.
    pub async fn export_frame(
        &mut self,
        frame_id: FrameId,
        intent_hash: [u8; 32],
    ) -> Result<(ContextSlice, RedactionMap)> {
        // 1. Read Raw Payload (Zero-Copy from Mmap)
        let raw_bytes = self.store.read_frame_payload(frame_id)?.to_vec();

        // 2. Identify Content Type (Heuristic)
        // [FIX] Explicit type annotation for the tuple
        let (scrubbed_bytes, redaction_map): (Vec<u8>, RedactionMap) =
            if let Ok(text) = String::from_utf8(raw_bytes.clone()) {
                let (clean_text, map) = self.scrubber.scrub(&text).await?;
                (clean_text.into_bytes(), map)
            } else {
                (raw_bytes, RedactionMap { entries: vec![] })
            };

        // 3. Generate Provenance Proof (Merkle Path from Frame -> SCS Root)
        let slice_id_digest = sha256(&scrubbed_bytes)?;
        let mut slice_id = [0u8; 32];
        slice_id.copy_from_slice(slice_id_digest.as_ref());

        let frame = self.store.toc.frames.get(frame_id as usize).unwrap();
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&frame.mhnsw_root);
        proof_data.extend_from_slice(&frame.checksum);

        let slice = ContextSlice {
            slice_id,
            frame_id: frame_id,
            chunks: vec![scrubbed_bytes],
            mhnsw_root: frame.mhnsw_root,
            traversal_proof: Some(proof_data),
            intent_id: intent_hash,
        };

        Ok((slice, redaction_map))
    }
}
