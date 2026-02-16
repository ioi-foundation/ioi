// Path: crates/scs/src/pii_scrubber.rs

//! Integration for the "Scrub-on-Export" pipeline.
//!
//! This module reads raw frames from the local SCS, applies canonical deterministic
//! redaction using the shared `ioi-pii` scrubber core, and produces clean
//! `ContextSlice` objects ready for transport.

use crate::format::FrameId;
use crate::store::SovereignContextStore;
use anyhow::Result;
use ioi_api::vm::inference::LocalSafetyModel;
use ioi_crypto::algorithms::hash::sha256;
use ioi_pii::scrub_text;
use ioi_types::app::{ContextSlice, RedactionMap};
use std::sync::Arc;

/// The PII Scrubber acts as the "Airlock" for data leaving the Orchestrator.
pub struct PiiScrubber {
    model: Arc<dyn LocalSafetyModel>,
}

impl PiiScrubber {
    /// Creates a new `PiiScrubber` backed by the given safety model.
    pub fn new(model: Arc<dyn LocalSafetyModel>) -> Self {
        Self { model }
    }

    /// Scrubs PII and secrets from text using canonical shared redaction behavior.
    pub async fn scrub(&self, input: &str) -> Result<(String, RedactionMap)> {
        let detections = self.model.detect_pii(input).await?;
        scrub_text(input, &detections)
    }
}

/// A specialized exporter that sanitizes data as it leaves secure local storage.
pub struct ScsExporter<'a> {
    store: &'a mut SovereignContextStore,
    scrubber: &'a PiiScrubber,
}

impl<'a> ScsExporter<'a> {
    pub fn new(store: &'a mut SovereignContextStore, scrubber: &'a PiiScrubber) -> Self {
        Self { store, scrubber }
    }

    /// Exports a specific frame as a sanitized `ContextSlice`.
    pub async fn export_frame(
        &mut self,
        frame_id: FrameId,
        intent_hash: [u8; 32],
    ) -> Result<(ContextSlice, RedactionMap)> {
        let raw_bytes = self.store.read_frame_payload(frame_id)?.to_vec();

        let (scrubbed_bytes, redaction_map): (Vec<u8>, RedactionMap) =
            if let Ok(text) = String::from_utf8(raw_bytes.clone()) {
                let (clean_text, map) = self.scrubber.scrub(&text).await?;
                (clean_text.into_bytes(), map)
            } else {
                (raw_bytes, RedactionMap { entries: vec![] })
            };

        let slice_id_digest = sha256(&scrubbed_bytes)?;
        let mut slice_id = [0u8; 32];
        slice_id.copy_from_slice(slice_id_digest.as_ref());

        let frame = self.store.toc.frames.get(frame_id as usize).unwrap();
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&frame.mhnsw_root);
        proof_data.extend_from_slice(&frame.checksum);

        let slice = ContextSlice {
            slice_id,
            frame_id,
            chunks: vec![scrubbed_bytes],
            mhnsw_root: frame.mhnsw_root,
            traversal_proof: Some(proof_data),
            intent_id: intent_hash,
        };

        Ok((slice, redaction_map))
    }
}
