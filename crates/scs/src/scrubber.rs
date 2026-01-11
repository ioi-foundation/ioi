// Path: crates/scs/src/scrubber.rs

//! Integration for the "Scrub-on-Export" pipeline.
//!
//! This module provides the logic to read raw frames from the local SCS,
//! apply semantic redaction using the `SemanticScrubber` from `ioi-services`,
//! and produce clean `ContextSlice` objects ready for network transport.

use crate::format::FrameId;
use crate::store::SovereignContextStore;
use anyhow::Result;
use ioi_crypto::algorithms::hash::sha256;
use ioi_services::agentic::scrubber::SemanticScrubber;
use ioi_types::app::{ContextSlice, RedactionMap};

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
    ///
    /// # Arguments
    /// * `frame_id` - The ID of the frame to export.
    /// * `intent_hash` - The hash of the agent's intent (ActionRequest) authorizing this export.
    ///
    /// # Returns
    /// A tuple containing:
    /// 1. The `ContextSlice` with redacted data.
    /// 2. A `RedactionMap` allowing the Orchestrator (User Node) to rehydrate the response later.
    pub async fn export_frame(
        &mut self,
        frame_id: FrameId,
        intent_hash: [u8; 32],
    ) -> Result<(ContextSlice, RedactionMap)> {
        // 1. Read Raw Payload (Zero-Copy from Mmap)
        // We clone to Vec because the scrubber needs an owned String/Vec usually,
        // or at least we need to mutate/replace parts of it.
        let raw_bytes = self.store.read_frame_payload(frame_id)?.to_vec();

        // 2. Identify Content Type (Heuristic)
        // Ideally, Frame metadata would store MIME type. For MVP, we check if it's text.
        // If binary (image), we might skip scrubbing or use OCR-based scrubbing (Phase 3).
        // For now, assume UTF-8 text (Accessibility Tree, JSON, etc.)
        let (scrubbed_bytes, redaction_map) = if let Ok(text) = String::from_utf8(raw_bytes.clone())
        {
            let (clean_text, map) = self.scrubber.scrub(&text).await?;
            (clean_text.into_bytes(), map)
        } else {
            // Binary data: For now, pass through or block based on policy.
            // Safe default: Pass through, assuming binary (image) scrubbing is handled by
            // a separate Vision model pass in the driver before storage, OR
            // we trust the image hash logic.
            // Let's assume text-only for this specific "Scrub-on-Export" implementation.
            (raw_bytes, RedactionMap { entries: vec![] })
        };

        // 3. Generate Provenance Proof (Merkle Path from Frame -> SCS Root)
        // For MVP, we use the Frame's own checksum as the proof root for single-frame slices.
        // In a full implementation, this would be a Merkle proof into the `toc.checksum` root.
        let slice_id_digest = sha256(&scrubbed_bytes)?;
        let mut slice_id = [0u8; 32];
        slice_id.copy_from_slice(slice_id_digest.as_ref());

        // The "Provenance Proof" here acts as the binding between the data and the store.
        // We use the mHNSW root stored in the frame header as part of this proof.
        let frame = self.store.toc.frames.get(frame_id as usize).unwrap();
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&frame.mhnsw_root);
        proof_data.extend_from_slice(&frame.checksum); // Original Raw Hash
                                                       // (In reality, a real Merkle proof would go here)

        let slice = ContextSlice {
            slice_id,
            frame_id: frame_id,                // [FIX] Added frame_id
            chunks: vec![scrubbed_bytes],      // [FIX] Wrapped in vec for chunks
            mhnsw_root: frame.mhnsw_root,      // [FIX] Added mhnsw_root
            traversal_proof: Some(proof_data), // [FIX] Renamed provenance_proof to traversal_proof
            intent_id: intent_hash,
        };

        Ok((slice, redaction_map))
    }
}
