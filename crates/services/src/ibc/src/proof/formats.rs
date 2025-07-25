// File: crates/ibc/src/proof/formats.rs

use depin_sdk_core::commitment::{ProofContext, Selector};
use depin_sdk_core::ibc::UniversalProofFormat as CoreProofFormat;
use std::collections::HashMap;

use crate::proof::UniversalProofFormat as LocalProofFormat;

/// Helper for converting between proof formats
pub struct ProofFormatConverter;

impl ProofFormatConverter {
    /// Convert from core to local proof format
    pub fn core_to_local(core: &CoreProofFormat) -> LocalProofFormat {
        // Extract selector from key
        let selector = if core.key.is_empty() {
            Selector::None
        } else {
            Selector::Key(core.key.clone())
        };

        // Create local proof format
        let mut local = LocalProofFormat::new(
            core.scheme_id.clone(),
            core.proof_data.clone(),
            selector,
            core.value.clone(),
        );

        // Copy metadata
        for (key, value) in &core.metadata {
            local.add_metadata(key, value.clone());
        }

        local
    }

    /// Convert from local to core proof format
    pub fn local_to_core(local: &LocalProofFormat) -> CoreProofFormat {
        // Extract key from selector if available
        let key = match &local.selector {
            Selector::Key(k) => k.clone(),
            _ => local.key.clone(), // Fall back to explicit key field
        };

        // Create core proof format
        let mut core = CoreProofFormat {
            scheme_id: local.scheme_id.clone(),
            format_version: local.format_version,
            proof_data: local.proof_data.clone(),
            metadata: HashMap::new(),
            key, // Using key directly
            value: local.value.clone(),
        };

        // Copy metadata
        for (key, value) in &local.metadata {
            core.metadata.insert(key.clone(), value.clone());
        }

        core
    }

    /// Create a combined context from proof and additional context
    pub fn create_combined_context(
        proof: &LocalProofFormat,
        additional: Option<&ProofContext>,
    ) -> ProofContext {
        let mut combined = proof.context.clone();

        // Add additional context data if provided
        if let Some(additional_ctx) = additional {
            for (key, value) in &additional_ctx.data {
                // Only add if not already present
                if !combined.data.contains_key(key) {
                    combined.add_data(key, value.clone());
                }
            }
        }

        combined
    }
}