//! IBC proof translation between different commitment schemes

use std::any::Any;
use std::collections::HashMap;

use crate::conversion::ByteConvertible;
use crate::proof::formats::ProofFormatConverter;
use crate::proof::UniversalProofFormat as LocalProofFormat;
use depin_sdk_api::commitment::{CommitmentScheme, ProofContext, SchemeIdentifier, Selector};
use depin_sdk_api::ibc::{ProofTranslator, UniversalProofFormat as CoreProofFormat};

/// Registry for proof translators
pub struct ProofTranslatorRegistry {
    /// Map from (source, target) scheme IDs to translator instances
    translators: HashMap<(String, String), Box<dyn ProofTranslator>>,
}

impl ProofTranslatorRegistry {
    /// Create a new proof translator registry
    pub fn new() -> Self {
        Self {
            translators: HashMap::new(),
        }
    }

    /// Register a proof translator
    pub fn register(&mut self, translator: Box<dyn ProofTranslator>) {
        let source = translator.source_scheme().0.clone();
        let target = translator.target_scheme().0.clone();
        self.translators.insert((source, target), translator);
    }

    /// Get a proof translator
    pub fn get(&self, source: &str, target: &str) -> Option<&dyn ProofTranslator> {
        self.translators
            .get(&(source.to_string(), target.to_string()))
            .map(|t| t.as_ref())
    }

    /// Translate a proof between schemes
    pub fn translate(
        &self,
        source: &str,
        target: &str,
        proof: &dyn Any,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<Box<dyn Any>> {
        // Get the translator and perform translation
        let translator = self.get(source, target)?;

        // Log translation attempt
        log::debug!(
            "Translating proof: {} -> {}, key: {} bytes",
            source,
            target,
            key.len()
        );

        translator.translate(proof, key, value)
    }

    /// Translate with context
    pub fn translate_with_context(
        &self,
        source: &str,
        target: &str,
        proof: &dyn Any,
        key: &[u8],
        value: Option<&[u8]>,
        context: &ProofContext,
    ) -> Option<Box<dyn Any>> {
        // For translators that don't support context directly,
        // we'll convert relevant context data to universal proof metadata
        let translator = self.get(source, target)?;

        // First attempt to use universal format as an intermediate
        if let Some(universal) = translator.to_universal(proof, key, value) {
            // Copy context data to metadata
            let mut enriched = universal;
            for (key, value) in &context.data {
                if !enriched.metadata.contains_key(key) {
                    enriched.metadata.insert(key.clone(), value.clone());
                }
            }

            // Then translate from the enriched universal format
            translator.from_universal(&enriched)
        } else {
            // Fall back to direct translation if universal conversion fails
            translator.translate(proof, key, value)
        }
    }

    /// Translate a universal proof to a specific scheme
    pub fn translate_universal(
        &self,
        target: &str,
        universal: &CoreProofFormat,
    ) -> Option<Box<dyn Any>> {
        let source = &universal.scheme_id.0;
        let translator = self.get(source, target)?;

        // Log translation attempt
        log::debug!("Translating universal proof: {} -> {}", source, target);

        translator.from_universal(universal)
    }

    /// Translate a local proof format to a specific scheme
    pub fn translate_local_universal(
        &self,
        target: &str,
        local_universal: &LocalProofFormat,
    ) -> Option<Box<dyn Any>> {
        // Convert local format to core format
        let core_universal = ProofFormatConverter::local_to_core(local_universal);

        // Then translate using the core format
        self.translate_universal(target, &core_universal)
    }

    /// Convert a proof to universal format
    pub fn to_universal(
        &self,
        source: &str,
        proof: &dyn Any,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<CoreProofFormat> {
        // Find any translator for this source scheme
        for ((src, _), translator) in &self.translators {
            if src == source {
                return translator.to_universal(proof, key, value);
            }
        }
        None
    }

    /// Convert a proof to local universal format
    pub fn to_local_universal(
        &self,
        source: &str,
        proof: &dyn Any,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<LocalProofFormat> {
        // First convert to core format
        let core = self.to_universal(source, proof, key, value)?;

        // Then convert to local format
        Some(ProofFormatConverter::core_to_local(&core))
    }

    /// List all supported source schemes
    pub fn source_schemes(&self) -> Vec<String> {
        let mut schemes = self
            .translators
            .keys()
            .map(|(source, _)| source.clone())
            .collect::<Vec<_>>();
        schemes.sort();
        schemes.dedup();
        schemes
    }

    /// List all supported target schemes
    pub fn target_schemes(&self) -> Vec<String> {
        let mut schemes = self
            .translators
            .keys()
            .map(|(_, target)| target.clone())
            .collect::<Vec<_>>();
        schemes.sort();
        schemes.dedup();
        schemes
    }

    /// List all supported translations
    pub fn supported_translations(&self) -> Vec<(String, String)> {
        self.translators.keys().cloned().collect()
    }
}
