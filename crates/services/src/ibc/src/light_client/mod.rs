//! IBC light client implementations

use crate::conversion::ByteConvertible;
use crate::translation::ProofTranslatorRegistry;
use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_core::ibc::{LightClient, UniversalProofFormat};
use std::any::Any;
use std::collections::HashMap;

/// Type-erased commitment scheme wrapper that avoids dynamic dispatch limitations
struct SchemeWrapper {
    /// The actual scheme (boxed as Any)
    inner: Box<dyn Any + Send + Sync>,
    /// Function pointer for commit operation
    commit_fn: fn(&dyn Any, &[Option<Vec<u8>>]) -> Box<dyn AsRef<[u8]> + Send + Sync>,
    /// Function pointer for create_proof operation
    create_proof_fn: fn(&dyn Any, &Selector, &[u8]) -> Result<Box<dyn Any + Send + Sync>, String>,
    /// Function pointer for verify operation
    verify_fn: fn(&dyn Any, &dyn Any, &dyn Any, &Selector, &[u8], &ProofContext) -> bool,
    /// Scheme identifier
    id: String,
}

/// Universal light client that can verify proofs from multiple commitment schemes
pub struct UniversalLightClient {
    /// Supported scheme implementations
    schemes: HashMap<String, SchemeWrapper>,
    /// Translator registry
    translators: ProofTranslatorRegistry,
    /// Default scheme to use
    default_scheme: Option<String>,
}

impl UniversalLightClient {
    /// Create a new universal light client
    pub fn new() -> Self {
        Self {
            schemes: HashMap::new(),
            translators: ProofTranslatorRegistry::new(),
            default_scheme: None,
        }
    }

    /// Register a commitment scheme
    pub fn register_scheme<C>(&mut self, scheme_id: &str, scheme: C)
    where
        C: CommitmentScheme + 'static,
        C::Value: ByteConvertible + AsRef<[u8]>, // Using unified trait
    {
        // Create type-erased wrapper functions
        let commit_fn = |any_scheme: &dyn Any,
                         values: &[Option<Vec<u8>>]|
         -> Box<dyn AsRef<[u8]> + Send + Sync> {
            let scheme = any_scheme.downcast_ref::<C>().unwrap();
            // Convert Vec<u8> to C::Value using ByteConvertible trait
            let typed_values: Vec<Option<C::Value>> = values
                .iter()
                .map(|v| v.as_ref().and_then(|bytes| C::Value::from_bytes(bytes)))
                .collect();

            let commitment = scheme.commit(&typed_values);
            Box::new(commitment)
        };

        let create_proof_fn = |any_scheme: &dyn Any,
                               selector: &Selector,
                               value: &[u8]|
         -> Result<Box<dyn Any + Send + Sync>, String> {
            let scheme = any_scheme.downcast_ref::<C>().unwrap();
            // Convert value to C::Value using ByteConvertible trait
            if let Some(typed_value) = C::Value::from_bytes(value) {
                scheme
                    .create_proof(selector, &typed_value)
                    .map(|proof| Box::new(proof) as Box<dyn Any + Send + Sync>)
            } else {
                Err(format!(
                    "Failed to convert {} bytes to the expected format",
                    value.len()
                ))
            }
        };

        let verify_fn = |any_scheme: &dyn Any,
                         any_commitment: &dyn Any,
                         any_proof: &dyn Any,
                         selector: &Selector,
                         value: &[u8],
                         context: &ProofContext|
         -> bool {
            if let Some(scheme) = any_scheme.downcast_ref::<C>() {
                if let Some(commitment) = any_commitment.downcast_ref::<C::Commitment>() {
                    if let Some(proof) = any_proof.downcast_ref::<C::Proof>() {
                        // Convert value to C::Value
                        if let Some(typed_value) = C::Value::from_bytes(value) {
                            return scheme.verify(
                                commitment,
                                proof,
                                selector,
                                &typed_value,
                                context,
                            );
                        }
                    }
                }
            }
            false
        };

        let wrapper = SchemeWrapper {
            inner: Box::new(scheme),
            commit_fn,
            create_proof_fn,
            verify_fn,
            id: scheme_id.to_string(),
        };

        self.schemes.insert(scheme_id.to_string(), wrapper);
        if self.default_scheme.is_none() {
            self.default_scheme = Some(scheme_id.to_string());
        }
    }

    /// Set the default scheme
    pub fn set_default_scheme(&mut self, scheme_id: &str) -> Result<(), String> {
        if self.schemes.contains_key(scheme_id) {
            self.default_scheme = Some(scheme_id.to_string());
            Ok(())
        } else {
            Err(format!("Scheme '{}' not registered", scheme_id))
        }
    }

    /// Register a proof translator
    pub fn register_translator(
        &mut self,
        translator: Box<dyn depin_sdk_core::ibc::ProofTranslator>,
    ) {
        self.translators.register(translator);
    }

    /// Get supported schemes
    pub fn supported_schemes(&self) -> Vec<String> {
        self.schemes.keys().cloned().collect()
    }

    /// Helper method to convert native proof bytes to a proof object
    fn deserialize_proof(
        &self,
        scheme_id: &str,
        proof_bytes: &[u8],
    ) -> Option<Box<dyn Any + Send + Sync>> {
        // In a real implementation, this would deserialize from the proper format
        // based on the scheme's expected proof format
        let _scheme = self.schemes.get(scheme_id)?;

        // Log the deserialization attempt for debugging
        log::debug!(
            "Deserializing proof for scheme {}, {} bytes",
            scheme_id,
            proof_bytes.len()
        );

        // Simply wrap the bytes for now
        // In a real implementation, you'd have scheme-specific deserialization
        Some(Box::new(proof_bytes.to_vec()))
    }

    /// Helper method to extract selector from proof bytes
    fn extract_selector_from_proof(
        &self,
        scheme_id: &str,
        _proof_bytes: &[u8],
        fallback_key: &[u8],
    ) -> Selector {
        // In a real implementation, this would extract the selector information
        // from the proof bytes based on the scheme's format

        // Log the extraction attempt
        log::debug!(
            "Extracting selector for scheme {}, fallback key: {} bytes",
            scheme_id,
            fallback_key.len()
        );

        // For now, return a key-based selector as a default
        Selector::Key(fallback_key.to_vec())
    }
}

impl LightClient for UniversalLightClient {
    fn verify_native_proof(
        &self,
        commitment: &[u8],
        proof: &[u8],
        key: &[u8],
        value: &[u8],
    ) -> bool {
        // Create a default context for internal use
        let context = ProofContext::default();

        // Use the default scheme if available
        if let Some(scheme_id) = &self.default_scheme {
            if let Some(scheme) = self.schemes.get(scheme_id) {
                // Extract selector from proof (or use key selector as fallback)
                let selector = self.extract_selector_from_proof(scheme_id, proof, key);

                // Deserialize proof data
                if let Some(deserialized_proof) = self.deserialize_proof(scheme_id, proof) {
                    // Attempt to verify with the scheme
                    // We use the type-erased function to avoid dynamic dispatch limitations
                    let result = (scheme.verify_fn)(
                        scheme.inner.as_ref(),
                        &commitment.to_vec(), // Simple wrapper for commitment bytes
                        deserialized_proof.as_ref(),
                        &selector,
                        value,
                        &context,
                    );

                    // Log the verification result
                    log::debug!(
                        "Native proof verification result: {}, scheme: {}",
                        result,
                        scheme_id
                    );

                    return result;
                }
            }
        }

        log::warn!("Native proof verification failed, no suitable scheme found");
        false
    }

    fn verify_universal_proof(
        &self,
        commitment: &[u8],
        proof: &UniversalProofFormat,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        let scheme_id = &proof.scheme_id.0;

        // Log received proof information
        log::debug!(
            "Verifying universal proof: scheme={}, key={} bytes, provided_key={} bytes",
            scheme_id,
            proof.key.len(),
            key.len()
        );

        // Create a context from the proof metadata
        let mut combined_context = ProofContext::new();

        // Migrate metadata from core proof to our context
        for (key, value) in &proof.metadata {
            combined_context.add_data(key, value.clone());
        }

        // Determine which key to use - prefer proof's key if present, otherwise use provided key
        let key_to_use = if !proof.key.is_empty() {
            &proof.key
        } else {
            key
        };

        // Create selector based on the key
        let selector = Selector::Key(key_to_use.to_vec());

        // Log the key decision
        log::debug!(
            "Using {} for verification: {} bytes",
            if key_to_use.as_ptr() == proof.key.as_ptr() {
                "proof key"
            } else {
                "provided key"
            },
            key_to_use.len()
        );

        // If we support this scheme directly, use it
        if let Some(scheme) = self.schemes.get(scheme_id) {
            // Deserialize the proof data
            if let Some(deserialized_proof) = self.deserialize_proof(scheme_id, &proof.proof_data) {
                // Verify using the scheme
                let result = (scheme.verify_fn)(
                    scheme.inner.as_ref(),
                    &commitment.to_vec(), // Simple wrapper for commitment bytes
                    deserialized_proof.as_ref(),
                    &selector,
                    value,
                    &combined_context,
                );

                // Log direct verification result
                log::debug!("Direct verification result: {}", result);

                return result;
            }
        }

        // If we don't support this scheme directly, try to translate it
        if let Some(default_id) = &self.default_scheme {
            log::debug!("Attempting translation to scheme: {}", default_id);

            // Attempt to translate the proof to our default scheme
            if let Some(translated_proof) = self.translators.translate_universal(default_id, proof)
            {
                if let Some(scheme) = self.schemes.get(default_id) {
                    // Verify using the translated proof
                    let result = (scheme.verify_fn)(
                        scheme.inner.as_ref(),
                        &commitment.to_vec(), // Simple wrapper for commitment bytes
                        translated_proof.as_ref(),
                        &selector,
                        value,
                        &combined_context,
                    );

                    // Log translation verification result
                    log::debug!("Translation verification result: {}", result);

                    return result;
                }
            } else {
                log::warn!("Failed to translate proof to scheme: {}", default_id);
            }
        }

        log::warn!(
            "Universal proof verification failed for scheme: {}",
            scheme_id
        );
        false
    }

    fn supported_schemes(&self) -> Vec<String> {
        self.schemes.keys().cloned().collect()
    }
}
