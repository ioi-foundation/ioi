//! Definition of the UniversalProofFormat
//!
use depin_sdk_api::commitment::{ProofContext, SchemeIdentifier, Selector};
use std::collections::HashMap;

// Explicitly declare the formats module
pub mod formats;
use formats::ProofFormatConverter;

/// Universal proof format that can represent any commitment scheme's proof
#[derive(Debug, Clone)]
pub struct UniversalProofFormat {
    /// Identifier of the commitment scheme that created this proof
    pub scheme_id: SchemeIdentifier,

    /// Version of the proof format
    pub format_version: u8,

    /// The serialized proof data
    pub proof_data: Vec<u8>,

    /// Additional metadata for the proof
    pub metadata: HashMap<String, Vec<u8>>,

    /// Selector that this proof is for
    pub selector: Selector,

    /// Key that this proof is for (backward compatibility)
    pub key: Vec<u8>,

    /// Value this proof is proving (if known)
    pub value: Option<Vec<u8>>,

    /// Verification context
    pub context: ProofContext,
}

impl UniversalProofFormat {
    /// Create a new universal proof format
    pub fn new(
        scheme_id: SchemeIdentifier,
        proof_data: Vec<u8>,
        selector: Selector,
        value: Option<Vec<u8>>,
    ) -> Self {
        // For backward compatibility, extract a key from the selector if possible
        let key = match &selector {
            Selector::Key(k) => k.clone(),
            _ => Vec::new(),
        };

        Self {
            scheme_id,
            format_version: 1,
            proof_data,
            metadata: HashMap::new(),
            selector,
            key,
            value,
            context: ProofContext::default(),
        }
    }

    /// Add metadata to the proof
    pub fn add_metadata(&mut self, key: &str, value: Vec<u8>) {
        self.metadata.insert(key.to_string(), value);
    }

    /// Get metadata from the proof
    pub fn get_metadata(&self, key: &str) -> Option<&Vec<u8>> {
        self.metadata.get(key)
    }

    /// Add context data
    pub fn add_context_data(&mut self, key: &str, value: Vec<u8>) {
        self.context.add_data(key, value);
    }

    /// Get context data
    pub fn get_context_data(&self, key: &str) -> Option<&Vec<u8>> {
        self.context.get_data(key)
    }

    /// Create a new proof with a position-based selector
    pub fn with_position(
        scheme_id: SchemeIdentifier,
        proof_data: Vec<u8>,
        position: usize,
        value: Option<Vec<u8>>,
    ) -> Self {
        Self::new(scheme_id, proof_data, Selector::Position(position), value)
    }

    /// Create a new proof with a key-based selector
    pub fn with_key(
        scheme_id: SchemeIdentifier,
        proof_data: Vec<u8>,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> Self {
        Self::new(scheme_id, proof_data, Selector::Key(key), value)
    }

    /// Create a new proof with a predicate-based selector
    pub fn with_predicate(
        scheme_id: SchemeIdentifier,
        proof_data: Vec<u8>,
        predicate: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> Self {
        Self::new(scheme_id, proof_data, Selector::Predicate(predicate), value)
    }

    /// Create a new proof with no selector
    pub fn with_no_selector(
        scheme_id: SchemeIdentifier,
        proof_data: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> Self {
        Self::new(scheme_id, proof_data, Selector::None, value)
    }
}

/// Helper functions for working with UniversalProofFormat
pub struct IBCProofUtils;

impl IBCProofUtils {
    /// Create a new universal proof format
    pub fn create_universal_proof(
        scheme_id: &str,
        proof_data: Vec<u8>,
        selector: Selector,
        value: Option<Vec<u8>>,
    ) -> UniversalProofFormat {
        UniversalProofFormat::new(
            SchemeIdentifier::new(scheme_id),
            proof_data,
            selector,
            value,
        )
    }

    /// Get scheme ID from a universal proof
    pub fn get_scheme_id(proof: &UniversalProofFormat) -> &str {
        &proof.scheme_id.0
    }

    /// Get proof data from a universal proof
    pub fn get_proof_data(proof: &UniversalProofFormat) -> &[u8] {
        &proof.proof_data
    }

    /// Get selector from a universal proof
    pub fn get_selector(proof: &UniversalProofFormat) -> &Selector {
        &proof.selector
    }

    /// Get key from a universal proof
    pub fn get_key(proof: &UniversalProofFormat) -> &[u8] {
        &proof.key
    }

    /// Get value from a universal proof
    ///
    /// This function returns a borrowed slice of the value stored in the proof,
    /// if it exists. The lifetime of the returned slice is bound to the lifetime
    /// of the input `proof`.
    pub fn get_value<'a>(proof: &'a UniversalProofFormat) -> Option<&'a [u8]> {
        proof.value.as_ref().map(|v| v.as_slice())
    }

    /// Add metadata to a universal proof
    pub fn add_metadata(proof: &mut UniversalProofFormat, key: &str, value: Vec<u8>) {
        proof.add_metadata(key, value);
    }

    /// Get metadata from a universal proof
    pub fn get_metadata<'a>(proof: &'a UniversalProofFormat, key: &str) -> Option<&'a Vec<u8>> {
        proof.get_metadata(key)
    }

    /// Add context data to a universal proof
    pub fn add_context_data(proof: &mut UniversalProofFormat, key: &str, value: Vec<u8>) {
        proof.add_context_data(key, value);
    }

    /// Get context data from a universal proof
    pub fn get_context_data<'a>(proof: &'a UniversalProofFormat, key: &str) -> Option<&'a Vec<u8>> {
        proof.get_context_data(key)
    }
}

/// Serialization utilities for proofs (snipped for brevity)
pub struct ProofSerialization;
// Implement serialization methods here...
