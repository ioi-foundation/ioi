//! Definition of the UniversalProofFormat

use std::collections::HashMap;
use crate::commitment::SchemeIdentifier;

/// Universal proof format that can represent any commitment scheme's proof
pub struct UniversalProofFormat {
    /// Identifier of the commitment scheme that created this proof
    pub scheme_id: SchemeIdentifier,
    
    /// Version of the proof format
    pub format_version: u8,
    
    /// The serialized proof data
    pub proof_data: Vec<u8>,
    
    /// Additional metadata for the proof
    pub metadata: HashMap<String, Vec<u8>>,
    
    /// Key that this proof is for
    pub key: Vec<u8>,
    
    /// Value this proof is proving (if known)
    pub value: Option<Vec<u8>>,
}

impl UniversalProofFormat {
    /// Create a new universal proof format
    pub fn new(
        scheme_id: SchemeIdentifier,
        proof_data: Vec<u8>,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> Self {
        Self {
            scheme_id,
            format_version: 1,
            proof_data,
            metadata: HashMap::new(),
            key,
            value,
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
}
