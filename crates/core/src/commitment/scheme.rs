// File: crates/core/src/commitment/scheme.rs

use std::fmt::Debug;
use crate::commitment::identifiers::SchemeIdentifier;
use std::collections::HashMap;

/// Selector for addressing elements in a commitment
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// Index-based position (for ordered commitments like Merkle trees)
    Position(usize),
    /// Key-based selector (for map-like commitments)
    Key(Vec<u8>),
    /// Predicate-based selector (for advanced schemes)
    Predicate(Vec<u8>), // Serialized predicate
    /// No selector (for single-value commitments)
    None,
}

/// Context for proof verification
#[derive(Debug, Clone, Default)]
pub struct ProofContext {
    /// Additional data for verification
    pub data: HashMap<String, Vec<u8>>,
}

impl ProofContext {
    /// Create a new empty proof context
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    /// Add data to the context
    pub fn add_data(&mut self, key: &str, value: Vec<u8>) {
        self.data.insert(key.to_string(), value);
    }

    /// Get data from the context
    pub fn get_data(&self, key: &str) -> Option<&Vec<u8>> {
        self.data.get(key)
    }
}

/// Core trait for all commitment schemes
pub trait CommitmentScheme: Debug + Send + Sync + 'static {
    /// The type of commitment produced
    type Commitment: AsRef<[u8]> + Clone + Send + Sync + 'static;

    /// The type of proof for this commitment scheme
    type Proof: Clone + Send + Sync + 'static;

    /// The type of values this scheme commits to
    type Value: AsRef<[u8]> + Clone + Send + Sync + 'static;

    /// Commit to a vector of values
    fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment;

    /// Create a proof for a specific selector and value
    fn create_proof(&self, selector: &Selector, value: &Self::Value)
        -> Result<Self::Proof, String>;

    /// Verify a proof against a commitment
    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        selector: &Selector,
        value: &Self::Value,
        context: &ProofContext,
    ) -> bool;

    /// Get scheme identifier
    fn scheme_id() -> SchemeIdentifier;

    /// Create a position-based proof (convenience method)
    fn create_proof_at_position(
        &self,
        position: usize,
        value: &Self::Value,
    ) -> Result<Self::Proof, String> {
        self.create_proof(&Selector::Position(position), value)
    }

    /// Create a key-based proof (convenience method)
    fn create_proof_for_key(&self, key: &[u8], value: &Self::Value) -> Result<Self::Proof, String> {
        self.create_proof(&Selector::Key(key.to_vec()), value)
    }

    /// Verify a position-based proof (convenience method)
    fn verify_at_position(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        position: usize,
        value: &Self::Value,
    ) -> bool {
        self.verify(
            commitment,
            proof,
            &Selector::Position(position),
            value,
            &ProofContext::default(),
        )
    }

    /// Verify a key-based proof (convenience method)
    fn verify_for_key(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &Self::Value,
    ) -> bool {
        self.verify(
            commitment,
            proof,
            &Selector::Key(key.to_vec()),
            value,
            &ProofContext::default(),
        )
    }
}