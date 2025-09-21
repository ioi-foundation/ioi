// Path: crates/api/src/commitment/scheme.rs
//! Defines the core `CommitmentScheme` trait and related types.

use crate::commitment::identifiers::SchemeIdentifier;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

/// Defines the cryptographic methods for building a verifiable data structure,
/// such as a Merkle or Verkle tree.
pub trait CommitmentStructure {
    /// Creates a commitment for a leaf node from its key and value.
    fn commit_leaf(key: &[u8], value: &[u8]) -> Vec<u8>;

    /// Creates a commitment for an internal (branch) node from its children's commitments.
    fn commit_branch(left: &[u8], right: &[u8]) -> Vec<u8>;
}

/// Selects an element or set of elements within a commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum Selector {
    /// Selects by an index-based position (for ordered commitments like Merkle trees).
    // MODIFICATION: Changed usize to u64 for deterministic encoding.
    Position(u64),
    /// Selects by a key (for map-like commitments).
    Key(Vec<u8>),
    /// Selects by a predicate (for advanced, content-based schemes).
    Predicate(Vec<u8>), // Serialized predicate
    /// Represents a commitment to a single value where no selector is needed.
    None,
}

/// Provides additional context for proof verification.
#[derive(Debug, Clone, Default)]
pub struct ProofContext {
    /// A map of additional data to be used during verification.
    pub data: HashMap<String, Vec<u8>>,
}

impl ProofContext {
    /// Creates a new, empty proof context.
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    /// Adds data to the context.
    pub fn add_data(&mut self, key: &str, value: Vec<u8>) {
        self.data.insert(key.to_string(), value);
    }

    /// Gets data from the context.
    pub fn get_data(&self, key: &str) -> Option<&Vec<u8>> {
        self.data.get(key)
    }
}

/// The core trait for all commitment schemes.
pub trait CommitmentScheme: CommitmentStructure + Debug + Send + Sync + 'static {
    /// The type of commitment produced by this scheme.
    type Commitment: AsRef<[u8]> + Clone + Send + Sync + 'static;

    /// The type of proof for this commitment scheme.
    type Proof: Clone + Encode + Decode + Send + Sync + 'static;

    /// The type of values this scheme commits to.
    type Value: AsRef<[u8]> + Clone + Send + Sync + 'static;

    /// Commits to a vector of optional values.
    fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment;

    /// Creates a proof for a specific value identified by a selector.
    fn create_proof(&self, selector: &Selector, value: &Self::Value)
        -> Result<Self::Proof, String>;

    /// Verifies that a proof for a given value is valid for a given commitment.
    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        selector: &Selector,
        value: &Self::Value,
        context: &ProofContext,
    ) -> bool;

    /// Returns the unique identifier for this commitment scheme.
    fn scheme_id() -> SchemeIdentifier;

    /// A convenience method to create a position-based proof.
    // MODIFICATION: Changed usize to u64.
    fn create_proof_at_position(
        &self,
        position: u64,
        value: &Self::Value,
    ) -> Result<Self::Proof, String> {
        self.create_proof(&Selector::Position(position), value)
    }

    /// A convenience method to create a key-based proof.
    fn create_proof_for_key(&self, key: &[u8], value: &Self::Value) -> Result<Self::Proof, String> {
        self.create_proof(&Selector::Key(key.to_vec()), value)
    }

    /// A convenience method to verify a position-based proof.
    // MODIFICATION: Changed usize to u64.
    fn verify_at_position(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        position: u64,
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

    /// A convenience method to verify a key-based proof.
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
