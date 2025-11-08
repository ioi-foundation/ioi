// Path: crates/api/src/state/proof.rs
//! Defines the `ProofProvider` trait for generating and verifying state proofs.

use crate::state::VerifiableState;
use ioi_types::app::Membership;
use ioi_types::error::StateError;

/// A trait for any stateful data structure that can generate and verify
/// cryptographic proofs about its contents.
pub trait ProofProvider: VerifiableState {
    /// Creates a proof for a specific key in the current state.
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof>;

    /// Verifies that a `value` is proven by a `proof` to be associated with a `key`
    /// under a given `commitment`.
    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StateError>;

    /// Generates a proof for a key's membership or non-membership against a historical root.
    fn get_with_proof_at(
        &self,
        root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError>;

    /// Resolves a 32-byte anchor hash into the full, potentially variable-length commitment.
    fn commitment_from_anchor(&self, anchor: &[u8; 32]) -> Option<Self::Commitment>;

    /// Generates a proof for a key's membership or non-membership against a historical anchor.
    /// This method resolves the 32-byte anchor hash into the full, potentially variable-length
    /// state root commitment before generating the proof.
    fn get_with_proof_at_anchor(
        &self,
        anchor: &[u8; 32],
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        let commitment = self
            .commitment_from_anchor(anchor)
            .ok_or_else(|| StateError::UnknownAnchor(hex::encode(anchor)))?;
        self.get_with_proof_at(&commitment, key)
    }

    /// Converts raw bytes into the concrete Commitment type.
    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError>;

    /// Converts a concrete Commitment type into raw bytes for transport.
    fn commitment_to_bytes(&self, c: &Self::Commitment) -> Vec<u8>;
}

// Blanket implementation for Box<T>
impl<T: ProofProvider + ?Sized> ProofProvider for Box<T> {
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        (**self).create_proof(key)
    }
    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StateError> {
        (**self).verify_proof(commitment, proof, key, value)
    }
    fn get_with_proof_at(
        &self,
        root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        (**self).get_with_proof_at(root, key)
    }
    fn commitment_from_anchor(&self, anchor: &[u8; 32]) -> Option<Self::Commitment> {
        (**self).commitment_from_anchor(anchor)
    }
    fn get_with_proof_at_anchor(
        &self,
        anchor: &[u8; 32],
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        (**self).get_with_proof_at_anchor(anchor, key)
    }
    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError> {
        (**self).commitment_from_bytes(bytes)
    }
    fn commitment_to_bytes(&self, c: &Self::Commitment) -> Vec<u8> {
        (**self).commitment_to_bytes(c)
    }
}