//! Definition of the CommitmentScheme trait

use std::fmt::Debug;

use crate::commitment::identifiers::SchemeIdentifier;

/// Core trait for all commitment schemes
pub trait CommitmentScheme: Debug + Send + Sync + 'static {
    /// The type of commitment produced
    type Commitment: AsRef<[u8]> + Clone + Send + Sync + 'static;
    
    /// The type of proof for this commitment scheme
    type Proof: Clone + Send + Sync + 'static;

    /// Commit to a vector of values
    fn commit(&self, values: &[Option<Vec<u8>>]) -> Self::Commitment;
    
    /// Create a proof for a specific position and value
    fn create_proof(&self, position: usize, value: &[u8]) -> Result<Self::Proof, String>;
    
    /// Verify a proof against a commitment
    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        position: usize,
        value: &[u8]
    ) -> bool;
    
    /// Get scheme identifier
    fn scheme_id() -> SchemeIdentifier;
}
