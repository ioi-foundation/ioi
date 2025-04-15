//! Definition of the StateManager trait

use crate::commitment::CommitmentScheme;

/// State manager trait for handling state operations
pub trait StateManager<CS: CommitmentScheme> {
    /// Get a value by key
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    
    /// Set a value for a key
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), String>;
    
    /// Delete a key-value pair
    fn delete(&mut self, key: &[u8]) -> Result<(), String>;
    
    /// Get the current root commitment
    fn root_commitment(&self) -> CS::Commitment;
    
    /// Create a proof for a specific key
    fn create_proof(&self, key: &[u8]) -> Option<CS::Proof>;
    
    /// Verify a proof against the root commitment
    fn verify_proof(
        &self,
        commitment: &CS::Commitment,
        proof: &CS::Proof,
        key: &[u8],
        value: &[u8]
    ) -> bool;
}
