// File: crates/core/src/state/manager.rs

use crate::error::StateError;

/// State manager interface for the DePIN SDK
///
/// The StateManager provides a higher-level interface for state operations,
/// potentially wrapping one or more state trees or other storage mechanisms.
/// It provides key-value access with optional commitment scheme capabilities.
pub trait StateManager {
    /// The commitment type this manager uses
    type Commitment;
    
    /// The proof type this manager uses
    type Proof;
    
    /// Get a value by key
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError>;
    
    /// Set a value for a key
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError>;
    
    /// Delete a key-value pair
    fn delete(&mut self, key: &[u8]) -> Result<(), StateError>;
    
    /// Set multiple key-value pairs in a single batch operation
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        // Default implementation applies updates one by one
        for (key, value) in updates {
            self.set(key, value)?;
        }
        Ok(())
    }
    
    /// Get multiple values by keys in a single batch operation
    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        // Default implementation retrieves values one by one
        let mut values = Vec::with_capacity(keys.len());
        for key in keys {
            values.push(self.get(key)?);
        }
        Ok(values)
    }
    
    /// Get the current root commitment
    ///
    /// # Returns
    /// * The current root commitment
    fn root_commitment(&self) -> Self::Commitment;
    
    /// Create a proof for a specific key
    ///
    /// # Arguments
    /// * `key` - The key to create a proof for
    ///
    /// # Returns
    /// * `Some(proof)` - If proof creation succeeded
    /// * `None` - If the key doesn't exist or proof creation isn't supported
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof>;
    
    /// Verify a proof against the root commitment
    ///
    /// # Arguments
    /// * `commitment` - The commitment to verify against
    /// * `proof` - The proof to verify
    /// * `key` - The key the proof is for
    /// * `value` - The value to verify
    ///
    /// # Returns
    /// * `true` - If the proof is valid
    /// * `false` - If the proof is invalid or verification isn't supported
    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8]
    ) -> bool;
}