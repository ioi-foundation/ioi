//! Definition of the StateTree trait

/// Generic state tree operations
pub trait StateTree {
    /// The commitment type this tree uses
    type Commitment;
    
    /// The proof type this tree uses
    type Proof;

    /// Insert a key-value pair
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), String>;
    
    /// Get a value by key
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    
    /// Delete a key-value pair
    fn delete(&mut self, key: &[u8]) -> Result<(), String>;
    
    /// Get the root commitment of the tree
    fn root_commitment(&self) -> Self::Commitment;
    
    /// Create a proof for a specific key
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof>;
    
    /// Verify a proof against the tree's root commitment
    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8]
    ) -> bool;
    
    /// Get the commitment scheme of this tree
    fn commitment_scheme(&self) -> &dyn std::any::Any;
}
