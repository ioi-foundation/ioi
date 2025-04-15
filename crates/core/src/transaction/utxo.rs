//! UTXO-specific trait definitions

/// UTXO transaction traits
pub trait UTXOTransaction {
    /// Get transaction ID
    fn txid(&self) -> &[u8];
    
    /// Get inputs
    fn inputs(&self) -> &[Self::Input];
    
    /// Get outputs
    fn outputs(&self) -> &[Self::Output];
    
    /// Input type
    type Input;
    
    /// Output type
    type Output;
}
