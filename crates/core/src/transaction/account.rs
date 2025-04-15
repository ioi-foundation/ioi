//! Account-specific trait definitions

/// Account transaction traits
pub trait AccountTransaction {
    /// Get transaction ID
    fn txid(&self) -> &[u8];
    
    /// Get sender
    fn sender(&self) -> &[u8];
    
    /// Get receiver
    fn receiver(&self) -> &[u8];
    
    /// Get value
    fn value(&self) -> u64;
    
    /// Get nonce
    fn nonce(&self) -> u64;
    
    /// Get signature
    fn signature(&self) -> &[u8];
}
