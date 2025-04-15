//! Post-quantum cryptography interfaces

use crate::crypto::traditional::{KeyPair, PublicKey, PrivateKey, Signature};

/// Key encapsulation mechanism trait
pub trait KeyEncapsulation {
    /// Key pair type
    type KeyPair: KeyPair<PublicKey = Self::PublicKey, PrivateKey = Self::PrivateKey>;
    
    /// Public key type
    type PublicKey: PublicKey;
    
    /// Private key type
    type PrivateKey: PrivateKey;
    
    /// Encapsulated key type
    type Encapsulated: Encapsulated;
    
    /// Encapsulate a shared secret using a public key
    fn encapsulate(&self, public_key: &Self::PublicKey) -> Self::Encapsulated;
    
    /// Decapsulate a shared secret using a private key
    fn decapsulate(&self, private_key: &Self::PrivateKey, encapsulated: &Self::Encapsulated) -> Option<Vec<u8>>;
}

/// Encapsulated key trait
pub trait Encapsulated {
    /// Get the ciphertext
    fn ciphertext(&self) -> &[u8];
    
    /// Get the shared secret
    fn shared_secret(&self) -> &[u8];
    
    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Create from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, String> where Self: Sized;
}
