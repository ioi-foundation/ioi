//! Traditional cryptography interfaces

/// Key pair trait
pub trait KeyPair {
    /// Public key type
    type PublicKey: PublicKey<Signature = Self::Signature>;
    
    /// Private key type
    type PrivateKey: PrivateKey;
    
    /// Signature type
    type Signature: Signature;
    
    /// Get the public key
    fn public_key(&self) -> Self::PublicKey;
    
    /// Get the private key
    fn private_key(&self) -> Self::PrivateKey;
    
    /// Sign a message
    fn sign(&self, message: &[u8]) -> Self::Signature;
}

/// Public key trait
pub trait PublicKey {
    /// Signature type
    type Signature: Signature;
    
    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool;
    
    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Create from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, String> where Self: Sized;
}

/// Private key trait
pub trait PrivateKey {
    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Create from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, String> where Self: Sized;
}

/// Signature trait
pub trait Signature {
    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8>;
    
    /// Create from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, String> where Self: Sized;
}
