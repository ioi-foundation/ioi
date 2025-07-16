// core/src/crypto/mod.rs
//! Cryptographic primitive interfaces
//!
//! This module provides trait definitions for both traditional and
//! post-quantum cryptographic primitives, creating a unified interface
//! for all cryptographic implementations.

#[cfg(test)]
mod tests;

/// Key pair trait - handles key generation and signing operations
pub trait KeyPair {
    /// Public key type associated with this key pair
    type PublicKey: PublicKey<Signature = Self::Signature>;

    /// Private key type associated with this key pair
    type PrivateKey: PrivateKey;

    /// Signature type produced by this key pair
    type Signature: Signature;

    /// Get the public key
    fn public_key(&self) -> Self::PublicKey;

    /// Get the private key
    fn private_key(&self) -> Self::PrivateKey;

    /// Sign a message
    fn sign(&self, message: &[u8]) -> Self::Signature;
}

/// Public key trait - handles verification operations
pub trait PublicKey {
    /// Signature type that this public key can verify
    type Signature: Signature;

    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool;

    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Create from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, String>
    where
        Self: Sized;
}

/// Private key trait - handles key serialization
pub trait PrivateKey {
    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Create from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, String>
    where
        Self: Sized;
}

/// Signature trait - handles signature serialization
pub trait Signature {
    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Create from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, String>
    where
        Self: Sized;
}

/// Key encapsulation mechanism trait for both traditional and post-quantum KEMs
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
    fn decapsulate(
        &self,
        private_key: &Self::PrivateKey,
        encapsulated: &Self::Encapsulated,
    ) -> Option<Vec<u8>>;
}

/// Encapsulated key trait for both traditional and post-quantum KEMs
pub trait Encapsulated {
    /// Get the ciphertext
    fn ciphertext(&self) -> &[u8];

    /// Get the shared secret
    fn shared_secret(&self) -> &[u8];

    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Create from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, String>
    where
        Self: Sized;
}
