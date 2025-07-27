// core/src/crypto/mod.rs
//! Cryptographic primitive interfaces
//!
//! This module provides trait definitions for both traditional and
//! post-quantum cryptographic primitives, creating a unified interface
//! for all cryptographic implementations.

// ============================================================================
// Common traits for all key types
// ============================================================================

/// Base trait for any key that can be serialized
pub trait SerializableKey {
    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Create from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, String>
    where
        Self: Sized;
}

// ============================================================================
// Signature-specific traits
// ============================================================================

/// Key pair trait for signature algorithms
pub trait SigningKeyPair {
    /// Public key type for verification
    type PublicKey: VerifyingKey<Signature = Self::Signature>;

    /// Private key type for signing
    type PrivateKey: SigningKey<Signature = Self::Signature>;

    /// Signature type produced
    type Signature: Signature;

    /// Get the public key
    fn public_key(&self) -> Self::PublicKey;

    /// Get the private key
    fn private_key(&self) -> Self::PrivateKey;

    /// Sign a message
    fn sign(&self, message: &[u8]) -> Self::Signature;
}

/// Public key trait for signature verification
pub trait VerifyingKey: SerializableKey {
    /// Signature type that this key can verify
    type Signature: Signature;

    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool;
}

/// Private key trait for signing operations
pub trait SigningKey: SerializableKey {
    /// Signature type that this key produces
    type Signature: Signature;

    /// Sign a message
    fn sign(&self, message: &[u8]) -> Self::Signature;
}

/// Signature trait
pub trait Signature: SerializableKey {
    // Signature-specific methods could go here
}

// ============================================================================
// KEM-specific traits
// ============================================================================

/// Key pair trait for key encapsulation mechanisms
pub trait KemKeyPair {
    /// Public key type for encapsulation
    type PublicKey: EncapsulationKey;

    /// Private key type for decapsulation
    type PrivateKey: DecapsulationKey;

    /// Get the public key
    fn public_key(&self) -> Self::PublicKey;

    /// Get the private key
    fn private_key(&self) -> Self::PrivateKey;
}

/// Public key trait for encapsulation
pub trait EncapsulationKey: SerializableKey {
    // Encapsulation-specific methods could go here
}

/// Private key trait for decapsulation
pub trait DecapsulationKey: SerializableKey {
    // Decapsulation-specific methods could go here
}

/// Key encapsulation mechanism trait
pub trait KeyEncapsulation {
    /// Key pair type
    type KeyPair: KemKeyPair<PublicKey = Self::PublicKey, PrivateKey = Self::PrivateKey>;

    /// Public key type
    type PublicKey: EncapsulationKey;

    /// Private key type
    type PrivateKey: DecapsulationKey;

    /// Encapsulated key type
    type Encapsulated: Encapsulated;

    /// Generate a new key pair
    fn generate_keypair(&self) -> Self::KeyPair;

    /// Encapsulate a shared secret using a public key
    fn encapsulate(&self, public_key: &Self::PublicKey) -> Self::Encapsulated;

    /// Decapsulate a shared secret using a private key
    fn decapsulate(
        &self,
        private_key: &Self::PrivateKey,
        encapsulated: &Self::Encapsulated,
    ) -> Option<Vec<u8>>;
}

/// Encapsulated key trait
pub trait Encapsulated: SerializableKey {
    /// Get the ciphertext
    fn ciphertext(&self) -> &[u8];

    /// Get the shared secret
    fn shared_secret(&self) -> &[u8];
}

#[cfg(test)]
mod tests;