// Path: crates/api/src/crypto/mod.rs
//! Defines unified traits for cryptographic primitives.

use crate::error::CryptoError;

/// A trait for any key that can be serialized to and from bytes.
pub trait SerializableKey {
    /// Converts the key to a byte vector.
    fn to_bytes(&self) -> Vec<u8>;

    /// Creates a key from a byte slice.
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>
    where
        Self: Sized;
}

/// A trait for a key pair used in a signature algorithm.
pub trait SigningKeyPair {
    /// The public key type used for verification.
    type PublicKey: VerifyingKey<Signature = Self::Signature>;
    /// The private key type used for signing.
    type PrivateKey: SigningKey<Signature = Self::Signature>;
    /// The signature type produced.
    type Signature: Signature;

    /// Gets the public key.
    fn public_key(&self) -> Self::PublicKey;
    /// Gets the private key.
    fn private_key(&self) -> Self::PrivateKey;
    /// Signs a message with the private key.
    fn sign(&self, message: &[u8]) -> Result<Self::Signature, CryptoError>;
}

/// A trait for a public key used for signature verification.
pub trait VerifyingKey: SerializableKey {
    /// The signature type that this key can verify.
    type Signature: Signature;
    /// Verifies a signature against a message.
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<(), CryptoError>;
}

/// A trait for a private key used for signing operations.
pub trait SigningKey: SerializableKey {
    /// The signature type that this key produces.
    type Signature: Signature;
    /// Signs a message.
    fn sign(&self, message: &[u8]) -> Result<Self::Signature, CryptoError>;
}

/// A marker trait for a cryptographic signature.
pub trait Signature: SerializableKey {}

/// A trait for a key pair used in a key encapsulation mechanism (KEM).
pub trait KemKeyPair {
    /// The public key type used for encapsulation.
    type PublicKey: EncapsulationKey;
    /// The private key type used for decapsulation.
    type PrivateKey: DecapsulationKey;

    /// Gets the public key.
    fn public_key(&self) -> Self::PublicKey;
    /// Gets the private key.
    fn private_key(&self) -> Self::PrivateKey;
}

/// A trait for a public key used for encapsulation.
pub trait EncapsulationKey: SerializableKey {}

/// A trait for a private key used for decapsulation.
pub trait DecapsulationKey: SerializableKey {}

/// A trait for a key encapsulation mechanism (KEM).
pub trait KeyEncapsulation {
    /// The key pair type for this KEM.
    type KeyPair: KemKeyPair<PublicKey = Self::PublicKey, PrivateKey = Self::PrivateKey>;
    /// The public key type for this KEM.
    type PublicKey: EncapsulationKey;
    /// The private key type for this KEM.
    type PrivateKey: DecapsulationKey;
    /// The encapsulated data type produced by this KEM.
    type Encapsulated: Encapsulated;

    /// Generates a new key pair.
    fn generate_keypair(&self) -> Result<Self::KeyPair, CryptoError>;
    /// Encapsulates a shared secret using a public key.
    fn encapsulate(&self, public_key: &Self::PublicKey) -> Result<Self::Encapsulated, CryptoError>;
    /// Decapsulates a shared secret using a private key.
    fn decapsulate(
        &self,
        private_key: &Self::PrivateKey,
        encapsulated: &Self::Encapsulated,
    ) -> Result<Vec<u8>, CryptoError>;
}

/// A trait for the result of a KEM encapsulation.
pub trait Encapsulated: SerializableKey {
    /// Gets the ciphertext component of the encapsulated data.
    fn ciphertext(&self) -> &[u8];
    /// Gets the shared secret component of the encapsulated data.
    fn shared_secret(&self) -> &[u8];
}