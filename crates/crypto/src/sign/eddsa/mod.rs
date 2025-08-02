// Path: crates/crypto/src/sign/eddsa/mod.rs
//! Implementation of elliptic curve cryptography using dcrypt

use depin_sdk_api::crypto::{SerializableKey, Signature, SigningKey, SigningKeyPair, VerifyingKey};
use dcrypt::api::Signature as SignatureTrait;
use rand::rngs::OsRng;

// Import dcrypt Ed25519 module with module qualification
use dcrypt::sign::traditional::eddsa;

/// Ed25519 key pair implementation
pub struct Ed25519KeyPair {
    /// Public verification key
    public_key: eddsa::Ed25519PublicKey,
    /// Private signing key
    secret_key: eddsa::Ed25519SecretKey,
}

/// Ed25519 signature implementation
pub struct Ed25519Signature(eddsa::Ed25519Signature);

/// Ed25519 public key implementation
pub struct Ed25519PublicKey(eddsa::Ed25519PublicKey);

/// Ed25519 private key implementation
pub struct Ed25519PrivateKey(eddsa::Ed25519SecretKey);

impl Ed25519KeyPair {
    /// Generate a new Ed25519 key pair
    pub fn generate() -> Self {
        let mut rng = OsRng;

        // Generate key pair using dcrypt
        let (public_key, secret_key) = eddsa::Ed25519::keypair(&mut rng)
            .expect("Failed to generate Ed25519 key pair");

        Self {
            public_key,
            secret_key,
        }
    }

    /// Create from an existing private key
    pub fn from_private_key(private_key: &Ed25519PrivateKey) -> Self {
        let secret_key = private_key.0.clone();

        // Use the helper method to derive public key
        let public_key = secret_key
            .public_key()
            .expect("Failed to derive public key from secret key");

        Self {
            public_key,
            secret_key,
        }
    }
}

impl SigningKeyPair for Ed25519KeyPair {
    type PublicKey = Ed25519PublicKey;
    type PrivateKey = Ed25519PrivateKey;
    type Signature = Ed25519Signature;

    fn public_key(&self) -> Self::PublicKey {
        Ed25519PublicKey(self.public_key.clone())
    }

    fn private_key(&self) -> Self::PrivateKey {
        Ed25519PrivateKey(self.secret_key.clone())
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let signature = eddsa::Ed25519::sign(message, &self.secret_key)
            .expect("Failed to sign message");
        Ed25519Signature(signature)
    }
}

impl VerifyingKey for Ed25519PublicKey {
    type Signature = Ed25519Signature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        eddsa::Ed25519::verify(message, &signature.0, &self.0).is_ok()
    }
}

impl SerializableKey for Ed25519PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        eddsa::Ed25519PublicKey::from_bytes(bytes)
            .map(Ed25519PublicKey)
            .map_err(|e| format!("Failed to parse public key: {e:?}"))
    }
}

impl SigningKey for Ed25519PrivateKey {
    type Signature = Ed25519Signature;

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let signature = eddsa::Ed25519::sign(message, &self.0)
            .expect("Failed to sign message");
        Ed25519Signature(signature)
    }
}

impl SerializableKey for Ed25519PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        // Export just the seed (32 bytes)
        self.0.seed().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err("Invalid private key length: expected 32 bytes".to_string());
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(bytes);

        // Use the from_seed method
        eddsa::Ed25519SecretKey::from_seed(&seed)
            .map(Ed25519PrivateKey)
            .map_err(|e| format!("Failed to create secret key from seed: {e:?}"))
    }
}

impl SerializableKey for Ed25519Signature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        eddsa::Ed25519Signature::from_bytes(bytes)
            .map(Ed25519Signature)
            .map_err(|e| format!("Failed to parse signature: {e:?}"))
    }
}

impl Signature for Ed25519Signature {}

// Additional Ed25519-specific functionality
impl Ed25519Signature {
    /// Get the raw signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0 .0 // Access the inner array through the public field
    }
}

impl Ed25519PublicKey {
    /// Get the raw public key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0 .0 // Access the inner array through the public field
    }

    /// Construct from dcrypt public key
    pub fn from_dcrypt_key(key: eddsa::Ed25519PublicKey) -> Self {
        Self(key)
    }
}

impl Ed25519PrivateKey {
    /// Get the raw private key seed bytes (32 bytes)
    pub fn as_bytes(&self) -> &[u8] {
        self.0.seed()
    }

    /// Construct from dcrypt secret key
    pub fn from_dcrypt_key(key: eddsa::Ed25519SecretKey) -> Self {
        Self(key)
    }

    /// Get the public key corresponding to this private key
    pub fn public_key(&self) -> Result<Ed25519PublicKey, String> {
        self.0
            .public_key()
            .map(Ed25519PublicKey)
            .map_err(|e| format!("Failed to derive public key: {e:?}"))
    }
}

#[cfg(test)]
mod tests;