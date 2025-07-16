// crates/crypto/src/traditional/elliptic/mod.rs
//! Implementation of elliptic curve cryptography

use depin_sdk_core::crypto::{KeyPair, PrivateKey, PublicKey, Signature};
use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};

/// Ed25519 key pair implementation
pub struct Ed25519KeyPair {
    /// Internal signing key
    signing_key: SigningKey,
    /// Public verification key
    verifying_key: VerifyingKey,
}

/// Ed25519 signature implementation
pub struct Ed25519Signature(EdSignature);

/// Ed25519 public key implementation
pub struct Ed25519PublicKey(VerifyingKey);

/// Ed25519 private key implementation
pub struct Ed25519PrivateKey(SigningKey);

impl Ed25519KeyPair {
    /// Generate a new Ed25519 key pair
    pub fn generate() -> Self {
        // Generate a random seed
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);

        // Create a signing key from the random seed
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Create from an existing private key
    pub fn from_private_key(private_key: &Ed25519PrivateKey) -> Self {
        let signing_key = private_key.0.clone();
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }
}

impl KeyPair for Ed25519KeyPair {
    type PublicKey = Ed25519PublicKey;
    type PrivateKey = Ed25519PrivateKey;
    type Signature = Ed25519Signature;

    fn public_key(&self) -> Self::PublicKey {
        Ed25519PublicKey(self.verifying_key)
    }

    fn private_key(&self) -> Self::PrivateKey {
        Ed25519PrivateKey(self.signing_key.clone())
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let signature = self.signing_key.sign(message);
        Ed25519Signature(signature)
    }
}

impl PublicKey for Ed25519PublicKey {
    type Signature = Ed25519Signature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        self.0.verify(message, &signature.0).is_ok()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let bytes_array: [u8; 32] = bytes.try_into().map_err(|_| "Invalid length".to_string())?;

        VerifyingKey::from_bytes(&bytes_array)
            .map(Ed25519PublicKey)
            .map_err(|e| e.to_string())
    }
}

impl PrivateKey for Ed25519PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let bytes_array: [u8; 32] = bytes.try_into().map_err(|_| "Invalid length".to_string())?;

        Ok(Ed25519PrivateKey(SigningKey::from_bytes(&bytes_array)))
    }
}

impl Signature for Ed25519Signature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let bytes_array: [u8; 64] = bytes.try_into().map_err(|_| "Invalid length".to_string())?;

        Ok(Ed25519Signature(EdSignature::from_bytes(&bytes_array)))
    }
}

// Additional Ed25519-specific functionality
impl Ed25519Signature {
    /// Get the raw signature bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl Ed25519PublicKey {
    /// Get the raw public key bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Construct from an existing verification key
    pub fn from_verifying_key(key: VerifyingKey) -> Self {
        Self(key)
    }
}

impl Ed25519PrivateKey {
    /// Get the raw private key bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Construct from an existing signing key
    pub fn from_signing_key(key: SigningKey) -> Self {
        Self(key)
    }
}

#[cfg(test)]
pub mod tests;
