//! Implementation of elliptic curve cryptography

use ed25519_dalek::{Keypair, Signer, Verifier, SigningKey, VerifyingKey, Signature as EdSignature};
use rand::rngs::OsRng;
use depin_sdk_core::crypto::{KeyPair, Signature, PublicKey, PrivateKey};

/// Ed25519 key pair
pub struct Ed25519KeyPair {
    /// Internal keypair
    keypair: Keypair,
}

/// Ed25519 signature
pub struct Ed25519Signature(EdSignature);

/// Ed25519 public key
pub struct Ed25519PublicKey(VerifyingKey);

/// Ed25519 private key
pub struct Ed25519PrivateKey(SigningKey);

impl Ed25519KeyPair {
    /// Generate a new key pair
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        Self { keypair }
    }
    
    /// Create from private key
    pub fn from_private_key(private_key: &Ed25519PrivateKey) -> Self {
        let keypair = Keypair::from_bytes(&private_key.to_bytes()).unwrap();
        Self { keypair }
    }
}

impl KeyPair for Ed25519KeyPair {
    type PublicKey = Ed25519PublicKey;
    type PrivateKey = Ed25519PrivateKey;
    type Signature = Ed25519Signature;
    
    fn public_key(&self) -> Self::PublicKey {
        Ed25519PublicKey(self.keypair.verifying_key())
    }
    
    fn private_key(&self) -> Self::PrivateKey {
        Ed25519PrivateKey(self.keypair.signing_key())
    }
    
    fn sign(&self, message: &[u8]) -> Self::Signature {
        let signature = self.keypair.sign(message);
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
        VerifyingKey::from_bytes(bytes.try_into().map_err(|_| "Invalid length".to_string())?)
            .map(Ed25519PublicKey)
            .map_err(|e| e.to_string())
    }
}

impl PrivateKey for Ed25519PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        SigningKey::from_bytes(bytes.try_into().map_err(|_| "Invalid length".to_string())?)
            .map(Ed25519PrivateKey)
            .map_err(|e| e.to_string())
    }
}

impl Signature for Ed25519Signature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        EdSignature::from_bytes(bytes.try_into().map_err(|_| "Invalid length".to_string())?)
            .map(Ed25519Signature)
            .map_err(|e| e.to_string())
    }
}
