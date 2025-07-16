//! Dilithium signature algorithm (using MLDSA implementation)
//!
use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{KeyPair, PrivateKey, PublicKey, Signature};
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_traits::sign::DetachedSignature;
use pqcrypto_traits::sign::SecretKey;
// Import with an alias to avoid the conflict
use pqcrypto_traits::sign::PublicKey as PQPublicKey;

/// Dilithium signature scheme
pub struct DilithiumScheme {
    /// Security level
    level: SecurityLevel,
}

/// Dilithium key pair
pub struct DilithiumKeyPair {
    /// Public key
    public_key: DilithiumPublicKey,
    /// Private key
    private_key: DilithiumPrivateKey,
}

/// Dilithium public key
pub struct DilithiumPublicKey(Vec<u8>);

/// Dilithium private key
pub struct DilithiumPrivateKey(Vec<u8>);

/// Dilithium signature
pub struct DilithiumSignature(Vec<u8>);

impl DilithiumScheme {
    /// Create a new Dilithium scheme with the specified security level
    pub fn new(level: SecurityLevel) -> Self {
        Self { level }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> DilithiumKeyPair {
        match self.level {
            SecurityLevel::Level2 => {
                let (pk, sk) = dilithium2::keypair();
                DilithiumKeyPair {
                    public_key: DilithiumPublicKey(pk.as_bytes().to_vec()),
                    private_key: DilithiumPrivateKey(sk.as_bytes().to_vec()),
                }
            }
            SecurityLevel::Level3 => {
                let (pk, sk) = dilithium3::keypair();
                DilithiumKeyPair {
                    public_key: DilithiumPublicKey(pk.as_bytes().to_vec()),
                    private_key: DilithiumPrivateKey(sk.as_bytes().to_vec()),
                }
            }
            SecurityLevel::Level5 => {
                let (pk, sk) = dilithium5::keypair();
                DilithiumKeyPair {
                    public_key: DilithiumPublicKey(pk.as_bytes().to_vec()),
                    private_key: DilithiumPrivateKey(sk.as_bytes().to_vec()),
                }
            }
            _ => {
                // Default to Level2 for any other security level
                let (pk, sk) = dilithium2::keypair();
                DilithiumKeyPair {
                    public_key: DilithiumPublicKey(pk.as_bytes().to_vec()),
                    private_key: DilithiumPrivateKey(sk.as_bytes().to_vec()),
                }
            }
        }
    }

    /// Sign a message
    pub fn sign(&self, private_key: &DilithiumPrivateKey, message: &[u8]) -> DilithiumSignature {
        match self.level {
            SecurityLevel::Level2 => {
                let sk = dilithium2::SecretKey::from_bytes(&private_key.0).unwrap();
                let signature = dilithium2::detached_sign(message, &sk);
                DilithiumSignature(signature.as_bytes().to_vec())
            }
            SecurityLevel::Level3 => {
                let sk = dilithium3::SecretKey::from_bytes(&private_key.0).unwrap();
                let signature = dilithium3::detached_sign(message, &sk);
                DilithiumSignature(signature.as_bytes().to_vec())
            }
            SecurityLevel::Level5 => {
                let sk = dilithium5::SecretKey::from_bytes(&private_key.0).unwrap();
                let signature = dilithium5::detached_sign(message, &sk);
                DilithiumSignature(signature.as_bytes().to_vec())
            }
            _ => {
                // Default to Level2 for any other security level
                let sk = dilithium2::SecretKey::from_bytes(&private_key.0).unwrap();
                let signature = dilithium2::detached_sign(message, &sk);
                DilithiumSignature(signature.as_bytes().to_vec())
            }
        }
    }

    /// Verify a signature
    pub fn verify(
        &self,
        public_key: &DilithiumPublicKey,
        message: &[u8],
        signature: &DilithiumSignature,
    ) -> bool {
        match self.level {
            SecurityLevel::Level2 => {
                let pk = dilithium2::PublicKey::from_bytes(&public_key.0).unwrap();
                let sig = dilithium2::DetachedSignature::from_bytes(&signature.0).unwrap();
                dilithium2::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            SecurityLevel::Level3 => {
                let pk = dilithium3::PublicKey::from_bytes(&public_key.0).unwrap();
                let sig = dilithium3::DetachedSignature::from_bytes(&signature.0).unwrap();
                dilithium3::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            SecurityLevel::Level5 => {
                let pk = dilithium5::PublicKey::from_bytes(&public_key.0).unwrap();
                let sig = dilithium5::DetachedSignature::from_bytes(&signature.0).unwrap();
                dilithium5::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            _ => {
                // Default to Level2 for any other security level
                let pk = dilithium2::PublicKey::from_bytes(&public_key.0).unwrap();
                let sig = dilithium2::DetachedSignature::from_bytes(&signature.0).unwrap();
                dilithium2::verify_detached_signature(&sig, message, &pk).is_ok()
            }
        }
    }
}

impl KeyPair for DilithiumKeyPair {
    type PublicKey = DilithiumPublicKey;
    type PrivateKey = DilithiumPrivateKey;
    type Signature = DilithiumSignature;

    fn public_key(&self) -> Self::PublicKey {
        DilithiumPublicKey(self.public_key.0.clone())
    }

    fn private_key(&self) -> Self::PrivateKey {
        DilithiumPrivateKey(self.private_key.0.clone())
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        // Infer the security level from the private key size
        match self.private_key.0.len() {
            2560 => {
                // Dilithium2 / MLDSA44
                let sk = dilithium2::SecretKey::from_bytes(&self.private_key.0).unwrap();
                let signature = dilithium2::detached_sign(message, &sk);
                DilithiumSignature(signature.as_bytes().to_vec())
            }
            4032 => {
                // Dilithium3 / MLDSA65
                let sk = dilithium3::SecretKey::from_bytes(&self.private_key.0).unwrap();
                let signature = dilithium3::detached_sign(message, &sk);
                DilithiumSignature(signature.as_bytes().to_vec())
            }
            4896 => {
                // Dilithium5 / MLDSA87
                let sk = dilithium5::SecretKey::from_bytes(&self.private_key.0).unwrap();
                let signature = dilithium5::detached_sign(message, &sk);
                DilithiumSignature(signature.as_bytes().to_vec())
            }
            _ => {
                // Default to Dilithium2
                let sk = dilithium2::SecretKey::from_bytes(&self.private_key.0).unwrap();
                let signature = dilithium2::detached_sign(message, &sk);
                DilithiumSignature(signature.as_bytes().to_vec())
            }
        }
    }
}

impl PublicKey for DilithiumPublicKey {
    type Signature = DilithiumSignature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        // Infer the security level from the public key size
        match self.0.len() {
            1312 => {
                // Dilithium2 / MLDSA44
                let pk = dilithium2::PublicKey::from_bytes(&self.0).unwrap();
                let sig = dilithium2::DetachedSignature::from_bytes(&signature.0).unwrap();
                dilithium2::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            1952 => {
                // Dilithium3 / MLDSA65
                let pk = dilithium3::PublicKey::from_bytes(&self.0).unwrap();
                let sig = dilithium3::DetachedSignature::from_bytes(&signature.0).unwrap();
                dilithium3::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            2592 => {
                // Dilithium5 / MLDSA87
                let pk = dilithium5::PublicKey::from_bytes(&self.0).unwrap();
                let sig = dilithium5::DetachedSignature::from_bytes(&signature.0).unwrap();
                dilithium5::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            _ => {
                // Default to Dilithium2
                let pk = dilithium2::PublicKey::from_bytes(&self.0).unwrap();
                let sig = dilithium2::DetachedSignature::from_bytes(&signature.0).unwrap();
                dilithium2::verify_detached_signature(&sig, message, &pk).is_ok()
            }
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(DilithiumPublicKey(bytes.to_vec()))
    }
}

impl PrivateKey for DilithiumPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(DilithiumPrivateKey(bytes.to_vec()))
    }
}

impl Signature for DilithiumSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(DilithiumSignature(bytes.to_vec()))
    }
}

#[cfg(test)]
mod tests;
