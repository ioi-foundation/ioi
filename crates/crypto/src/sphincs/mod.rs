// crates/crypto/src/sphincs/mod.rs
//! SPHINCS+ hash-based signature algorithm implementation

use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{KeyPair, PrivateKey, PublicKey, Signature};
use pqcrypto_sphincsplus::{sphincssha2128fsimple, sphincssha2256fsimple};
use pqcrypto_traits::sign::DetachedSignature;
use pqcrypto_traits::sign::SecretKey;
// Import with an alias to avoid the conflict
use pqcrypto_traits::sign::PublicKey as PQPublicKey;

/// SPHINCS+ signature scheme
pub struct SphincsScheme {
    /// Security level
    level: SecurityLevel,
}

/// SPHINCS+ key pair
pub struct SphincsKeyPair {
    /// Public key
    public_key: SphincsPublicKey,
    /// Private key
    private_key: SphincsPrivateKey,
}

/// SPHINCS+ public key
pub struct SphincsPublicKey(Vec<u8>);

/// SPHINCS+ private key
pub struct SphincsPrivateKey(Vec<u8>);

/// SPHINCS+ signature
pub struct SphincsSignature(Vec<u8>);

impl SphincsScheme {
    /// Create a new SPHINCS+ scheme with the specified security level
    pub fn new(level: SecurityLevel) -> Self {
        Self { level }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> SphincsKeyPair {
        match self.level {
            SecurityLevel::Level1 => {
                let (pk, sk) = sphincssha2128fsimple::keypair();
                SphincsKeyPair {
                    public_key: SphincsPublicKey(pk.as_bytes().to_vec()),
                    private_key: SphincsPrivateKey(sk.as_bytes().to_vec()),
                }
            }
            SecurityLevel::Level5 => {
                let (pk, sk) = sphincssha2256fsimple::keypair();
                SphincsKeyPair {
                    public_key: SphincsPublicKey(pk.as_bytes().to_vec()),
                    private_key: SphincsPrivateKey(sk.as_bytes().to_vec()),
                }
            }
            _ => {
                // Default to Level1 for other security levels
                let (pk, sk) = sphincssha2128fsimple::keypair();
                SphincsKeyPair {
                    public_key: SphincsPublicKey(pk.as_bytes().to_vec()),
                    private_key: SphincsPrivateKey(sk.as_bytes().to_vec()),
                }
            }
        }
    }

    /// Sign a message
    pub fn sign(&self, private_key: &SphincsPrivateKey, message: &[u8]) -> SphincsSignature {
        match self.level {
            SecurityLevel::Level1 => {
                let sk = sphincssha2128fsimple::SecretKey::from_bytes(&private_key.0).unwrap();
                let signature = sphincssha2128fsimple::detached_sign(message, &sk);
                SphincsSignature(signature.as_bytes().to_vec())
            }
            SecurityLevel::Level5 => {
                let sk = sphincssha2256fsimple::SecretKey::from_bytes(&private_key.0).unwrap();
                let signature = sphincssha2256fsimple::detached_sign(message, &sk);
                SphincsSignature(signature.as_bytes().to_vec())
            }
            _ => {
                // Default to Level1 for other security levels
                let sk = sphincssha2128fsimple::SecretKey::from_bytes(&private_key.0).unwrap();
                let signature = sphincssha2128fsimple::detached_sign(message, &sk);
                SphincsSignature(signature.as_bytes().to_vec())
            }
        }
    }

    /// Verify a signature
    pub fn verify(
        &self,
        public_key: &SphincsPublicKey,
        message: &[u8],
        signature: &SphincsSignature,
    ) -> bool {
        match self.level {
            SecurityLevel::Level1 => {
                let pk = sphincssha2128fsimple::PublicKey::from_bytes(&public_key.0).unwrap();
                let sig =
                    sphincssha2128fsimple::DetachedSignature::from_bytes(&signature.0).unwrap();
                sphincssha2128fsimple::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            SecurityLevel::Level5 => {
                let pk = sphincssha2256fsimple::PublicKey::from_bytes(&public_key.0).unwrap();
                let sig =
                    sphincssha2256fsimple::DetachedSignature::from_bytes(&signature.0).unwrap();
                sphincssha2256fsimple::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            _ => {
                // Default to Level1 for other security levels
                let pk = sphincssha2128fsimple::PublicKey::from_bytes(&public_key.0).unwrap();
                let sig =
                    sphincssha2128fsimple::DetachedSignature::from_bytes(&signature.0).unwrap();
                sphincssha2128fsimple::verify_detached_signature(&sig, message, &pk).is_ok()
            }
        }
    }
}

impl KeyPair for SphincsKeyPair {
    type PublicKey = SphincsPublicKey;
    type PrivateKey = SphincsPrivateKey;
    type Signature = SphincsSignature;

    fn public_key(&self) -> Self::PublicKey {
        SphincsPublicKey(self.public_key.0.clone())
    }

    fn private_key(&self) -> Self::PrivateKey {
        SphincsPrivateKey(self.private_key.0.clone())
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        // Infer the security level from the private key size
        match self.private_key.0.len() {
            64 => {
                // SPHINCS+ 128-bit
                let sk = sphincssha2128fsimple::SecretKey::from_bytes(&self.private_key.0).unwrap();
                let signature = sphincssha2128fsimple::detached_sign(message, &sk);
                SphincsSignature(signature.as_bytes().to_vec())
            }
            128 => {
                // SPHINCS+ 256-bit
                let sk = sphincssha2256fsimple::SecretKey::from_bytes(&self.private_key.0).unwrap();
                let signature = sphincssha2256fsimple::detached_sign(message, &sk);
                SphincsSignature(signature.as_bytes().to_vec())
            }
            _ => {
                // Default to SPHINCS+ 128-bit for unknown key sizes
                let sk = sphincssha2128fsimple::SecretKey::from_bytes(&self.private_key.0).unwrap();
                let signature = sphincssha2128fsimple::detached_sign(message, &sk);
                SphincsSignature(signature.as_bytes().to_vec())
            }
        }
    }
}

impl PublicKey for SphincsPublicKey {
    type Signature = SphincsSignature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        // Infer the security level from the public key size
        match self.0.len() {
            32 => {
                // SPHINCS+ 128-bit
                let pk = sphincssha2128fsimple::PublicKey::from_bytes(&self.0).unwrap();
                let sig =
                    sphincssha2128fsimple::DetachedSignature::from_bytes(&signature.0).unwrap();
                sphincssha2128fsimple::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            64 => {
                // SPHINCS+ 256-bit
                let pk = sphincssha2256fsimple::PublicKey::from_bytes(&self.0).unwrap();
                let sig =
                    sphincssha2256fsimple::DetachedSignature::from_bytes(&signature.0).unwrap();
                sphincssha2256fsimple::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            _ => {
                // Default to SPHINCS+ 128-bit for unknown key sizes
                let pk = sphincssha2128fsimple::PublicKey::from_bytes(&self.0).unwrap();
                let sig =
                    sphincssha2128fsimple::DetachedSignature::from_bytes(&signature.0).unwrap();
                sphincssha2128fsimple::verify_detached_signature(&sig, message, &pk).is_ok()
            }
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(SphincsPublicKey(bytes.to_vec()))
    }
}

impl PrivateKey for SphincsPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(SphincsPrivateKey(bytes.to_vec()))
    }
}

impl Signature for SphincsSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(SphincsSignature(bytes.to_vec()))
    }
}

#[cfg(test)]
pub mod tests;
