// crates/crypto/src/kyber/mod.rs
//! Kyber key encapsulation mechanism

use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{
    Encapsulated, KeyEncapsulation, KeyPair, PrivateKey, PublicKey, Signature,
};
use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
use pqcrypto_traits::kem::{
    Ciphertext as PQCiphertext, PublicKey as PQPublicKey, SecretKey as PQSecretKey,
    SharedSecret as PQSharedSecret,
};
use std::any::Any;

/// Kyber key encapsulation mechanism
pub struct KyberKEM {
    /// Security level
    level: SecurityLevel,
}

/// Kyber key pair
pub struct KyberKeyPair {
    /// Public key
    public_key: KyberPublicKey,
    /// Private key
    private_key: KyberPrivateKey,
    /// Security level
    level: SecurityLevel,
}

/// Kyber public key
#[derive(Clone)]
pub struct KyberPublicKey {
    /// Raw bytes
    bytes: Vec<u8>,
    /// Security level
    level: SecurityLevel,
}

/// Kyber private key
#[derive(Clone)]
pub struct KyberPrivateKey {
    /// Raw bytes
    bytes: Vec<u8>,
    /// Security level
    level: SecurityLevel,
}

/// Kyber encapsulated key
pub struct KyberEncapsulated {
    /// Ciphertext
    ciphertext: Vec<u8>,
    /// Shared secret
    shared_secret: Vec<u8>,
    /// Security level
    level: SecurityLevel,
}

/// Kyber signature (placeholder since Kyber is a KEM)
pub struct KyberSignature(Vec<u8>);

impl KyberKEM {
    /// Create a new Kyber KEM with the specified security level
    pub fn new(level: SecurityLevel) -> Self {
        Self { level }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> KyberKeyPair {
        match self.level {
            SecurityLevel::Level1 => {
                // Kyber512
                let (pk, sk) = kyber512::keypair();
                KyberKeyPair {
                    public_key: KyberPublicKey {
                        bytes: pk.as_bytes().to_vec(),
                        level: self.level,
                    },
                    private_key: KyberPrivateKey {
                        bytes: sk.as_bytes().to_vec(),
                        level: self.level,
                    },
                    level: self.level,
                }
            }
            SecurityLevel::Level3 => {
                // Kyber768
                let (pk, sk) = kyber768::keypair();
                KyberKeyPair {
                    public_key: KyberPublicKey {
                        bytes: pk.as_bytes().to_vec(),
                        level: self.level,
                    },
                    private_key: KyberPrivateKey {
                        bytes: sk.as_bytes().to_vec(),
                        level: self.level,
                    },
                    level: self.level,
                }
            }
            SecurityLevel::Level5 => {
                // Kyber1024
                let (pk, sk) = kyber1024::keypair();
                KyberKeyPair {
                    public_key: KyberPublicKey {
                        bytes: pk.as_bytes().to_vec(),
                        level: self.level,
                    },
                    private_key: KyberPrivateKey {
                        bytes: sk.as_bytes().to_vec(),
                        level: self.level,
                    },
                    level: self.level,
                }
            }
            _ => {
                // Default to Kyber512 for any other security level
                let (pk, sk) = kyber512::keypair();
                KyberKeyPair {
                    public_key: KyberPublicKey {
                        bytes: pk.as_bytes().to_vec(),
                        level: SecurityLevel::Level1,
                    },
                    private_key: KyberPrivateKey {
                        bytes: sk.as_bytes().to_vec(),
                        level: SecurityLevel::Level1,
                    },
                    level: SecurityLevel::Level1,
                }
            }
        }
    }
}

impl KeyEncapsulation for KyberKEM {
    type KeyPair = KyberKeyPair;
    type PublicKey = KyberPublicKey;
    type PrivateKey = KyberPrivateKey;
    type Encapsulated = KyberEncapsulated;

    fn encapsulate(&self, public_key: &Self::PublicKey) -> Self::Encapsulated {
        match public_key.level {
            SecurityLevel::Level1 => {
                // Kyber512
                let pk = kyber512::PublicKey::from_bytes(&public_key.bytes)
                    .expect("Invalid Kyber512 public key");
                let (ss, ct) = kyber512::encapsulate(&pk);
                KyberEncapsulated {
                    ciphertext: ct.as_bytes().to_vec(),
                    shared_secret: ss.as_bytes().to_vec(),
                    level: SecurityLevel::Level1,
                }
            }
            SecurityLevel::Level3 => {
                // Kyber768
                let pk = kyber768::PublicKey::from_bytes(&public_key.bytes)
                    .expect("Invalid Kyber768 public key");
                let (ss, ct) = kyber768::encapsulate(&pk);
                KyberEncapsulated {
                    ciphertext: ct.as_bytes().to_vec(),
                    shared_secret: ss.as_bytes().to_vec(),
                    level: SecurityLevel::Level3,
                }
            }
            SecurityLevel::Level5 => {
                // Kyber1024
                let pk = kyber1024::PublicKey::from_bytes(&public_key.bytes)
                    .expect("Invalid Kyber1024 public key");
                let (ss, ct) = kyber1024::encapsulate(&pk);
                KyberEncapsulated {
                    ciphertext: ct.as_bytes().to_vec(),
                    shared_secret: ss.as_bytes().to_vec(),
                    level: SecurityLevel::Level5,
                }
            }
            _ => {
                // Default to Kyber512
                let pk = kyber512::PublicKey::from_bytes(&public_key.bytes)
                    .expect("Invalid Kyber512 public key");
                let (ss, ct) = kyber512::encapsulate(&pk);
                KyberEncapsulated {
                    ciphertext: ct.as_bytes().to_vec(),
                    shared_secret: ss.as_bytes().to_vec(),
                    level: SecurityLevel::Level1,
                }
            }
        }
    }

    fn decapsulate(
        &self,
        private_key: &Self::PrivateKey,
        encapsulated: &Self::Encapsulated,
    ) -> Option<Vec<u8>> {
        match private_key.level {
            SecurityLevel::Level1 => {
                // Kyber512
                let sk = kyber512::SecretKey::from_bytes(&private_key.bytes)
                    .expect("Invalid Kyber512 secret key");
                let ct = kyber512::Ciphertext::from_bytes(&encapsulated.ciphertext)
                    .expect("Invalid Kyber512 ciphertext");
                let ss = kyber512::decapsulate(&ct, &sk);
                Some(ss.as_bytes().to_vec())
            }
            SecurityLevel::Level3 => {
                // Kyber768
                let sk = kyber768::SecretKey::from_bytes(&private_key.bytes)
                    .expect("Invalid Kyber768 secret key");
                let ct = kyber768::Ciphertext::from_bytes(&encapsulated.ciphertext)
                    .expect("Invalid Kyber768 ciphertext");
                let ss = kyber768::decapsulate(&ct, &sk);
                Some(ss.as_bytes().to_vec())
            }
            SecurityLevel::Level5 => {
                // Kyber1024
                let sk = kyber1024::SecretKey::from_bytes(&private_key.bytes)
                    .expect("Invalid Kyber1024 secret key");
                let ct = kyber1024::Ciphertext::from_bytes(&encapsulated.ciphertext)
                    .expect("Invalid Kyber1024 ciphertext");
                let ss = kyber1024::decapsulate(&ct, &sk);
                Some(ss.as_bytes().to_vec())
            }
            _ => {
                // Default to Kyber512
                let sk = kyber512::SecretKey::from_bytes(&private_key.bytes)
                    .expect("Invalid Kyber512 secret key");
                let ct = kyber512::Ciphertext::from_bytes(&encapsulated.ciphertext)
                    .expect("Invalid Kyber512 ciphertext");
                let ss = kyber512::decapsulate(&ct, &sk);
                Some(ss.as_bytes().to_vec())
            }
        }
    }
}

impl KeyPair for KyberKeyPair {
    type PublicKey = KyberPublicKey;
    type PrivateKey = KyberPrivateKey;
    type Signature = KyberSignature;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn private_key(&self) -> Self::PrivateKey {
        self.private_key.clone()
    }

    fn sign(&self, _message: &[u8]) -> Self::Signature {
        // KEM doesn't provide signatures, but we need to satisfy the trait
        KyberSignature(vec![0; 32])
    }
}

impl PublicKey for KyberPublicKey {
    type Signature = KyberSignature;

    fn verify(&self, _message: &[u8], _signature: &Self::Signature) -> bool {
        // KEM doesn't provide signatures
        false
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Try to determine the security level from the public key size
        let level = match bytes.len() {
            800 => SecurityLevel::Level1,  // Kyber512
            1184 => SecurityLevel::Level3, // Kyber768
            1568 => SecurityLevel::Level5, // Kyber1024
            _ => return Err(format!("Invalid Kyber public key size: {}", bytes.len())),
        };

        // Validate the key by attempting to parse it
        match level {
            SecurityLevel::Level1 => {
                kyber512::PublicKey::from_bytes(bytes)
                    .map_err(|_| "Invalid Kyber512 public key format".to_string())?;
            }
            SecurityLevel::Level3 => {
                kyber768::PublicKey::from_bytes(bytes)
                    .map_err(|_| "Invalid Kyber768 public key format".to_string())?;
            }
            SecurityLevel::Level5 => {
                kyber1024::PublicKey::from_bytes(bytes)
                    .map_err(|_| "Invalid Kyber1024 public key format".to_string())?;
            }
            _ => return Err("Unexpected security level".to_string()),
        }

        Ok(KyberPublicKey {
            bytes: bytes.to_vec(),
            level,
        })
    }
}

impl PrivateKey for KyberPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Try to determine the security level from the private key size
        let level = match bytes.len() {
            1632 => SecurityLevel::Level1, // Kyber512
            2400 => SecurityLevel::Level3, // Kyber768
            3168 => SecurityLevel::Level5, // Kyber1024
            _ => return Err(format!("Invalid Kyber private key size: {}", bytes.len())),
        };

        // Validate the key by attempting to parse it
        match level {
            SecurityLevel::Level1 => {
                kyber512::SecretKey::from_bytes(bytes)
                    .map_err(|_| "Invalid Kyber512 secret key format".to_string())?;
            }
            SecurityLevel::Level3 => {
                kyber768::SecretKey::from_bytes(bytes)
                    .map_err(|_| "Invalid Kyber768 secret key format".to_string())?;
            }
            SecurityLevel::Level5 => {
                kyber1024::SecretKey::from_bytes(bytes)
                    .map_err(|_| "Invalid Kyber1024 secret key format".to_string())?;
            }
            _ => return Err("Unexpected security level".to_string()),
        }

        Ok(KyberPrivateKey {
            bytes: bytes.to_vec(),
            level,
        })
    }
}

impl Signature for KyberSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(KyberSignature(bytes.to_vec()))
    }
}

impl Encapsulated for KyberEncapsulated {
    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Try to determine the security level from the ciphertext size
        let level = match bytes.len() {
            768 => SecurityLevel::Level1,  // Kyber512
            1088 => SecurityLevel::Level3, // Kyber768
            1568 => SecurityLevel::Level5, // Kyber1024
            _ => return Err(format!("Invalid Kyber ciphertext size: {}", bytes.len())),
        };

        // Validate the ciphertext by attempting to parse it
        match level {
            SecurityLevel::Level1 => {
                kyber512::Ciphertext::from_bytes(bytes)
                    .map_err(|_| "Invalid Kyber512 ciphertext format".to_string())?;
            }
            SecurityLevel::Level3 => {
                kyber768::Ciphertext::from_bytes(bytes)
                    .map_err(|_| "Invalid Kyber768 ciphertext format".to_string())?;
            }
            SecurityLevel::Level5 => {
                kyber1024::Ciphertext::from_bytes(bytes)
                    .map_err(|_| "Invalid Kyber1024 ciphertext format".to_string())?;
            }
            _ => return Err("Unexpected security level".to_string()),
        }

        // We can't recover the shared secret from just the ciphertext
        // This will need to be decapsulated using a private key to get the shared secret
        Ok(KyberEncapsulated {
            ciphertext: bytes.to_vec(),
            shared_secret: vec![0; 32], // Placeholder until decapsulated
            level,
        })
    }
}

#[cfg(test)]
mod tests;
