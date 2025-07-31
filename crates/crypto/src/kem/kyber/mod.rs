// Path: crates/crypto/src/kem/kyber/mod.rs
// Change: Removed unused imports and prefixed unused fields with an underscore.

use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{
    DecapsulationKey, Encapsulated, EncapsulationKey, KemKeyPair, KeyEncapsulation,
    SerializableKey,
};
use dcrypt::api::Kem;
use dcrypt::kem::kyber::{
    Kyber1024, Kyber512, Kyber768, KyberCiphertext, KyberPublicKey as DcryptPublicKey,
    KyberSecretKey as DcryptSecretKey,
};

/// Kyber key encapsulation mechanism
pub struct KyberKEM {
    /// Security level
    level: SecurityLevel,
}

/// Kyber key pair
pub struct KyberKeyPair {
    /// Public key
    pub public_key: KyberPublicKey,
    /// Private key
    pub private_key: KyberPrivateKey,
    /// Security level
    _level: SecurityLevel,
}

/// Kyber public key wrapper
#[derive(Clone)]
pub struct KyberPublicKey {
    /// The underlying dcrypt public key
    inner: DcryptPublicKey,
    /// Security level
    level: SecurityLevel,
}

/// Kyber private key wrapper
#[derive(Clone)]
pub struct KyberPrivateKey {
    /// The underlying dcrypt secret key
    inner: DcryptSecretKey,
    /// Security level
    level: SecurityLevel,
}

/// Kyber encapsulated key
pub struct KyberEncapsulated {
    /// The ciphertext bytes
    ciphertext: Vec<u8>,
    /// The shared secret
    shared_secret: Vec<u8>,
    /// Security level
    _level: SecurityLevel,
}

impl KyberKEM {
    /// Create a new Kyber KEM with the specified security level
    pub fn new(level: SecurityLevel) -> Self {
        Self { level }
    }
}

impl KeyEncapsulation for KyberKEM {
    type KeyPair = KyberKeyPair;
    type PublicKey = KyberPublicKey;
    type PrivateKey = KyberPrivateKey;
    type Encapsulated = KyberEncapsulated;

    fn generate_keypair(&self) -> Self::KeyPair {
        let mut rng = rand::thread_rng();

        // Use dcrypt's KEM trait to generate keypair based on security level
        let (pk, sk) = match self.level {
            SecurityLevel::Level1 => {
                let (pk, sk) = Kyber512::keypair(&mut rng)
                    .expect("Failed to generate Kyber512 keypair");
                (
                    KyberPublicKey {
                        inner: pk,
                        level: self.level,
                    },
                    KyberPrivateKey {
                        inner: sk,
                        level: self.level,
                    },
                )
            }
            SecurityLevel::Level3 => {
                let (pk, sk) = Kyber768::keypair(&mut rng)
                    .expect("Failed to generate Kyber768 keypair");
                (
                    KyberPublicKey {
                        inner: pk,
                        level: self.level,
                    },
                    KyberPrivateKey {
                        inner: sk,
                        level: self.level,
                    },
                )
            }
            SecurityLevel::Level5 => {
                let (pk, sk) = Kyber1024::keypair(&mut rng)
                    .expect("Failed to generate Kyber1024 keypair");
                (
                    KyberPublicKey {
                        inner: pk,
                        level: self.level,
                    },
                    KyberPrivateKey {
                        inner: sk,
                        level: self.level,
                    },
                )
            }
            _ => {
                // Default to Level1
                let (pk, sk) = Kyber512::keypair(&mut rng)
                    .expect("Failed to generate Kyber512 keypair");
                (
                    KyberPublicKey {
                        inner: pk,
                        level: SecurityLevel::Level1,
                    },
                    KyberPrivateKey {
                        inner: sk,
                        level: SecurityLevel::Level1,
                    },
                )
            }
        };

        KyberKeyPair {
            public_key: pk,
            private_key: sk,
            _level: self.level,
        }
    }

    fn encapsulate(&self, public_key: &Self::PublicKey) -> Self::Encapsulated {
        let mut rng = rand::thread_rng();

        // Use dcrypt's KEM trait to encapsulate based on security level
        let (ct, ss) = match public_key.level {
            SecurityLevel::Level1 => {
                Kyber512::encapsulate(&mut rng, &public_key.inner)
                    .expect("Failed to encapsulate with Kyber512")
            }
            SecurityLevel::Level3 => {
                Kyber768::encapsulate(&mut rng, &public_key.inner)
                    .expect("Failed to encapsulate with Kyber768")
            }
            SecurityLevel::Level5 => {
                Kyber1024::encapsulate(&mut rng, &public_key.inner)
                    .expect("Failed to encapsulate with Kyber1024")
            }
            _ => {
                Kyber512::encapsulate(&mut rng, &public_key.inner)
                    .expect("Failed to encapsulate with Kyber512")
            }
        };

        KyberEncapsulated {
            ciphertext: ct.to_bytes(),
            shared_secret: ss.to_bytes_zeroizing().to_vec(),
            _level: public_key.level,
        }
    }

    fn decapsulate(
        &self,
        private_key: &Self::PrivateKey,
        encapsulated: &Self::Encapsulated,
    ) -> Option<Vec<u8>> {
        // Reconstruct the ciphertext from bytes
        let ct = KyberCiphertext::from_bytes(&encapsulated.ciphertext).ok()?;

        // Use dcrypt's KEM trait to decapsulate based on security level
        let ss = match private_key.level {
            SecurityLevel::Level1 => {
                Kyber512::decapsulate(&private_key.inner, &ct).ok()?
            }
            SecurityLevel::Level3 => {
                Kyber768::decapsulate(&private_key.inner, &ct).ok()?
            }
            SecurityLevel::Level5 => {
                Kyber1024::decapsulate(&private_key.inner, &ct).ok()?
            }
            _ => Kyber512::decapsulate(&private_key.inner, &ct).ok()?,
        };

        Some(ss.to_bytes_zeroizing().to_vec())
    }
}

impl KemKeyPair for KyberKeyPair {
    type PublicKey = KyberPublicKey;
    type PrivateKey = KyberPrivateKey;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn private_key(&self) -> Self::PrivateKey {
        self.private_key.clone()
    }
}

// KyberPublicKey implements the EncapsulationKey trait
impl SerializableKey for KyberPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        // Use dcrypt's built-in to_bytes method
        self.inner.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Use dcrypt's built-in from_bytes method
        let inner = DcryptPublicKey::from_bytes(bytes)
            .map_err(|e| format!("Failed to deserialize Kyber public key: {:?}", e))?;

        // Try to determine the security level from the public key size
        let level = match bytes.len() {
            800 => SecurityLevel::Level1,  // Kyber512
            1184 => SecurityLevel::Level3, // Kyber768
            1568 => SecurityLevel::Level5, // Kyber1024
            _ => return Err(format!("Invalid Kyber public key size: {}", bytes.len())),
        };

        Ok(KyberPublicKey { inner, level })
    }
}

impl EncapsulationKey for KyberPublicKey {
    // EncapsulationKey trait has no additional methods beyond SerializableKey
}

// KyberPrivateKey implements the DecapsulationKey trait
impl SerializableKey for KyberPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        // Use dcrypt's built-in to_bytes_zeroizing method
        self.inner.to_bytes_zeroizing().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Use dcrypt's built-in from_bytes method
        let inner = DcryptSecretKey::from_bytes(bytes)
            .map_err(|e| format!("Failed to deserialize Kyber private key: {:?}", e))?;

        // Try to determine the security level from the private key size
        let level = match bytes.len() {
            1632 => SecurityLevel::Level1, // Kyber512
            2400 => SecurityLevel::Level3, // Kyber768
            3168 => SecurityLevel::Level5, // Kyber1024
            _ => return Err(format!("Invalid Kyber private key size: {}", bytes.len())),
        };

        Ok(KyberPrivateKey { inner, level })
    }
}

impl DecapsulationKey for KyberPrivateKey {
    // DecapsulationKey trait has no additional methods beyond SerializableKey
}

// KyberEncapsulated implements the Encapsulated trait
impl SerializableKey for KyberEncapsulated {
    fn to_bytes(&self) -> Vec<u8> {
        // Return the ciphertext bytes
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

        // We can't recover the shared secret from just the ciphertext
        // This will need to be decapsulated using a private key to get the shared secret
        Ok(KyberEncapsulated {
            ciphertext: bytes.to_vec(),
            shared_secret: vec![0; 32], // Placeholder until decapsulated
            _level: level,
        })
    }
}

impl Encapsulated for KyberEncapsulated {
    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }
}

#[cfg(test)]
mod tests;