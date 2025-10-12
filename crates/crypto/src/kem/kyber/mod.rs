// Path: crates/crypto/src/kem/kyber/mod.rs
use crate::error::CryptoError;
use crate::security::SecurityLevel;
use dcrypt::api::Kem;
use dcrypt::kem::kyber::{
    Kyber1024, Kyber512, Kyber768, KyberCiphertext, KyberPublicKey as DcryptPublicKey,
    KyberSecretKey as DcryptSecretKey,
};
use depin_sdk_api::crypto::{
    DecapsulationKey, Encapsulated, EncapsulationKey, KemKeyPair, KeyEncapsulation, SerializableKey,
};
use zeroize::Zeroizing;

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

    fn generate_keypair(&self) -> Result<Self::KeyPair, CryptoError> {
        let mut rng = rand::thread_rng();

        let (pk, sk) = match self.level {
            SecurityLevel::Level1 => {
                let (pk, sk) = Kyber512::keypair(&mut rng)?;
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
                let (pk, sk) = Kyber768::keypair(&mut rng)?;
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
                let (pk, sk) = Kyber1024::keypair(&mut rng)?;
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
                let (pk, sk) = Kyber512::keypair(&mut rng)?;
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

        Ok(KyberKeyPair {
            public_key: pk,
            private_key: sk,
            _level: self.level,
        })
    }

    fn encapsulate(&self, public_key: &Self::PublicKey) -> Result<Self::Encapsulated, CryptoError> {
        let mut rng = rand::thread_rng();

        let (ct, ss) = match public_key.level {
            SecurityLevel::Level1 => Kyber512::encapsulate(&mut rng, &public_key.inner)?,
            SecurityLevel::Level3 => Kyber768::encapsulate(&mut rng, &public_key.inner)?,
            SecurityLevel::Level5 => Kyber1024::encapsulate(&mut rng, &public_key.inner)?,
            _ => Kyber512::encapsulate(&mut rng, &public_key.inner)?,
        };

        Ok(KyberEncapsulated {
            ciphertext: ct.to_bytes(),
            shared_secret: ss.to_bytes_zeroizing().to_vec(),
            _level: public_key.level,
        })
    }

    fn decapsulate(
        &self,
        private_key: &Self::PrivateKey,
        encapsulated: &Self::Encapsulated,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let ct = KyberCiphertext::from_bytes(&encapsulated.ciphertext)?;

        let ss = match private_key.level {
            SecurityLevel::Level1 => Kyber512::decapsulate(&private_key.inner, &ct)?,
            SecurityLevel::Level3 => Kyber768::decapsulate(&private_key.inner, &ct)?,
            SecurityLevel::Level5 => Kyber1024::decapsulate(&private_key.inner, &ct)?,
            _ => Kyber512::decapsulate(&private_key.inner, &ct)?,
        };

        Ok(ss.to_bytes_zeroizing())
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

impl SerializableKey for KyberPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let inner = DcryptPublicKey::from_bytes(bytes)?;

        let level = match bytes.len() {
            800 => SecurityLevel::Level1,  // Kyber512
            1184 => SecurityLevel::Level3, // Kyber768
            1568 => SecurityLevel::Level5, // Kyber1024
            _ => {
                return Err(CryptoError::InvalidKey(format!(
                    "Invalid Kyber public key size: {}",
                    bytes.len()
                )))
            }
        };

        Ok(KyberPublicKey { inner, level })
    }
}

impl EncapsulationKey for KyberPublicKey {}

impl SerializableKey for KyberPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes_zeroizing().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let inner = DcryptSecretKey::from_bytes(bytes)?;

        let level = match bytes.len() {
            1632 => SecurityLevel::Level1, // Kyber512
            2400 => SecurityLevel::Level3, // Kyber768
            3168 => SecurityLevel::Level5, // Kyber1024
            _ => {
                return Err(CryptoError::InvalidKey(format!(
                    "Invalid Kyber private key size: {}",
                    bytes.len()
                )))
            }
        };

        Ok(KyberPrivateKey { inner, level })
    }
}

impl DecapsulationKey for KyberPrivateKey {}

impl SerializableKey for KyberEncapsulated {
    fn to_bytes(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let level = match bytes.len() {
            768 => SecurityLevel::Level1,  // Kyber512
            1088 => SecurityLevel::Level3, // Kyber768
            1568 => SecurityLevel::Level5, // Kyber1024
            _ => {
                return Err(CryptoError::InvalidKey(format!(
                    "Invalid Kyber ciphertext size: {}",
                    bytes.len()
                )))
            }
        };

        Ok(KyberEncapsulated {
            ciphertext: bytes.to_vec(),
            shared_secret: vec![0; 32],
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