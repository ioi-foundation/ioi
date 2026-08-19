// Path: crates/crypto/src/kem/kyber/mod.rs
use crate::error::CryptoError;
use crate::security::SecurityLevel;
use dcrypt::api::Kem;
use dcrypt::kem::ml_kem::{
    MlKem1024, MlKem1024Ciphertext, MlKem1024DecapsulationKey, MlKem1024EncapsulationKey, MlKem512,
    MlKem512Ciphertext, MlKem512DecapsulationKey, MlKem512EncapsulationKey, MlKem768,
    MlKem768Ciphertext, MlKem768DecapsulationKey, MlKem768EncapsulationKey,
};
use ioi_api::crypto::{
    DecapsulationKey, Encapsulated, EncapsulationKey, KemKeyPair, KeyEncapsulation, SerializableKey,
};
use zeroize::Zeroizing;

/// Kyber (FIPS 203 ML-KEM) key encapsulation mechanism.
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

/// Kyber public key wrapper. v4 ML-KEM keys are parameterized by security
/// level, so the wrapper stores the serialized encapsulation key and its level
/// and reconstructs the level-specific dcrypt type on demand.
#[derive(Clone)]
pub struct KyberPublicKey {
    /// Serialized ML-KEM encapsulation key bytes
    inner: Vec<u8>,
    /// Security level
    level: SecurityLevel,
}

/// Kyber private key wrapper (serialized ML-KEM decapsulation key bytes).
#[derive(Clone)]
pub struct KyberPrivateKey {
    /// Serialized ML-KEM decapsulation key bytes (zeroized on drop)
    inner: Zeroizing<Vec<u8>>,
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
        let mut rng = crate::rng::os_rng();

        let (pk_bytes, sk_bytes, level) = match self.level {
            SecurityLevel::Level3 => {
                let kp = MlKem768::keypair(&mut rng)?;
                (
                    MlKem768::public_key(&kp).to_bytes(),
                    MlKem768::secret_key(&kp).to_bytes_zeroizing().to_vec(),
                    SecurityLevel::Level3,
                )
            }
            SecurityLevel::Level5 => {
                let kp = MlKem1024::keypair(&mut rng)?;
                (
                    MlKem1024::public_key(&kp).to_bytes(),
                    MlKem1024::secret_key(&kp).to_bytes_zeroizing().to_vec(),
                    SecurityLevel::Level5,
                )
            }
            // Level1 (and any other value) default to ML-KEM-512.
            _ => {
                let kp = MlKem512::keypair(&mut rng)?;
                (
                    MlKem512::public_key(&kp).to_bytes(),
                    MlKem512::secret_key(&kp).to_bytes_zeroizing().to_vec(),
                    SecurityLevel::Level1,
                )
            }
        };

        Ok(KyberKeyPair {
            public_key: KyberPublicKey {
                inner: pk_bytes,
                level,
            },
            private_key: KyberPrivateKey {
                inner: Zeroizing::new(sk_bytes),
                level,
            },
            _level: level,
        })
    }

    fn encapsulate(&self, public_key: &Self::PublicKey) -> Result<Self::Encapsulated, CryptoError> {
        let mut rng = crate::rng::os_rng();

        let (ciphertext, shared_secret) = match public_key.level {
            SecurityLevel::Level3 => {
                let pk = MlKem768EncapsulationKey::from_bytes(&public_key.inner)?;
                let (ct, ss) = MlKem768::encapsulate(&mut rng, &pk)?;
                (ct.to_bytes(), ss.to_bytes_zeroizing().to_vec())
            }
            SecurityLevel::Level5 => {
                let pk = MlKem1024EncapsulationKey::from_bytes(&public_key.inner)?;
                let (ct, ss) = MlKem1024::encapsulate(&mut rng, &pk)?;
                (ct.to_bytes(), ss.to_bytes_zeroizing().to_vec())
            }
            _ => {
                let pk = MlKem512EncapsulationKey::from_bytes(&public_key.inner)?;
                let (ct, ss) = MlKem512::encapsulate(&mut rng, &pk)?;
                (ct.to_bytes(), ss.to_bytes_zeroizing().to_vec())
            }
        };

        Ok(KyberEncapsulated {
            ciphertext,
            shared_secret,
            _level: public_key.level,
        })
    }

    fn decapsulate(
        &self,
        private_key: &Self::PrivateKey,
        encapsulated: &Self::Encapsulated,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let ss_bytes: Vec<u8> = match private_key.level {
            SecurityLevel::Level3 => {
                let sk = MlKem768DecapsulationKey::from_bytes(&private_key.inner)?;
                let ct = MlKem768Ciphertext::from_bytes(&encapsulated.ciphertext)?;
                MlKem768::decapsulate(&sk, &ct)?
                    .to_bytes_zeroizing()
                    .to_vec()
            }
            SecurityLevel::Level5 => {
                let sk = MlKem1024DecapsulationKey::from_bytes(&private_key.inner)?;
                let ct = MlKem1024Ciphertext::from_bytes(&encapsulated.ciphertext)?;
                MlKem1024::decapsulate(&sk, &ct)?
                    .to_bytes_zeroizing()
                    .to_vec()
            }
            _ => {
                let sk = MlKem512DecapsulationKey::from_bytes(&private_key.inner)?;
                let ct = MlKem512Ciphertext::from_bytes(&encapsulated.ciphertext)?;
                MlKem512::decapsulate(&sk, &ct)?
                    .to_bytes_zeroizing()
                    .to_vec()
            }
        };

        Ok(Zeroizing::new(ss_bytes))
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
        self.inner.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let level = match bytes.len() {
            800 => SecurityLevel::Level1,  // ML-KEM-512
            1184 => SecurityLevel::Level3, // ML-KEM-768
            1568 => SecurityLevel::Level5, // ML-KEM-1024
            _ => {
                return Err(CryptoError::InvalidKey(format!(
                    "Invalid Kyber public key size: {}",
                    bytes.len()
                )))
            }
        };

        // Reject bytes that do not parse as a well-formed encapsulation key.
        match level {
            SecurityLevel::Level3 => {
                MlKem768EncapsulationKey::from_bytes(bytes)?;
            }
            SecurityLevel::Level5 => {
                MlKem1024EncapsulationKey::from_bytes(bytes)?;
            }
            _ => {
                MlKem512EncapsulationKey::from_bytes(bytes)?;
            }
        }

        Ok(KyberPublicKey {
            inner: bytes.to_vec(),
            level,
        })
    }
}

impl EncapsulationKey for KyberPublicKey {}

impl SerializableKey for KyberPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let level = match bytes.len() {
            1632 => SecurityLevel::Level1, // ML-KEM-512
            2400 => SecurityLevel::Level3, // ML-KEM-768
            3168 => SecurityLevel::Level5, // ML-KEM-1024
            _ => {
                return Err(CryptoError::InvalidKey(format!(
                    "Invalid Kyber private key size: {}",
                    bytes.len()
                )))
            }
        };

        match level {
            SecurityLevel::Level3 => {
                MlKem768DecapsulationKey::from_bytes(bytes)?;
            }
            SecurityLevel::Level5 => {
                MlKem1024DecapsulationKey::from_bytes(bytes)?;
            }
            _ => {
                MlKem512DecapsulationKey::from_bytes(bytes)?;
            }
        }

        Ok(KyberPrivateKey {
            inner: Zeroizing::new(bytes.to_vec()),
            level,
        })
    }
}

impl DecapsulationKey for KyberPrivateKey {}

impl SerializableKey for KyberEncapsulated {
    fn to_bytes(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let level = match bytes.len() {
            768 => SecurityLevel::Level1,  // ML-KEM-512
            1088 => SecurityLevel::Level3, // ML-KEM-768
            1568 => SecurityLevel::Level5, // ML-KEM-1024
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
