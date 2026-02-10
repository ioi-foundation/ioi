// Path: crates/crypto/src/sign/dilithium/mod.rs
//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm) implementation.
//! Formerly known as CRYSTALS-Dilithium.
//!
//! Uses the `dcrypt` library implementation.
//! Mappings to NIST FIPS 204:
//! - Level 2 -> ML-DSA-44
//! - Level 3 -> ML-DSA-65
//! - Level 5 -> ML-DSA-87

use crate::error::CryptoError;
use crate::security::SecurityLevel;
use ioi_api::crypto::{SerializableKey, Signature, SigningKey, SigningKeyPair, VerifyingKey};
// Import the trait needed for the signature operations
use dcrypt::api::Signature as SignatureTrait;
// Import the Dilithium implementations and types from the correct module path
use dcrypt::sign::dilithium::{
    Dilithium2, Dilithium3, Dilithium5, DilithiumPublicKey as DcryptPublicKey,
    DilithiumSecretKey as DcryptSecretKey, DilithiumSignatureData as DcryptSignatureData,
};

/// ML-DSA signature scheme
pub struct MldsaScheme {
    /// Security level
    level: SecurityLevel,
}

/// ML-DSA key pair
#[derive(Clone)]
pub struct MldsaKeyPair {
    /// Public key
    pub public_key: MldsaPublicKey,
    /// Private key
    pub private_key: MldsaPrivateKey,
    /// Security level (needed for signing)
    level: SecurityLevel,
}

/// ML-DSA public key
#[derive(Clone)]
pub struct MldsaPublicKey(pub Vec<u8>);

/// ML-DSA private key
#[derive(Clone)]
pub struct MldsaPrivateKey {
    data: Vec<u8>,
    level: SecurityLevel,
}

/// ML-DSA signature
pub struct MldsaSignature(Vec<u8>);

impl MldsaScheme {
    /// Create a new ML-DSA scheme with the specified security level
    pub fn new(level: SecurityLevel) -> Self {
        Self { level }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> Result<MldsaKeyPair, CryptoError> {
        let mut rng = rand::rngs::OsRng;

        match self.level {
            SecurityLevel::Level2 => {
                // ML-DSA-44
                let (pk, sk) = Dilithium2::keypair(&mut rng)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaKeyPair {
                    public_key: MldsaPublicKey(pk.to_bytes().to_vec()),
                    private_key: MldsaPrivateKey {
                        data: sk.to_bytes().to_vec(),
                        level: self.level,
                    },
                    level: self.level,
                })
            }
            SecurityLevel::Level3 => {
                // ML-DSA-65
                let (pk, sk) = Dilithium3::keypair(&mut rng)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaKeyPair {
                    public_key: MldsaPublicKey(pk.to_bytes().to_vec()),
                    private_key: MldsaPrivateKey {
                        data: sk.to_bytes().to_vec(),
                        level: self.level,
                    },
                    level: self.level,
                })
            }
            SecurityLevel::Level5 => {
                // ML-DSA-87
                let (pk, sk) = Dilithium5::keypair(&mut rng)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaKeyPair {
                    public_key: MldsaPublicKey(pk.to_bytes().to_vec()),
                    private_key: MldsaPrivateKey {
                        data: sk.to_bytes().to_vec(),
                        level: self.level,
                    },
                    level: self.level,
                })
            }
            _ => {
                // Default to Level2 (ML-DSA-44) for any other security level
                let (pk, sk) = Dilithium2::keypair(&mut rng)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaKeyPair {
                    public_key: MldsaPublicKey(pk.to_bytes().to_vec()),
                    private_key: MldsaPrivateKey {
                        data: sk.to_bytes().to_vec(),
                        level: SecurityLevel::Level2,
                    },
                    level: SecurityLevel::Level2,
                })
            }
        }
    }

    /// Sign a message
    pub fn sign(
        &self,
        private_key: &MldsaPrivateKey,
        message: &[u8],
    ) -> Result<MldsaSignature, CryptoError> {
        match private_key.level {
            SecurityLevel::Level2 => {
                let sk = DcryptSecretKey::from_bytes(&private_key.data)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let signature = Dilithium2::sign(message, &sk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaSignature(signature.to_bytes().to_vec()))
            }
            SecurityLevel::Level3 => {
                let sk = DcryptSecretKey::from_bytes(&private_key.data)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let signature = Dilithium3::sign(message, &sk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaSignature(signature.to_bytes().to_vec()))
            }
            SecurityLevel::Level5 => {
                let sk = DcryptSecretKey::from_bytes(&private_key.data)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let signature = Dilithium5::sign(message, &sk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaSignature(signature.to_bytes().to_vec()))
            }
            _ => {
                // Default to Level2
                let sk = DcryptSecretKey::from_bytes(&private_key.data)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let signature = Dilithium2::sign(message, &sk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaSignature(signature.to_bytes().to_vec()))
            }
        }
    }

    /// Verify a signature
    pub fn verify(
        &self,
        public_key: &MldsaPublicKey,
        message: &[u8],
        signature: &MldsaSignature,
    ) -> Result<(), CryptoError> {
        // Determine security level from key size
        let level = match public_key.0.len() {
            1312 => SecurityLevel::Level2, // ML-DSA-44
            1952 => SecurityLevel::Level3, // ML-DSA-65
            2592 => SecurityLevel::Level5, // ML-DSA-87
            _ => return Err(CryptoError::InvalidKey("Invalid public key size".into())),
        };

        match level {
            SecurityLevel::Level2 => {
                let pk = DcryptPublicKey::from_bytes(&public_key.0)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let sig = DcryptSignatureData::from_bytes(&signature.0)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Dilithium2::verify(message, &sig, &pk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
            }
            SecurityLevel::Level3 => {
                let pk = DcryptPublicKey::from_bytes(&public_key.0)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let sig = DcryptSignatureData::from_bytes(&signature.0)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Dilithium3::verify(message, &sig, &pk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
            }
            SecurityLevel::Level5 => {
                let pk = DcryptPublicKey::from_bytes(&public_key.0)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let sig = DcryptSignatureData::from_bytes(&signature.0)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Dilithium5::verify(message, &sig, &pk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
            }
            _ => return Err(CryptoError::Unsupported("Security level".into())),
        }
        Ok(())
    }
}

impl SigningKeyPair for MldsaKeyPair {
    type PublicKey = MldsaPublicKey;
    type PrivateKey = MldsaPrivateKey;
    type Signature = MldsaSignature;

    fn public_key(&self) -> Self::PublicKey {
        MldsaPublicKey(self.public_key.0.clone())
    }

    fn private_key(&self) -> Self::PrivateKey {
        MldsaPrivateKey {
            data: self.private_key.data.clone(),
            level: self.private_key.level,
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Self::Signature, CryptoError> {
        match self.level {
            SecurityLevel::Level2 => {
                let sk = DcryptSecretKey::from_bytes(&self.private_key.data)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let signature = Dilithium2::sign(message, &sk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaSignature(signature.to_bytes().to_vec()))
            }
            SecurityLevel::Level3 => {
                let sk = DcryptSecretKey::from_bytes(&self.private_key.data)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let signature = Dilithium3::sign(message, &sk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaSignature(signature.to_bytes().to_vec()))
            }
            SecurityLevel::Level5 => {
                let sk = DcryptSecretKey::from_bytes(&self.private_key.data)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let signature = Dilithium5::sign(message, &sk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaSignature(signature.to_bytes().to_vec()))
            }
            _ => {
                // Default to Level2
                let sk = DcryptSecretKey::from_bytes(&self.private_key.data)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let signature = Dilithium2::sign(message, &sk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaSignature(signature.to_bytes().to_vec()))
            }
        }
    }
}

impl VerifyingKey for MldsaPublicKey {
    type Signature = MldsaSignature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<(), CryptoError> {
        // Determine security level from key size
        let level = match self.0.len() {
            1312 => SecurityLevel::Level2, // ML-DSA-44
            1952 => SecurityLevel::Level3, // ML-DSA-65
            2592 => SecurityLevel::Level5, // ML-DSA-87
            _ => return Err(CryptoError::InvalidKey("Invalid public key size".into())),
        };

        match level {
            SecurityLevel::Level2 => {
                let pk = DcryptPublicKey::from_bytes(&self.0)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let sig = DcryptSignatureData::from_bytes(&signature.0)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Dilithium2::verify(message, &sig, &pk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))
            }
            SecurityLevel::Level3 => {
                let pk = DcryptPublicKey::from_bytes(&self.0)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let sig = DcryptSignatureData::from_bytes(&signature.0)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Dilithium3::verify(message, &sig, &pk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))
            }
            SecurityLevel::Level5 => {
                let pk = DcryptPublicKey::from_bytes(&self.0)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let sig = DcryptSignatureData::from_bytes(&signature.0)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Dilithium5::verify(message, &sig, &pk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))
            }
            _ => Err(CryptoError::Unsupported("Security level".into())),
        }
    }
}

impl SerializableKey for MldsaPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        match bytes.len() {
            1312 | 1952 | 2592 => Ok(MldsaPublicKey(bytes.to_vec())),
            n => Err(CryptoError::InvalidKey(format!(
                "Invalid ML-DSA public key size: {} bytes",
                n
            ))),
        }
    }
}

impl SigningKey for MldsaPrivateKey {
    type Signature = MldsaSignature;

    fn sign(&self, message: &[u8]) -> Result<Self::Signature, CryptoError> {
        match self.level {
            SecurityLevel::Level2 => {
                let sk = DcryptSecretKey::from_bytes(&self.data)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let signature = Dilithium2::sign(message, &sk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaSignature(signature.to_bytes().to_vec()))
            }
            SecurityLevel::Level3 => {
                let sk = DcryptSecretKey::from_bytes(&self.data)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let signature = Dilithium3::sign(message, &sk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaSignature(signature.to_bytes().to_vec()))
            }
            SecurityLevel::Level5 => {
                let sk = DcryptSecretKey::from_bytes(&self.data)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let signature = Dilithium5::sign(message, &sk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaSignature(signature.to_bytes().to_vec()))
            }
            _ => {
                // Default to Level2
                let sk = DcryptSecretKey::from_bytes(&self.data)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                let signature = Dilithium2::sign(message, &sk)
                    .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
                Ok(MldsaSignature(signature.to_bytes().to_vec()))
            }
        }
    }
}

impl SerializableKey for MldsaPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        // Determine security level from key size
        let level = match bytes.len() {
            2560 => SecurityLevel::Level2, // ML-DSA-44
            4032 => SecurityLevel::Level3, // ML-DSA-65
            4896 => SecurityLevel::Level5, // ML-DSA-87
            _ => {
                return Err(CryptoError::InvalidKey(
                    "Invalid ML-DSA private key size".into(),
                ))
            }
        };

        Ok(MldsaPrivateKey {
            data: bytes.to_vec(),
            level,
        })
    }
}

impl SerializableKey for MldsaSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(MldsaSignature(bytes.to_vec()))
    }
}

impl Signature for MldsaSignature {}

impl MldsaKeyPair {
    /// Rebuild a keypair from its serialized public & private keys.
    pub fn from_bytes(public: &[u8], private: &[u8]) -> Result<Self, CryptoError> {
        let public_key = MldsaPublicKey::from_bytes(public)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let private_key = MldsaPrivateKey::from_bytes(private)?;

        // Sanity check: public key length must match the level derived from the private key.
        let expected_pk_len = match private_key.level {
            SecurityLevel::Level2 => 1312,
            SecurityLevel::Level3 => 1952,
            SecurityLevel::Level5 => 2592,
            _ => return Err(CryptoError::Unsupported("ML-DSA security level".into())),
        };
        if public_key.0.len() != expected_pk_len {
            return Err(CryptoError::InvalidKey(format!(
                "Public/private key size mismatch: got public {} bytes, expected {} for {:?}",
                public_key.0.len(),
                expected_pk_len,
                private_key.level
            )));
        }

        Ok(Self {
            public_key,
            level: private_key.level,
            private_key,
        })
    }
}

#[cfg(test)]
mod tests;
