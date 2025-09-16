// Path: crates/crypto/src/sign/dilithium/mod.rs
//! Dilithium signature algorithm (using dcrypt implementation)
//!
use crate::security::SecurityLevel;
use depin_sdk_api::crypto::{SerializableKey, Signature, SigningKey, SigningKeyPair, VerifyingKey};
// Import the trait needed for the signature operations
use dcrypt::api::Signature as SignatureTrait;
// Import the Dilithium implementations and types from the correct module path
use dcrypt::sign::dilithium::{
    Dilithium2, Dilithium3, Dilithium5, DilithiumPublicKey as DcryptPublicKey,
    DilithiumSecretKey as DcryptSecretKey, DilithiumSignatureData as DcryptSignatureData,
};

/// Dilithium signature scheme
pub struct DilithiumScheme {
    /// Security level
    level: SecurityLevel,
}

/// Dilithium key pair
#[derive(Clone)]
pub struct DilithiumKeyPair {
    /// Public key
    public_key: DilithiumPublicKey,
    /// Private key
    private_key: DilithiumPrivateKey,
    /// Security level (needed for signing)
    level: SecurityLevel,
}

/// Dilithium public key
#[derive(Clone)]
pub struct DilithiumPublicKey(Vec<u8>);

/// Dilithium private key
#[derive(Clone)]
pub struct DilithiumPrivateKey {
    data: Vec<u8>,
    level: SecurityLevel,
}

/// Dilithium signature
pub struct DilithiumSignature(Vec<u8>);

impl DilithiumScheme {
    /// Create a new Dilithium scheme with the specified security level
    pub fn new(level: SecurityLevel) -> Self {
        Self { level }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> DilithiumKeyPair {
        let mut rng = rand::rngs::OsRng;

        match self.level {
            SecurityLevel::Level2 => {
                let (pk, sk) = Dilithium2::keypair(&mut rng).unwrap();
                DilithiumKeyPair {
                    public_key: DilithiumPublicKey(pk.to_bytes().to_vec()),
                    private_key: DilithiumPrivateKey {
                        data: sk.to_bytes().to_vec(),
                        level: self.level,
                    },
                    level: self.level,
                }
            }
            SecurityLevel::Level3 => {
                let (pk, sk) = Dilithium3::keypair(&mut rng).unwrap();
                DilithiumKeyPair {
                    public_key: DilithiumPublicKey(pk.to_bytes().to_vec()),
                    private_key: DilithiumPrivateKey {
                        data: sk.to_bytes().to_vec(),
                        level: self.level,
                    },
                    level: self.level,
                }
            }
            SecurityLevel::Level5 => {
                let (pk, sk) = Dilithium5::keypair(&mut rng).unwrap();
                DilithiumKeyPair {
                    public_key: DilithiumPublicKey(pk.to_bytes().to_vec()),
                    private_key: DilithiumPrivateKey {
                        data: sk.to_bytes().to_vec(),
                        level: self.level,
                    },
                    level: self.level,
                }
            }
            _ => {
                // Default to Level2 for any other security level
                let (pk, sk) = Dilithium2::keypair(&mut rng).unwrap();
                DilithiumKeyPair {
                    public_key: DilithiumPublicKey(pk.to_bytes().to_vec()),
                    private_key: DilithiumPrivateKey {
                        data: sk.to_bytes().to_vec(),
                        level: SecurityLevel::Level2,
                    },
                    level: SecurityLevel::Level2,
                }
            }
        }
    }

    /// Sign a message
    pub fn sign(&self, private_key: &DilithiumPrivateKey, message: &[u8]) -> DilithiumSignature {
        match private_key.level {
            SecurityLevel::Level2 => {
                let sk = DcryptSecretKey::from_bytes(&private_key.data).unwrap();
                let signature = Dilithium2::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            SecurityLevel::Level3 => {
                let sk = DcryptSecretKey::from_bytes(&private_key.data).unwrap();
                let signature = Dilithium3::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            SecurityLevel::Level5 => {
                let sk = DcryptSecretKey::from_bytes(&private_key.data).unwrap();
                let signature = Dilithium5::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            _ => {
                // Default to Level2
                let sk = DcryptSecretKey::from_bytes(&private_key.data).unwrap();
                let signature = Dilithium2::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
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
        // Determine security level from key size
        let level = match public_key.0.len() {
            1312 => SecurityLevel::Level2, // Dilithium2
            1952 => SecurityLevel::Level3, // Dilithium3
            2592 => SecurityLevel::Level5, // Dilithium5
            _ => return false,
        };

        match level {
            SecurityLevel::Level2 => {
                let pk = DcryptPublicKey::from_bytes(&public_key.0).unwrap();
                let sig = DcryptSignatureData::from_bytes(&signature.0).unwrap();
                Dilithium2::verify(message, &sig, &pk).is_ok()
            }
            SecurityLevel::Level3 => {
                let pk = DcryptPublicKey::from_bytes(&public_key.0).unwrap();
                let sig = DcryptSignatureData::from_bytes(&signature.0).unwrap();
                Dilithium3::verify(message, &sig, &pk).is_ok()
            }
            SecurityLevel::Level5 => {
                let pk = DcryptPublicKey::from_bytes(&public_key.0).unwrap();
                let sig = DcryptSignatureData::from_bytes(&signature.0).unwrap();
                Dilithium5::verify(message, &sig, &pk).is_ok()
            }
            _ => false,
        }
    }
}

impl SigningKeyPair for DilithiumKeyPair {
    type PublicKey = DilithiumPublicKey;
    type PrivateKey = DilithiumPrivateKey;
    type Signature = DilithiumSignature;

    fn public_key(&self) -> Self::PublicKey {
        DilithiumPublicKey(self.public_key.0.clone())
    }

    fn private_key(&self) -> Self::PrivateKey {
        DilithiumPrivateKey {
            data: self.private_key.data.clone(),
            level: self.private_key.level,
        }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        match self.level {
            SecurityLevel::Level2 => {
                let sk = DcryptSecretKey::from_bytes(&self.private_key.data).unwrap();
                let signature = Dilithium2::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            SecurityLevel::Level3 => {
                let sk = DcryptSecretKey::from_bytes(&self.private_key.data).unwrap();
                let signature = Dilithium3::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            SecurityLevel::Level5 => {
                let sk = DcryptSecretKey::from_bytes(&self.private_key.data).unwrap();
                let signature = Dilithium5::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            _ => {
                // Default to Level2
                let sk = DcryptSecretKey::from_bytes(&self.private_key.data).unwrap();
                let signature = Dilithium2::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
        }
    }
}

impl VerifyingKey for DilithiumPublicKey {
    type Signature = DilithiumSignature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        // Determine security level from key size
        let level = match self.0.len() {
            1312 => SecurityLevel::Level2, // Dilithium2
            1952 => SecurityLevel::Level3, // Dilithium3
            2592 => SecurityLevel::Level5, // Dilithium5
            _ => return false,
        };

        match level {
            SecurityLevel::Level2 => {
                let pk = DcryptPublicKey::from_bytes(&self.0).unwrap();
                let sig = DcryptSignatureData::from_bytes(&signature.0).unwrap();
                Dilithium2::verify(message, &sig, &pk).is_ok()
            }
            SecurityLevel::Level3 => {
                let pk = DcryptPublicKey::from_bytes(&self.0).unwrap();
                let sig = DcryptSignatureData::from_bytes(&signature.0).unwrap();
                Dilithium3::verify(message, &sig, &pk).is_ok()
            }
            SecurityLevel::Level5 => {
                let pk = DcryptPublicKey::from_bytes(&self.0).unwrap();
                let sig = DcryptSignatureData::from_bytes(&signature.0).unwrap();
                Dilithium5::verify(message, &sig, &pk).is_ok()
            }
            _ => false,
        }
    }
}

impl SerializableKey for DilithiumPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(DilithiumPublicKey(bytes.to_vec()))
    }
}

impl SigningKey for DilithiumPrivateKey {
    type Signature = DilithiumSignature;

    fn sign(&self, message: &[u8]) -> Self::Signature {
        match self.level {
            SecurityLevel::Level2 => {
                let sk = DcryptSecretKey::from_bytes(&self.data).unwrap();
                let signature = Dilithium2::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            SecurityLevel::Level3 => {
                let sk = DcryptSecretKey::from_bytes(&self.data).unwrap();
                let signature = Dilithium3::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            SecurityLevel::Level5 => {
                let sk = DcryptSecretKey::from_bytes(&self.data).unwrap();
                let signature = Dilithium5::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            _ => {
                // Default to Level2
                let sk = DcryptSecretKey::from_bytes(&self.data).unwrap();
                let signature = Dilithium2::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
        }
    }
}

impl SerializableKey for DilithiumPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Determine security level from key size
        let level = match bytes.len() {
            2560 => SecurityLevel::Level2, // Dilithium2
            4032 => SecurityLevel::Level3, // Dilithium3
            4896 => SecurityLevel::Level5, // Dilithium5
            _ => return Err("Invalid Dilithium private key size".to_string()),
        };

        Ok(DilithiumPrivateKey {
            data: bytes.to_vec(),
            level,
        })
    }
}

impl SerializableKey for DilithiumSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(DilithiumSignature(bytes.to_vec()))
    }
}

impl Signature for DilithiumSignature {}

impl DilithiumKeyPair {
    /// Rebuild a keypair from its serialized public & private keys.
    pub fn from_bytes(public: &[u8], private: &[u8]) -> Result<Self, String> {
        let public_key = DilithiumPublicKey::from_bytes(public)?;
        let private_key = DilithiumPrivateKey::from_bytes(private)?;
        // The private key carries the security level we need for signing.
        Ok(Self {
            public_key,
            level: private_key.level,
            private_key,
        })
    }
}

#[cfg(test)]
mod tests;