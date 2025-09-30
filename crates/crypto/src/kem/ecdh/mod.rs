// Path: crates/crypto/src/kem/ecdh/mod.rs
use crate::security::SecurityLevel;
use dcrypt::api::Kem;
use dcrypt::kem::ecdh::{
    p384::{EcdhP384, EcdhP384Ciphertext, EcdhP384PublicKey, EcdhP384SecretKey},
    p521::{EcdhP521, EcdhP521Ciphertext, EcdhP521PublicKey, EcdhP521SecretKey},
    EcdhK256, EcdhK256Ciphertext, EcdhK256PublicKey, EcdhK256SecretKey,
};
use depin_sdk_api::crypto::{
    DecapsulationKey, Encapsulated, EncapsulationKey, KemKeyPair, KeyEncapsulation, SerializableKey,
};
use depin_sdk_api::error::CryptoError;

/// ECDH curve type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdhCurve {
    /// NIST P-256 curve (128-bit security) - using K256 (secp256k1) as substitute
    P256,
    /// NIST P-384 curve (192-bit security)
    P384,
    /// NIST P-521 curve (256-bit security)
    P521,
}

impl EcdhCurve {
    /// Get the appropriate curve for a security level
    pub fn from_security_level(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::Level1 => EcdhCurve::P256,
            SecurityLevel::Level3 => EcdhCurve::P384,
            SecurityLevel::Level5 => EcdhCurve::P521,
            _ => EcdhCurve::P256, // Default to P256
        }
    }
}

/// ECDH key encapsulation mechanism
pub struct EcdhKEM {
    /// The curve to use
    pub(crate) curve: EcdhCurve,
}

/// ECDH key pair
pub struct EcdhKeyPair {
    /// Public key
    pub public_key: EcdhPublicKey,
    /// Private key
    pub private_key: EcdhPrivateKey,
    /// Curve type
    _curve: EcdhCurve,
}

/// ECDH public key wrapper
#[derive(Clone)]
pub enum EcdhPublicKey {
    P256(EcdhK256PublicKey),
    P384(EcdhP384PublicKey),
    P521(EcdhP521PublicKey),
}

/// ECDH private key wrapper
#[derive(Clone)]
pub enum EcdhPrivateKey {
    P256(EcdhK256SecretKey),
    P384(EcdhP384SecretKey),
    P521(EcdhP521SecretKey),
}

/// ECDH encapsulated key
pub struct EcdhEncapsulated {
    /// Ciphertext
    ciphertext: Vec<u8>,
    /// Shared secret
    shared_secret: Vec<u8>,
    /// Curve type
    _curve: EcdhCurve,
}

impl EcdhKEM {
    /// Create a new ECDH KEM with the specified curve
    pub fn new(curve: EcdhCurve) -> Self {
        Self { curve }
    }

    /// Create a new ECDH KEM with the specified security level
    pub fn with_security_level(level: SecurityLevel) -> Self {
        Self {
            curve: EcdhCurve::from_security_level(level),
        }
    }
}

impl KeyEncapsulation for EcdhKEM {
    type KeyPair = EcdhKeyPair;
    type PublicKey = EcdhPublicKey;
    type PrivateKey = EcdhPrivateKey;
    type Encapsulated = EcdhEncapsulated;

    fn generate_keypair(&self) -> Result<Self::KeyPair, depin_sdk_api::error::CryptoError> {
        let mut rng = rand::thread_rng();

        match self.curve {
            EcdhCurve::P256 => {
                let (pk, sk) = EcdhK256::keypair(&mut rng)?;
                Ok(EcdhKeyPair {
                    public_key: EcdhPublicKey::P256(pk),
                    private_key: EcdhPrivateKey::P256(sk),
                    _curve: self.curve,
                })
            }
            EcdhCurve::P384 => {
                let (pk, sk) = EcdhP384::keypair(&mut rng)?;
                Ok(EcdhKeyPair {
                    public_key: EcdhPublicKey::P384(pk),
                    private_key: EcdhPrivateKey::P384(sk),
                    _curve: self.curve,
                })
            }
            EcdhCurve::P521 => {
                let (pk, sk) = EcdhP521::keypair(&mut rng)?;
                Ok(EcdhKeyPair {
                    public_key: EcdhPublicKey::P521(pk),
                    private_key: EcdhPrivateKey::P521(sk),
                    _curve: self.curve,
                })
            }
        }
    }

    fn encapsulate(
        &self,
        public_key: &Self::PublicKey,
    ) -> Result<Self::Encapsulated, depin_sdk_api::error::CryptoError> {
        let mut rng = rand::thread_rng();

        match (self.curve, public_key) {
            (EcdhCurve::P256, EcdhPublicKey::P256(pk)) => {
                let (ct, ss) = EcdhK256::encapsulate(&mut rng, pk)?;

                Ok(EcdhEncapsulated {
                    ciphertext: ct.to_bytes(),
                    shared_secret: ss.to_bytes().to_vec(), // FIX: Convert Zeroizing Vec
                    _curve: EcdhCurve::P256,
                })
            }
            (EcdhCurve::P384, EcdhPublicKey::P384(pk)) => {
                let (ct, ss) = EcdhP384::encapsulate(&mut rng, pk)?;
                Ok(EcdhEncapsulated {
                    ciphertext: ct.to_bytes(),
                    shared_secret: ss.to_bytes().to_vec(), // FIX: Convert Zeroizing Vec
                    _curve: self.curve,
                })
            }
            (EcdhCurve::P521, EcdhPublicKey::P521(pk)) => {
                let (ct, ss) = EcdhP521::encapsulate(&mut rng, pk)?;
                Ok(EcdhEncapsulated {
                    ciphertext: ct.to_bytes(),
                    shared_secret: ss.to_bytes().to_vec(), // FIX: Convert Zeroizing Vec
                    _curve: self.curve,
                })
            }
            _ => Err(CryptoError::Unsupported(
                "Curve mismatch or unsupported curve in encapsulation".into(),
            )
            .into()),
        }
    }

    fn decapsulate(
        &self,
        private_key: &Self::PrivateKey,
        encapsulated: &Self::Encapsulated,
    ) -> Result<Vec<u8>, depin_sdk_api::error::CryptoError> {
        match (self.curve, private_key) {
            (EcdhCurve::P256, EcdhPrivateKey::P256(sk)) => {
                let ct = EcdhK256Ciphertext::from_bytes(&encapsulated.ciphertext)?;
                Ok(EcdhK256::decapsulate(sk, &ct)?.to_bytes().to_vec()) // FIX: Convert Zeroizing Vec
            }
            (EcdhCurve::P384, EcdhPrivateKey::P384(sk)) => {
                let ct = EcdhP384Ciphertext::from_bytes(&encapsulated.ciphertext)?;
                Ok(EcdhP384::decapsulate(sk, &ct)?.to_bytes().to_vec()) // FIX: Convert Zeroizing Vec
            }
            (EcdhCurve::P521, EcdhPrivateKey::P521(sk)) => {
                let ct = EcdhP521Ciphertext::from_bytes(&encapsulated.ciphertext)?;
                Ok(EcdhP521::decapsulate(sk, &ct)?.to_bytes().to_vec()) // FIX: Convert Zeroizing Vec
            }
            _ => Err(CryptoError::DecapsulationFailed.into()),
        }
    }
}

impl KemKeyPair for EcdhKeyPair {
    type PublicKey = EcdhPublicKey;
    type PrivateKey = EcdhPrivateKey;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn private_key(&self) -> Self::PrivateKey {
        self.private_key.clone()
    }
}

impl SerializableKey for EcdhPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            EcdhPublicKey::P256(pk) => pk.to_bytes(),
            EcdhPublicKey::P384(pk) => pk.to_bytes(),
            EcdhPublicKey::P521(pk) => pk.to_bytes(),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, depin_sdk_api::error::CryptoError> {
        match bytes.len() {
            33 => Ok(EcdhPublicKey::P256(EcdhK256PublicKey::from_bytes(bytes)?)),
            49 => Ok(EcdhPublicKey::P384(EcdhP384PublicKey::from_bytes(bytes)?)),
            67 => Ok(EcdhPublicKey::P521(EcdhP521PublicKey::from_bytes(bytes)?)),
            _ => Err(CryptoError::InvalidKey(format!(
                "Invalid ECDH public key size: {}",
                bytes.len()
            ))
            .into()),
        }
    }
}

impl EncapsulationKey for EcdhPublicKey {}

impl SerializableKey for EcdhPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            EcdhPrivateKey::P256(sk) => sk.to_bytes().to_vec(), // FIX: Convert Zeroizing Vec
            EcdhPrivateKey::P384(sk) => sk.to_bytes().to_vec(), // FIX: Convert Zeroizing Vec
            EcdhPrivateKey::P521(sk) => sk.to_bytes().to_vec(), // FIX: Convert Zeroizing Vec
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, depin_sdk_api::error::CryptoError> {
        match bytes.len() {
            32 => Ok(EcdhPrivateKey::P256(EcdhK256SecretKey::from_bytes(bytes)?)),
            48 => Ok(EcdhPrivateKey::P384(EcdhP384SecretKey::from_bytes(bytes)?)),
            66 => Ok(EcdhPrivateKey::P521(EcdhP521SecretKey::from_bytes(bytes)?)),
            _ => Err(CryptoError::InvalidKey(format!(
                "Invalid ECDH private key size: {}",
                bytes.len()
            ))
            .into()),
        }
    }
}

impl DecapsulationKey for EcdhPrivateKey {}

impl SerializableKey for EcdhEncapsulated {
    fn to_bytes(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, depin_sdk_api::error::CryptoError> {
        let curve = match bytes.len() {
            33 => EcdhCurve::P256,
            49 => EcdhCurve::P384,
            67 => EcdhCurve::P521,
            _ => {
                return Err(CryptoError::InvalidKey(format!(
                    "Invalid ECDH ciphertext size: {}",
                    bytes.len()
                ))
                .into())
            }
        };

        Ok(EcdhEncapsulated {
            ciphertext: bytes.to_vec(),
            shared_secret: vec![],
            _curve: curve,
        })
    }
}

impl Encapsulated for EcdhEncapsulated {
    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }
}

#[cfg(test)]
mod tests;
