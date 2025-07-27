// crates/crypto/src/kem/ecdh/mod.rs
//! ECDH key encapsulation mechanism using dcrypt

use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{
    DecapsulationKey, Encapsulated, EncapsulationKey, KemKeyPair, KeyEncapsulation,
    SerializableKey,
};
use dcrypt::api::Kem;
use dcrypt::kem::ecdh::{
    EcdhK256,
    EcdhK256Ciphertext,
    EcdhK256PublicKey,
    EcdhK256SecretKey,
    EcdhK256SharedSecret,
    // Note: dcrypt might not have P384/P521 implementations yet
    // This is a simplified version using only K256
};
use rand::{CryptoRng, RngCore};

/// ECDH curve type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdhCurve {
    /// NIST P-256 curve (128-bit security) - using K256 (secp256k1) as substitute
    P256,
    /// NIST P-384 curve (192-bit security) - not available in dcrypt
    P384,
    /// NIST P-521 curve (256-bit security) - not available in dcrypt
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
    curve: EcdhCurve,
}

/// ECDH public key wrapper
#[derive(Clone)]
pub enum EcdhPublicKey {
    K256(EcdhK256PublicKey),
    // P384 and P521 would need their own dcrypt implementations
    P384(Vec<u8>), // Placeholder
    P521(Vec<u8>), // Placeholder
}

/// ECDH private key wrapper
#[derive(Clone)]
pub enum EcdhPrivateKey {
    K256(EcdhK256SecretKey),
    // P384 and P521 would need their own dcrypt implementations
    P384(Vec<u8>), // Placeholder
    P521(Vec<u8>), // Placeholder
}

/// ECDH encapsulated key
pub struct EcdhEncapsulated {
    /// Ciphertext
    ciphertext: Vec<u8>,
    /// Shared secret
    shared_secret: Vec<u8>,
    /// Curve type
    curve: EcdhCurve,
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

    fn generate_keypair(&self) -> Self::KeyPair {
        let mut rng = rand::thread_rng();
        
        match self.curve {
            EcdhCurve::P256 => {
                // Use K256 from dcrypt
                let (pk, sk) = EcdhK256::keypair(&mut rng)
                    .expect("Failed to generate K256 keypair");
                EcdhKeyPair {
                    public_key: EcdhPublicKey::K256(pk),
                    private_key: EcdhPrivateKey::K256(sk),
                    curve: self.curve,
                }
            }
            EcdhCurve::P384 | EcdhCurve::P521 => {
                // Not implemented in dcrypt yet
                panic!("P384 and P521 curves are not yet implemented in dcrypt");
            }
        }
    }

    fn encapsulate(&self, public_key: &Self::PublicKey) -> Self::Encapsulated {
        let mut rng = rand::thread_rng();
        
        match (self.curve, public_key) {
            (EcdhCurve::P256, EcdhPublicKey::K256(pk)) => {
                let (ct, ss) = EcdhK256::encapsulate(&mut rng, pk)
                    .expect("Failed to encapsulate with K256");
                
                EcdhEncapsulated {
                    ciphertext: ct.to_bytes(),
                    shared_secret: ss.to_bytes(),
                    curve: EcdhCurve::P256,
                }
            }
            _ => panic!("Curve mismatch or unsupported curve in encapsulation"),
        }
    }

    fn decapsulate(
        &self,
        private_key: &Self::PrivateKey,
        encapsulated: &Self::Encapsulated,
    ) -> Option<Vec<u8>> {
        match (self.curve, private_key) {
            (EcdhCurve::P256, EcdhPrivateKey::K256(sk)) => {
                // Reconstruct the ciphertext from bytes
                let ct = EcdhK256Ciphertext::from_bytes(&encapsulated.ciphertext)
                    .ok()?;
                
                let ss = EcdhK256::decapsulate(sk, &ct)
                    .ok()?;
                
                Some(ss.to_bytes())
            }
            _ => None,
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

// EcdhPublicKey implements the EncapsulationKey trait
impl SerializableKey for EcdhPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            EcdhPublicKey::K256(pk) => pk.to_bytes(),
            EcdhPublicKey::P384(bytes) => bytes.clone(),
            EcdhPublicKey::P521(bytes) => bytes.clone(),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Try to determine the curve from the public key size
        match bytes.len() {
            33 => {
                // K256 compressed point
                let pk = EcdhK256PublicKey::from_bytes(bytes)
                    .map_err(|e| format!("Failed to deserialize K256 public key: {:?}", e))?;
                Ok(EcdhPublicKey::K256(pk))
            }
            49 => Ok(EcdhPublicKey::P384(bytes.to_vec())),
            67 => Ok(EcdhPublicKey::P521(bytes.to_vec())),
            _ => Err(format!("Invalid ECDH public key size: {}", bytes.len())),
        }
    }
}

impl EncapsulationKey for EcdhPublicKey {
    // EncapsulationKey trait has no additional methods beyond SerializableKey
}

// EcdhPrivateKey implements the DecapsulationKey trait
impl SerializableKey for EcdhPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            EcdhPrivateKey::K256(sk) => sk.to_bytes().to_vec(),
            EcdhPrivateKey::P384(bytes) => bytes.clone(),
            EcdhPrivateKey::P521(bytes) => bytes.clone(),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Try to determine the curve from the private key size
        match bytes.len() {
            32 => {
                // K256 scalar
                let sk = EcdhK256SecretKey::from_bytes(bytes)
                    .map_err(|e| format!("Failed to deserialize K256 private key: {:?}", e))?;
                Ok(EcdhPrivateKey::K256(sk))
            }
            48 => Ok(EcdhPrivateKey::P384(bytes.to_vec())),
            66 => Ok(EcdhPrivateKey::P521(bytes.to_vec())),
            _ => Err(format!("Invalid ECDH private key size: {}", bytes.len())),
        }
    }
}

impl DecapsulationKey for EcdhPrivateKey {
    // DecapsulationKey trait has no additional methods beyond SerializableKey
}

// EcdhEncapsulated implements the Encapsulated trait
impl SerializableKey for EcdhEncapsulated {
    fn to_bytes(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Try to determine the curve from the ciphertext size
        let curve = match bytes.len() {
            33 => EcdhCurve::P256,
            49 => EcdhCurve::P384,
            67 => EcdhCurve::P521,
            _ => return Err(format!("Invalid ECDH ciphertext size: {}", bytes.len())),
        };

        // We can't recover the shared secret from just the ciphertext
        // This will need to be decapsulated using a private key to get the shared secret
        Ok(EcdhEncapsulated {
            ciphertext: bytes.to_vec(),
            shared_secret: vec![0; 32], // Placeholder until decapsulated
            curve,
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