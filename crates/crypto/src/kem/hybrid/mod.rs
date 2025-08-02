// Path: crates/crypto/src/kem/hybrid/mod.rs
use crate::security::SecurityLevel;
use depin_sdk_api::crypto::{
    DecapsulationKey, Encapsulated, EncapsulationKey, KemKeyPair, KeyEncapsulation, SerializableKey,
};

use dcrypt::api::Kem;
use dcrypt::kem::ecdh::p256::EcdhP256SecretKey;
use dcrypt::kem::kyber::KyberSecretKey;

use dcrypt::hybrid::kem::ecdh_kyber::{
    EcdhKyber768, HybridCiphertext, HybridPublicKey as DcryptHybridPublicKey,
    HybridSecretKey as DcryptHybridSecretKey,
};
use rand::thread_rng;

/// Hybrid key encapsulation mechanism
pub struct HybridKEM {
    /// Security level
    level: SecurityLevel,
}

/// Hybrid key pair
pub struct HybridKeyPair {
    /// Public key
    pub public_key: HybridPublicKey,
    /// Private key
    pub private_key: HybridPrivateKey,
    /// Security level
    _level: SecurityLevel,
}

/// Hybrid public key wrapper
#[derive(Clone)]
pub struct HybridPublicKey {
    /// The underlying dcrypt hybrid public key
    inner: DcryptHybridPublicKey,
    /// Security level
    level: SecurityLevel,
}

/// Hybrid private key wrapper
#[derive(Clone)]
pub struct HybridPrivateKey {
    /// The underlying dcrypt hybrid secret key
    inner: DcryptHybridSecretKey,
    /// Security level
    _level: SecurityLevel,
}

/// Hybrid encapsulated key
pub struct HybridEncapsulated {
    /// The ciphertext bytes
    ciphertext: Vec<u8>,
    /// The shared secret
    shared_secret: Vec<u8>,
    /// Security level
    _level: SecurityLevel,
}

impl HybridKEM {
    /// Create a new hybrid KEM with the specified security level
    ///
    /// Currently only supports Level3 (EcdhKyber768: ECDH P-256 + Kyber768)
    pub fn new(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::Level3 => Self { level },
            _ => panic!("Hybrid KEM currently only supports Level3 security"),
        }
    }
}

impl Default for HybridKEM {
    /// Create a new hybrid KEM with default security level (Level3)
    fn default() -> Self {
        Self::new(SecurityLevel::Level3)
    }
}

impl KeyEncapsulation for HybridKEM {
    type KeyPair = HybridKeyPair;
    type PublicKey = HybridPublicKey;
    type PrivateKey = HybridPrivateKey;
    type Encapsulated = HybridEncapsulated;

    fn generate_keypair(&self) -> Self::KeyPair {
        let mut rng = thread_rng();

        // Use dcrypt's hybrid KEM to generate keypair
        let (pk, sk) = EcdhKyber768::keypair(&mut rng).expect("Failed to generate hybrid keypair");

        HybridKeyPair {
            public_key: HybridPublicKey {
                inner: pk,
                level: self.level,
            },
            private_key: HybridPrivateKey {
                inner: sk,
                _level: self.level,
            },
            _level: self.level,
        }
    }

    fn encapsulate(&self, public_key: &Self::PublicKey) -> Self::Encapsulated {
        let mut rng = thread_rng();

        // Use dcrypt's hybrid KEM to encapsulate
        let (ct, ss) = EcdhKyber768::encapsulate(&mut rng, &public_key.inner)
            .expect("Failed to encapsulate with hybrid KEM");

        HybridEncapsulated {
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
        let ct = HybridCiphertext::from_bytes(&encapsulated.ciphertext).ok()?;

        // Use dcrypt's hybrid KEM to decapsulate
        let ss = EcdhKyber768::decapsulate(&private_key.inner, &ct).ok()?;

        Some(ss.to_bytes_zeroizing().to_vec())
    }
}

impl KemKeyPair for HybridKeyPair {
    type PublicKey = HybridPublicKey;
    type PrivateKey = HybridPrivateKey;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn private_key(&self) -> Self::PrivateKey {
        self.private_key.clone()
    }
}

// HybridPublicKey implements the EncapsulationKey trait
impl SerializableKey for HybridPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        // Use dcrypt's built-in to_bytes method
        self.inner.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Use dcrypt's built-in from_bytes method
        let inner = DcryptHybridPublicKey::from_bytes(bytes)
            .map_err(|e| format!("Failed to deserialize hybrid public key: {e:?}"))?;

        // For now, we only support Level3
        Ok(HybridPublicKey {
            inner,
            level: SecurityLevel::Level3,
        })
    }
}

impl EncapsulationKey for HybridPublicKey {}

// HybridPrivateKey implements the DecapsulationKey trait
impl SerializableKey for HybridPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        // Note: dcrypt's HybridSecretKey doesn't have a direct to_bytes method
        // We need to serialize the components
        [
            self.inner.ecdh_sk.to_bytes().to_vec(),
            self.inner.kyber_sk.to_bytes_zeroizing().to_vec(),
        ]
        .concat()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Expected sizes from dcrypt's implementation
        const ECDH_SK_LEN: usize = 32; // P-256 scalar
        const KYBER_SK_LEN: usize = 2400; // Kyber768
        const TOTAL_LEN: usize = ECDH_SK_LEN + KYBER_SK_LEN;

        if bytes.len() != TOTAL_LEN {
            return Err(format!(
                "Invalid hybrid private key size: expected {}, got {}",
                TOTAL_LEN,
                bytes.len()
            ));
        }

        let (ecdh_bytes, kyber_bytes) = bytes.split_at(ECDH_SK_LEN);

        let ecdh_sk = EcdhP256SecretKey::from_bytes(ecdh_bytes)
            .map_err(|e| format!("Failed to deserialize ECDH private key: {e:?}"))?;

        let kyber_sk = KyberSecretKey::from_bytes(kyber_bytes)
            .map_err(|e| format!("Failed to deserialize Kyber private key: {e:?}"))?;

        Ok(HybridPrivateKey {
            inner: DcryptHybridSecretKey { ecdh_sk, kyber_sk },
            _level: SecurityLevel::Level3,
        })
    }
}

impl DecapsulationKey for HybridPrivateKey {}

// HybridEncapsulated implements the Encapsulated trait
impl SerializableKey for HybridEncapsulated {
    fn to_bytes(&self) -> Vec<u8> {
        // Return the ciphertext bytes
        self.ciphertext.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Try to verify this is a valid hybrid ciphertext size
        // ECDH P-256 (33) + Kyber768 (1088) = 1121
        const EXPECTED_LEN: usize = 1121;

        if bytes.len() != EXPECTED_LEN {
            return Err(format!(
                "Invalid hybrid ciphertext size: expected {}, got {}",
                EXPECTED_LEN,
                bytes.len()
            ));
        }

        // We can't recover the shared secret from just the ciphertext
        // This will need to be decapsulated using a private key to get the shared secret
        Ok(HybridEncapsulated {
            ciphertext: bytes.to_vec(),
            shared_secret: vec![0; 32], // Placeholder until decapsulated
            _level: SecurityLevel::Level3,
        })
    }
}

impl Encapsulated for HybridEncapsulated {
    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }
}

pub mod ecdh_kyber;

// Re-export commonly used types
pub use ecdh_kyber::{
    EcdhP256Kyber768, EcdhP256Kyber768Encapsulated, EcdhP256Kyber768KeyPair,
    EcdhP256Kyber768PrivateKey, EcdhP256Kyber768PublicKey,
};

#[cfg(test)]
mod tests;
