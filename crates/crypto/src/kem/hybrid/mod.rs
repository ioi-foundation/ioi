// Path: crates/crypto/src/kem/hybrid/mod.rs
use crate::security::SecurityLevel;
use dcrypt::api::Kem;
use dcrypt::prelude::{Serialize, SerializeSecret};
use depin_sdk_api::crypto::{
    DecapsulationKey, Encapsulated, EncapsulationKey, KemKeyPair, KeyEncapsulation, SerializableKey,
};

// --- FIX: NO LONGER IMPORT FROM `engine` ---
// We only import the concrete, public KEMs and their associated types.
use dcrypt::hybrid::kem::{EcdhP256Kyber512, EcdhP256Kyber768, EcdhP384Kyber1024};
use rand::thread_rng;

/// Hybrid key encapsulation mechanism
pub struct HybridKEM {
    level: SecurityLevel,
}

/// Hybrid key pair
pub struct HybridKeyPair {
    pub public_key: HybridPublicKey,
    pub private_key: HybridPrivateKey,
    _level: SecurityLevel,
}

/// Hybrid public key wrapper (holds serialized key)
#[derive(Clone)]
pub struct HybridPublicKey {
    bytes: Vec<u8>,
    level: SecurityLevel,
}

/// Hybrid private key wrapper (holds serialized key)
#[derive(Clone)]
pub struct HybridPrivateKey {
    bytes: Vec<u8>,
    _level: SecurityLevel,
}

/// Hybrid encapsulated key (holds serialized ciphertext)
pub struct HybridEncapsulated {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
    _level: SecurityLevel,
}

impl HybridKEM {
    pub fn new(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::Level1 | SecurityLevel::Level3 | SecurityLevel::Level5 => Self { level },
            _ => panic!("Hybrid KEM only supports Level 1, 3, and 5 security"),
        }
    }
}

impl Default for HybridKEM {
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

        let (pk_bytes, sk_bytes) = match self.level {
            SecurityLevel::Level1 => {
                let (pk, sk) =
                    EcdhP256Kyber512::keypair(&mut rng).expect("Failed to generate L1 keypair");
                (pk.to_bytes(), sk.to_bytes_zeroizing().to_vec())
            }
            SecurityLevel::Level3 => {
                let (pk, sk) =
                    EcdhP256Kyber768::keypair(&mut rng).expect("Failed to generate L3 keypair");
                (pk.to_bytes(), sk.to_bytes_zeroizing().to_vec())
            }
            SecurityLevel::Level5 => {
                let (pk, sk) =
                    EcdhP384Kyber1024::keypair(&mut rng).expect("Failed to generate L5 keypair");
                (pk.to_bytes(), sk.to_bytes_zeroizing().to_vec())
            }
            _ => unreachable!(),
        };

        HybridKeyPair {
            public_key: HybridPublicKey {
                bytes: pk_bytes,
                level: self.level,
            },
            private_key: HybridPrivateKey {
                bytes: sk_bytes,
                _level: self.level,
            },
            _level: self.level,
        }
    }

    fn encapsulate(&self, public_key: &Self::PublicKey) -> Self::Encapsulated {
        let mut rng = thread_rng();

        let (ct_bytes, ss_bytes) = match public_key.level {
            SecurityLevel::Level1 => {
                let pk =
                    <EcdhP256Kyber512 as Kem>::PublicKey::from_bytes(&public_key.bytes).unwrap();
                let (ct, ss) = EcdhP256Kyber512::encapsulate(&mut rng, &pk)
                    .expect("Failed to encapsulate with L1 hybrid KEM");
                (ct.to_bytes(), ss.to_bytes_zeroizing().to_vec())
            }
            SecurityLevel::Level3 => {
                let pk =
                    <EcdhP256Kyber768 as Kem>::PublicKey::from_bytes(&public_key.bytes).unwrap();
                let (ct, ss) = EcdhP256Kyber768::encapsulate(&mut rng, &pk)
                    .expect("Failed to encapsulate with L3 hybrid KEM");
                (ct.to_bytes(), ss.to_bytes_zeroizing().to_vec())
            }
            SecurityLevel::Level5 => {
                let pk =
                    <EcdhP384Kyber1024 as Kem>::PublicKey::from_bytes(&public_key.bytes).unwrap();
                let (ct, ss) = EcdhP384Kyber1024::encapsulate(&mut rng, &pk)
                    .expect("Failed to encapsulate with L5 hybrid KEM");
                (ct.to_bytes(), ss.to_bytes_zeroizing().to_vec())
            }
            _ => unreachable!(),
        };

        HybridEncapsulated {
            ciphertext: ct_bytes,
            shared_secret: ss_bytes,
            _level: public_key.level,
        }
    }

    fn decapsulate(
        &self,
        private_key: &Self::PrivateKey,
        encapsulated: &Self::Encapsulated,
    ) -> Option<Vec<u8>> {
        let ss_bytes = match private_key._level {
            SecurityLevel::Level1 => {
                // FIX: Use the now-functional from_bytes methods from dcrypt's public API
                let sk =
                    <EcdhP256Kyber512 as Kem>::SecretKey::from_bytes(&private_key.bytes).ok()?;
                let ct =
                    <EcdhP256Kyber512 as Kem>::Ciphertext::from_bytes(&encapsulated.ciphertext)
                        .ok()?;
                EcdhP256Kyber512::decapsulate(&sk, &ct)
                    .ok()?
                    .to_bytes_zeroizing()
                    .to_vec()
            }
            SecurityLevel::Level3 => {
                // FIX: Use the now-functional from_bytes methods from dcrypt's public API
                let sk =
                    <EcdhP256Kyber768 as Kem>::SecretKey::from_bytes(&private_key.bytes).ok()?;
                let ct =
                    <EcdhP256Kyber768 as Kem>::Ciphertext::from_bytes(&encapsulated.ciphertext)
                        .ok()?;
                EcdhP256Kyber768::decapsulate(&sk, &ct)
                    .ok()?
                    .to_bytes_zeroizing()
                    .to_vec()
            }
            SecurityLevel::Level5 => {
                // FIX: Use the now-functional from_bytes methods from dcrypt's public API
                let sk =
                    <EcdhP384Kyber1024 as Kem>::SecretKey::from_bytes(&private_key.bytes).ok()?;
                let ct =
                    <EcdhP384Kyber1024 as Kem>::Ciphertext::from_bytes(&encapsulated.ciphertext)
                        .ok()?;
                EcdhP384Kyber1024::decapsulate(&sk, &ct)
                    .ok()?
                    .to_bytes_zeroizing()
                    .to_vec()
            }
            _ => return None,
        };
        Some(ss_bytes)
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

impl SerializableKey for HybridPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let level = match bytes.len() {
            // EcdhP256 (33) + Kyber512 (800)
            833 => SecurityLevel::Level1,
            // EcdhP256 (33) + Kyber768 (1184)
            1217 => SecurityLevel::Level3,
            // EcdhP384 (49) + Kyber1024 (1568)
            1617 => SecurityLevel::Level5,
            _ => return Err(format!("Invalid hybrid public key size: {}", bytes.len())),
        };
        Ok(HybridPublicKey {
            bytes: bytes.to_vec(),
            level,
        })
    }
}

impl EncapsulationKey for HybridPublicKey {}

impl SerializableKey for HybridPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let level = match bytes.len() {
            // EcdhP256 (32) + Kyber512 (1632)
            1664 => SecurityLevel::Level1,
            // EcdhP256 (32) + Kyber768 (2400)
            2432 => SecurityLevel::Level3,
            // EcdhP384 (48) + Kyber1024 (3168)
            3216 => SecurityLevel::Level5,
            _ => return Err(format!("Invalid hybrid private key size: {}", bytes.len())),
        };
        Ok(HybridPrivateKey {
            bytes: bytes.to_vec(),
            _level: level,
        })
    }
}

impl DecapsulationKey for HybridPrivateKey {}

impl SerializableKey for HybridEncapsulated {
    fn to_bytes(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let level = match bytes.len() {
            // EcdhP256 (33) + Kyber512 (768)
            801 => SecurityLevel::Level1,
            // EcdhP256 (33) + Kyber768 (1088)
            1121 => SecurityLevel::Level3,
            // EcdhP384 (49) + Kyber1024 (1568)
            1617 => SecurityLevel::Level5,
            _ => return Err(format!("Invalid hybrid ciphertext size: {}", bytes.len())),
        };
        Ok(HybridEncapsulated {
            ciphertext: bytes.to_vec(),
            shared_secret: vec![],
            _level: level,
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

#[cfg(test)]
mod tests;
