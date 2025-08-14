// Path: crates/crypto/src/kem/hybrid/ecdh_kyber.rs

//! ECDH-Kyber hybrid key encapsulation mechanism
//!
//! This module provides specific, named type aliases for the generalized HybridKEM,
//! mapping them to different NIST security levels.

use super::{HybridEncapsulated, HybridKEM, HybridKeyPair, HybridPrivateKey, HybridPublicKey};

// --- NIST Level 1 ---

/// ECDH-P256 + Kyber512 hybrid KEM (NIST Level 1).
///
/// A convenience type alias for `HybridKEM` configured with `SecurityLevel::Level1`.
pub type EcdhP256Kyber512 = HybridKEM;
/// A key pair for the `EcdhP256Kyber512` scheme.
pub type EcdhP256Kyber512KeyPair = HybridKeyPair;
/// A public key for the `EcdhP256Kyber512` scheme.
pub type EcdhP256Kyber512PublicKey = HybridPublicKey;
/// A private key for the `EcdhP256Kyber512` scheme.
pub type EcdhP256Kyber512PrivateKey = HybridPrivateKey;
/// An encapsulated ciphertext for the `EcdhP256Kyber512` scheme.
pub type EcdhP256Kyber512Encapsulated = HybridEncapsulated;

// --- NIST Level 3 ---

/// ECDH-P256 + Kyber768 hybrid KEM (NIST Level 3).
///
/// A convenience type alias for `HybridKEM` configured with `SecurityLevel::Level3`.
pub type EcdhP256Kyber768 = HybridKEM;
/// A key pair for the `EcdhP256Kyber768` scheme.
pub type EcdhP256Kyber768KeyPair = HybridKeyPair;
/// A public key for the `EcdhP256Kyber768` scheme.
pub type EcdhP256Kyber768PublicKey = HybridPublicKey;
/// A private key for the `EcdhP256Kyber768` scheme.
pub type EcdhP256Kyber768PrivateKey = HybridPrivateKey;
/// An encapsulated ciphertext for the `EcdhP256Kyber768` scheme.
pub type EcdhP256Kyber768Encapsulated = HybridEncapsulated;

// --- NIST Level 5 ---

/// ECDH-P384 + Kyber1024 hybrid KEM (NIST Level 5).
///
/// A convenience type alias for `HybridKEM` configured with `SecurityLevel::Level5`.
pub type EcdhP384Kyber1024 = HybridKEM;
/// A key pair for the `EcdhP384Kyber1024` scheme.
pub type EcdhP384Kyber1024KeyPair = HybridKeyPair;
/// A public key for the `EcdhP384Kyber1024` scheme.
pub type EcdhP384Kyber1024PublicKey = HybridPublicKey;
/// A private key for the `EcdhP384Kyber1024` scheme.
pub type EcdhP384Kyber1024PrivateKey = HybridPrivateKey;
/// An encapsulated ciphertext for the `EcdhP384Kyber1024` scheme.
pub type EcdhP384Kyber1024Encapsulated = HybridEncapsulated;
