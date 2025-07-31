// Path: crates/crypto/src/kem/hybrid/ecdh_kyber.rs
// Change: Removed unused imports.

//! ECDH-Kyber hybrid key encapsulation mechanism
//!
//! This module provides specific hybrid combinations of ECDH and Kyber KEMs.

use super::{HybridEncapsulated, HybridKEM, HybridKeyPair, HybridPrivateKey, HybridPublicKey};

/// ECDH-P256 + Kyber768 hybrid KEM
///
/// Provides Level3 security by combining:
/// - ECDH on P-256 curve (128-bit classical security)
/// - Kyber768 (192-bit post-quantum security)
///
/// This is a convenience type alias for HybridKEM configured with Level3 security.
pub type EcdhP256Kyber768 = HybridKEM;

/// ECDH-P256 + Kyber768 key pair
pub type EcdhP256Kyber768KeyPair = HybridKeyPair;

/// ECDH-P256 + Kyber768 public key
pub type EcdhP256Kyber768PublicKey = HybridPublicKey;

/// ECDH-P256 + Kyber768 private key
pub type EcdhP256Kyber768PrivateKey = HybridPrivateKey;

/// ECDH-P256 + Kyber768 encapsulated ciphertext
pub type EcdhP256Kyber768Encapsulated = HybridEncapsulated;

// Note: EcdhP256Kyber768 is a type alias for HybridKEM and inherits all its methods.
// To create an instance, use: HybridKEM::new(SecurityLevel::Level3)
// or HybridKEM::default() which defaults to Level3.

// Future implementations could include:
// - EcdhP256Kyber512 for Level1 security
// - EcdhP521Kyber1024 for Level5 security