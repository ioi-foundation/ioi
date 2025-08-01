// crates/crypto/src/kem/hybrid/tests/mod.rs
use super::*;
use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{Encapsulated, KeyEncapsulation};

#[test]
fn test_hybrid_keypair_generation() {
    let kem = HybridKEM::new(SecurityLevel::Level3);
    let keypair = kem.generate_keypair();

    // Verify key sizes match the expected sizes
    // ECDH K256 (33) + Kyber768 (1184) = 1217
    assert_eq!(keypair.public_key.to_bytes().len(), 1217);
    // ECDH K256 (32) + Kyber768 (2400) = 2432
    assert_eq!(keypair.private_key.to_bytes().len(), 2432);

    // Ensure keys are different
    assert_ne!(
        keypair.public_key.to_bytes(),
        keypair.private_key.to_bytes()
    );
}

#[test]
#[should_panic(expected = "Hybrid KEM currently only supports Level3 security")]
fn test_hybrid_unsupported_security_levels() {
    // Test Level1
    let _ = HybridKEM::new(SecurityLevel::Level1);
}

#[test]
#[should_panic(expected = "Hybrid KEM currently only supports Level3 security")]
fn test_hybrid_unsupported_security_level5() {
    // Test Level5
    let _ = HybridKEM::new(SecurityLevel::Level5);
}

#[test]
fn test_hybrid_encapsulation() {
    let kem = HybridKEM::new(SecurityLevel::Level3);
    let keypair = kem.generate_keypair();

    // Encapsulate a key
    let encapsulated = kem.encapsulate(&keypair.public_key);

    // Verify the encapsulated data sizes
    // ECDH K256 (33) + Kyber768 (1088) = 1121
    assert_eq!(encapsulated.ciphertext().len(), 1121);
    // Combined shared secret should be 32 bytes (HKDF output)
    assert_eq!(encapsulated.shared_secret().len(), 32);

    // Decapsulate and verify
    let shared_secret = kem.decapsulate(&keypair.private_key, &encapsulated);

    // We should get a valid shared secret
    assert!(shared_secret.is_some());
    let shared_secret = shared_secret.unwrap();

    // The shared secret should match what's in the encapsulated key
    assert_eq!(shared_secret, encapsulated.shared_secret());
    assert_eq!(shared_secret.len(), 32);
}

#[test]
fn test_hybrid_multiple_encapsulations() {
    let kem = HybridKEM::new(SecurityLevel::Level3);
    let keypair = kem.generate_keypair();

    // Multiple encapsulations with the same public key should produce different results
    let encapsulated1 = kem.encapsulate(&keypair.public_key);
    let encapsulated2 = kem.encapsulate(&keypair.public_key);

    // Ciphertexts should be different due to randomness
    assert_ne!(encapsulated1.ciphertext(), encapsulated2.ciphertext());
    // Shared secrets should be different
    assert_ne!(encapsulated1.shared_secret(), encapsulated2.shared_secret());

    // But both should decapsulate correctly
    let shared_secret1 = kem
        .decapsulate(&keypair.private_key, &encapsulated1)
        .unwrap();
    let shared_secret2 = kem
        .decapsulate(&keypair.private_key, &encapsulated2)
        .unwrap();

    assert_eq!(shared_secret1, encapsulated1.shared_secret());
    assert_eq!(shared_secret2, encapsulated2.shared_secret());
}

#[test]
fn test_hybrid_wrong_key_decapsulation() {
    let kem = HybridKEM::new(SecurityLevel::Level3);
    let keypair1 = kem.generate_keypair();
    let keypair2 = kem.generate_keypair();

    // Encapsulate with keypair1's public key
    let encapsulated = kem.encapsulate(&keypair1.public_key);

    // Try to decapsulate with keypair2's private key
    let wrong_shared_secret = kem.decapsulate(&keypair2.private_key, &encapsulated);

    // Should still produce a result (KEMs don't fail on wrong key)
    assert!(wrong_shared_secret.is_some());
    // But it should be different from the correct shared secret
    assert_ne!(wrong_shared_secret.unwrap(), encapsulated.shared_secret());
}

#[test]
fn test_hybrid_serialization() {
    let kem = HybridKEM::new(SecurityLevel::Level3);
    let keypair = kem.generate_keypair();

    // Serialize keys
    let public_key_bytes = keypair.public_key.to_bytes();
    let private_key_bytes = keypair.private_key.to_bytes();

    // Deserialize keys
    let _restored_public_key = HybridPublicKey::from_bytes(&public_key_bytes).unwrap();
    let restored_private_key = HybridPrivateKey::from_bytes(&private_key_bytes).unwrap();

    // Encapsulate with original key
    let encapsulated = kem.encapsulate(&keypair.public_key);
    let ciphertext_bytes = encapsulated.to_bytes();

    // Deserialize ciphertext
    let restored_encapsulated = HybridEncapsulated::from_bytes(&ciphertext_bytes).unwrap();

    // Decapsulate with restored key and restored ciphertext
    let shared_secret = kem.decapsulate(&restored_private_key, &restored_encapsulated);

    // We should still get a valid shared secret
    assert!(shared_secret.is_some());

    // Verify the original encapsulated ciphertext matches the serialized version
    assert_eq!(
        encapsulated.ciphertext(),
        restored_encapsulated.ciphertext()
    );
}

#[test]
fn test_hybrid_invalid_serialization() {
    // Test invalid public key sizes
    let too_short_pk = vec![0u8; 100];
    assert!(HybridPublicKey::from_bytes(&too_short_pk).is_err());

    let too_long_pk = vec![0u8; 2000];
    assert!(HybridPublicKey::from_bytes(&too_long_pk).is_err());

    // Test invalid private key sizes
    let too_short_sk = vec![0u8; 100];
    assert!(HybridPrivateKey::from_bytes(&too_short_sk).is_err());

    let too_long_sk = vec![0u8; 3000];
    assert!(HybridPrivateKey::from_bytes(&too_long_sk).is_err());

    // Test invalid ciphertext sizes
    let too_short_ct = vec![0u8; 100];
    assert!(HybridEncapsulated::from_bytes(&too_short_ct).is_err());

    let too_long_ct = vec![0u8; 2000];
    assert!(HybridEncapsulated::from_bytes(&too_long_ct).is_err());
}

#[test]
fn test_hybrid_security_properties() {
    let kem = HybridKEM::new(SecurityLevel::Level3);
    let keypair = kem.generate_keypair();

    // Test that the shared secret is deterministic for a given ciphertext
    let encapsulated = kem.encapsulate(&keypair.public_key);

    // Multiple decapsulations of the same ciphertext should produce the same result
    let shared_secret1 = kem
        .decapsulate(&keypair.private_key, &encapsulated)
        .unwrap();
    let shared_secret2 = kem
        .decapsulate(&keypair.private_key, &encapsulated)
        .unwrap();

    assert_eq!(shared_secret1, shared_secret2);
}

#[test]
fn test_hybrid_default_constructor() {
    let kem = HybridKEM::default();
    let keypair = kem.generate_keypair();

    // Should use Level3 by default
    assert_eq!(keypair.public_key.level, SecurityLevel::Level3);

    // Should work normally
    let encapsulated = kem.encapsulate(&keypair.public_key);
    let shared_secret = kem.decapsulate(&keypair.private_key, &encapsulated);

    assert!(shared_secret.is_some());
    assert_eq!(shared_secret.unwrap(), encapsulated.shared_secret());
}

#[test]
fn test_hybrid_independent_verification() {
    // Test that keys can be used independently after serialization
    let kem = HybridKEM::new(SecurityLevel::Level3);
    let keypair = kem.generate_keypair();

    // Serialize and deserialize to ensure independence
    let pk_bytes = keypair.public_key.to_bytes();
    let sk_bytes = keypair.private_key.to_bytes();

    let pk = HybridPublicKey::from_bytes(&pk_bytes).unwrap();
    let sk = HybridPrivateKey::from_bytes(&sk_bytes).unwrap();

    // Use the deserialized keys
    let encapsulated = kem.encapsulate(&pk);
    let shared_secret = kem.decapsulate(&sk, &encapsulated);

    assert!(shared_secret.is_some());
    assert_eq!(shared_secret.unwrap(), encapsulated.shared_secret());
}
