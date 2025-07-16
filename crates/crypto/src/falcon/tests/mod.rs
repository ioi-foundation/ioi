// crates/crypto/src/falcon/tests/mod.rs
use super::*;
use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{KeyPair, PrivateKey, PublicKey, Signature};

#[test]
fn test_falcon_keypair_generation() {
    // Test all valid security levels for Falcon
    let levels = vec![SecurityLevel::Level1, SecurityLevel::Level5];

    for level in levels {
        let scheme = FalconScheme::new(level);
        let keypair = scheme.generate_keypair();

        // Verify key sizes match the expected sizes for the security level
        match level {
            SecurityLevel::Level1 => {
                assert_eq!(keypair.public_key.0.len(), 897); // Falcon-512
                assert_eq!(keypair.private_key.0.len(), 1281); // Falcon-512
            }
            SecurityLevel::Level5 => {
                assert_eq!(keypair.public_key.0.len(), 1793); // Falcon-1024
                assert_eq!(keypair.private_key.0.len(), 2305); // Falcon-1024
            }
            _ => panic!("Unexpected security level"),
        }

        // Ensure keys are different
        assert_ne!(keypair.public_key.0, keypair.private_key.0);
    }
}

#[test]
fn test_falcon_sign_verify() {
    // Test all valid security levels
    let levels = vec![SecurityLevel::Level1, SecurityLevel::Level5];

    for level in levels {
        let scheme = FalconScheme::new(level);
        let keypair = scheme.generate_keypair();
        let message = b"This is a test message for Falcon signature";

        // Sign using scheme
        let signature = scheme.sign(&keypair.private_key, message);

        // Verify using scheme
        assert!(scheme.verify(&keypair.public_key, message, &signature));

        // Verify with wrong message should fail
        let wrong_message = b"This is a different message";
        assert!(!scheme.verify(&keypair.public_key, wrong_message, &signature));
    }
}

#[test]
fn test_falcon_serialization() {
    let scheme = FalconScheme::new(SecurityLevel::Level1);
    let keypair = scheme.generate_keypair();
    let message = b"Testing serialization";

    // Serialize keys
    let public_key_bytes = keypair.public_key.to_bytes();
    let private_key_bytes = keypair.private_key.to_bytes();

    // Deserialize keys
    let restored_public_key = FalconPublicKey::from_bytes(&public_key_bytes).unwrap();
    let restored_private_key = FalconPrivateKey::from_bytes(&private_key_bytes).unwrap();

    // Test with restored keys
    let signature = scheme.sign(&restored_private_key, message);
    assert!(scheme.verify(&restored_public_key, message, &signature));

    // Serialize signature
    let signature_bytes = signature.to_bytes();

    // Deserialize signature
    let restored_signature = FalconSignature::from_bytes(&signature_bytes).unwrap();

    // Verify with restored signature
    assert!(scheme.verify(&keypair.public_key, message, &restored_signature));
}

// Add these tests to crates/crypto/src/falcon/tests/mod.rs

#[test]
fn test_falcon_keypair_interface() {
    // Test the KeyPair trait implementation
    let scheme = FalconScheme::new(SecurityLevel::Level1);
    let keypair = scheme.generate_keypair();
    let message = b"Testing KeyPair trait";

    // Get keys using trait methods
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();

    // Sign using KeyPair trait
    let signature = keypair.sign(message);

    // Verify using PublicKey trait
    assert!(public_key.verify(message, &signature));

    // Verify with wrong message
    let wrong_message = b"Wrong message";
    assert!(!public_key.verify(wrong_message, &signature));
}

#[test]
fn test_falcon_empty_message() {
    // Test signing an empty message
    let scheme = FalconScheme::new(SecurityLevel::Level1);
    let keypair = scheme.generate_keypair();
    let message = b"";

    // Sign using scheme
    let signature = scheme.sign(&keypair.private_key, message);

    // Verify using scheme
    assert!(scheme.verify(&keypair.public_key, message, &signature));
}

#[test]
fn test_falcon_large_message() {
    // Test signing a large message
    let scheme = FalconScheme::new(SecurityLevel::Level1);
    let keypair = scheme.generate_keypair();

    // Create a large message (10KB)
    let large_message = vec![0xAB; 10 * 1024];

    // Sign and verify large message
    let signature = scheme.sign(&keypair.private_key, &large_message);
    assert!(scheme.verify(&keypair.public_key, &large_message, &signature));
}

#[test]
fn test_falcon_cross_security_levels() {
    // Test that signatures from one security level cannot be verified by another
    let scheme_level1 = FalconScheme::new(SecurityLevel::Level1);
    let scheme_level5 = FalconScheme::new(SecurityLevel::Level5);

    let keypair_level1 = scheme_level1.generate_keypair();
    let keypair_level5 = scheme_level5.generate_keypair();

    let message = b"Test message for cross-level verification";

    // Sign with Level1 key
    let signature_level1 = scheme_level1.sign(&keypair_level1.private_key, message);

    // Sign with Level5 key
    let signature_level5 = scheme_level5.sign(&keypair_level5.private_key, message);

    // Verify signatures with correct public keys
    assert!(scheme_level1.verify(&keypair_level1.public_key, message, &signature_level1));
    assert!(scheme_level5.verify(&keypair_level5.public_key, message, &signature_level5));

    // Cross-verification should fail due to different key sizes
    assert!(!scheme_level1.verify(&keypair_level5.public_key, message, &signature_level1));
    assert!(!scheme_level5.verify(&keypair_level1.public_key, message, &signature_level5));
}

#[test]
fn test_falcon_deterministic_signing() {
    // Test that signing the same message with the same key produces the same signature
    let scheme = FalconScheme::new(SecurityLevel::Level1);
    let keypair = scheme.generate_keypair();
    let message = b"Test deterministic signing";

    // Sign the message twice
    let signature1 = scheme.sign(&keypair.private_key, message);
    let signature2 = scheme.sign(&keypair.private_key, message);

    // The signatures should be identical for deterministic signing
    assert_eq!(signature1.to_bytes(), signature2.to_bytes());
}
