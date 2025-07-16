use crate::dilithium::{
    DilithiumKeyPair, DilithiumPrivateKey, DilithiumPublicKey, DilithiumScheme, DilithiumSignature,
};

use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{KeyPair, PrivateKey, PublicKey, Signature};

#[test]
pub fn test_dilithium_keypair_generation() {
    // Test all security levels
    let levels = vec![
        SecurityLevel::Level2,
        SecurityLevel::Level3,
        SecurityLevel::Level5,
    ];

    for level in levels {
        let scheme = DilithiumScheme::new(level);
        let keypair = scheme.generate_keypair();

        // Verify key sizes match the expected sizes for the security level
        match level {
            SecurityLevel::Level2 => {
                assert_eq!(keypair.public_key.0.len(), 1312);
                assert_eq!(keypair.private_key.0.len(), 2560); // Updated from 2528 to 2560
            }
            SecurityLevel::Level3 => {
                assert_eq!(keypair.public_key.0.len(), 1952);
                assert_eq!(keypair.private_key.0.len(), 4032); // Updated from 4000 to 4032
            }
            SecurityLevel::Level5 => {
                assert_eq!(keypair.public_key.0.len(), 2592);
                assert_eq!(keypair.private_key.0.len(), 4896); // Updated from 4864 to 4896
            }
            _ => panic!("Unexpected security level"),
        }

        // Ensure keys are different
        assert_ne!(keypair.public_key.0, keypair.private_key.0);
    }
}

#[test]
pub fn test_dilithium_sign_verify() {
    // Test all security levels
    let levels = vec![
        SecurityLevel::Level2,
        SecurityLevel::Level3,
        SecurityLevel::Level5,
    ];

    for level in levels {
        let scheme = DilithiumScheme::new(level);
        let keypair = scheme.generate_keypair();
        let message = b"This is a test message for Dilithium signature";

        // Sign using scheme
        let signature = scheme.sign(&keypair.private_key, message);

        // Verify using scheme
        assert!(scheme.verify(&keypair.public_key, message, &signature));

        // Verify with wrong message
        let wrong_message = b"This is a different message";
        assert!(!scheme.verify(&keypair.public_key, wrong_message, &signature));
    }
}

#[test]
pub fn test_dilithium_keypair_interface() {
    // Test the KeyPair trait implementation
    let scheme = DilithiumScheme::new(SecurityLevel::Level2);
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
pub fn test_dilithium_serialization() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let keypair = scheme.generate_keypair();
    let message = b"Testing serialization";

    // Serialize keys
    let public_key_bytes = keypair.public_key.to_bytes();
    let private_key_bytes = keypair.private_key.to_bytes();

    // Deserialize keys
    let restored_public_key = DilithiumPublicKey::from_bytes(&public_key_bytes).unwrap();
    let restored_private_key = DilithiumPrivateKey::from_bytes(&private_key_bytes).unwrap();

    // Test with restored keys
    let signature = scheme.sign(&restored_private_key, message);
    assert!(scheme.verify(&restored_public_key, message, &signature));

    // Serialize signature
    let signature_bytes = signature.to_bytes();

    // Deserialize signature
    let restored_signature = DilithiumSignature::from_bytes(&signature_bytes).unwrap();

    // Verify with restored signature
    assert!(scheme.verify(&keypair.public_key, message, &restored_signature));
}

#[test]
pub fn test_large_message_signing() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let keypair = scheme.generate_keypair();

    // Create a medium-sized message (10KB) to keep test runtime reasonable
    let large_message = vec![0xAB; 10 * 1024];

    // Sign and verify large message
    let signature = scheme.sign(&keypair.private_key, &large_message);
    assert!(scheme.verify(&keypair.public_key, &large_message, &signature));
}

#[test]
pub fn test_keypair_from_known_keys() {
    // First generate a keypair
    let scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let original_keypair = scheme.generate_keypair();

    // Extract keys
    let public_bytes = original_keypair.public_key.to_bytes();
    let private_bytes = original_keypair.private_key.to_bytes();

    // Create new keys from bytes
    let public_key = DilithiumPublicKey::from_bytes(&public_bytes).unwrap();
    let private_key = DilithiumPrivateKey::from_bytes(&private_bytes).unwrap();

    // Manually reconstruct a keypair
    let reconstructed_keypair = DilithiumKeyPair {
        public_key,
        private_key,
    };

    // Test the reconstructed keypair
    let message = b"Testing reconstructed keypair";
    let signature = reconstructed_keypair.sign(message);

    assert!(scheme.verify(&reconstructed_keypair.public_key, message, &signature));
}
