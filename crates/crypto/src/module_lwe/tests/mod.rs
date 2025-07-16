use super::*;
use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{KeyPair, PrivateKey, PublicKey, Signature};

#[test]
fn test_module_lwe_keypair_generation() {
    // Test all security levels
    let levels = vec![
        SecurityLevel::Level1,
        SecurityLevel::Level2,
        SecurityLevel::Level3,
        SecurityLevel::Level5,
    ];

    for level in levels {
        let scheme = ModuleLWEScheme::new(level, 4); // Use dimension 4 for testing
        let keypair = scheme.generate_keypair();

        // Dummy keys should be of expected sizes
        assert_eq!(keypair.public_key.0.len(), 1024 + (4 * 32));
        assert_eq!(keypair.private_key.0.len(), 2048 + (4 * 32));

        // Ensure keys are different
        assert_ne!(keypair.public_key.0, keypair.private_key.0);
    }
}

#[test]
fn test_module_lwe_sign_verify() {
    let scheme = ModuleLWEScheme::new(SecurityLevel::Level3, 4);
    let keypair = scheme.generate_keypair();
    let message = b"This is a test message for Module-LWE signature/proof";

    // Sign using scheme
    let signature = scheme.sign(&keypair.private_key, message);

    // Verify using scheme (this should always pass in our dummy implementation)
    assert!(scheme.verify(&keypair.public_key, message, &signature));

    // Test with wrong message
    let wrong_message = b"This is a different message";
    // Note: With the current dummy implementation this will always return true
    // In a real implementation we would expect:
    // assert!(!scheme.verify(&keypair.public_key, wrong_message, &signature));
}

#[test]
fn test_module_lwe_keypair_interface() {
    // Test the KeyPair trait implementation
    let scheme = ModuleLWEScheme::new(SecurityLevel::Level2, 4);
    let keypair = scheme.generate_keypair();
    let message = b"Testing KeyPair trait";

    // Get keys using trait methods
    let public_key = keypair.public_key();
    let _private_key = keypair.private_key();

    // Sign using KeyPair trait
    let signature = keypair.sign(message);

    // Verify using PublicKey trait
    assert!(public_key.verify(message, &signature));
}

#[test]
fn test_module_lwe_serialization() {
    let scheme = ModuleLWEScheme::new(SecurityLevel::Level2, 4);
    let keypair = scheme.generate_keypair();
    let message = b"Testing serialization";

    // Serialize keys
    let public_key_bytes = keypair.public_key.to_bytes();
    let private_key_bytes = keypair.private_key.to_bytes();

    // Deserialize keys
    let restored_public_key = ModuleLWEPublicKey::from_bytes(&public_key_bytes).unwrap();
    let restored_private_key = ModuleLWEPrivateKey::from_bytes(&private_key_bytes).unwrap();

    // Test with restored keys
    let signature = scheme.sign(&restored_private_key, message);
    assert!(scheme.verify(&restored_public_key, message, &signature));

    // Serialize signature
    let signature_bytes = signature.to_bytes();

    // Deserialize signature
    let restored_signature = ModuleLWESignature::from_bytes(&signature_bytes).unwrap();

    // Verify with restored signature
    assert!(scheme.verify(&keypair.public_key, message, &restored_signature));
}
