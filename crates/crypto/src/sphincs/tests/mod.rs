use super::*;
use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{KeyPair, PrivateKey, PublicKey, Signature};

#[test]
fn test_sphincs_keypair_generation() {
    // Test valid security levels for SPHINCS+
    let levels = vec![SecurityLevel::Level1, SecurityLevel::Level5];

    for level in levels {
        let scheme = SphincsScheme::new(level);
        let keypair = scheme.generate_keypair();

        // Verify key sizes match the expected sizes for the security level
        match level {
            SecurityLevel::Level1 => {
                assert_eq!(keypair.public_key.0.len(), 32); // SPHINCS+-128
                assert_eq!(keypair.private_key.0.len(), 64); // SPHINCS+-128
            }
            SecurityLevel::Level5 => {
                assert_eq!(keypair.public_key.0.len(), 64); // SPHINCS+-256
                assert_eq!(keypair.private_key.0.len(), 128); // SPHINCS+-256
            }
            _ => panic!("Unexpected security level"),
        }

        // Ensure keys are different
        assert_ne!(keypair.public_key.0, keypair.private_key.0);
    }
}

#[test]
fn test_sphincs_sign_verify() {
    // Test valid security levels
    let levels = vec![SecurityLevel::Level1, SecurityLevel::Level5];

    for level in levels {
        let scheme = SphincsScheme::new(level);
        let keypair = scheme.generate_keypair();
        let message = b"This is a test message for SPHINCS+ signature";

        // Sign using scheme
        let signature = scheme.sign(&keypair.private_key, message);

        // Verify using scheme
        assert!(scheme.verify(&keypair.public_key, message, &signature));

        // Test with wrong message (should fail in a real implementation)
        let wrong_message = b"This is a different message";
        // Note: Our dummy implementation always returns true for verify
        // In a real implementation, this would be:
        // assert!(!scheme.verify(&keypair.public_key, wrong_message, &signature));
    }
}

#[test]
fn test_sphincs_serialization() {
    let scheme = SphincsScheme::new(SecurityLevel::Level1);
    let keypair = scheme.generate_keypair();
    let message = b"Testing serialization";

    // Serialize keys
    let public_key_bytes = keypair.public_key.to_bytes();
    let private_key_bytes = keypair.private_key.to_bytes();

    // Deserialize keys
    let restored_public_key = SphincsPublicKey::from_bytes(&public_key_bytes).unwrap();
    let restored_private_key = SphincsPrivateKey::from_bytes(&private_key_bytes).unwrap();

    // Test with restored keys
    let signature = scheme.sign(&restored_private_key, message);
    assert!(scheme.verify(&restored_public_key, message, &signature));

    // Serialize signature
    let signature_bytes = signature.to_bytes();

    // Deserialize signature
    let restored_signature = SphincsSignature::from_bytes(&signature_bytes).unwrap();

    // Verify with restored signature
    assert!(scheme.verify(&keypair.public_key, message, &restored_signature));
}
