use super::*;

#[test]
fn test_dilithium_level2_sign_verify() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let keypair = scheme.generate_keypair();
    
    let message = b"Test message for Dilithium";
    let signature = keypair.sign(message);
    
    assert!(keypair.public_key().verify(message, &signature));
    
    // Test with wrong message
    let wrong_message = b"Wrong message";
    assert!(!keypair.public_key().verify(wrong_message, &signature));
}

#[test]
fn test_dilithium_level3_sign_verify() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level3);
    let keypair = scheme.generate_keypair();
    
    let message = b"Test message for Dilithium Level 3";
    let signature = keypair.sign(message);
    
    assert!(keypair.public_key().verify(message, &signature));
}

#[test]
fn test_dilithium_level5_sign_verify() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level5);
    let keypair = scheme.generate_keypair();
    
    let message = b"Test message for Dilithium Level 5";
    let signature = keypair.sign(message);
    
    assert!(keypair.public_key().verify(message, &signature));
}

#[test]
fn test_key_serialization() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let keypair = scheme.generate_keypair();
    
    // Test public key serialization
    let pk_bytes = keypair.public_key().to_bytes();
    let pk_restored = DilithiumPublicKey::from_bytes(&pk_bytes).unwrap();
    assert_eq!(pk_bytes, pk_restored.to_bytes());
    
    // Test private key serialization
    let sk_bytes = keypair.private_key().to_bytes();
    let sk_restored = DilithiumPrivateKey::from_bytes(&sk_bytes).unwrap();
    assert_eq!(sk_bytes, sk_restored.to_bytes());
    
    // Test signature with restored keys
    let message = b"Test serialization";
    let signature = scheme.sign(&sk_restored, message);
    assert!(scheme.verify(&pk_restored, message, &signature));
}

#[test]
fn test_signature_serialization() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let keypair = scheme.generate_keypair();
    
    let message = b"Test signature serialization";
    let signature = keypair.sign(message);
    
    // Serialize and deserialize signature
    let sig_bytes = signature.to_bytes();
    let sig_restored = DilithiumSignature::from_bytes(&sig_bytes).unwrap();
    
    // Verify with restored signature
    assert!(keypair.public_key().verify(message, &sig_restored));
}

#[test]
fn test_wrong_key_size_detection() {
    // Test with invalid key sizes
    let invalid_pk = vec![0u8; 1000]; // Invalid size
    let pk = DilithiumPublicKey::from_bytes(&invalid_pk).unwrap();
    
    let message = b"Test";
    let signature = DilithiumSignature(vec![0u8; 2420]); // Dilithium2 signature size
    
    // Should return false for invalid key size
    assert!(!pk.verify(message, &signature));
}

#[test]
fn test_cross_level_verification() {
    // Generate keys at different levels
    let scheme2 = DilithiumScheme::new(SecurityLevel::Level2);
    let keypair2 = scheme2.generate_keypair();
    
    let scheme3 = DilithiumScheme::new(SecurityLevel::Level3);
    let keypair3 = scheme3.generate_keypair();
    
    let message = b"Cross level test";
    let signature2 = keypair2.sign(message);
    
    // Level 3 public key should not verify Level 2 signature
    // (will fail due to key size mismatch detection)
    assert!(!keypair3.public_key().verify(message, &signature2));
}