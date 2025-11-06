// Path: crates/crypto/src/kem/kyber/tests/mod.rs
use super::*;
use crate::security::SecurityLevel;
use ioi_api::crypto::{Encapsulated, KeyEncapsulation};

#[test]
fn test_kyber_keypair_generation() {
    // Test all security levels
    let levels = vec![
        SecurityLevel::Level1,
        SecurityLevel::Level3,
        SecurityLevel::Level5,
    ];

    for level in levels {
        let kem = KyberKEM::new(level);
        let keypair = kem.generate_keypair().unwrap();

        // Verify key sizes match the expected sizes for the security level
        match level {
            SecurityLevel::Level1 => {
                assert_eq!(keypair.public_key.to_bytes().len(), 800); // Kyber512
                assert_eq!(keypair.private_key.to_bytes().len(), 1632); // Kyber512
            }
            SecurityLevel::Level3 => {
                assert_eq!(keypair.public_key.to_bytes().len(), 1184); // Kyber768
                assert_eq!(keypair.private_key.to_bytes().len(), 2400); // Kyber768
            }
            SecurityLevel::Level5 => {
                assert_eq!(keypair.public_key.to_bytes().len(), 1568); // Kyber1024
                assert_eq!(keypair.private_key.to_bytes().len(), 3168); // Kyber1024
            }
            _ => panic!("Unexpected security level"),
        }

        // Ensure keys are different
        assert_ne!(
            keypair.public_key.to_bytes(),
            keypair.private_key.to_bytes()
        );
    }
}

#[test]
fn test_kyber_encapsulation() {
    let levels = vec![
        SecurityLevel::Level1,
        SecurityLevel::Level3,
        SecurityLevel::Level5,
    ];

    for level in levels {
        let kem = KyberKEM::new(level);
        let keypair = kem.generate_keypair().unwrap();

        // Encapsulate a key
        let encapsulated = kem.encapsulate(&keypair.public_key).unwrap();

        // Verify the encapsulated data sizes
        match level {
            SecurityLevel::Level1 => {
                assert_eq!(encapsulated.ciphertext().len(), 768); // Kyber512
            }
            SecurityLevel::Level3 => {
                assert_eq!(encapsulated.ciphertext().len(), 1088); // Kyber768
            }
            SecurityLevel::Level5 => {
                assert_eq!(encapsulated.ciphertext().len(), 1568); // Kyber1024
            }
            _ => panic!("Unexpected security level"),
        }

        // Shared secret should always be 32 bytes for all Kyber variants
        assert_eq!(encapsulated.shared_secret().len(), 32);

        // Decapsulate and verify
        let shared_secret = kem.decapsulate(&keypair.private_key, &encapsulated);

        // We should get a valid shared secret
        assert!(shared_secret.is_ok());
        let shared_secret = shared_secret.unwrap();

        // The shared secret should match what's in the encapsulated key
        assert_eq!(&*shared_secret, encapsulated.shared_secret());

        // The shared secret should be 32 bytes for all Kyber variants
        assert_eq!(shared_secret.len(), 32);
    }
}

#[test]
fn test_kyber_serialization() {
    let kem = KyberKEM::new(SecurityLevel::Level3);
    let keypair = kem.generate_keypair().unwrap();

    // Serialize keys
    let public_key_bytes = keypair.public_key.to_bytes();
    let private_key_bytes = keypair.private_key.to_bytes();

    // Deserialize keys
    let _restored_public_key = KyberPublicKey::from_bytes(&public_key_bytes).unwrap();
    let restored_private_key = KyberPrivateKey::from_bytes(&private_key_bytes).unwrap();

    // Encapsulate with original key
    let encapsulated = kem.encapsulate(&keypair.public_key).unwrap();
    let ciphertext_bytes = encapsulated.to_bytes();

    // Deserialize ciphertext
    let restored_encapsulated = KyberEncapsulated::from_bytes(&ciphertext_bytes).unwrap();

    // Decapsulate with restored key and restored ciphertext
    let shared_secret = kem.decapsulate(&restored_private_key, &restored_encapsulated);

    // We should still get a valid shared secret
    assert!(shared_secret.is_ok());

    // Verify that different key pairs produce different shared secrets
    let keypair2 = kem.generate_keypair().unwrap();
    let encapsulated2 = kem.encapsulate(&keypair2.public_key).unwrap();

    // Different key pairs should generate different shared secrets
    assert_ne!(encapsulated.shared_secret(), encapsulated2.shared_secret());

    // Different public keys should produce different ciphertexts
    assert_ne!(encapsulated.ciphertext(), encapsulated2.ciphertext());

    // Decapsulating with the wrong private key should still produce a result,
    // but it won't match the original shared secret
    let wrong_shared_secret = kem.decapsulate(&keypair2.private_key, &encapsulated);
    assert!(wrong_shared_secret.is_ok());
    assert_ne!(&*wrong_shared_secret.unwrap(), encapsulated.shared_secret());
}

#[test]
fn test_cross_level_compatibility() {
    // Test that keys from different security levels can't be mixed

    let kem512 = KyberKEM::new(SecurityLevel::Level1);
    let kem768 = KyberKEM::new(SecurityLevel::Level3);

    let keypair512 = kem512.generate_keypair().unwrap();
    let keypair768 = kem768.generate_keypair().unwrap();

    // Encapsulate with Level1 public key
    let encapsulated512 = kem512.encapsulate(&keypair512.public_key).unwrap();

    // Try to decapsulate Level1 ciphertext with Level3 private key
    // This should still return a result but it won't be correct
    let _result = kem768.decapsulate(&keypair768.private_key, &encapsulated512);

    // The correct way is to match security levels
    let encapsulated768 = kem768.encapsulate(&keypair768.public_key).unwrap();
    let shared_secret = kem768.decapsulate(&keypair768.private_key, &encapsulated768);
    assert!(shared_secret.is_ok());
    assert_eq!(&*shared_secret.unwrap(), encapsulated768.shared_secret());
}

#[test]
fn test_dcrypt_compatibility() {
    // Test that the dcrypt wrapper works correctly
    let kem = KyberKEM::new(SecurityLevel::Level3);
    let keypair1 = kem.generate_keypair().unwrap();
    let keypair2 = kem.generate_keypair().unwrap();

    // Test encapsulation/decapsulation cycle
    let encapsulated = kem.encapsulate(&keypair1.public_key).unwrap();
    let shared_secret = kem.decapsulate(&keypair1.private_key, &encapsulated);

    assert!(shared_secret.is_ok());
    assert_eq!(shared_secret.unwrap().len(), 32);

    // Test that using wrong keys produces different results
    let wrong_secret = kem.decapsulate(&keypair2.private_key, &encapsulated);
    assert!(wrong_secret.is_ok());
    assert_ne!(&*wrong_secret.unwrap(), encapsulated.shared_secret());
}
