// Path: crates/crypto/src/kem/ecdh/tests/mod.rs
use super::*;
use crate::security::SecurityLevel;
use depin_sdk_api::crypto::{Encapsulated, KeyEncapsulation};

#[test]
fn test_ecdh_keypair_generation() {
    // Test P256 curve (K256)
    let curve = EcdhCurve::P256;
    let kem = EcdhKEM::new(curve);
    let keypair = kem.generate_keypair();

    // Verify key sizes match the expected sizes for K256
    assert_eq!(keypair.public_key.to_bytes().len(), 33); // Compressed K256 point
    assert_eq!(keypair.private_key.to_bytes().len(), 32); // K256 scalar

    // Ensure keys are different
    assert_ne!(
        keypair.public_key.to_bytes(),
        keypair.private_key.to_bytes()
    );
}

#[test]
fn test_ecdh_p384_round_trip() {
    let kem = EcdhKEM::new(EcdhCurve::P384);
    let keypair = kem.generate_keypair();

    // Check sizes
    assert_eq!(keypair.public_key.to_bytes().len(), 49);
    assert_eq!(keypair.private_key.to_bytes().len(), 48);

    let encapsulated = kem.encapsulate(&keypair.public_key);
    assert_eq!(encapsulated.ciphertext().len(), 49);
    assert_eq!(encapsulated.shared_secret().len(), 48); // P384 shared secret is 48 bytes

    let decapsulated_secret = kem
        .decapsulate(&keypair.private_key, &encapsulated)
        .unwrap();

    assert_eq!(decapsulated_secret, encapsulated.shared_secret());
}

#[test]
fn test_ecdh_p521_round_trip() {
    let kem = EcdhKEM::new(EcdhCurve::P521);
    let keypair = kem.generate_keypair();

    // Check sizes
    assert_eq!(keypair.public_key.to_bytes().len(), 67);
    assert_eq!(keypair.private_key.to_bytes().len(), 66);

    let encapsulated = kem.encapsulate(&keypair.public_key);
    assert_eq!(encapsulated.ciphertext().len(), 67);
    assert_eq!(encapsulated.shared_secret().len(), 66); // P521 shared secret is 66 bytes

    let decapsulated_secret = kem
        .decapsulate(&keypair.private_key, &encapsulated)
        .unwrap();

    assert_eq!(decapsulated_secret, encapsulated.shared_secret());
}

#[test]
fn test_ecdh_encapsulation() {
    let curve = EcdhCurve::P256;
    let kem = EcdhKEM::new(curve);
    let keypair = kem.generate_keypair();

    // Encapsulate a key
    let encapsulated = kem.encapsulate(&keypair.public_key);

    // Verify the encapsulated data sizes
    assert_eq!(encapsulated.ciphertext().len(), 33); // Compressed K256 point
    assert_eq!(encapsulated.shared_secret().len(), 32); // SHA-256 output

    // Decapsulate and verify
    let shared_secret = kem.decapsulate(&keypair.private_key, &encapsulated);

    // We should get a valid shared secret
    assert!(shared_secret.is_some());
    let shared_secret = shared_secret.unwrap();

    // The shared secret should match what's in the encapsulated key
    assert_eq!(shared_secret, encapsulated.shared_secret());
}

#[test]
fn test_ecdh_security_level_mapping() {
    // Test Level1 -> P256
    let kem = EcdhKEM::with_security_level(SecurityLevel::Level1);
    assert_eq!(kem.curve, EcdhCurve::P256);

    // Test Level3 -> P384
    let kem = EcdhKEM::with_security_level(SecurityLevel::Level3);
    assert_eq!(kem.curve, EcdhCurve::P384);

    // Test Level5 -> P521
    let kem = EcdhKEM::with_security_level(SecurityLevel::Level5);
    assert_eq!(kem.curve, EcdhCurve::P521);
}

#[test]
fn test_ecdh_serialization() {
    let kem = EcdhKEM::new(EcdhCurve::P256);
    let keypair = kem.generate_keypair();

    // Serialize keys
    let public_key_bytes = keypair.public_key.to_bytes();
    let private_key_bytes = keypair.private_key.to_bytes();

    // Deserialize keys
    let _restored_public_key = EcdhPublicKey::from_bytes(&public_key_bytes).unwrap();
    let restored_private_key = EcdhPrivateKey::from_bytes(&private_key_bytes).unwrap();

    // Encapsulate with original key
    let encapsulated = kem.encapsulate(&keypair.public_key);
    let ciphertext_bytes = encapsulated.to_bytes();

    // Deserialize ciphertext
    let restored_encapsulated = EcdhEncapsulated::from_bytes(&ciphertext_bytes).unwrap();

    // Decapsulate with restored key and restored ciphertext
    let shared_secret = kem.decapsulate(&restored_private_key, &restored_encapsulated);

    // We should still get a valid shared secret
    assert!(shared_secret.is_some());

    // Verify that different key pairs produce different shared secrets
    let keypair2 = kem.generate_keypair();
    let encapsulated2 = kem.encapsulate(&keypair2.public_key);

    // Different key pairs should generate different shared secrets
    assert_ne!(encapsulated.shared_secret(), encapsulated2.shared_secret());

    // Different public keys should produce different ciphertexts
    assert_ne!(encapsulated.ciphertext(), encapsulated2.ciphertext());

    // Decapsulating with the wrong private key should produce a different result
    let wrong_shared_secret = kem.decapsulate(&keypair2.private_key, &encapsulated);
    assert!(wrong_shared_secret.is_some());
    assert_ne!(wrong_shared_secret.unwrap(), encapsulated.shared_secret());
}

#[test]
fn test_ecdh_dcrypt_compatibility() {
    // Test that the dcrypt wrapper works correctly
    let kem = EcdhKEM::new(EcdhCurve::P256);
    let keypair1 = kem.generate_keypair();
    let keypair2 = kem.generate_keypair();

    // Test encapsulation/decapsulation cycle
    let encapsulated = kem.encapsulate(&keypair1.public_key);
    let shared_secret = kem.decapsulate(&keypair1.private_key, &encapsulated);

    assert!(shared_secret.is_some());
    assert_eq!(shared_secret.unwrap().len(), 32); // K256 produces 32-byte shared secrets

    // Test that using wrong keys produces different results
    let wrong_secret = kem.decapsulate(&keypair2.private_key, &encapsulated);
    assert!(wrong_secret.is_some());
    assert_ne!(wrong_secret.unwrap(), encapsulated.shared_secret());
}

#[test]
fn test_ecdh_independent_verification() {
    // Test that keys can be used independently
    let kem = EcdhKEM::new(EcdhCurve::P256);
    let keypair = kem.generate_keypair();

    // Serialize and deserialize to ensure independence
    let pk_bytes = keypair.public_key.to_bytes();
    let sk_bytes = keypair.private_key.to_bytes();

    let pk = EcdhPublicKey::from_bytes(&pk_bytes).unwrap();
    let sk = EcdhPrivateKey::from_bytes(&sk_bytes).unwrap();

    // Use the deserialized keys
    let encapsulated = kem.encapsulate(&pk);
    let shared_secret = kem.decapsulate(&sk, &encapsulated);

    assert!(shared_secret.is_some());
    assert_eq!(shared_secret.unwrap(), encapsulated.shared_secret());
}