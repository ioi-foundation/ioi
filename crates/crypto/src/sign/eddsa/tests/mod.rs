// Path: crates/crypto/src/sign/eddsa/tests/mod.rs
use super::*;

#[test]
fn test_keypair_generation() {
    let keypair = Ed25519KeyPair::generate().unwrap();
    let message = b"Test message";

    // Sign
    let signature = keypair.sign(message).unwrap();

    // Verify
    let public_key = keypair.public_key();
    assert!(public_key.verify(message, &signature).is_ok());
}

#[test]
fn test_serialization_roundtrip() {
    let keypair = Ed25519KeyPair::generate().unwrap();

    // Serialize keys
    let public_bytes = keypair.public_key().to_bytes();
    let private_bytes = keypair.private_key().to_bytes();

    // Verify lengths
    assert_eq!(public_bytes.len(), 32);
    assert_eq!(private_bytes.len(), 32); // Just the seed

    // Deserialize
    let public_key = Ed25519PublicKey::from_bytes(&public_bytes).unwrap();
    let private_key = Ed25519PrivateKey::from_bytes(&private_bytes).unwrap();

    // Verify we can derive the same public key from the loaded private key
    let derived_public = private_key.public_key().unwrap();
    assert_eq!(public_key.to_bytes(), derived_public.to_bytes());
}

#[test]
fn test_sign_verify_with_loaded_keys() {
    // Generate original keypair
    let original_keypair = Ed25519KeyPair::generate().unwrap();
    let message = b"Test message for persistence";

    // Sign with original
    let original_sig = original_keypair.sign(message).unwrap();

    // Serialize private key
    let private_bytes = original_keypair.private_key().to_bytes();

    // Load private key from bytes
    let loaded_private = Ed25519PrivateKey::from_bytes(&private_bytes).unwrap();

    // Reconstruct keypair from loaded private key
    let reconstructed_keypair = Ed25519KeyPair::from_private_key(&loaded_private).unwrap();

    // Sign with reconstructed keypair
    let new_sig = reconstructed_keypair.sign(message).unwrap();

    // Signatures should be deterministic and identical
    assert_eq!(original_sig.to_bytes(), new_sig.to_bytes());

    // Verify with both public keys
    let original_public = original_keypair.public_key();
    let reconstructed_public = reconstructed_keypair.public_key();

    assert!(original_public.verify(message, &original_sig).is_ok());
    assert!(reconstructed_public.verify(message, &new_sig).is_ok());
    assert!(original_public.verify(message, &new_sig).is_ok());
    assert!(reconstructed_public.verify(message, &original_sig).is_ok());
}

#[test]
fn test_wrong_signature_fails() {
    let keypair1 = Ed25519KeyPair::generate().unwrap();
    let keypair2 = Ed25519KeyPair::generate().unwrap();

    let message = b"Test message";

    // Sign with keypair1
    let signature = keypair1.sign(message).unwrap();

    // Verify with keypair2's public key should fail
    let public_key2 = keypair2.public_key();
    assert!(public_key2.verify(message, &signature).is_err());
}

#[test]
fn test_tampered_message_fails() {
    let keypair = Ed25519KeyPair::generate().unwrap();
    let message = b"Original message";
    let tampered = b"Tampered message";

    // Sign original
    let signature = keypair.sign(message).unwrap();

    // Verify tampered message with same signature should fail
    let public_key = keypair.public_key();
    assert!(public_key.verify(message, &signature).is_ok());
    assert!(public_key.verify(tampered, &signature).is_err());
}
