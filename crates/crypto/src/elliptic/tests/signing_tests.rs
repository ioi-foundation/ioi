//! Tests for elliptic curve cryptography implementations

use super::super::*;
use depin_sdk_core::crypto::{KeyPair, PrivateKey, PublicKey, Signature};

#[test]
fn test_ed25519_signing() {
    let keypair = Ed25519KeyPair::generate();
    let message = b"test message";

    let signature = keypair.sign(message);
    let public_key = keypair.public_key();

    assert!(public_key.verify(message, &signature));

    // Test with wrong message
    let wrong_message = b"wrong message";
    assert!(!public_key.verify(wrong_message, &signature));
}

#[test]
fn test_ed25519_serialization() {
    let keypair = Ed25519KeyPair::generate();
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();

    let pk_bytes = public_key.to_bytes();
    let sk_bytes = private_key.to_bytes();

    let pk_recovered = Ed25519PublicKey::from_bytes(&pk_bytes).unwrap();
    let sk_recovered = Ed25519PrivateKey::from_bytes(&sk_bytes).unwrap();

    // Create a new keypair from recovered private key
    let recovered_keypair = Ed25519KeyPair::from_private_key(&sk_recovered);

    // Sign with recovered keypair
    let message = b"test message";
    let signature = recovered_keypair.sign(message);

    // Verify with original public key
    assert!(public_key.verify(message, &signature));

    // Verify with recovered public key
    assert!(pk_recovered.verify(message, &signature));
}
