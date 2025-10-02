// Path: crates/crypto/src/kem/hybrid/tests/mod.rs
use super::*;
use crate::security::SecurityLevel;
use depin_sdk_api::crypto::{Encapsulated, KeyEncapsulation};

#[test]
fn test_hybrid_level1_roundtrip() {
    let kem = HybridKEM::new(SecurityLevel::Level1).unwrap();
    let keypair = kem.generate_keypair().unwrap();

    // Verify key sizes for Level 1 (P256 + Kyber512)
    assert_eq!(keypair.public_key.to_bytes().len(), 833);
    assert_eq!(keypair.private_key.to_bytes().len(), 1664);
    assert_eq!(keypair.public_key.level, SecurityLevel::Level1);

    // Encapsulate and verify sizes
    let encapsulated = kem.encapsulate(&keypair.public_key).unwrap();
    assert_eq!(encapsulated.ciphertext().len(), 801);
    assert_eq!(encapsulated.shared_secret().len(), 32);

    // Decapsulate and verify
    let shared_secret = kem
        .decapsulate(&keypair.private_key, &encapsulated)
        .unwrap();
    assert_eq!(shared_secret, encapsulated.shared_secret());
}

#[test]
fn test_hybrid_level3_roundtrip() {
    let kem = HybridKEM::new(SecurityLevel::Level3).unwrap();
    let keypair = kem.generate_keypair().unwrap();

    // Verify key sizes for Level 3 (P256 + Kyber768)
    assert_eq!(keypair.public_key.to_bytes().len(), 1217);
    assert_eq!(keypair.private_key.to_bytes().len(), 2432);

    // Encapsulate and verify sizes
    let encapsulated = kem.encapsulate(&keypair.public_key).unwrap();
    assert_eq!(encapsulated.ciphertext().len(), 1121);
    assert_eq!(encapsulated.shared_secret().len(), 32);

    // Decapsulate and verify
    let shared_secret = kem
        .decapsulate(&keypair.private_key, &encapsulated)
        .unwrap();
    assert_eq!(shared_secret, encapsulated.shared_secret());
}

#[test]
fn test_hybrid_level5_roundtrip() {
    let kem = HybridKEM::new(SecurityLevel::Level5).unwrap();
    let keypair = kem.generate_keypair().unwrap();

    // Verify key sizes for Level 5 (P384 + Kyber1024)
    assert_eq!(keypair.public_key.to_bytes().len(), 1617);
    assert_eq!(keypair.private_key.to_bytes().len(), 3216);
    assert_eq!(keypair.public_key.level, SecurityLevel::Level5);

    // Encapsulate and verify sizes
    let encapsulated = kem.encapsulate(&keypair.public_key).unwrap();
    assert_eq!(encapsulated.ciphertext().len(), 1617);
    assert_eq!(encapsulated.shared_secret().len(), 32);

    // Decapsulate and verify
    let shared_secret = kem
        .decapsulate(&keypair.private_key, &encapsulated)
        .unwrap();
    assert_eq!(shared_secret, encapsulated.shared_secret());
}

#[test]
fn test_hybrid_multiple_encapsulations() {
    let kem = HybridKEM::new(SecurityLevel::Level3).unwrap();
    let keypair = kem.generate_keypair().unwrap();

    // Multiple encapsulations with the same public key should produce different results
    let encapsulated1 = kem.encapsulate(&keypair.public_key).unwrap();
    let encapsulated2 = kem.encapsulate(&keypair.public_key).unwrap();

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
    let kem = HybridKEM::new(SecurityLevel::Level3).unwrap();
    let keypair1 = kem.generate_keypair().unwrap();
    let keypair2 = kem.generate_keypair().unwrap();

    // Encapsulate with keypair1's public key
    let encapsulated = kem.encapsulate(&keypair1.public_key).unwrap();

    // Try to decapsulate with keypair2's private key
    let wrong_shared_secret = kem.decapsulate(&keypair2.private_key, &encapsulated);

    // Should still produce a result (KEMs don't fail on wrong key)
    assert!(wrong_shared_secret.is_ok());
    // But it should be different from the correct shared secret
    assert_ne!(wrong_shared_secret.unwrap(), encapsulated.shared_secret());
}

#[test]
fn test_hybrid_serialization() {
    let kem = HybridKEM::new(SecurityLevel::Level3).unwrap();
    let keypair = kem.generate_keypair().unwrap();

    // Serialize keys
    let public_key_bytes = keypair.public_key.to_bytes();
    let private_key_bytes = keypair.private_key.to_bytes();

    // Deserialize keys
    let _restored_public_key = HybridPublicKey::from_bytes(&public_key_bytes).unwrap();
    let restored_private_key = HybridPrivateKey::from_bytes(&private_key_bytes).unwrap();

    // Encapsulate with original key
    let encapsulated = kem.encapsulate(&keypair.public_key).unwrap();
    let ciphertext_bytes = encapsulated.to_bytes();

    // Deserialize ciphertext
    let restored_encapsulated = HybridEncapsulated::from_bytes(&ciphertext_bytes).unwrap();

    // Decapsulate with restored key and restored ciphertext
    let shared_secret = kem.decapsulate(&restored_private_key, &restored_encapsulated);

    // We should still get a valid shared secret
    assert!(shared_secret.is_ok());

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
    let kem = HybridKEM::new(SecurityLevel::Level3).unwrap();
    let keypair = kem.generate_keypair().unwrap();

    // Test that the shared secret is deterministic for a given ciphertext
    let encapsulated = kem.encapsulate(&keypair.public_key).unwrap();

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
    let keypair = kem.generate_keypair().unwrap();

    // Should use Level3 by default
    assert_eq!(keypair.public_key.level, SecurityLevel::Level3);

    // Should work normally
    let encapsulated = kem.encapsulate(&keypair.public_key).unwrap();
    let shared_secret = kem.decapsulate(&keypair.private_key, &encapsulated);

    assert!(shared_secret.is_ok());
    assert_eq!(shared_secret.unwrap(), encapsulated.shared_secret());
}

#[test]
fn test_hybrid_independent_verification() {
    // Test that keys can be used independently after serialization
    let kem = HybridKEM::new(SecurityLevel::Level3).unwrap();
    let keypair = kem.generate_keypair().unwrap();

    // Serialize and deserialize to ensure independence
    let pk_bytes = keypair.public_key.to_bytes();
    let sk_bytes = keypair.private_key.to_bytes();

    let pk = HybridPublicKey::from_bytes(&pk_bytes).unwrap();
    let sk = HybridPrivateKey::from_bytes(&sk_bytes).unwrap();

    // Use the deserialized keys
    let encapsulated = kem.encapsulate(&pk).unwrap();
    let shared_secret = kem.decapsulate(&sk, &encapsulated);

    assert!(shared_secret.is_ok());
    assert_eq!(shared_secret.unwrap(), encapsulated.shared_secret());
}

#[test]
fn test_hybrid_secret_changes_if_either_component_changes() {
    use crate::kem::ecdh::{EcdhCurve, EcdhEncapsulated, EcdhKEM, EcdhPrivateKey, EcdhPublicKey};
    use crate::kem::kyber::{KyberEncapsulated, KyberKEM, KyberPrivateKey, KyberPublicKey};
    use crate::security::SecurityLevel;
    use depin_sdk_api::crypto::{Encapsulated, KeyEncapsulation, SerializableKey};

    // Helper: sizes for (ECDH_pk_len, Kyber_pk_len, Kyber_ct_len) by level
    fn sizes(level: SecurityLevel) -> (usize, usize, usize, EcdhCurve) {
        match level {
            SecurityLevel::Level1 => (33, 800, 768, EcdhCurve::P256),
            SecurityLevel::Level3 => (33, 1184, 1088, EcdhCurve::P256),
            SecurityLevel::Level5 => (49, 1568, 1568, EcdhCurve::P384),
            _ => panic!("unsupported"),
        }
    }

    // Levels to exercise
    for &level in &[
        SecurityLevel::Level1,
        SecurityLevel::Level3,
        SecurityLevel::Level5,
    ] {
        let hybrid = HybridKEM::new(level).unwrap();
        let kp = hybrid.generate_keypair().unwrap();

        // Baseline encapsulation & shared secret
        let enc0 = hybrid.encapsulate(&kp.public_key).unwrap();
        let ss0 = enc0.shared_secret().to_vec();

        let pk_bytes = kp.public_key.to_bytes();
        let ct_bytes = enc0.ciphertext().to_vec();
        let (ecdh_pk_len, kyber_pk_len, kyber_ct_len, ecdh_curve) = sizes(level);

        // --- Mutate KYBER component (all levels) ---
        // Parse Kyber public key and produce a fresh Kyber ciphertext for the same key.
        let kyber_pk =
            KyberPublicKey::from_bytes(&pk_bytes[ecdh_pk_len..ecdh_pk_len + kyber_pk_len]).unwrap();
        let kyber = KyberKEM::new(level);
        let kyber_new = kyber.encapsulate(&kyber_pk).unwrap();

        // Splice new Kyber ciphertext into the original hybrid ciphertext
        let mut ct_mut = ct_bytes.clone();
        ct_mut[ecdh_pk_len..ecdh_pk_len + kyber_ct_len].copy_from_slice(kyber_new.ciphertext());
        let enc_mut = HybridEncapsulated::from_bytes(&ct_mut).unwrap();
        let ss_mut = hybrid.decapsulate(&kp.private_key, &enc_mut).unwrap();
        assert_ne!(ss0, ss_mut, "hybrid secret must depend on Kyber component");

        // --- Mutate ECDH component (Level 5 only, where we have P-384 support locally) ---
        if level == SecurityLevel::Level5 {
            let ecdh = EcdhKEM::new(ecdh_curve);
            let ecdh_pk = EcdhPublicKey::from_bytes(&pk_bytes[..ecdh_pk_len]).unwrap();
            let ecdh_new = ecdh.encapsulate(&ecdh_pk).unwrap(); // fresh ephemeral

            let mut ct_mut2 = ct_bytes.clone();
            ct_mut2[..ecdh_pk_len].copy_from_slice(ecdh_new.ciphertext());
            let enc_mut2 = HybridEncapsulated::from_bytes(&ct_mut2).unwrap();
            let ss_mut2 = hybrid.decapsulate(&kp.private_key, &enc_mut2).unwrap();
            assert_ne!(ss0, ss_mut2, "hybrid secret must depend on ECDH component");
        }
    }
}
