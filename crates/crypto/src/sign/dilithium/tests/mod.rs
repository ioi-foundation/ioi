// Path: crates/crypto/src/sign/dilithium/tests/mod.rs
use super::*;
use dcrypt::sign::mldsa::{
    MlDsa44 as DcryptMlDsa44, MlDsaPublicKey as DcryptMlDsaPublicKey,
    MlDsaSignature as DcryptMlDsaSignature,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpSigVerTest {
    tc_id: u64,
    test_passed: bool,
    pk: String,
    mu: String,
    signature: String,
}

#[derive(Deserialize)]
struct AcvpSigVerFixture {
    source: String,
    source_commit: String,
    revision: String,
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "signatureInterface")]
    signature_interface: String,
    test: AcvpSigVerTest,
}

#[test]
fn nist_acvp_fips204_mldsa44_internal_sigver_tc91() {
    let fixture: AcvpSigVerFixture =
        serde_json::from_str(include_str!("vectors/nist_acvp_mldsa44_sigver_tc91.json"))
            .expect("checked-in NIST ACVP fixture must parse");

    assert_eq!(fixture.source, "NIST ACVP-Server");
    assert_eq!(
        fixture.source_commit,
        "975de31eb83d87039ec88934fdc47d8c312b892d"
    );
    assert_eq!(fixture.revision, "FIPS204");
    assert_eq!(fixture.parameter_set, "ML-DSA-44");
    assert_eq!(fixture.signature_interface, "internal");
    assert_eq!(fixture.test.tc_id, 91);
    assert!(fixture.test.test_passed);

    let public_key = DcryptMlDsaPublicKey::from_bytes(
        &hex::decode(&fixture.test.pk).expect("ACVP public key is hex"),
    )
    .expect("ACVP public key must decode");
    let signature_bytes = hex::decode(&fixture.test.signature).expect("ACVP signature is hex");
    let signature = DcryptMlDsaSignature::from_bytes(&signature_bytes)
        .expect("ACVP signature must be canonical");
    let mu: [u8; 64] = hex::decode(&fixture.test.mu)
        .expect("ACVP mu is hex")
        .try_into()
        .expect("ACVP mu must be 64 bytes");

    DcryptMlDsa44::verify_mu(&mu, &signature, &public_key)
        .expect("official valid FIPS 204 vector must verify");

    let mut corrupted = signature_bytes;
    corrupted[0] ^= 1;
    let corrupted = DcryptMlDsaSignature::from_bytes(&corrupted)
        .expect("commitment corruption remains structurally canonical");
    assert!(DcryptMlDsa44::verify_mu(&mu, &corrupted, &public_key).is_err());
}

#[test]
fn test_dilithium_level2_sign_verify() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let keypair = scheme.generate_keypair().unwrap();

    let message = b"Test message for Dilithium";
    let signature = keypair.sign(message).unwrap();

    assert!(keypair.public_key().verify(message, &signature).is_ok());

    // Test with wrong message
    let wrong_message = b"Wrong message";
    assert!(keypair
        .public_key()
        .verify(wrong_message, &signature)
        .is_err());
}

#[test]
fn test_dilithium_level3_sign_verify() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level3);
    let keypair = scheme.generate_keypair().unwrap();

    let message = b"Test message for Dilithium Level 3";
    let signature = keypair.sign(message).unwrap();

    assert!(keypair.public_key().verify(message, &signature).is_ok());
}

#[test]
fn test_dilithium_level5_sign_verify() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level5);
    let keypair = scheme.generate_keypair().unwrap();

    let message = b"Test message for Dilithium Level 5";
    let signature = keypair.sign(message).unwrap();

    assert!(keypair.public_key().verify(message, &signature).is_ok());
}

#[test]
fn test_key_serialization() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let keypair = scheme.generate_keypair().unwrap();

    // Test public key serialization
    let pk_bytes = keypair.public_key().to_bytes();
    let pk_restored = MldsaPublicKey::from_bytes(&pk_bytes).unwrap();
    assert_eq!(pk_bytes, pk_restored.to_bytes());

    // Test private key serialization
    let sk_bytes = keypair.private_key().to_bytes();
    let sk_restored = MldsaPrivateKey::from_bytes(&sk_bytes).unwrap();
    assert_eq!(sk_bytes, sk_restored.to_bytes());

    // Test signature with restored keys
    let message = b"Test serialization";
    let signature = scheme.sign(&sk_restored, message).unwrap();
    assert!(scheme.verify(&pk_restored, message, &signature).is_ok());
}

#[test]
fn test_signature_serialization() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let keypair = scheme.generate_keypair().unwrap();

    let message = b"Test signature serialization";
    let signature = keypair.sign(message).unwrap();

    // Serialize and deserialize signature
    let sig_bytes = signature.to_bytes();
    let sig_restored = DilithiumSignature::from_bytes(&sig_bytes).unwrap();

    // Verify with restored signature
    assert!(keypair.public_key().verify(message, &sig_restored).is_ok());
}

#[test]
fn signature_deserialization_rejects_noncanonical_hint_encoding() {
    // ML-DSA-44 signatures end in 80 hint indices followed by four cumulative
    // boundaries. Repeated indices inside one polynomial are non-canonical.
    let mut encoded = vec![0u8; 2420];
    let hint_offset = 32 + 4 * 576;
    encoded[hint_offset] = 7;
    encoded[hint_offset + 1] = 7;
    encoded[hint_offset + 80] = 2;

    assert!(MldsaSignature::from_bytes(&encoded).is_err());
}

#[test]
fn test_wrong_key_size_detection() {
    // Test with invalid key sizes
    let invalid_pk = vec![0u8; 1000]; // Invalid size
    let pk_result = MldsaPublicKey::from_bytes(&invalid_pk);
    assert!(pk_result.is_err());
}

#[test]
fn test_cross_level_verification() {
    // Generate keys at different levels
    let scheme2 = DilithiumScheme::new(SecurityLevel::Level2);
    let keypair2 = scheme2.generate_keypair().unwrap();

    let keypair3 = DilithiumScheme::new(SecurityLevel::Level3)
        .generate_keypair()
        .unwrap();

    let message = b"Cross level test";
    let signature2 = keypair2.sign(message).unwrap();

    // Level 3 public key should not verify Level 2 signature
    // (will fail due to key size mismatch detection in verify)
    assert!(keypair3.public_key().verify(message, &signature2).is_err());
}

/// OBS-9 (P7): a scheme configured for one level refuses a valid key and signature of another
/// level (the trunk picked the parameter set from the key's length and accepted it).
#[test]
fn obs9_a_scheme_refuses_a_valid_key_of_another_level() {
    let message = b"OBS-9 level binding";
    let scheme2 = DilithiumScheme::new(SecurityLevel::Level2);
    let scheme3 = DilithiumScheme::new(SecurityLevel::Level3);
    let keypair2 = scheme2.generate_keypair().unwrap();
    let keypair3 = scheme3.generate_keypair().unwrap();
    let signature2 = keypair2.sign(message).unwrap();
    let signature3 = keypair3.sign(message).unwrap();

    scheme2
        .verify(&keypair2.public_key(), message, &signature2)
        .expect("a scheme verifies its own level");
    scheme3
        .verify(&keypair3.public_key(), message, &signature3)
        .expect("a scheme verifies its own level");
    // The downgrade: an ML-DSA-65 scheme handed a valid ML-DSA-44 key and signature.
    assert!(matches!(
        scheme3.verify(&keypair2.public_key(), message, &signature2),
        Err(CryptoError::InvalidKey(_))
    ));
    // And the other way round.
    assert!(scheme2
        .verify(&keypair3.public_key(), message, &signature3)
        .is_err());
}

/// OBS-9 (P7): a level ML-DSA has no parameter set for is refused, never silently ML-DSA-44.
#[test]
fn obs9_no_silent_ml_dsa_44_fallback() {
    assert!(matches!(
        DilithiumScheme::new(SecurityLevel::Level1).generate_keypair(),
        Err(CryptoError::Unsupported(_))
    ));
}

/// OBS-9 (P7): a private key labelled with a level ML-DSA has no parameter set for never signs as
/// ML-DSA-44, on any of the three signing paths (the scheme, the key pair, the private key). Such a
/// key is not constructible through the public API (generation refuses the level; `from_bytes`
/// infers the level from the length), so the refusals are defence in depth, pinned here.
#[test]
fn obs9_no_silent_ml_dsa_44_signing() {
    let message = b"OBS-9 signing";
    let real = DilithiumScheme::new(SecurityLevel::Level2)
        .generate_keypair()
        .unwrap();
    let mislabelled = MldsaPrivateKey {
        data: real.private_key.data.clone(),
        level: SecurityLevel::Level1,
    };
    let pair = MldsaKeyPair {
        public_key: MldsaPublicKey(real.public_key.0.clone()),
        private_key: mislabelled.clone(),
        level: SecurityLevel::Level1,
    };
    assert!(matches!(
        DilithiumScheme::new(SecurityLevel::Level1).sign(&mislabelled, message),
        Err(CryptoError::Unsupported(_))
    ));
    assert!(matches!(
        SigningKeyPair::sign(&pair, message),
        Err(CryptoError::Unsupported(_))
    ));
    assert!(matches!(
        SigningKey::sign(&mislabelled, message),
        Err(CryptoError::Unsupported(_))
    ));
}
