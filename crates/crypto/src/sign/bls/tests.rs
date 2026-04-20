use super::*;

#[test]
fn test_bls_sign_verify() {
    let keypair = BlsKeyPair::generate().unwrap();
    let message = b"consensus_on_meaning";
    let signature = keypair.sign(message).unwrap();

    // Positive verification
    assert!(keypair.public_key().verify(message, &signature).is_ok());

    // Negative verification (wrong message)
    assert!(keypair.public_key().verify(b"wrong", &signature).is_err());

    // Serialization Roundtrip
    let pk_bytes = keypair.public_key().to_bytes();
    let restored_pk = BlsPublicKey::from_bytes(&pk_bytes).unwrap();
    assert_eq!(keypair.public_key(), restored_pk);
}

#[test]
fn test_bls_aggregation() {
    let kp1 = BlsKeyPair::generate().unwrap();
    let kp2 = BlsKeyPair::generate().unwrap();
    let kp3 = BlsKeyPair::generate().unwrap();

    let message = b"aggregate_this";

    let s1 = kp1.sign(message).unwrap();
    let s2 = kp2.sign(message).unwrap();
    let s3 = kp3.sign(message).unwrap();

    let agg_sig = aggregate_signatures(&[s1, s2, s3]).unwrap();

    let pks = vec![kp1.public_key(), kp2.public_key(), kp3.public_key()];

    let valid = verify_aggregate_fast(&pks, message, &agg_sig).unwrap();
    assert!(valid, "Aggregate signature verification failed");
}
