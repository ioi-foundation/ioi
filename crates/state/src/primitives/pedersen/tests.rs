use super::*;
use ioi_api::commitment::Selector;

#[test]
fn test_pedersen_witness_and_verification_flow() {
    // 1. Setup: Create scheme with 1 value generator
    let scheme = PedersenCommitmentScheme::new(1).expect("Failed to create scheme");
    let value = b"secret_data";

    // 2. Commit: Ensure we get a witness (scalar) back
    let (commitment, witness): (PedersenCommitment, Scalar) = scheme
        .commit_with_witness(&[Some(value.to_vec())])
        .expect("Commitment failed");

    // 3. Prove: Use the returned witness to create the proof
    let proof = scheme
        .create_proof(&witness, &Selector::Position(0), &value.to_vec())
        .expect("Proof generation failed");

    // 4. Verify: The proof (containing the blinding factor) must satisfy the verification equation
    let valid = scheme.verify(
        &commitment,
        &proof,
        &Selector::Position(0),
        &value.to_vec(),
        &ProofContext::default(),
    );

    assert!(valid, "Proof verification failed with valid witness");
}

#[test]
fn test_pedersen_verify_fails_with_wrong_value() {
    let scheme = PedersenCommitmentScheme::new(1).unwrap();
    let value = b"secret_data";
    let wrong_value = b"wrong_data";

    let (commitment, witness) = scheme.commit_with_witness(&[Some(value.to_vec())]).unwrap();

    let proof = scheme
        .create_proof(&witness, &Selector::Position(0), &value.to_vec())
        .unwrap();

    let valid = scheme.verify(
        &commitment,
        &proof,
        &Selector::Position(0),
        &wrong_value.to_vec(),
        &ProofContext::default(),
    );

    assert!(!valid, "Verification should fail for mismatched value");
}
