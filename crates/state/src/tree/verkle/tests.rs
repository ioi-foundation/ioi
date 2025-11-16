use super::*;
use crate::primitives::kzg::{KZGCommitmentScheme, KZGParams};
use ioi_api::state::ProofProvider; // Import the trait for verify_proof

#[test]
fn test_verkle_commit_with_witness_and_create_proof() {
    // 1. SETUP
    // VerkleTree requires a KZG scheme with valid parameters.
    let params = KZGParams::new_insecure_for_testing(1234, 256);
    let scheme = KZGCommitmentScheme::new(params);
    let mut tree = VerkleTree::new(scheme, 256).unwrap();

    // 2. ACT: Insert data and commit a version.
    // The `insert` method internally builds the polynomial and its KZGWitness.
    let key1 = b"this is a key";
    let value1 = b"this is a value";
    tree.insert(key1, value1).unwrap();
    tree.commit_version(1).unwrap();

    let root_commitment = tree.root_commitment();

    // 3. ASSERT EXISTENCE PROOF
    // Calling `create_proof` on the tree should now correctly use the internal witness
    // and call the refactored `KZGCommitmentScheme::create_proof` method.
    let proof_for_key1 = tree.create_proof(key1).expect("Proof should be generated");

    // Verify the proof against the root commitment.
    let verification_result = tree.verify_proof(&root_commitment, &proof_for_key1, key1, value1);
    assert!(
        verification_result.is_ok(),
        "Existence proof for key1 should be valid"
    );

    // 4. ASSERT NON-EXISTENCE PROOF
    let non_existent_key = b"this key does not exist";
    let proof_for_non_existent = tree
        .create_proof(non_existent_key)
        .expect("Non-existence proof should be generated");

    // Verify that the proof correctly proves the absence of the key.
    // The `verify` method should return an error if the membership outcome is wrong.
    let non_existence_result = tree.verify_proof(
        &root_commitment,
        &proof_for_non_existent,
        non_existent_key,
        b"any value", // The value here doesn't matter for an absence proof check
    );

    // A correct verifier will fail because the proof is for non-existence,
    // but we are asking it to verify existence. This is the expected negative case.
    // A full `verify_membership` function would make this cleaner.
    // For now, we check the proof structure manually.
    assert!(
        non_existence_result.is_err(),
        "Verification should fail when checking for existence with a non-existence proof"
    );

    // Manually decode the proof to check its terminal type
    let proof_bytes = proof_for_non_existent.as_ref();
    let vpp = VerklePathProof::decode(&mut &*proof_bytes).unwrap();
    assert!(
        matches!(vpp.terminal, Terminal::Empty)
            || matches!(vpp.terminal, Terminal::Neighbor { .. }),
        "Proof for a non-existent key should be Empty or a Neighbor"
    );
}
