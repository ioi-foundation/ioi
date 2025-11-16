use super::*;
use crate::primitives::hash::HashCommitmentScheme;

#[test]
fn test_iavl_commit_with_witness_and_create_proof() {
    // 1. SETUP
    // The IAVLTree uses a HashCommitmentScheme, which has a stateless witness `()`.
    let scheme = HashCommitmentScheme::new();
    let mut tree = IAVLTree::new(scheme);

    // 2. ACT: Insert data and commit a version to finalize the state.
    tree.insert(b"key1", b"value1").unwrap();
    tree.insert(b"key3", b"value3").unwrap();
    tree.commit_version(1).unwrap();

    let root_commitment = tree.root_commitment();

    // 3. ASSERT EXISTENCE PROOF
    // The `create_proof` method should now correctly use the new trait signature.
    // For HashCommitmentScheme, the witness is just `()`.
    let proof_for_key1 = tree
        .create_proof(b"key1")
        .expect("Proof should be generated");

    // Verify the proof against the root commitment.
    let verification_result =
        tree.verify_proof(&root_commitment, &proof_for_key1, b"key1", b"value1");
    assert!(
        verification_result.is_ok(),
        "Existence proof for key1 should be valid"
    );

    // 4. ASSERT NON-EXISTENCE PROOF
    // Create a proof for a key that does not exist but is between two existing keys.
    let proof_for_key2 = tree
        .create_proof(b"key2")
        .expect("Non-existence proof should be generated");

    // Verify that the proof correctly proves the absence of "key2".
    // The `verify_iavl_proof` helper takes an `Option<&[u8]>` for the value.
    // `None` signifies a non-existence check.
    let proof_bytes = proof_for_key2.as_ref();
    let iavl_proof = IavlProof::decode(&mut &*proof_bytes).unwrap();
    let root_hash: [u8; 32] = root_commitment.as_ref().try_into().unwrap();
    let non_existence_result =
        proof::verify_iavl_proof(&root_hash, b"key2", None, &iavl_proof).unwrap();
    assert!(
        non_existence_result,
        "Non-existence proof for key2 should be valid"
    );
}
