// Path: crates/commitment/src/tree/sparse_merkle/tests.rs

use super::{Node, SparseMerkleProof, SparseMerkleTree};
use crate::primitives::hash::HashCommitmentScheme;
use depin_sdk_api::state::{StateCommitment, StateManager};
use depin_sdk_types::app::Membership;
use proptest::prelude::*;

#[test]
fn test_smt_presence_and_absence_proofs() {
    let mut tree = SparseMerkleTree::new(HashCommitmentScheme::new());

    // Insert two keys that are siblings deep in the tree.
    // Their paths will match for the first 8 bits (0xAA).
    tree.insert(b"\xAA\x00", b"value1").unwrap();
    tree.insert(b"\xAA\xFF", b"value2").unwrap();
    tree.commit_version(1).unwrap();

    let root = tree.root_commitment();
    assert_ne!(root.as_ref(), Node::Empty.hash().as_slice());

    // Test 1: Proof of PRESENCE for an existing key.
    let (membership_present, proof_present_outer) = tree
        .get_with_proof_at(&root, b"\xAA\x00")
        .expect("Should generate presence proof");

    assert_eq!(
        membership_present,
        depin_sdk_types::app::Membership::Present(b"value1".to_vec())
    );

    let proof_present_inner: SparseMerkleProof =
        serde_json::from_slice(proof_present_outer.as_ref()).unwrap();
    assert!(
        SparseMerkleTree::<HashCommitmentScheme>::verify_proof_static(
            root.as_ref(),
            b"\xAA\x00",
            Some(b"value1"),
            &proof_present_inner,
        )
    );

    // Test 2: Proof of ABSENCE for a key between two siblings.
    let (membership_absent, proof_absent_outer) = tree
        .get_with_proof_at(&root, b"\xAA\x80")
        .expect("Should generate absence proof");

    assert_eq!(membership_absent, depin_sdk_types::app::Membership::Absent);

    let proof_absent_inner: SparseMerkleProof =
        serde_json::from_slice(proof_absent_outer.as_ref()).unwrap();

    // --- FIX START ---
    // More robust assertions:
    // The implementation may prove absence either by:
    //  - terminating on an EMPTY branch (leaf == None), or
    //  - providing a witness leaf with a different key (leaf == Some).
    if let Some((witness_key, _)) = &proof_absent_inner.leaf {
        // If a witness is provided, it must NOT be the query key.
        assert_ne!(witness_key.as_slice(), b"\xAA\x80");
    }
    // --- FIX END ---

    // The proof must verify correctly. This is the ultimate source of truth.
    assert!(
        SparseMerkleTree::<HashCommitmentScheme>::verify_proof_static(
            root.as_ref(),
            b"\xAA\x80",
            None,
            &proof_absent_inner
        )
    );

    // Test 3: Proof of ABSENCE for a key in an empty branch.
    let (membership_empty, proof_empty_outer) = tree
        .get_with_proof_at(&root, b"\xBB\x00")
        .expect("Should generate empty proof");
    assert_eq!(membership_empty, depin_sdk_types::app::Membership::Absent);
    let proof_empty_inner: SparseMerkleProof =
        serde_json::from_slice(proof_empty_outer.as_ref()).unwrap();
    assert!(proof_empty_inner.leaf.is_none());
    assert!(
        SparseMerkleTree::<HashCommitmentScheme>::verify_proof_static(
            root.as_ref(),
            b"\xBB\x00",
            None,
            &proof_empty_inner,
        )
    );
}

proptest! {
    #[test]
    fn smt_absence_proof_between_siblings_proptest(
        k1 in prop::collection::vec(any::<u8>(), 32),
        k2 in prop::collection::vec(any::<u8>(), 32),
        v1 in prop::collection::vec(any::<u8>(), 1..128),
        v2 in prop::collection::vec(any::<u8>(), 1..128),
    ) {
        prop_assume!(k1 != k2, "Keys must be different for this test");

        // Find the first differing bit to construct a key 'q' that is guaranteed
        // to not exist and to lie between k1 and k2 in the key space.
        let mut q = k1.clone();
        let mut differing_bit_found = false;
        for i in 0..(32 * 8) {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            let bit1 = (k1[byte_idx] >> bit_idx) & 1;
            let bit2 = (k2[byte_idx] >> bit_idx) & 1;

            if bit1 != bit2 {
                // Flip the bit in q to create the absent key
                q[byte_idx] ^= 1 << bit_idx;
                differing_bit_found = true;
                break;
            }
        }
        prop_assume!(differing_bit_found, "Keys were different, so a differing bit must exist");

        // Set up the tree
        let mut tree = SparseMerkleTree::new(HashCommitmentScheme::new());
        tree.insert(&k1, &v1).unwrap();
        tree.insert(&k2, &v2).unwrap();
        tree.commit_version(1).unwrap();
        let root = tree.root_commitment();

        // Act: Generate the non-membership proof for the constructed key 'q'.
        let (membership, proof_outer) = tree.get_with_proof_at(&root, &q).unwrap();

        // Assert: The proof must be valid for an absent key.
        prop_assert_eq!(membership, Membership::Absent, "Membership for constructed key should be Absent");
        let proof_inner: SparseMerkleProof = serde_json::from_slice(proof_outer.as_ref()).unwrap();

        // The core assertion: the generated proof must be verifiable.
        prop_assert!(
            SparseMerkleTree::<HashCommitmentScheme>::verify_proof_static(
                root.as_ref(), &q, None, &proof_inner
            ),
            "Non-membership proof for key between two siblings must be valid"
        );
    }
}
