use super::{Node, SparseMerkleProof, SparseMerkleTree};
use crate::primitives::hash::HashCommitmentScheme;
use ioi_api::state::{ProofProvider, StateAccess, StateManager, VerifiableState};
use ioi_types::app::Membership;
use parity_scale_codec::Decode;
use proptest::prelude::*;

#[test]
fn test_smt_presence_and_absence_proofs() {
    let mut tree = SparseMerkleTree::new(HashCommitmentScheme::new());

    tree.insert(b"\xAA\x00", b"value1").unwrap();
    tree.insert(b"\xAA\xFF", b"value2").unwrap();
    tree.commit_version(1).unwrap();

    let root = tree.root_commitment();
    assert_ne!(root.as_ref(), Node::Empty.hash().as_slice());

    let (membership_present, proof_present_outer) =
        tree.get_with_proof_at(&root, b"\xAA\x00").unwrap();

    assert_eq!(membership_present, Membership::Present(b"value1".to_vec()));

    let proof_present_inner = SparseMerkleProof::decode(&mut proof_present_outer.as_ref()).unwrap();
    assert!(
        SparseMerkleTree::<HashCommitmentScheme>::verify_proof_static(
            root.as_ref(),
            b"\xAA\x00",
            Some(b"value1"),
            &proof_present_inner,
        )
        .unwrap()
    );

    let (membership_absent, proof_absent_outer) =
        tree.get_with_proof_at(&root, b"\xAA\x80").unwrap();

    assert_eq!(membership_absent, Membership::Absent);

    let proof_absent_inner = SparseMerkleProof::decode(&mut proof_absent_outer.as_ref()).unwrap();
    if let Some((witness_key, _)) = &proof_absent_inner.leaf {
        assert_ne!(witness_key.as_slice(), b"\xAA\x80");
    }
    assert!(
        SparseMerkleTree::<HashCommitmentScheme>::verify_proof_static(
            root.as_ref(),
            b"\xAA\x80",
            None,
            &proof_absent_inner,
        )
        .unwrap()
    );

    let (membership_empty, proof_empty_outer) = tree.get_with_proof_at(&root, b"\xBB\x00").unwrap();
    assert_eq!(membership_empty, Membership::Absent);
    let proof_empty_inner = SparseMerkleProof::decode(&mut proof_empty_outer.as_ref()).unwrap();
    assert!(proof_empty_inner.leaf.is_none());
    assert!(
        SparseMerkleTree::<HashCommitmentScheme>::verify_proof_static(
            root.as_ref(),
            b"\xBB\x00",
            None,
            &proof_empty_inner,
        )
        .unwrap()
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

        let mut query = k1.clone();
        let mut differing_bit_found = false;
        for index in 0..(32 * 8) {
            let byte_idx = index / 8;
            let bit_idx = 7 - (index % 8);
            let bit1 = (k1[byte_idx] >> bit_idx) & 1;
            let bit2 = (k2[byte_idx] >> bit_idx) & 1;

            if bit1 != bit2 {
                query[byte_idx] ^= 1 << bit_idx;
                differing_bit_found = true;
                break;
            }
        }
        prop_assume!(differing_bit_found, "Keys were different, so a differing bit must exist");

        let mut tree = SparseMerkleTree::new(HashCommitmentScheme::new());
        tree.insert(&k1, &v1).unwrap();
        tree.insert(&k2, &v2).unwrap();
        tree.commit_version(1).unwrap();
        let root = tree.root_commitment();

        let (membership, proof_outer) = tree.get_with_proof_at(&root, &query).unwrap();
        prop_assert_eq!(membership, Membership::Absent);

        let proof_inner = SparseMerkleProof::decode(&mut proof_outer.as_ref()).unwrap();
        prop_assert!(
            SparseMerkleTree::<HashCommitmentScheme>::verify_proof_static(
                root.as_ref(),
                &query,
                None,
                &proof_inner,
            )
            .unwrap(),
            "Non-membership proof for key between two siblings must be valid"
        );
    }
}

#[test]
fn test_smt_get_with_proof_at_anchor() {
    let mut tree = SparseMerkleTree::new(HashCommitmentScheme::new());
    tree.insert(b"key1", b"value1").unwrap();
    let root_hash_v1 = tree.commit_version(1).unwrap();
    let commitment_v1 = tree.root_commitment();

    tree.insert(b"key2", b"value2").unwrap();
    tree.commit_version(2).unwrap();

    let (membership_from_anchor, proof_from_anchor) = tree
        .get_with_proof_at_anchor(&root_hash_v1, b"key1")
        .unwrap();

    assert_eq!(
        membership_from_anchor,
        Membership::Present(b"value1".to_vec())
    );

    let (membership_from_commitment, proof_from_commitment) =
        tree.get_with_proof_at(&commitment_v1, b"key1").unwrap();

    assert_eq!(membership_from_anchor, membership_from_commitment);
    assert_eq!(proof_from_anchor.as_ref(), proof_from_commitment.as_ref());

    let (membership_absent, _) = tree
        .get_with_proof_at_anchor(&root_hash_v1, b"key2")
        .unwrap();
    assert_eq!(membership_absent, Membership::Absent);
}
