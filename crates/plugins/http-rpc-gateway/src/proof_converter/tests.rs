// Path: crates/http-rpc-gateway/src/proof_converter/tests.rs
use super::*;
use ibc_host::existence_root_from_proof_bytes;
use ibc_proto::ics23 as pb_ics23;
use ioi_api::state::{ProofProvider, StateAccess, StateManager, VerifiableState};
use ioi_state::tree::iavl::{proof as iavl_proof, IAVLTree};
use parity_scale_codec::{Decode, Encode};
use proptest::prelude::*;

/// Helper to set up a simple tree with two keys and get the native IAVL proof for one.
fn setup_tree_and_get_iavl_proof() -> (
    IAVLTree<ioi_state::primitives::hash::HashCommitmentScheme>,
    [u8; 32],
    Vec<u8>,
) {
    let mut tree = IAVLTree::new(ioi_state::primitives::hash::HashCommitmentScheme::new());
    tree.insert(b"key1", b"value1").unwrap();
    tree.insert(b"key3", b"value3").unwrap();
    tree.commit_version(1).unwrap();

    let root_commit = tree.root_commitment();
    let root_hash: [u8; 32] = root_commit.as_ref().try_into().unwrap();

    let (_membership, proof_wrapper) = tree.get_with_proof_at(&root_commit, b"key1").unwrap();

    // The proof wrapper is a `HashProof`. Its `value` field contains the SCALE-encoded `IavlProof`.
    // The raw proof for conversion is the content of the `value` field.
    let iavl_proof_bytes = proof_wrapper.value;

    (tree, root_hash, iavl_proof_bytes)
}

#[test]
fn test_case_1_native_scale_iavl_existence() {
    let (_tree, root_hash, iavl_proof_bytes) = setup_tree_and_get_iavl_proof();

    // Convert the raw IAVL proof bytes to ICS-23
    let converted_proof_bytes =
        convert_proof(&iavl_proof_bytes, ProofFormat::Ics23, Some("key1")).unwrap();

    // Decode the MerkleProof and extract the inner CommitmentProof for verification
    let merkle_proof = PbMerkleProof::decode(converted_proof_bytes.as_slice()).unwrap();
    let commitment_proof_bytes = merkle_proof.proofs.first().unwrap().encode_to_vec();

    // Recompute the root from the converted proof
    let recomputed_root = existence_root_from_proof_bytes(&commitment_proof_bytes).unwrap();

    assert_eq!(root_hash.as_ref(), recomputed_root.as_slice());
}

#[test]
fn test_case_2_wrapped_in_hashproof() {
    let mut tree = IAVLTree::new(ioi_state::primitives::hash::HashCommitmentScheme::new());
    tree.insert(b"key1", b"value1").unwrap();
    tree.commit_version(1).unwrap();
    let root_commit = tree.root_commitment();
    let root_hash: [u8; 32] = root_commit.as_ref().try_into().unwrap();

    let (_membership, proof_wrapper) = tree.get_with_proof_at(&root_commit, b"key1").unwrap();

    // The `proof_wrapper` *is* the `HashProof`. We encode the entire struct.
    let hash_proof_bytes = proof_wrapper.encode();

    // The converter should peel the HashProof wrapper.
    let converted_proof_bytes =
        convert_proof(&hash_proof_bytes, ProofFormat::Ics23, Some("key1")).unwrap();
    let merkle_proof = PbMerkleProof::decode(converted_proof_bytes.as_slice()).unwrap();
    let commitment_proof_bytes = merkle_proof.proofs.first().unwrap().encode_to_vec();
    let recomputed_root = existence_root_from_proof_bytes(&commitment_proof_bytes).unwrap();

    assert_eq!(root_hash.as_ref(), recomputed_root.as_slice());
}

#[test]
fn test_case_3_wrapped_in_scale_vec() {
    let (_tree, root_hash, iavl_proof_bytes) = setup_tree_and_get_iavl_proof();

    // Double-wrap the proof bytes in a SCALE `Vec<u8>` encoding
    let double_wrapped_bytes = parity_scale_codec::Encode::encode(&iavl_proof_bytes);

    // The converter should peel the extra Vec wrapper
    let converted_proof_bytes =
        convert_proof(&double_wrapped_bytes, ProofFormat::Ics23, Some("key1")).unwrap();
    let merkle_proof = PbMerkleProof::decode(converted_proof_bytes.as_slice()).unwrap();
    let commitment_proof_bytes = merkle_proof.proofs.first().unwrap().encode_to_vec();
    let recomputed_root = existence_root_from_proof_bytes(&commitment_proof_bytes).unwrap();

    assert_eq!(root_hash.as_ref(), recomputed_root.as_slice());
}

#[test]
fn test_case_4_wrapped_in_hex() {
    let (_tree, root_hash, iavl_proof_bytes) = setup_tree_and_get_iavl_proof();

    // Wrap the proof bytes as a "0x..." hex string
    let hex_wrapped_bytes = format!("0x{}", hex::encode(&iavl_proof_bytes)).into_bytes();

    // The converter should peel the hex wrapper
    let converted_proof_bytes =
        convert_proof(&hex_wrapped_bytes, ProofFormat::Ics23, Some("key1")).unwrap();
    let merkle_proof = PbMerkleProof::decode(converted_proof_bytes.as_slice()).unwrap();
    let commitment_proof_bytes = merkle_proof.proofs.first().unwrap().encode_to_vec();
    let recomputed_root = existence_root_from_proof_bytes(&commitment_proof_bytes).unwrap();

    assert_eq!(root_hash.as_ref(), recomputed_root.as_slice());
}

#[test]
fn test_case_5_non_existence() {
    let (tree, root_hash, _) = setup_tree_and_get_iavl_proof();
    let root_commit = tree.root_commitment();

    // Generate non-existence proof for a key between "key1" and "key3"
    let (_membership, proof_wrapper) = tree.get_with_proof_at(&root_commit, b"key2").unwrap();
    let iavl_proof_bytes = proof_wrapper.value;

    // Verify it's a valid non-existence proof natively first
    let iavl_proof = iavl_proof::IavlProof::decode(&mut &*iavl_proof_bytes).unwrap();
    let verification =
        iavl_proof::verify_iavl_proof(&root_hash, b"key2", None, &iavl_proof).unwrap();
    assert!(verification, "Native non-existence proof should be valid");

    // Now convert it to ICS-23
    let converted_proof_bytes =
        convert_proof(&iavl_proof_bytes, ProofFormat::Ics23, Some("key2")).unwrap();
    let merkle_proof = PbMerkleProof::decode(converted_proof_bytes.as_slice()).unwrap();
    let commitment_proof = merkle_proof.proofs.first().unwrap();

    // Assert the converted proof is of the non-existence variant
    assert!(matches!(
        commitment_proof.proof,
        Some(pb_ics23::commitment_proof::Proof::Nonexist(_))
    ));
}

#[test]
fn test_case_6_malformed_inputs() {
    // Random bytes
    let res = decode_iavl_proof_flex(&[1, 2, 3, 4, 5]);
    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .to_string()
        .contains("unsupported proof encoding"));

    // Truncated valid proof
    let (_, _, mut iavl_proof_bytes) = setup_tree_and_get_iavl_proof();
    iavl_proof_bytes.truncate(iavl_proof_bytes.len() / 2);
    let res = decode_iavl_proof_flex(&iavl_proof_bytes);
    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .to_string()
        .contains("Not enough data to fill buffer"));
}

#[test]
fn test_case_7_sibling_placement() {
    let mut tree = IAVLTree::new(ioi_state::primitives::hash::HashCommitmentScheme::new());
    tree.insert(b"b", b"val_b").unwrap();
    tree.insert(b"a", b"val_a").unwrap(); // Triggers a rotation, creating an inner node
    tree.commit_version(1).unwrap();

    let root = tree.root_commitment();

    // Proof for "a" (left child)
    let (_mem_a, proof_a_wrapper) = tree.get_with_proof_at(&root, b"a").unwrap();
    let iavl_proof_bytes_a = proof_a_wrapper.value;
    let converted_a = convert_proof(&iavl_proof_bytes_a, ProofFormat::Ics23, Some("a")).unwrap();
    let merkle_proof_a = PbMerkleProof::decode(converted_a.as_slice()).unwrap();
    let cp_a = merkle_proof_a.proofs.first().unwrap();
    if let Some(pb_ics23::commitment_proof::Proof::Exist(ex_a)) = &cp_a.proof {
        let inner_op = ex_a.path.first().unwrap();
        assert!(
            !inner_op.prefix.is_empty(),
            "Proof for left child 'a' should have a non-empty prefix (header)"
        );
        assert!(
            !inner_op.suffix.is_empty(),
            "Proof for left child 'a' should have a non-empty suffix (sibling hash)"
        );
    } else {
        panic!("Expected existence proof for 'a'");
    }

    // Proof for "b" (right child)
    let (_mem_b, proof_b_wrapper) = tree.get_with_proof_at(&root, b"b").unwrap();
    let iavl_proof_bytes_b = proof_b_wrapper.value;
    let converted_b = convert_proof(&iavl_proof_bytes_b, ProofFormat::Ics23, Some("b")).unwrap();
    let merkle_proof_b = PbMerkleProof::decode(converted_b.as_slice()).unwrap();
    let cp_b = merkle_proof_b.proofs.first().unwrap();
    if let Some(pb_ics23::commitment_proof::Proof::Exist(ex_b)) = &cp_b.proof {
        let inner_op = ex_b.path.first().unwrap();
        assert!(
            !inner_op.prefix.is_empty(),
            "Proof for right child 'b' should have a non-empty prefix (header + sibling hash)"
        );
        assert!(
            inner_op.suffix.is_empty(),
            "Proof for right child 'b' should have an empty suffix"
        );
    } else {
        panic!("Expected existence proof for 'b'");
    }
}

proptest! {
    #[test]
    fn proof_conversion_does_not_panic(
        key in prop::collection::vec(any::<u8>(), 1..64),
        value in prop::collection::vec(any::<u8>(), 1..128)
    ) {
        let mut tree = IAVLTree::new(ioi_state::primitives::hash::HashCommitmentScheme::new());
        tree.insert(&key, &value).unwrap();
        tree.commit_version(1).unwrap();
        let root_commit = tree.root_commitment();

        let (_mem, proof_wrapper) = tree.get_with_proof_at(&root_commit, &key).unwrap();
        let iavl_proof_bytes = proof_wrapper.value;

        // The property being tested is that conversion never panics for valid proofs.
        let _ = convert_proof(&iavl_proof_bytes, ProofFormat::Ics23, Some(std::str::from_utf8(&key).unwrap_or(""))).unwrap();
    }
}
