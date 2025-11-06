// Path: crates/commitment/src/tree/verkle/tests.rs

mod verkle_tests {
    use crate::primitives::kzg::{KZGCommitmentScheme, KZGParams};
    use crate::tree::verkle::proof::{Terminal, VerklePathProof};
    use crate::tree::verkle::verifier::KZGVerifier;
    use crate::tree::verkle::VerkleTree;
    use depin_sdk_api::state::{StateCommitment, StateManager, Verifier};
    use depin_sdk_types::app::Membership;
    use parity_scale_codec::Decode;

    fn setup() -> (VerkleTree<KZGCommitmentScheme>, KZGCommitmentScheme) {
        let params = KZGParams::new_insecure_for_testing(1234, 255);
        let scheme = KZGCommitmentScheme::new(params);
        let tree = VerkleTree::new(scheme.clone(), 256).unwrap();
        (tree, scheme)
    }

    #[test]
    fn test_verkle_insert_get_proof() {
        let (mut tree, _scheme) = setup();
        let key = b"test_key";
        let value = b"test_value";

        // Insert key and commit version
        tree.insert(key, value).unwrap();
        tree.commit_version(1).unwrap();

        let root_v1 = tree.root_commitment();

        // 1. Test basic get
        assert_eq!(tree.get(key).unwrap(), Some(value.to_vec()));
        assert_eq!(tree.get(b"non_existent_key").unwrap(), None);

        // 2. Test existence proof
        let (membership, proof) = tree
            .get_with_proof_at(&root_v1, key)
            .expect("Should generate existence proof");
        assert_eq!(membership, Membership::Present(value.to_vec()));
        assert!(tree.verify_proof(&root_v1, &proof, key, value).is_ok());

        // 3. Test proof fails with wrong value or key
        assert!(tree
            .verify_proof(&root_v1, &proof, key, b"wrong_value")
            .is_err());
        assert!(tree
            .verify_proof(&root_v1, &proof, b"wrong_key", value)
            .is_err());
    }

    #[test]
    fn test_verkle_non_membership_proof() {
        let (mut tree, scheme) = setup();
        let key1 = b"existing_key";
        let value1 = b"value1";
        let non_existent_key = b"non_existent_key";

        // Insert one key and commit
        tree.insert(key1, value1).unwrap();
        tree.commit_version(1).unwrap();

        let root = tree.root_commitment();

        // Generate non-membership proof
        let (membership, proof) = tree
            .get_with_proof_at(&root, non_existent_key)
            .expect("Should generate non-membership proof");
        assert_eq!(membership, Membership::Absent);

        // Verify non-membership proof using the stateless verifier
        let verifier = KZGVerifier::new(scheme.params.clone());
        let is_valid = verifier.verify(&root, &proof, non_existent_key, &membership);
        assert!(is_valid.is_ok(), "Non-membership proof should be valid");

        // Ensure it fails if we falsely claim the key is present
        let fake_membership = Membership::Present(b"fake_value".to_vec());
        let is_invalid = verifier.verify(&root, &proof, non_existent_key, &fake_membership);
        assert!(
            is_invalid.is_err(),
            "Non-membership proof should be invalid for a Present claim"
        );
    }

    #[test]
    fn test_verkle_non_membership_proof_neighbor() {
        let (mut tree, scheme) = setup();
        let key1 = b"key100";
        let value1 = b"value100";
        let non_existent_key = b"key101"; // Adjacent key

        tree.insert(key1, value1).expect("insert should succeed");
        tree.commit_version(1).unwrap();
        let root = tree.root_commitment();

        let (membership, proof_obj) = tree
            .get_with_proof_at(&root, non_existent_key)
            .expect("proof for neighbor absence should be generated");
        assert_eq!(membership, Membership::Absent);

        // Assert that the proof terminal is a Neighbor, not Empty
        let vpp = VerklePathProof::decode(&mut proof_obj.as_ref())
            .expect("deserializing proof object should succeed");
        assert!(matches!(vpp.terminal, Terminal::Neighbor { key_stem, .. } if key_stem == key1));

        let verifier = KZGVerifier::new(scheme.params);
        assert!(verifier
            .verify(&root, &proof_obj, non_existent_key, &membership)
            .is_ok());
    }

    #[test]
    fn test_verkle_versioning_and_historical_proofs() {
        let (mut tree, scheme) = setup();

        // Version 1: Insert key1
        let key1 = b"key_v1";
        let value1 = b"value_v1";
        tree.insert(key1, value1).unwrap();
        tree.commit_version(1).unwrap();
        let root_v1 = tree.root_commitment();

        // Version 2: Insert key2
        let key2 = b"key_v2";
        let value2 = b"value_v2";
        tree.insert(key2, value2).unwrap();
        tree.commit_version(2).unwrap();
        let root_v2 = tree.root_commitment();

        assert_ne!(
            root_v1.as_ref(),
            root_v2.as_ref(),
            "Roots of different versions should be different"
        );

        // Verify key1 exists in state v1
        let (mem1, proof1) = tree
            .get_with_proof_at(&root_v1, key1)
            .expect("Proof for v1 should succeed");

        // Sanity check that the proof is anchored to the historical root
        let vpp1 = VerklePathProof::decode(&mut proof1.as_ref()).unwrap();
        assert_eq!(vpp1.node_commitments[0], root_v1.as_ref());

        assert_eq!(mem1, Membership::Present(value1.to_vec()));
        assert!(tree.verify_proof(&root_v1, &proof1, key1, value1).is_ok());

        // Verify key2 does NOT exist in state v1
        let (mem2_absent, proof2_absent) = tree.get_with_proof_at(&root_v1, key2).unwrap();
        assert_eq!(mem2_absent, Membership::Absent);
        let verifier = KZGVerifier::new(scheme.params.clone());
        assert!(verifier
            .verify(&root_v1, &proof2_absent, key2, &mem2_absent)
            .is_ok());

        // Verify key2 exists in state v2
        let (mem2_present, proof2_present) = tree.get_with_proof_at(&root_v2, key2).unwrap();
        assert_eq!(mem2_present, Membership::Present(value2.to_vec()));
        assert!(tree
            .verify_proof(&root_v2, &proof2_present, key2, value2)
            .is_ok());
    }

    #[test]
    fn test_verkle_overwrite_key() {
        let (mut tree, _scheme) = setup();
        let key = b"key_to_overwrite";
        let value1 = b"initial_value";
        let value2 = b"updated_value";

        // Insert initial value and commit
        tree.insert(key, value1).unwrap();
        tree.commit_version(1).unwrap();
        let root_v1 = tree.root_commitment();

        // Verify initial state
        let (mem1, proof1) = tree.get_with_proof_at(&root_v1, key).unwrap();
        assert_eq!(mem1, Membership::Present(value1.to_vec()));
        assert!(tree.verify_proof(&root_v1, &proof1, key, value1).is_ok());

        // Overwrite the key with a new value and commit
        tree.insert(key, value2).unwrap();
        tree.commit_version(2).unwrap();
        let root_v2 = tree.root_commitment();

        // Verify the new state
        let (mem2, proof2) = tree.get_with_proof_at(&root_v2, key).unwrap();
        assert_eq!(mem2, Membership::Present(value2.to_vec()));
        assert!(tree.verify_proof(&root_v2, &proof2, key, value2).is_ok());

        // Verify the old value still exists in the old state
        let (old_mem, old_proof) = tree.get_with_proof_at(&root_v1, key).unwrap();
        assert_eq!(old_mem, Membership::Present(value1.to_vec()));
        assert!(tree.verify_proof(&root_v1, &old_proof, key, value1).is_ok());
    }

    #[test]
    fn test_verkle_get_with_proof_at_anchor() {
        let (mut tree, _scheme) = setup();
        let key1 = b"key_v1_anchor_test";
        let value1 = b"value_v1_anchor_test";
        tree.insert(key1, value1).unwrap();
        let root_hash_v1 = tree.commit_version(1).unwrap();
        let commitment_v1 = tree.root_commitment();

        tree.insert(b"another_key", b"another_value").unwrap();
        tree.commit_version(2).unwrap();

        // 1. Get proof from historical anchor.
        let (membership_from_anchor, proof_from_anchor) = tree
            .get_with_proof_at_anchor(&root_hash_v1, key1)
            .expect("Should get proof from anchor");

        assert_eq!(membership_from_anchor, Membership::Present(value1.to_vec()));

        // 2. Get proof from historical commitment.
        let (membership_from_commit, proof_from_commit) = tree
            .get_with_proof_at(&commitment_v1, key1)
            .expect("Should get proof from commitment");

        // 3. Assert they are identical.
        assert_eq!(membership_from_anchor, membership_from_commit);
        assert_eq!(proof_from_anchor.as_ref(), proof_from_commit.as_ref());
    }
}