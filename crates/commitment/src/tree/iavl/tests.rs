// Path: crates/commitment/src/tree/iavl/tests.rs

#[cfg(test)]
mod iavl_tests {
    use crate::primitives::hash::HashCommitmentScheme;
    use crate::tree::iavl::{proof, to_root_hash, IAVLTree};
    use depin_sdk_api::state::{StateCommitment, StateManager};
    use depin_sdk_types::app::Membership;
    use std::collections::BTreeMap;

    #[test]
    fn test_iavl_tree_insert_get_proof() {
        let mut tree = IAVLTree::new(HashCommitmentScheme::new());

        // Insert some key-value pairs
        tree.insert(b"key1", b"value1").unwrap();
        tree.insert(b"key2", b"value2").unwrap();
        tree.commit_version(1).unwrap(); // v1

        // 1. Test basic get
        assert_eq!(tree.get(b"key1").unwrap(), Some(b"value1".to_vec()));
        assert_eq!(tree.get(b"key2").unwrap(), Some(b"value2".to_vec()));
        assert_eq!(tree.get(b"key3").unwrap(), None);

        // 2. Test existence proof
        let root_v1 = tree.root_commitment();
        let (membership, proof) = tree.get_with_proof_at(&root_v1, b"key1").unwrap();

        assert_eq!(membership, Membership::Present(b"value1".to_vec()));
        assert!(tree
            .verify_proof(&root_v1, &proof, b"key1", b"value1")
            .is_ok());

        // 3. Test that proof fails with wrong value
        assert!(tree
            .verify_proof(&root_v1, &proof, b"key1", b"wrong_value")
            .is_err());

        // 4. Test non-existence proof
        let (membership_absent, proof_absent) = tree.get_with_proof_at(&root_v1, b"key3").unwrap();
        assert_eq!(membership_absent, Membership::Absent);

        // Verify the non-existence proof directly using the verifier function
        let root_hash_v1: [u8; 32] = root_v1.as_ref().try_into().unwrap();
        let verification_result = proof::verify_iavl_proof_bytes(
            &root_hash_v1,
            b"key3",
            None, // `None` signifies we are proving absence
            proof_absent.as_ref(),
        );
        assert!(verification_result.is_ok());
        assert!(verification_result.unwrap());
    }

    #[test]
    fn iavl_rotations_preserve_invariant_and_proofs() {
        let mut tree = IAVLTree::new(HashCommitmentScheme::default());
        let mut oracle = BTreeMap::new();

        // A sequence of key insertions designed to trigger various AVL rebalancing cases:
        // LL, RR, LR, and RL rotations.
        let keys_to_insert = vec![
            b"k50".to_vec(),
            b"k30".to_vec(), // Simple insert
            b"k70".to_vec(), // Simple insert
            b"k20".to_vec(), // Still balanced
            b"k10".to_vec(), // Triggers LL case (Right Rotation) at node 30
            b"k80".to_vec(), // Still balanced
            b"k90".to_vec(), // Triggers RR case (Left Rotation) at node 70
            b"k40".to_vec(), // Still balanced
            b"k35".to_vec(), // Triggers LR case (Left-Right Rotation) at node 30
            b"k75".to_vec(), // Triggers RL case (Right-Left Rotation) at node 70
        ];

        // Act: Insert keys one by one, committing after each to update versions
        for (i, key) in keys_to_insert.iter().enumerate() {
            let value = format!("value{}", i);
            tree.insert(key, value.as_bytes()).unwrap();
            oracle.insert(key.clone(), value.into_bytes());
            tree.commit_version((i + 1) as u64).unwrap();
        }

        // Assert: After all insertions and rotations, every key must be retrievable and provable
        let final_root = tree.root_commitment();

        for (key, expected_value) in &oracle {
            // Test 1: Direct `get()` must return the correct value.
            assert_eq!(
                tree.get(key).unwrap().as_deref(),
                Some(expected_value.as_slice()),
                "get() failed for key: {}",
                String::from_utf8_lossy(key)
            );

            // Test 2: `get_with_proof_at()` must return a valid existence proof.
            let (membership, proof) =
                tree.get_with_proof_at(&final_root, key)
                    .unwrap_or_else(|e| {
                        panic!(
                            "get_with_proof_at failed for key '{}': {:?}",
                            String::from_utf8_lossy(key),
                            e
                        )
                    });

            // Assert that membership is correct
            assert_eq!(
                membership,
                Membership::Present(expected_value.clone()),
                "Membership was not Present for key: {}",
                String::from_utf8_lossy(key)
            );

            // Assert that the proof verifies correctly
            assert!(
                tree.verify_proof(&final_root, &proof, key, expected_value)
                    .is_ok(),
                "Proof verification failed for key: {}",
                String::from_utf8_lossy(key)
            );
        }
    }

    #[test]
    fn test_get_with_proof_at_anchor() {
        let mut tree = IAVLTree::new(HashCommitmentScheme::new());
        tree.insert(b"key1", b"value1").unwrap();
        let root_hash_v1 = tree.commit_version(1).unwrap();
        let commitment_v1 = tree.root_commitment();

        tree.insert(b"key2", b"value2").unwrap();
        tree.commit_version(2).unwrap();

        // 1. Get proof from historical anchor
        let (membership_from_anchor, proof_from_anchor) = tree
            .get_with_proof_at_anchor(&root_hash_v1, b"key1")
            .unwrap();

        assert_eq!(membership_from_anchor, Membership::Present(b"value1".to_vec()));

        // 2. Get proof from historical commitment (the old way)
        let (membership_from_commit, proof_from_commit) = tree
            .get_with_proof_at(&commitment_v1, b"key1")
            .unwrap();

        // 3. Assert they are identical
        assert_eq!(membership_from_anchor, membership_from_commit);
        assert_eq!(proof_from_anchor.as_ref(), proof_from_commit.as_ref());

        // 4. Test non-existence at historical anchor
        let (membership_absent, _) = tree.get_with_proof_at_anchor(&root_hash_v1, b"key2").unwrap();
        assert_eq!(membership_absent, Membership::Absent);
    }
}