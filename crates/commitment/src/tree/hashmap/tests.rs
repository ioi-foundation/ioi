// Path: crates/commitment/src/tree/hashmap/tests.rs

use crate::primitives::hash::HashCommitmentScheme;
use crate::tree::hashmap::{HashMapStateTree, HashMapTreeHashVerifier};
use depin_sdk_api::state::{StateManager, Verifier};
use depin_sdk_types::app::Membership;
use proptest::prelude::*;
use std::collections::BTreeMap;

proptest! {
    #[test]
    fn proof_roundtrip_proptest(
        // Generate a sequence of operations. An operation is a (key, Option<value>) tuple.
        // Some(value) represents an insert/update, while None represents a delete.
        ops in prop::collection::vec(
            // Strategy for a single operation
            prop::collection::vec(0u8..255, 1..32) // Random key (1-32 bytes)
            .prop_flat_map(|key| (
                Just(key), // The key itself
                prop::option::of(prop::collection::vec(0u8..255, 1..128)) // An optional random value
            )),
            1..50 // Generate between 1 and 50 such operations
        )
    ) {
        let mut tree = HashMapStateTree::new(HashCommitmentScheme::new());
        let verifier = HashMapTreeHashVerifier::default();

        // Apply all generated operations to build a final state
        let mut final_state = BTreeMap::new();
        for (key, value_opt) in ops {
            if let Some(value) = value_opt {
                tree.insert(&key, &value).unwrap();
                final_state.insert(key, value);
            } else {
                tree.delete(&key).unwrap();
                final_state.remove(&key);
            }
        }

        let final_root_bytes = tree.root_commitment().as_ref().to_vec();
        let final_root_commitment = verifier.commitment_from_bytes(&final_root_bytes).unwrap();

        // Test every key that should exist in the final state
        for (existing_key, existing_value) in &final_state {
            let (membership, proof) = tree.get_with_proof_at(&final_root_commitment, existing_key).unwrap();

            // 1. Assert that the correct membership is reported
            prop_assert_eq!(membership, Membership::Present(existing_value.clone()), "Membership should be Present with the correct value");

            // 2. Assert that the valid proof verifies successfully
            prop_assert!(verifier.verify(&final_root_commitment, &proof, existing_key, &membership), "Valid proof should verify");

            // 3. Assert that a tampered proof fails verification
            let mut tampered_proof_data = proof.as_ref().to_vec();
            if !tampered_proof_data.is_empty() {
                // Flip the first byte to invalidate the proof
                tampered_proof_data[0] ^= 0xff;
                let tampered_proof = crate::primitives::hash::HashProof::new(
                    tampered_proof_data, proof.selector().clone(), proof.additional_data().to_vec()
                );
                prop_assert!(!verifier.verify(&final_root_commitment, &tampered_proof, existing_key, &membership), "Tampered proof should not verify");
            }

            // 4. Assert that verifying with the wrong value fails
            let wrong_value = Membership::Present(b"completely different value".to_vec());
            prop_assert!(!verifier.verify(&final_root_commitment, &proof, existing_key, &wrong_value), "Proof with wrong value should not verify");
        }

        // Test a key that is guaranteed not to exist
        let non_existent_key = b"this key definitely does not exist in the random map".to_vec();
        if !final_state.contains_key(&non_existent_key) {
             let (membership, proof) = tree.get_with_proof_at(&final_root_commitment, &non_existent_key).unwrap();
             prop_assert_eq!(membership, Membership::Absent, "Membership for non-existent key should be Absent");

             // Note: The simple HashMapStateTree verifier does not support non-membership proofs, so this will fail.
             // A more advanced tree like IAVL or SparseMerkle would pass this check.
             // For now, we expect `verify` to return false.
             prop_assert!(!verifier.verify(&final_root_commitment, &proof, &non_existent_key, &membership), "Non-membership proof verification should be handled (currently fails as expected for this simple tree)");
        }
    }
}