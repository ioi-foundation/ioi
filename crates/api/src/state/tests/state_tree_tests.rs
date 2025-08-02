//! Tests for state tree interface definitions

#[cfg(test)]
mod tests {
    use crate::commitment::{CommitmentScheme, ProofContext, Selector};
    use crate::state::{StateManager, StateTree};
    use crate::test_utils::mock_commitment::{
        helpers, MockCommitment, MockCommitmentScheme, MockProof,
    };
    use std::any::Any;
    use std::collections::HashMap;

    // Mock state tree implementation for testing
    struct MockStateTree {
        data: HashMap<Vec<u8>, Vec<u8>>,
        scheme: MockCommitmentScheme,
    }

    impl MockStateTree {
        fn new() -> Self {
            Self {
                data: HashMap::new(),
                scheme: MockCommitmentScheme,
            }
        }
    }

    impl StateTree for MockStateTree {
        type Commitment = MockCommitment;
        type Proof = MockProof;

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), String> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.data.get(key).cloned()
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), String> {
            self.data.remove(key);
            Ok(())
        }

        fn root_commitment(&self) -> Self::Commitment {
            let values: Vec<Option<Vec<u8>>> =
                self.data.values().map(|v| Some(v.clone())).collect();

            self.scheme.commit(&values)
        }

        fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
            let value = self.get(key)?;
            // Use key-based selector in proof creation
            let selector = Selector::Key(key.to_vec());
            self.scheme.create_proof(&selector, &value).ok()
        }

        fn verify_proof(
            &self,
            commitment: &Self::Commitment,
            proof: &Self::Proof,
            key: &[u8],
            value: &[u8],
        ) -> bool {
            // Create a context for verification
            let mut context = ProofContext::default();

            // Regenerate the selector from the key - ensure keys actually match
            let selector = Selector::Key(key.to_vec());

            // Check if the proof was created with a matching key
            if let Selector::Key(proof_key) = &proof.selector {
                if proof_key != key {
                    return false;
                }
            }

            // Convert value to Vec<u8> to match the expected type
            self.scheme
                .verify(commitment, proof, &selector, &value.to_vec(), &context)
        }

        fn commitment_scheme(&self) -> &dyn Any {
            &self.scheme
        }
    }

    // Mock state manager implementation for testing
    struct MockStateManager {
        tree: MockStateTree,
    }

    impl MockStateManager {
        fn new() -> Self {
            Self {
                tree: MockStateTree::new(),
            }
        }
    }

    impl StateManager<MockCommitmentScheme> for MockStateManager {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.tree.get(key)
        }

        fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), String> {
            self.tree.insert(key, value)
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), String> {
            self.tree.delete(key)
        }

        fn root_commitment(&self) -> <MockCommitmentScheme as CommitmentScheme>::Commitment {
            self.tree.root_commitment()
        }

        fn create_proof(
            &self,
            key: &[u8],
        ) -> Option<<MockCommitmentScheme as CommitmentScheme>::Proof> {
            self.tree.create_proof(key)
        }

        fn verify_proof(
            &self,
            commitment: &<MockCommitmentScheme as CommitmentScheme>::Commitment,
            proof: &<MockCommitmentScheme as CommitmentScheme>::Proof,
            key: &[u8],
            value: &[u8],
        ) -> bool {
            // Delegate to tree's verify_proof method which now uses the key
            self.tree.verify_proof(commitment, proof, key, value)
        }
    }

    #[test]
    fn test_state_tree_basic_operations() {
        let mut tree = MockStateTree::new();

        // Test insert and get
        let key1 = b"key1";
        let value1 = b"value1";

        tree.insert(key1, value1).unwrap();
        assert_eq!(tree.get(key1), Some(value1.to_vec()));

        // Test delete
        tree.delete(key1).unwrap();
        assert_eq!(tree.get(key1), None);
    }

    #[test]
    fn test_state_tree_commitments_and_proofs() {
        let mut tree = MockStateTree::new();

        let key1 = b"key1";
        let value1 = b"value1";
        let key2 = b"key2";
        let value2 = b"value2";

        tree.insert(key1, value1).unwrap();
        tree.insert(key2, value2).unwrap();

        // Test root commitment
        let commitment = tree.root_commitment();

        // Test proof creation
        let proof = tree.create_proof(key1).unwrap();

        // Test proof verification
        assert!(tree.verify_proof(&commitment, &proof, key1, value1));

        // Test invalid proof - wrong value
        let wrong_value = b"wrong_value";
        assert!(!tree.scheme.verify(
            &commitment,
            &proof,
            &Selector::Key(key1.to_vec()),
            &wrong_value.to_vec(), // Convert to Vec<u8>
            &ProofContext::default()
        ));

        // Test wrong key
        assert!(!tree.verify_proof(&commitment, &proof, key2, value1));
    }

    #[test]
    fn test_proof_context_usage() {
        let mut tree = MockStateTree::new();
        let key1 = b"key1";
        let value1 = b"value1";

        tree.insert(key1, value1).unwrap();
        let commitment = tree.root_commitment();

        // Get a proof for key1
        let proof = tree.create_proof(key1).unwrap();

        // Create a context with strict verification enabled
        let context = helpers::create_context(true);

        // Verify with context - convert value to Vec<u8>
        assert!(tree.scheme.verify(
            &commitment,
            &proof,
            &Selector::Key(key1.to_vec()),
            &value1.to_vec(), // Convert to Vec<u8>
            &context
        ));

        // Try with wrong key but same value - should fail in strict mode
        let wrong_key = b"wrong_key".to_vec();
        assert!(!tree.scheme.verify(
            &commitment,
            &proof,
            &Selector::Key(wrong_key),
            &value1.to_vec(), // Convert to Vec<u8>
            &context
        ));
    }

    #[test]
    fn test_state_manager() {
        let mut manager = MockStateManager::new();

        let key1 = b"key1";
        let value1 = b"value1";

        // Test set and get
        manager.set(key1, value1).unwrap();
        assert_eq!(manager.get(key1), Some(value1.to_vec()));

        // Test root commitment
        let commitment = manager.root_commitment();

        // Test proof creation and verification
        let proof = manager.create_proof(key1).unwrap();
        assert!(manager.verify_proof(&commitment, &proof, key1, value1));

        // Test delete
        manager.delete(key1).unwrap();
        assert_eq!(manager.get(key1), None);
    }

    #[test]
    fn test_with_helper_functions() {
        // Test the helper functions from the mock_commitment module
        let value = b"test_value";
        let key = b"test_key";

        // Create a commitment
        let commitment = helpers::create_commitment(value);

        // Create a proof
        let proof = helpers::create_key_proof(key, value).unwrap();

        // Create a context
        let context = helpers::create_context(true);

        // Verify the proof - convert value to Vec<u8>
        let scheme = MockCommitmentScheme;
        assert!(scheme.verify(
            &commitment,
            &proof,
            &Selector::Key(key.to_vec()),
            &value.to_vec(), // Convert to Vec<u8>
            &context
        ));
    }
}
// TODO: Add more comprehensive tests covering:
// - Complex state tree operations with multiple keys
// - Proof verification across different states
// - State transition validations
// - Edge cases like empty trees, large values, etc.
