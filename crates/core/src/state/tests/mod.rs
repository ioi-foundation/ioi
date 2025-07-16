#[cfg(test)]
mod basic_state_tests {
    use crate::error::StateError;
    use crate::state::StateManager;
    use std::collections::HashMap;

    // Mock commitment and proof types for testing
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockCommitment(Vec<u8>);

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockProof(Vec<u8>);

    // Mock state manager implementation
    struct MockStateManager {
        data: HashMap<Vec<u8>, Vec<u8>>,
    }

    impl MockStateManager {
        fn new() -> Self {
            Self {
                data: HashMap::new(),
            }
        }
    }

    impl StateManager for MockStateManager {
        type Commitment = MockCommitment;
        type Proof = MockProof;

        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.data.get(key).cloned())
        }

        fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.data.remove(key);
            Ok(())
        }
        
        fn root_commitment(&self) -> Self::Commitment {
            // Simple mock implementation
            let mut combined = Vec::new();
            for (k, v) in &self.data {
                combined.extend_from_slice(k);
                combined.extend_from_slice(v);
            }
            MockCommitment(combined)
        }
        
        fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
            // Simple mock implementation
            self.get(key).ok().flatten().map(MockProof)
        }
        
        fn verify_proof(
            &self,
            _commitment: &Self::Commitment,
            proof: &Self::Proof,
            _key: &[u8],
            value: &[u8],
        ) -> bool {
            // Simple mock implementation
            proof.0 == value
        }
    }

    #[test]
    fn test_basic_state_operations() {
        let mut state = MockStateManager::new();
        
        // Test set and get
        let key = b"test_key";
        let value = b"test_value";
        
        state.set(key, value).unwrap();
        assert_eq!(state.get(key).unwrap(), Some(value.to_vec()));
        
        // Test delete
        state.delete(key).unwrap();
        assert_eq!(state.get(key).unwrap(), None);
    }

    #[test]
    fn test_batch_operations() {
        let mut state = MockStateManager::new();
        
        // Test batch set
        let updates = vec![
            (b"key1".to_vec(), b"value1".to_vec()),
            (b"key2".to_vec(), b"value2".to_vec()),
            (b"key3".to_vec(), b"value3".to_vec()),
        ];
        
        state.batch_set(&updates).unwrap();
        
        // Test batch get
        let keys = vec![
            b"key1".to_vec(),
            b"key2".to_vec(),
            b"key3".to_vec(),
            b"nonexistent".to_vec(),
        ];
        
        let values = state.batch_get(&keys).unwrap();
        
        assert_eq!(values.len(), 4);
        assert_eq!(values[0], Some(b"value1".to_vec()));
        assert_eq!(values[1], Some(b"value2".to_vec()));
        assert_eq!(values[2], Some(b"value3".to_vec()));
        assert_eq!(values[3], None);
    }
    
    #[test]
    fn test_commitment_and_proof() {
        let mut state = MockStateManager::new();
        
        // Set up test data
        let key = b"test_key";
        let value = b"test_value";
        state.set(key, value).unwrap();
        
        // Test commitment
        let commitment = state.root_commitment();
        assert!(!commitment.0.is_empty());
        
        // Test proof creation
        let proof = state.create_proof(key).unwrap();
        assert_eq!(proof.0, value);
        
        // Test proof verification
        assert!(state.verify_proof(&commitment, &proof, key, value));
        
        // Test verification with wrong value
        let wrong_value = b"wrong_value";
        assert!(!state.verify_proof(&commitment, &proof, key, wrong_value));
    }
}