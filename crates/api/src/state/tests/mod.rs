// Path: crates/api/src/state/tests/mod.rs
#[cfg(test)]
mod basic_state_tests {
    use crate::error::StateError;
    use crate::state::{
        PrunePlan, ProofProvider, StateAccess, StateManager, StateScanIter, VerifiableState,
    };
    use ioi_types::app::{Membership, RootHash};
    use std::any::Any;
    use std::collections::HashMap;
    use std::sync::Arc;

    // Mock commitment and proof types for testing
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockCommitment(Vec<u8>);

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockProof(Vec<u8>);

    // Mock state manager implementation
    #[derive(Debug, Clone)]
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

    // First, implement the base traits.
    impl StateAccess for MockStateManager {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.data.get(key).cloned())
        }

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.data.remove(key);
            Ok(())
        }

        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            for (key, value) in updates {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            let mut results = Vec::new();
            for key in keys {
                results.push(self.get(key)?);
            }
            Ok(results)
        }

        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            for key in deletes {
                self.delete(key)?;
            }
            for (key, value) in inserts {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
            let results: Vec<_> = self
                .data
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| Ok((Arc::from(k.as_slice()), Arc::from(v.as_slice()))))
                .collect();
            Ok(Box::new(results.into_iter()))
        }
    }

    impl VerifiableState for MockStateManager {
        type Commitment = MockCommitment;
        type Proof = MockProof;

        fn root_commitment(&self) -> Self::Commitment {
            let mut combined = Vec::new();
            for (k, v) in &self.data {
                combined.extend_from_slice(k);
                combined.extend_from_slice(v);
            }
            MockCommitment(combined)
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    impl ProofProvider for MockStateManager {
        type Commitment = MockCommitment;
        type Proof = MockProof;

        fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
            self.get(key).ok().flatten().map(MockProof)
        }

        fn verify_proof(
            &self,
            _commitment: &Self::Commitment,
            proof: &Self::Proof,
            _key: &[u8],
            value: &[u8],
        ) -> Result<(), StateError> {
            if proof.0 == *value {
                Ok(())
            } else {
                Err(StateError::Validation("Proof value mismatch".into()))
            }
        }

        fn get_with_proof_at(
            &self,
            _root: &Self::Commitment,
            key: &[u8],
        ) -> Result<(Membership, Self::Proof), StateError> {
            match self.get(key)? {
                Some(value) => Ok((Membership::Present(value.clone()), MockProof(value))),
                None => Ok((Membership::Absent, MockProof(vec![]))),
            }
        }

        fn commitment_from_anchor(&self, anchor: &[u8; 32]) -> Option<Self::Commitment> {
            Some(MockCommitment(anchor.to_vec()))
        }

        fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError> {
            Ok(MockCommitment(bytes.to_vec()))
        }

        fn commitment_to_bytes(&self, c: &Self::Commitment) -> Vec<u8> {
            c.0.clone()
        }
    }

    // Now, implement the StateManager trait, which only has lifecycle methods.
    impl StateManager for MockStateManager {
        fn prune(&mut self, _plan: &PrunePlan) -> Result<(), StateError> {
            Ok(())
        }
        fn prune_batch(&mut self, _plan: &PrunePlan, _limit: usize) -> Result<usize, StateError> {
            Ok(0)
        }
        fn commit_version(&mut self, _height: u64) -> Result<RootHash, StateError> {
            Ok([0; 32])
        }
        fn adopt_known_root(
            &mut self,
            _root_bytes: &[u8],
            _version: u64,
        ) -> Result<(), StateError> {
            Ok(())
        }
    }

    #[test]
    fn test_basic_state_operations() {
        let mut state = MockStateManager::new();
        let key = b"test_key";
        let value = b"test_value";
        state.insert(key, value).unwrap();
        assert_eq!(state.get(key).unwrap(), Some(value.to_vec()));
        state.delete(key).unwrap();
        assert_eq!(state.get(key).unwrap(), None);
    }

    #[test]
    fn test_batch_operations() {
        let mut state = MockStateManager::new();
        let updates = vec![
            (b"key1".to_vec(), b"value1".to_vec()),
            (b"key2".to_vec(), b"value2".to_vec()),
        ];
        state.batch_set(&updates).unwrap();
        let keys = vec![
            b"key1".to_vec(),
            b"key2".to_vec(),
            b"nonexistent".to_vec(),
        ];
        let values = state.batch_get(&keys).unwrap();
        assert_eq!(values.len(), 3);
        assert_eq!(values[0], Some(b"value1".to_vec()));
        assert_eq!(values[1], Some(b"value2".to_vec()));
        assert_eq!(values[2], None);
    }

    #[test]
    fn test_commitment_and_proof() {
        let mut state = MockStateManager::new();
        let key = b"test_key";
        let value = b"test_value";
        state.insert(key, value).unwrap();
        let commitment = state.root_commitment();
        assert!(!commitment.0.is_empty());
        let proof = state.create_proof(key).unwrap();
        assert_eq!(proof.0, value);
        assert!(state.verify_proof(&commitment, &proof, key, value).is_ok());
        let wrong_value = b"wrong_value";
        assert!(state
            .verify_proof(&commitment, &proof, key, wrong_value)
            .is_err());
    }
}