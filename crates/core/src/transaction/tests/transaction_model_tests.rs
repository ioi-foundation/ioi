//! Tests for transaction model trait definitions

#[cfg(test)]
mod tests {
    use crate::commitment::{CommitmentScheme, ProofContext, SchemeIdentifier, Selector};
    use crate::state::StateManager;
    use crate::transaction::{Error, TransactionModel};
    use std::collections::HashMap;

    // Mock commitment scheme implementation for testing
    #[derive(Debug, Clone)]
    struct MockCommitmentScheme;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockCommitment(Vec<u8>);

    impl AsRef<[u8]> for MockCommitment {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockProof {
        position: usize,
        value: Vec<u8>,
    }

    impl CommitmentScheme for MockCommitmentScheme {
        type Commitment = MockCommitment;
        type Proof = MockProof;
        type Value = Vec<u8>; // Still using Vec<u8> but will access via as_ref()

        fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment {
            // Simple implementation for testing
            let mut combined = Vec::new();
            for v in values {
                if let Some(data) = v {
                    combined.extend_from_slice(data.as_ref());
                }
            }
            MockCommitment(combined)
        }

        fn create_proof(
            &self,
            selector: &Selector,
            value: &Self::Value,
        ) -> Result<Self::Proof, String> {
            // Extract position from selector
            let position = match selector {
                Selector::Position(pos) => *pos,
                _ => 0, // Default to position 0 for other selector types
            };

            Ok(MockProof {
                position,
                value: value.clone(),
            })
        }

        fn verify(
            &self,
            _commitment: &Self::Commitment,
            proof: &Self::Proof,
            selector: &Selector,
            value: &Self::Value,
            _context: &ProofContext, // Added context parameter
        ) -> bool {
            // Extract position from selector if it's a position-based selector
            match selector {
                Selector::Position(pos) => proof.position == *pos && proof.value == *value,
                Selector::Key(_) => proof.value == *value, // For key-based selectors, only check value
                _ => false, // Other selector types not supported in this implementation
            }
        }

        fn scheme_id() -> SchemeIdentifier {
            SchemeIdentifier::new("mock")
        }
    }

    // Mock state manager implementation for testing
    struct MockStateManager {
        state: HashMap<Vec<u8>, Vec<u8>>,
        scheme: MockCommitmentScheme,
    }

    impl MockStateManager {
        fn new() -> Self {
            Self {
                state: HashMap::new(),
                scheme: MockCommitmentScheme,
            }
        }
    }

    impl StateManager<MockCommitmentScheme> for MockStateManager {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.state.get(key).cloned()
        }

        fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), String> {
            self.state.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), String> {
            self.state.remove(key);
            Ok(())
        }

        fn root_commitment(&self) -> <MockCommitmentScheme as CommitmentScheme>::Commitment {
            let values: Vec<Option<Vec<u8>>> =
                self.state.values().map(|v| Some(v.clone())).collect();

            self.scheme.commit(&values)
        }

        fn create_proof(
            &self,
            key: &[u8],
        ) -> Option<<MockCommitmentScheme as CommitmentScheme>::Proof> {
            let value = self.get(key)?;
            self.scheme
                .create_proof(&Selector::Position(0), &value)
                .ok()
        }

        fn verify_proof(
            &self,
            _commitment: &<MockCommitmentScheme as CommitmentScheme>::Commitment,
            proof: &<MockCommitmentScheme as CommitmentScheme>::Proof,
            _key: &[u8],
            value: &[u8],
        ) -> bool {
            // Updated to include context parameter and use Position selector
            self.scheme.verify(
                &self.root_commitment(),
                proof,
                &Selector::Position(proof.position),
                &value.to_vec(), // Convert slice to Vec<u8> for Value type
                &ProofContext::default(),
            )
        }
    }

    // Mock transaction model for testing

    // Mock UTXO-style transaction model
    #[derive(Debug, Clone)]
    struct MockUTXOTransaction {
        txid: Vec<u8>,
        inputs: Vec<MockUTXOInput>,
        outputs: Vec<MockUTXOOutput>,
    }

    #[derive(Debug, Clone)]
    struct MockUTXOInput {
        prev_txid: Vec<u8>,
        prev_index: u32,
        signature: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    struct MockUTXOOutput {
        value: u64,
        recipient: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    struct MockUTXOProof {
        proof: MockProof,
    }

    // Mock transaction model implementation
    struct MockTransactionModel {
        scheme: MockCommitmentScheme,
    }

    impl MockTransactionModel {
        fn new() -> Self {
            Self {
                scheme: MockCommitmentScheme,
            }
        }

        // Helper method to create a unique UTXO key from txid and output index
        fn create_utxo_key(txid: &[u8], output_index: u32) -> Vec<u8> {
            let mut key = txid.to_vec();
            key.extend_from_slice(&output_index.to_le_bytes());
            key
        }
    }

    impl TransactionModel<MockCommitmentScheme> for MockTransactionModel {
        type Transaction = MockUTXOTransaction;
        type Proof = MockUTXOProof;

        fn validate(&self, tx: &Self::Transaction, _commitment: &MockCommitment) -> bool {
            // Simple validation for testing
            !tx.inputs.is_empty() && !tx.outputs.is_empty()
        }

        fn apply(
            &self,
            tx: &Self::Transaction,
            state: &mut dyn StateManager<MockCommitmentScheme>,
        ) -> Result<(), String> {
            // Simple application logic for testing
            for input in &tx.inputs {
                // Create a key for the UTXO being spent using the helper method
                let key = Self::create_utxo_key(&input.prev_txid, input.prev_index);
                state.delete(&key)?;
            }

            for (i, output) in tx.outputs.iter().enumerate() {
                // Create a unique key for each output using the helper method
                let key = Self::create_utxo_key(&tx.txid, i as u32);

                // Simple manual serialization instead of using bincode
                let mut value = Vec::new();
                // Serialize value
                value.extend_from_slice(&output.value.to_le_bytes());
                // Serialize recipient length
                value.extend_from_slice(&(output.recipient.len() as u32).to_le_bytes());
                // Serialize recipient
                value.extend_from_slice(&output.recipient);

                state.set(&key, &value)?;
            }

            Ok(())
        }
    }

    #[test]
    fn test_transaction_validation() {
        let model = MockTransactionModel::new();
        let commitment = MockCommitment(vec![0]);

        // Valid transaction
        let valid_tx = MockUTXOTransaction {
            txid: vec![1, 2, 3],
            inputs: vec![MockUTXOInput {
                prev_txid: vec![4, 5, 6],
                prev_index: 0,
                signature: vec![7, 8, 9],
            }],
            outputs: vec![MockUTXOOutput {
                value: 100,
                recipient: vec![10, 11, 12],
            }],
        };

        assert!(model.validate(&valid_tx, &commitment));

        // Invalid transaction - no inputs
        let invalid_tx = MockUTXOTransaction {
            txid: vec![1, 2, 3],
            inputs: vec![],
            outputs: vec![MockUTXOOutput {
                value: 100,
                recipient: vec![10, 11, 12],
            }],
        };

        assert!(!model.validate(&invalid_tx, &commitment));
    }

    #[test]
    fn test_transaction_application() {
        let model = MockTransactionModel::new();
        let mut state = MockStateManager::new();

        // Set up initial state
        let prev_txid = vec![4, 5, 6];
        let prev_index = 0;

        // Create the UTXO key using the helper method
        let prev_utxo_key = MockTransactionModel::create_utxo_key(&prev_txid, prev_index);

        // Simple manual serialization instead of using bincode
        let mut prev_output = Vec::new();
        // Serialize value
        prev_output.extend_from_slice(&100u64.to_le_bytes());
        // Serialize recipient length
        prev_output.extend_from_slice(&(3u32).to_le_bytes());
        // Serialize recipient
        prev_output.extend_from_slice(&[7, 8, 9]);

        state.set(&prev_utxo_key, &prev_output).unwrap();

        // Create and apply transaction
        let tx = MockUTXOTransaction {
            txid: vec![1, 2, 3],
            inputs: vec![MockUTXOInput {
                prev_txid: prev_txid.clone(),
                prev_index,
                signature: vec![10, 11, 12],
            }],
            outputs: vec![
                MockUTXOOutput {
                    value: 50,
                    recipient: vec![13, 14, 15],
                },
                MockUTXOOutput {
                    value: 50,
                    recipient: vec![16, 17, 18],
                },
            ],
        };

        model.apply(&tx, &mut state).unwrap();

        // Verify state changes
        assert_eq!(state.get(&prev_utxo_key), None); // Input was spent

        // Check that both outputs were created with their proper keys
        let output0_key = MockTransactionModel::create_utxo_key(&tx.txid, 0);
        let output1_key = MockTransactionModel::create_utxo_key(&tx.txid, 1);

        assert!(state.get(&output0_key).is_some()); // First output was created
        assert!(state.get(&output1_key).is_some()); // Second output was created
    }

    #[test]
    fn test_error_handling() {
        // Test the Error enum formatting
        let invalid_error = Error::Invalid("test error".to_string());
        let insufficient_error = Error::InsufficientFunds;
        let nonce_error = Error::NonceMismatch;
        let signature_error = Error::InvalidSignature;
        let other_error = Error::Other("other error".to_string());

        assert_eq!(
            format!("{}", invalid_error),
            "Invalid transaction: test error"
        );
        assert_eq!(format!("{}", insufficient_error), "Insufficient funds");
        assert_eq!(format!("{}", nonce_error), "Nonce mismatch");
        assert_eq!(format!("{}", signature_error), "Invalid signature");
        assert_eq!(format!("{}", other_error), "Other error: other error");
    }

    // TODO: Add more comprehensive tests covering:
    // - Different transaction models (UTXO, account-based)
    // - Transaction validation rules
    // - Error cases in transaction application
    // - Complex state changes
}
