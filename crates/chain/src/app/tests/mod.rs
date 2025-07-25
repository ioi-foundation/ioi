use crate::app::*;
use depin_sdk_commitment_schemes::merkle::MerkleCommitmentScheme;
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::{StateError, TransactionError};
use depin_sdk_core::services::{ServiceType, UpgradableService};
use depin_sdk_core::state::{StateManager, StateTree};
use depin_sdk_core::transaction::TransactionModel;
use depin_sdk_core::validator::{ValidatorModel, ValidatorType};
use std::sync::Arc;
use std::collections::HashMap;

// Mock state tree implementation for testing
struct MockStateTree {
    data: HashMap<Vec<u8>, Vec<u8>>,
    commitment_scheme: MerkleCommitmentScheme,
}

impl MockStateTree {
    fn new(commitment_scheme: MerkleCommitmentScheme) -> Self {
        Self {
            data: HashMap::new(),
            commitment_scheme,
        }
    }
}

impl StateTree for MockStateTree {
    type Commitment = <MerkleCommitmentScheme as CommitmentScheme>::Commitment;
    type Proof = <MerkleCommitmentScheme as CommitmentScheme>::Proof;

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

    fn root_commitment(&self) -> Self::Commitment {
        // Simple implementation for testing
        let values: Vec<Option<Vec<u8>>> = self.data.values()
            .map(|v| Some(v.clone()))
            .collect();
        self.commitment_scheme.commit(&values)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        None // Simplified for testing
    }

    fn verify_proof(
        &self,
        _commitment: &Self::Commitment,
        _proof: &Self::Proof,
        _key: &[u8],
        _value: &[u8],
    ) -> bool {
        true // Simplified for testing
    }
}

impl StateManager for MockStateTree {
    type Commitment = <MerkleCommitmentScheme as CommitmentScheme>::Commitment;
    type Proof = <MerkleCommitmentScheme as CommitmentScheme>::Proof;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        <Self as StateTree>::get(self, key)
    }

    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        <Self as StateTree>::insert(self, key, value)
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        <Self as StateTree>::delete(self, key)
    }

    fn root_commitment(&self) -> Self::Commitment {
        <Self as StateTree>::root_commitment(self)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        <Self as StateTree>::create_proof(self, key)
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        <Self as StateTree>::verify_proof(self, commitment, proof, key, value)
    }
}

// Mock transaction model for testing
struct MockTransactionModel {
    commitment_scheme: MerkleCommitmentScheme,
}

impl MockTransactionModel {
    fn new(commitment_scheme: MerkleCommitmentScheme) -> Self {
        Self { commitment_scheme }
    }
}

#[derive(Clone)]
struct MockTransaction {
    id: Vec<u8>,
}

struct MockProof;

impl TransactionModel for MockTransactionModel {
    type Transaction = MockTransaction;
    type Proof = MockProof;
    type CommitmentScheme = MerkleCommitmentScheme;

    fn validate<S>(&self, _tx: &Self::Transaction, _state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
            Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
            Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof
        > + ?Sized
    {
        Ok(true) // Always valid for testing
    }

    fn apply<S>(&self, _tx: &Self::Transaction, _state: &mut S) -> Result<(), TransactionError>
    where
        S: StateManager<
            Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
            Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof
        > + ?Sized
    {
        Ok(()) // No-op for testing
    }

    fn generate_proof<S>(&self, _tx: &Self::Transaction, _state: &S) -> Result<Self::Proof, TransactionError>
    where
        S: StateManager<
            Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
            Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof
        > + ?Sized
    {
        Ok(MockProof)
    }

    fn verify_proof<S>(&self, _proof: &Self::Proof, _state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
            Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
            Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof
        > + ?Sized
    {
        Ok(true)
    }

    fn serialize_transaction(&self, _tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        Ok(vec![])
    }

    fn deserialize_transaction(&self, _data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        Ok(MockTransaction { id: vec![] })
    }
}

// Mock validator model for testing
struct MockValidatorModel {
    running: std::cell::RefCell<bool>,
}

impl MockValidatorModel {
    fn new() -> Self {
        Self {
            running: std::cell::RefCell::new(false),
        }
    }
}

impl ValidatorModel for MockValidatorModel {
    fn start(&self) -> Result<(), String> {
        *self.running.borrow_mut() = true;
        Ok(())
    }

    fn stop(&self) -> Result<(), String> {
        *self.running.borrow_mut() = false;
        Ok(())
    }

    fn is_running(&self) -> bool {
        *self.running.borrow()
    }

    fn validator_type(&self) -> ValidatorType {
        ValidatorType::Standard
    }
}

// Helper function to create a test chain
fn create_test_chain() -> SovereignAppChain<
    MerkleCommitmentScheme,
    MockStateTree,
    MockTransactionModel,
    MockValidatorModel,
> {
    let commitment_scheme = MerkleCommitmentScheme;
    let state_tree = MockStateTree::new(commitment_scheme.clone());
    let transaction_model = MockTransactionModel::new(commitment_scheme.clone());
    let validator_model = MockValidatorModel::new();

    SovereignAppChain::new(
        commitment_scheme,
        state_tree,
        transaction_model,
        validator_model,
        "test-chain",
        vec![], // No initial services for testing
    )
}

// Helper function to create a sample transaction
fn create_sample_transaction() -> MockTransaction {
    MockTransaction {
        id: vec![1, 2, 3],
    }
}

#[test]
fn test_chain_initialization() {
    let chain = create_test_chain();

    assert_eq!(chain.chain_id(), "test-chain");
    assert_eq!(chain.status().height, 0);
    assert_eq!(chain.status().total_transactions, 0);
    assert_eq!(chain.status().is_running, false);
}

#[test]
fn test_state_operations() {
    let mut chain = create_test_chain();

    // Test state update
    let key = b"test-key";
    let value = b"test-value";
    chain.update_state(key, value).unwrap();

    // Test state query
    let retrieved = chain.query_state(key).unwrap();
    assert_eq!(retrieved.unwrap(), value);

    // Test state deletion
    chain.delete_state(key).unwrap();
    assert!(chain.query_state(key).is_none());
}

#[test]
fn test_transaction_processing() {
    let mut chain = create_test_chain();

    let tx = create_sample_transaction();

    // Test processing a single transaction
    assert!(chain.process_transaction(&tx).is_ok());

    // Test processing a batch of transactions
    let txs = vec![tx.clone(), tx.clone()];
    let results = chain.process_transactions(&txs).unwrap();

    assert_eq!(results.len(), 2);
    for result in results {
        assert_eq!(result, "Success");
    }
}

#[test]
fn test_block_processing() {
    let mut chain = create_test_chain();

    // Start the chain
    chain.start().unwrap();

    // Create a block with transactions
    let txs = vec![create_sample_transaction(), create_sample_transaction()];
    let block = chain.create_block(txs);

    // Verify the block height is correct
    assert_eq!(block.header.height, 1);

    // Process the block
    assert!(chain.process_block(block).is_ok());

    // Verify chain height increased
    assert_eq!(chain.status().height, 1);

    // Verify the block is in recent blocks
    let retrieved_block = chain.get_block(1).unwrap();
    assert_eq!(retrieved_block.header.height, 1);

    // Verify latest block is accessible
    let latest = chain.get_latest_block().unwrap();
    assert_eq!(latest.header.height, 1);
}

#[test]
fn test_chain_lifecycle() {
    let mut chain = create_test_chain();

    // Test start
    chain.start().unwrap();
    assert!(chain.status().is_running);

    // Test stop
    chain.stop().unwrap();
    assert!(!chain.status().is_running);

    // Test reset
    chain.update_state(b"key", b"value").unwrap();
    chain.reset().unwrap();
    assert_eq!(chain.status().height, 0);
    assert_eq!(chain.status().total_transactions, 0);
    assert!(!chain.status().is_running);
}

#[test]
fn test_max_recent_blocks() {
    let mut chain = create_test_chain();

    // Set a small limit
    chain.set_max_recent_blocks(2);

    // Start the chain
    chain.start().unwrap();

    // Process several blocks
    for _ in 0..3 {
        let txs = vec![create_sample_transaction()];
        let block = chain.create_block(txs);
        chain.process_block(block).unwrap();
    }

    // Verify we only have the latest 2 blocks
    assert!(chain.get_block(1).is_none()); // Should be removed
    assert!(chain.get_block(2).is_some()); // Should be present
    assert!(chain.get_block(3).is_some()); // Should be present
}