#[cfg(test)]
mod tests {
    use super::*;
    use depin_sdk_commitment_schemes::merkle::MerkleCommitmentScheme;
    use depin_sdk_core::commitment::CommitmentScheme;
    use depin_sdk_state_trees::generic::HashMapStateTree;
    use depin_sdk_transaction_models::utxo::{UTXOInput, UTXOModel, UTXOOutput, UTXOTransaction};
    use depin_sdk_validator::standard::StandardValidator;
    use std::path::Path;
    use tempfile::tempdir;

    // Mock validator model for testing
    struct MockValidatorModel {
        running: bool,
    }

    impl MockValidatorModel {
        fn new() -> Self {
            Self { running: false }
        }
    }

    impl depin_sdk_core::validator::ValidatorModel for MockValidatorModel {
        fn start(&self) -> Result<(), String> {
            let mut running = self.running.clone();
            running = true;
            Ok(())
        }

        fn stop(&self) -> Result<(), String> {
            let mut running = self.running.clone();
            running = false;
            Ok(())
        }

        fn is_running(&self) -> bool {
            self.running
        }

        fn validator_type(&self) -> depin_sdk_core::validator::ValidatorType {
            depin_sdk_core::validator::ValidatorType::Standard
        }
    }

    // Helper function to create a test chain
    fn create_test_chain() -> SovereignAppChain<
        MerkleCommitmentScheme,
        HashMapStateTree<MerkleCommitmentScheme>,
        UTXOModel<MerkleCommitmentScheme>,
        MockValidatorModel,
    > {
        let commitment_scheme = MerkleCommitmentScheme;
        let state_tree = HashMapStateTree::new(commitment_scheme.clone());
        let transaction_model = UTXOModel::new(commitment_scheme.clone());
        let validator_model = MockValidatorModel::new();

        SovereignAppChain::new(
            commitment_scheme,
            state_tree,
            transaction_model,
            validator_model,
            "test-chain",
        )
    }

    // Helper function to create a sample transaction
    fn create_sample_transaction() -> UTXOTransaction {
        UTXOTransaction {
            txid: vec![1, 2, 3],
            inputs: vec![UTXOInput {
                prev_txid: vec![0, 0, 0],
                prev_index: 0,
                signature: vec![0, 1, 2],
            }],
            outputs: vec![UTXOOutput {
                value: 100,
                lock_script: vec![4, 5, 6],
            }],
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
        assert_eq!(retrieved, value);

        // Test proof creation and verification
        let proof = chain.create_state_proof(key).unwrap();
        let commitment = chain.get_state_commitment();

        assert!(chain.verify_state_proof(&commitment, &proof, key, value));

        // Test state deletion
        chain.delete_state(key).unwrap();
        assert!(chain.query_state(key).is_none());
    }

    #[test]
    fn test_transaction_processing() {
        let mut chain = create_test_chain();

        // Our test transaction model's validation always returns true in this test setup
        // and apply() is a no-op, so we can just check that our methods execute without error

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
        for i in 0..3 {
            let txs = vec![create_sample_transaction()];
            let block = chain.create_block(txs);
            chain.process_block(block).unwrap();
        }

        // Verify we only have the latest 2 blocks
        assert!(chain.get_block(1).is_none()); // Should be removed
        assert!(chain.get_block(2).is_some()); // Should be present
        assert!(chain.get_block(3).is_some()); // Should be present
    }
}
