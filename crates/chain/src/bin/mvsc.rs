//! # Minimum Viable Single-Node Chain (MVSC)
//!
//! This binary assembles and runs a self-contained, in-memory blockchain
//! using components from the DePIN SDK. It demonstrates the end-to-end
//! integration of the state tree, commitment scheme, transaction model,
//! and the new `dcrypt`-backed crypto layer.

// --- IMPORTS ---
use depin_sdk_chain::app::SovereignAppChain;
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
use depin_sdk_core::{
    commitment::CommitmentScheme,
    crypto::{SerializableKey, SigningKeyPair},
    state::{StateManager, StateTree},
    transaction::TransactionModel,
    validator::{ValidatorModel, ValidatorType},
};
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_crypto::sign::eddsa::Ed25519KeyPair;
use depin_sdk_state_trees::hashmap::HashMapStateTree;
use depin_sdk_transaction_models::utxo::{UTXOInput, UTXOOutput, UTXOTransaction, UTXOModel};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// --- MOCK VALIDATOR MODEL ---
// A simple validator model implementation for the in-memory chain.
// Adapted from `depin-sdk-chain` tests.
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

// --- TRANSACTION CREATION HELPER ---
/// Creates a dummy UTXO transaction for demonstration purposes.
/// Each new transaction spends the output of the previous one.
fn create_dummy_transaction(
    keypair: &Ed25519KeyPair,
    nonce: u64,
    prev_txid: Vec<u8>,
) -> UTXOTransaction {
    let mut tx = UTXOTransaction {
        txid: Vec::new(), // To be filled after signing
        inputs: vec![UTXOInput {
            prev_txid,
            prev_index: 0,
            signature: Vec::new(), // To be filled after signing
        }],
        outputs: vec![UTXOOutput {
            value: 100,
            lock_script: keypair.public_key().to_bytes(), // Lock to our own key for simplicity
        }],
    };

    // Create a digest for signing. A real implementation would have a more
    // robust and standardized serialization format for signing.
    let mut digest_data = Vec::new();
    digest_data.extend_from_slice(&tx.inputs[0].prev_txid);
    digest_data.extend_from_slice(&tx.inputs[0].prev_index.to_le_bytes());
    digest_data.extend_from_slice(&tx.outputs[0].value.to_le_bytes());
    digest_data.extend_from_slice(&tx.outputs[0].lock_script);
    digest_data.extend_from_slice(&nonce.to_le_bytes()); // Add nonce to make each tx hash unique
    
    let digest = sha256(&digest_data);

    // Sign the digest using the dcrypt-backed Ed25519 implementation
    let signature = keypair.sign(&digest);
    tx.inputs[0].signature = signature.to_bytes();

    // The transaction ID is the hash of the signed transaction data
    let mut txid_data = Vec::new();
    txid_data.extend_from_slice(&digest);
    txid_data.extend_from_slice(&tx.inputs[0].signature);
    tx.txid = sha256(&txid_data);

    tx
}

/// Creates a genesis transaction that creates initial UTXOs from nothing
fn create_genesis_transaction(keypair: &Ed25519KeyPair) -> UTXOTransaction {
    let mut tx = UTXOTransaction {
        txid: Vec::new(),
        inputs: vec![], // No inputs for genesis/coinbase transaction
        outputs: vec![UTXOOutput {
            value: 1000000, // Initial supply
            lock_script: keypair.public_key().to_bytes(),
        }],
    };

    // For genesis, we just hash the outputs
    let mut digest_data = Vec::new();
    digest_data.extend_from_slice(b"GENESIS");
    digest_data.extend_from_slice(&tx.outputs[0].value.to_le_bytes());
    digest_data.extend_from_slice(&tx.outputs[0].lock_script);
    
    tx.txid = sha256(&digest_data);
    tx
}

// --- MAIN APPLICATION ---
#[tokio::main]
async fn main() {
    println!("Starting Minimum Viable Single-Node Chain (MVSC)...");

    // Step 1: Instantiate Components
    let commitment_scheme = HashCommitmentScheme::new();
    let state_tree = HashMapStateTree::new(commitment_scheme.clone());
    let transaction_model = UTXOModel::new(commitment_scheme.clone());
    let validator_model = MockValidatorModel::new();

    // Step 2: Instantiate SovereignAppChain
    let mut chain = SovereignAppChain::new(
        commitment_scheme,
        state_tree,
        transaction_model,
        validator_model,
        "mvsc-chain-1",
        vec![], // No initial services
    );

    // Start the chain logic
    if let Err(e) = chain.start() {
        eprintln!("Failed to start chain: {}", e);
        return;
    }
    println!("Chain started successfully. Producing a new block every 5 seconds.");

    // Create a persistent Ed25519 keypair for signing all dummy transactions
    let keypair = Ed25519KeyPair::generate();
    println!("Generated signing keypair for dummy transactions.");

    // Create and process genesis block
    println!("Creating genesis block...");
    let genesis_tx = create_genesis_transaction(&keypair);
    let genesis_txid = genesis_tx.txid.clone();
    println!("  -> Created genesis transaction with txid: 0x{}", hex::encode(&genesis_txid));
    
    let genesis_block = chain.create_block(vec![genesis_tx]);
    match chain.process_block(genesis_block) {
        Ok(_) => {
            let status = chain.status();
            let state_commitment = chain.get_state_commitment();
            let state_root_bytes: &[u8] = state_commitment.as_ref();
            println!(
                "Processed Genesis Block. New State Root: 0x{}",
                hex::encode(state_root_bytes)
            );
        }
        Err(e) => {
            eprintln!("Error processing genesis block: {}", e);
            return;
        }
    }

    let nonce = AtomicU64::new(0);
    let mut last_txid = genesis_txid; // Start with genesis transaction ID

    // Step 3 & 4: Main Loop for Block Production and Transaction Creation
    loop {
        // Wait for 5 seconds to simulate block time
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Create a dummy transaction that spends the output of the previous one
        let current_nonce = nonce.fetch_add(1, Ordering::SeqCst);
        let dummy_tx = create_dummy_transaction(&keypair, current_nonce, last_txid.clone());
        println!("  -> Created dummy transaction with txid: 0x{}", hex::encode(&dummy_tx.txid));
        last_txid = dummy_tx.txid.clone(); // Chain to the next transaction

        // Create and process a block containing the new transaction
        let block = chain.create_block(vec![dummy_tx]);
        match chain.process_block(block) {
            Ok(_) => {
                let status = chain.status();
                let state_commitment = chain.get_state_commitment();
                let state_root_bytes: &[u8] = state_commitment.as_ref();
                println!(
                    "Processed Block #{}. New State Root: 0x{}",
                    status.height,
                    hex::encode(state_root_bytes)
                );
            }
            Err(e) => {
                eprintln!("Error processing block: {}", e);
            }
        }
    }
}