//! A simple example of a sovereign app chain using DePIN SDK
//!
//! This example demonstrates how to create a basic chain with a Merkle tree state

use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::state::StateTree;
use depin_sdk_commitment_schemes::merkle::MerkleCommitmentScheme;
use depin_sdk_state_trees::sparse_merkle::SparseMerkleTree;

fn main() {
    println!("DePIN SDK Simple Chain Example");
    
    // Create a new sparse Merkle tree for state storage
    let mut state_tree = SparseMerkleTree::new();
    
    // Insert some key-value pairs
    state_tree.insert(b"key1", b"value1").expect("Failed to insert key1");
    state_tree.insert(b"key2", b"value2").expect("Failed to insert key2");
    
    // Get the root commitment
    let root_commitment = state_tree.root_commitment();
    println!("Root commitment: {:?}", root_commitment.as_ref());
    
    // Create a proof for key1
    let proof = state_tree.create_proof(b"key1").expect("Failed to create proof");
    
    // Verify the proof
    let value = state_tree.get(b"key1").expect("Failed to get value");
    let verified = state_tree.verify_proof(&root_commitment, &proof, b"key1", &value);
    println!("Proof verification: {}", verified);
    
    // Get the commitment scheme used by the tree
    let scheme = state_tree.commitment_scheme();
    println!("Commitment scheme: {:?}", scheme);
}
