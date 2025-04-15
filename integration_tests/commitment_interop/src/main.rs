//! Integration tests for commitment scheme interoperability
//!
//! This test demonstrates how different commitment schemes can interoperate
//! using the universal proof format.

use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_commitment_schemes::merkle::MerkleCommitmentScheme;

fn main() {
    println!("Running commitment scheme interoperability tests...");
    
    // Create an instance of MerkleCommitmentScheme
    let merkle_scheme = MerkleCommitmentScheme;
    
    // Test commit function
    let values = vec![Some(b"test data".to_vec())];
    let commitment = merkle_scheme.commit(&values);
    
    println!("Merkle commitment: {:?}", commitment.as_ref());
    
    // Test proof creation and verification
    match merkle_scheme.create_proof(0, b"test data") {
        Ok(proof) => {
            let verified = merkle_scheme.verify(&commitment, &proof, 0, b"test data");
            println!("Merkle proof verification: {}", verified);
            
            if !verified {
                panic!("Merkle proof verification failed");
            }
        },
        Err(e) => panic!("Failed to create Merkle proof: {}", e),
    }
    
    println!("All tests passed successfully!");
}
