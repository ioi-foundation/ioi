//! Integration tests for commitment scheme interoperability
//!
//! This test demonstrates how different commitment schemes can interoperate
//! using the universal proof format.

use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, Selector};

fn main() {
    println!("Running commitment scheme interoperability tests...");

    // Create an instance of HashCommitmentScheme
    let hash_scheme = HashCommitmentScheme::new();

    // Test commit function
    let test_data = b"test data".to_vec();
    let values = vec![Some(test_data.clone())];
    let commitment = hash_scheme.commit(&values);

    println!("Hash commitment: {:?}", commitment.as_ref());

    // Create a position-based selector
    let selector = Selector::Position(0);

    // Create a default proof context
    let context = ProofContext::default();

    // Test proof creation and verification
    match hash_scheme.create_proof(&selector, &test_data) {
        Ok(proof) => {
            let verified = hash_scheme.verify(&commitment, &proof, &selector, &test_data, &context);

            println!("Hash proof verification: {}", verified);

            if !verified {
                panic!("Hash proof verification failed");
            }
        }
        Err(e) => panic!("Failed to create Hash proof: {}", e),
    }

    println!("All tests passed successfully!");
}
