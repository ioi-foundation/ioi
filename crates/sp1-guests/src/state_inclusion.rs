// Path: crates/sp1-guests/src/state_inclusion.rs
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{Bytes, B256};
use alloy_trie::{proof::verify_proof, Nibbles};
use zk_types::StateInclusionPublicInputs;

pub fn main() {
    // 1. Read Public Inputs
    let inputs = sp1_zkvm::io::read::<StateInclusionPublicInputs>();

    // 2. Read the Witness (The Proof)
    // The proof is a vector of RLP-encoded nodes.
    let proof_nodes_raw = sp1_zkvm::io::read::<Vec<Vec<u8>>>();

    // 3. Prepare Verification Data
    let root = B256::from(inputs.state_root);

    if inputs.key.len() != 32 {
        panic!(
            "MPT key must be 32 bytes (keccak hash), got {}",
            inputs.key.len()
        );
    }

    // FIX: Convert key hash to Nibbles
    let key_hash = B256::from_slice(&inputs.key);
    let key_nibbles = Nibbles::unpack(key_hash);

    // FIX: Expected value must be Option<Vec<u8>>
    let expected_value = if inputs.value.is_empty() {
        None
    } else {
        Some(inputs.value.clone())
    };

    // FIX: Convert raw proof nodes to Bytes
    let proof_nodes: Vec<Bytes> = proof_nodes_raw.into_iter().map(Bytes::from).collect();

    // 4. Verify
    if inputs.scheme_id == 0 {
        // Scheme 0 = Ethereum MPT
        match verify_proof(root, key_nibbles, expected_value, &proof_nodes) {
            Ok(_) => {
                // Success
            }
            Err(e) => {
                panic!("MPT Verification Failed: {:?}", e);
            }
        }
    } else {
        panic!("Unsupported proof scheme ID: {}", inputs.scheme_id);
    }

    // 5. Commit Inputs
    sp1_zkvm::io::commit(&inputs);
}
