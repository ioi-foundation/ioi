// Path: crates/sp1-guests/src/state_inclusion.rs
#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};
use zk_types::StateInclusionPublicInputs;

pub fn main() {
    // 1. Read Public Inputs
    let public_input_bytes: Vec<u8> = sp1_zkvm::io::read();
    let inputs: StateInclusionPublicInputs = bincode::deserialize(&public_input_bytes)
        .expect("Failed to deserialize StateInclusionPublicInputs");

    // 2. Read Private Inputs (The Merkle Proof)
    let proof_bytes: Vec<u8> = sp1_zkvm::io::read();

    // 3. Verification Logic (Placeholder)
    match inputs.scheme_id {
        0 => verify_mpt(&inputs, &proof_bytes),
        1 => verify_verkle(&inputs, &proof_bytes),
        _ => panic!("Unsupported proof scheme ID"),
    }

    // 4. Commit Public Values
    sp1_zkvm::io::commit(&public_input_bytes);
}

fn verify_mpt(inputs: &StateInclusionPublicInputs, _proof: &[u8]) {
    // TODO: Implement MPT verification logic:
    // 1. Decode proof (RLP).
    // 2. Traverse trie from inputs.state_root using inputs.key.
    // 3. Assert value found matches inputs.value.

    // Placeholder: just succeed
    sp1_zkvm::io::commit(&inputs.state_root); // Use to prevent unused var warning in mock
}

fn verify_verkle(inputs: &StateInclusionPublicInputs, _proof: &[u8]) {
    // TODO: Implement Verkle verification logic:
    // 1. Decode proof (IPA/KZG).
    // 2. Verify commitments against inputs.state_root.

    // Placeholder: just succeed
    sp1_zkvm::io::commit(&inputs.state_root); // Use to prevent unused var warning in mock
}
