// Path: crates/sp1-guests/src/beacon_update.rs
#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};
use zk_types::BeaconPublicInputs;

pub fn main() {
    // 1. Read Public Inputs (encoded by host via bincode)
    let public_input_bytes: Vec<u8> = sp1_zkvm::io::read();
    let inputs: BeaconPublicInputs = bincode::deserialize(&public_input_bytes)
        .expect("Failed to deserialize BeaconPublicInputs");

    // 2. Read Private Inputs (the SSZ beacon update)
    let _beacon_update_bytes: Vec<u8> = sp1_zkvm::io::read();

    // 3. Verification Logic (Placeholder)
    // Here we would:
    // a. Decode the SSZ update.
    // b. Verify the sync committee aggregate signature.
    // c. Verify the finality branch.
    // d. Compute the new state root.

    // For now, we simulate the verification by asserting the provided input
    // matches our expectation (mock logic for skeleton).
    let computed_new_state_root = inputs.new_state_root;

    // 4. Constraint Check
    // We ensure the computed root matches the public claim.
    assert_eq!(
        computed_new_state_root, inputs.new_state_root,
        "Computed state root does not match public input claim"
    );

    // 5. Commit Public Values
    // We write the public inputs back to the output to bind the proof to them.
    sp1_zkvm::io::commit(&public_input_bytes);
}
