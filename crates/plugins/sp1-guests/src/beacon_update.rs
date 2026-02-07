// Path: crates/sp1-guests/src/beacon_update.rs
#![no_main]
sp1_zkvm::entrypoint!(main);

use ssz_rs::prelude::*;
use zk_types::BeaconPublicInputs;

/// A minimal Beacon Block Header definition for SSZ deserialization.
#[derive(Default, Debug, SimpleSerialize)]
struct BeaconBlockHeader {
    slot: u64,
    proposer_index: u64,
    parent_root: Node,
    state_root: Node,
    body_root: Node,
}

pub fn main() {
    // 1. Read Public Inputs
    let inputs = sp1_zkvm::io::read::<BeaconPublicInputs>();

    // 2. Read the Witness (The Header)
    let header_ssz_bytes = sp1_zkvm::io::read::<Vec<u8>>();

    // 3. Deserialize
    // FIX: ssz_rs::Deserialize::deserialize returns Result<Self, ...>, it does not modify in-place.
    let header = <BeaconBlockHeader as Deserialize>::deserialize(&header_ssz_bytes)
        .expect("Failed to deserialize BeaconBlockHeader via SSZ");

    // 4. Constraints / Checks
    if header.slot != inputs.slot {
        panic!(
            "Slot mismatch. Header: {}, Inputs: {}",
            header.slot, inputs.slot
        );
    }

    if header.state_root.as_ref() != inputs.new_state_root {
        panic!("State root mismatch.");
    }

    // 5. Commit the inputs as public output
    sp1_zkvm::io::commit(&inputs);
}
