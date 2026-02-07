// Path: crates/zk-driver-succinct/src/tests/native_verification.rs

#![cfg(feature = "native")] // Only compile when native SP1 verification is enabled

use std::fs;
use std::path::PathBuf;

use ioi_api::ibc::IbcZkVerifier; // Import the trait
use ioi_types::ibc::StateProofScheme;
// FIX: Use `crate::` to refer to the library items when inside `src/`
use crate::{
    config::SuccinctDriverConfig, BeaconPublicInputs, StateInclusionPublicInputs, SuccinctDriver,
};

/// Helper: locate fixtures directory
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Helper: build a driver config for beacon verification from fixtures
fn load_beacon_driver_config() -> SuccinctDriverConfig {
    let dir = fixtures_dir();
    // FIX: This file now contains the 32-byte hash directly
    let vk_bytes = fs::read(dir.join("beacon_vk.bin")).expect("missing beacon_vk.bin fixture");

    // The hash string is just the hex of the bytes
    let vk_hash = hex::encode(&vk_bytes);

    SuccinctDriverConfig {
        beacon_vkey_hash: vk_hash,
        beacon_vkey_bytes: vk_bytes,
        // For this test we do not exercise state inclusion; fill with dummies
        state_inclusion_vkey_hash: "00".repeat(32),
        state_inclusion_vkey_bytes: Vec::new(),
    }
}

/// Helper: build a driver config for state inclusion verification from fixtures
fn load_state_driver_config() -> SuccinctDriverConfig {
    let dir = fixtures_dir();
    // FIX: This file now contains the 32-byte hash directly
    let vk_bytes = fs::read(dir.join("state_vk.bin")).expect("missing state_vk.bin fixture");

    let vk_hash = hex::encode(&vk_bytes);

    SuccinctDriverConfig {
        beacon_vkey_hash: "00".repeat(32),
        beacon_vkey_bytes: Vec::new(),
        state_inclusion_vkey_hash: vk_hash,
        state_inclusion_vkey_bytes: vk_bytes,
    }
}

#[test]
#[ignore = "Requires real SP1 beacon_vk.bin / proof / public_inputs fixtures"]
fn native_beacon_verification_succeeds() {
    let dir = fixtures_dir();

    // Load fixtures
    let proof = fs::read(dir.join("beacon_proof.bin")).expect("missing beacon_proof.bin fixture");
    let public_inputs_bytes = fs::read(dir.join("beacon_public_inputs.bin"))
        .expect("missing beacon_public_inputs.bin fixture");

    // Sanity: public inputs should decode as BeaconPublicInputs
    let _inputs: BeaconPublicInputs =
        bincode::deserialize(&public_inputs_bytes).expect("invalid BeaconPublicInputs encoding");

    let cfg = load_beacon_driver_config();
    let driver = SuccinctDriver::new(cfg);

    // Positive path: valid proof must verify
    driver
        .verify_beacon_update(&proof, &public_inputs_bytes)
        .expect("beacon SP1 verification should succeed");
}

#[test]
#[ignore = "Requires real SP1 beacon fixtures"]
fn native_beacon_verification_fails_on_mutated_proof() {
    let dir = fixtures_dir();

    let mut proof =
        fs::read(dir.join("beacon_proof.bin")).expect("missing beacon_proof.bin fixture");
    let public_inputs_bytes = fs::read(dir.join("beacon_public_inputs.bin"))
        .expect("missing beacon_public_inputs.bin fixture");

    // Flip one byte in the proof to guarantee failure
    if let Some(b) = proof.get_mut(0) {
        *b ^= 0x01;
    }

    let cfg = load_beacon_driver_config();
    let driver = SuccinctDriver::new(cfg);

    let result = driver.verify_beacon_update(&proof, &public_inputs_bytes);
    assert!(result.is_err(), "mutated beacon proof should not verify");
}

#[test]
#[ignore = "Requires real SP1 state_vk.bin / proof / public_inputs fixtures"]
fn native_state_inclusion_verification_succeeds() {
    let dir = fixtures_dir();

    // In the simplified driver model, the proof is passed raw.
    // The driver reconstructs inputs from the root.

    let proof_only =
        fs::read(dir.join("state_proof.bin")).expect("missing state_proof.bin fixture");
    let public_inputs_bytes = fs::read(dir.join("state_public_inputs.bin"))
        .expect("missing state_public_inputs.bin fixture");

    // Decode inputs to extract root for the trait call
    let inputs: StateInclusionPublicInputs =
        bincode::deserialize(&public_inputs_bytes).expect("invalid StateInclusionPublicInputs");
    let root = inputs.state_root;

    let cfg = load_state_driver_config();
    let driver = SuccinctDriver::new(cfg);

    // We only care about scheme for encoding; the driver reconstructs inputs internally.
    // Note: The fixture generation MUST ensure that the proof was generated
    // with inputs where key/value are empty, to match the driver's reconstruction logic.
    let scheme = StateProofScheme::Mpt;

    driver
        .verify_state_inclusion(scheme, &proof_only, root)
        .expect("state inclusion SP1 verification should succeed");
}

#[test]
#[ignore = "Requires real SP1 state fixtures"]
fn native_state_inclusion_verification_fails_on_mutated_proof() {
    let dir = fixtures_dir();

    let mut proof_only =
        fs::read(dir.join("state_proof.bin")).expect("missing state_proof.bin fixture");
    let public_inputs_bytes = fs::read(dir.join("state_public_inputs.bin"))
        .expect("missing state_public_inputs.bin fixture");

    // Mutate the proof
    if let Some(b) = proof_only.get_mut(0) {
        *b ^= 0x01;
    }

    let inputs: StateInclusionPublicInputs =
        bincode::deserialize(&public_inputs_bytes).expect("invalid StateInclusionPublicInputs");
    let root = inputs.state_root;

    let cfg = load_state_driver_config();
    let driver = SuccinctDriver::new(cfg);

    let scheme = StateProofScheme::Mpt;

    let result = driver.verify_state_inclusion(scheme, &proof_only, root);
    assert!(
        result.is_err(),
        "mutated state inclusion proof should not verify"
    );
}
