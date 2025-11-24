// Path: crates/test_utils/src/bin/generate_zk_fixtures.rs
use alloy_primitives::{keccak256, Bytes};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles};
use sp1_sdk::{utils, ProverClient, SP1Stdin, HashableKey};
use ssz_rs::prelude::*;
use std::fs::{self};
use std::io::Write;
use zk_types::{BeaconPublicInputs, StateInclusionPublicInputs};

// NOTE: These paths assume you have run `cargo prove build` in crates/sp1-guests first
// and moved the resulting ELFs to crates/sp1-guests/elf/
const BEACON_ELF: &[u8] =
    include_bytes!("../../../sp1-guests/elf/riscv32im-succinct-zkvm-elf-beacon_update");
const STATE_ELF: &[u8] =
    include_bytes!("../../../sp1-guests/elf/riscv32im-succinct-zkvm-elf-state_inclusion");

fn main() {
    utils::setup_logger();
    let output_dir = "crates/zk-driver-succinct/tests/fixtures";
    fs::create_dir_all(output_dir).unwrap();
    let client = ProverClient::new();

    // ==========================================
    // 1. Beacon Update Fixtures
    // ==========================================
    println!("Generating Beacon Fixtures...");

    #[derive(Default, Debug, SimpleSerialize)]
    struct BeaconBlockHeader {
        slot: u64,
        proposer_index: u64,
        parent_root: Node,
        state_root: Node,
        body_root: Node,
    }
    let mut header = BeaconBlockHeader::default();
    header.slot = 100;
    header.state_root = Node::try_from(vec![0xAA; 32].as_slice()).unwrap();

    // We pass the serialized SSZ bytes to the guest
    let header_ssz = ssz_rs::serialize(&header).unwrap();

    let beacon_inputs = BeaconPublicInputs {
        previous_state_root: [0; 32],
        new_state_root: [0xAA; 32],
        slot: 100,
    };

    // Write raw inputs to disk for the driver to load in tests
    let inputs_bytes = bincode::serialize(&beacon_inputs).unwrap();
    fs::write(
        format!("{}/beacon_public_inputs.bin", output_dir),
        &inputs_bytes,
    )
    .unwrap();

    // Setup Prover
    let (pk, vk) = client.setup(BEACON_ELF);
    
    // FIX: Save canonical hash bytes instead of bincode(vk) to match sp1-verifier expectations
    let vk_hash_str = vk.bytes32();
    let vk_hash_bytes = hex::decode(vk_hash_str.trim_start_matches("0x")).unwrap();
    fs::write(format!("{}/beacon_vk.bin", output_dir), &vk_hash_bytes).unwrap();

    // Generate Proof
    let mut stdin = SP1Stdin::new();
    stdin.write(&beacon_inputs); // Writes bincode(beacon_inputs)
    stdin.write(&header_ssz); // Writes bincode(vec<u8>)

    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .expect("Beacon proving failed");
    let proof_bytes = bincode::serialize(&proof).unwrap();
    fs::write(format!("{}/beacon_proof.bin", output_dir), proof_bytes).unwrap();

    // ==========================================
    // 2. State Inclusion Fixtures
    // ==========================================
    println!("Generating State Inclusion Fixtures...");

    // Generate a real MPT
    let mut hb = HashBuilder::default();
    let key_hash = keccak256(b"my_key");
    // FIX: Convert to Nibbles for alloy-trie API
    let key_nibbles = Nibbles::unpack(key_hash);
    let value = b"my_value";
    hb.add_leaf(key_nibbles.clone(), value);
    let root = hb.root();

    // Generate Proof
    // FIX: Pass Nibbles to ProofRetainer
    let retainer = ProofRetainer::new(vec![key_nibbles.clone()]);
    let mut hb_proof = HashBuilder::default().with_proof_retainer(retainer);
    hb_proof.add_leaf(key_nibbles, value);
    let _ = hb_proof.root();
    
    // FIX: Use take_proofs() instead of take_proof_nodes()
    let proof_nodes = hb_proof.take_proofs();

    // Format proof for guest (Vec<Vec<u8>>)
    // FIX: Explicitly annotate `b` as `Bytes` for type inference
    let proof_vec: Vec<Vec<u8>> = proof_nodes.into_values().map(|b: Bytes| b.to_vec()).collect();

    let state_inputs = StateInclusionPublicInputs {
        state_root: root.into(),
        key: key_hash.to_vec(),
        value: value.to_vec(),
        scheme_id: 0, // MPT
    };

    // Write inputs to disk
    let state_inputs_bytes = bincode::serialize(&state_inputs).unwrap();
    fs::write(
        format!("{}/state_public_inputs.bin", output_dir),
        &state_inputs_bytes,
    )
    .unwrap();

    // Setup Prover
    let (pk_state, vk_state) = client.setup(STATE_ELF);
    
    // FIX: Save canonical hash bytes
    let vk_state_hash_str = vk_state.bytes32();
    let vk_state_hash_bytes = hex::decode(vk_state_hash_str.trim_start_matches("0x")).unwrap();
    fs::write(format!("{}/state_vk.bin", output_dir), &vk_state_hash_bytes).unwrap();

    // Generate Proof
    let mut stdin = SP1Stdin::new();
    stdin.write(&state_inputs);
    stdin.write(&proof_vec);

    let proof_state = client
        .prove(&pk_state, stdin)
        .groth16()
        .run()
        .expect("State proving failed");
    let proof_state_bytes = bincode::serialize(&proof_state).unwrap();
    fs::write(format!("{}/state_proof.bin", output_dir), proof_state_bytes).unwrap();

    println!("Done! Fixtures generated in {}", output_dir);
}