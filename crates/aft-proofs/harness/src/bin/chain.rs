//! AFT-CB P2.5 — the 3-step continuity chain, end to end.
//!
//! Builds three collapse steps (genesis → step2 → step3), each closed by a
//! real 3-member ed25519 ring over the domain-separated tuple, proves each
//! step with SP1 (CORE proofs, CPU), verifies every proof, and checks the
//! hash chain across the steps' committed public values.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};

pub const ELF: Elf = include_elf!("aft-continuity-program");

fn tuple_hash(prev: &[u8; 32], boundary: &[u8; 32], batch: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"aft-cb/final-ack");
    h.update(prev);
    h.update(boundary);
    h.update(batch);
    h.finalize().into()
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let client = ProverClient::from_env();
    let pk = client.setup(ELF).expect("setup failed");

    // ---- pinned verifying key (governed upgrade = a reviewed edit of ----
    // ---- vkey.json in this crate; a mismatch is a refusal, never a  ----
    // ---- fallback)                                                   ----
    let vkey_bytes32 = pk.verifying_key().bytes32();
    let pin_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vkey.json");
    let pin: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(pin_path).expect("vkey.json missing — the pin is part of the protocol parameters"),
    )
    .expect("vkey.json unparseable");
    let pinned = pin["vkey_bytes32"].as_str().expect("vkey_bytes32 missing");
    if pinned == "UNPINNED" {
        eprintln!("vkey is UNPINNED. Computed vkey_bytes32 = {vkey_bytes32}");
        eprintln!("Pin it via a reviewed edit of crates/aft-proofs/vkey.json.");
        std::process::exit(2);
    }
    assert_eq!(
        pinned, vkey_bytes32,
        "verifying key does not match the governed pin — refusing to prove"
    );
    println!("vkey pin OK: {vkey_bytes32}");

    // A real 3-member ring.
    let keys: Vec<SigningKey> = (0..3u8)
        .map(|i| SigningKey::from_bytes(&[i + 1; 32]))
        .collect();
    let ring_keys: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();

    let mut prev_commitment = [0u8; 32];
    let mut total_prove_secs = 0f64;

    for step in 1..=3u8 {
        let boundary_root = [step; 32];
        let batch_root = [step + 100; 32];
        let order_leaves: Vec<[u8; 32]> = vec![[step + 1; 32], [step + 2; 32]];

        let th = tuple_hash(&prev_commitment, &boundary_root, &batch_root);
        let signatures: Vec<Vec<u8>> = keys
            .iter()
            .map(|k| k.sign(&th).to_bytes().to_vec())
            .collect();

        let mut stdin = SP1Stdin::new();
        stdin.write(&prev_commitment);
        stdin.write(&u8::from(step == 1));
        stdin.write(&boundary_root);
        stdin.write(&batch_root);
        stdin.write(&order_leaves);
        stdin.write(&ring_keys);
        stdin.write(&signatures);

        let t0 = std::time::Instant::now();
        let proof = client.prove(&pk, stdin).run().expect("proving failed");
        let dt = t0.elapsed().as_secs_f64();
        total_prove_secs += dt;

        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("verification failed");

        let mut public = proof.public_values.clone();
        let bound_prev: [u8; 32] = public.read();
        let commitment: [u8; 32] = public.read();
        assert_eq!(
            bound_prev, prev_commitment,
            "step {step}: bound prev != chain prev"
        );
        prev_commitment = commitment;
        println!(
            "step {step}: proof verified, prev bound, commitment {} ({dt:.1}s)",
            hex::encode(&commitment[..8])
        );
    }

    println!(
        "3-step continuity chain COMPLETE: every step proof verified, hash chain intact ({total_prove_secs:.1}s total proving)"
    );
}
