//! AFT-CB P2.5 — the leg's mutation drills, run as refusal assertions:
//!   (1) corrupt one byte of a real proof → verification (or the typed
//!       decode in front of it) REFUSES;
//!   (2) verify against a foreign (byte-tampered) verifying key → REFUSES.
//! The process exits 0 only if BOTH tampers produced refusals and the
//! untampered control verified.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin, SP1VerifyingKey,
};

pub const ELF: Elf = include_elf!("aft-continuity-program");

fn main() {
    sp1_sdk::utils::setup_logger();
    let client = ProverClient::from_env();
    let pk = client.setup(ELF).expect("setup failed");

    // One real step (genesis), real 3-member ring.
    let keys: Vec<SigningKey> = (0..3u8)
        .map(|i| SigningKey::from_bytes(&[i + 1; 32]))
        .collect();
    let ring_keys: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let prev = [0u8; 32];
    let boundary = [1u8; 32];
    let batch = [101u8; 32];
    let mut h = Sha256::new();
    h.update(b"aft-cb/final-ack");
    h.update(prev);
    h.update(boundary);
    h.update(batch);
    let th: [u8; 32] = h.finalize().into();
    let sigs: Vec<Vec<u8>> = keys.iter().map(|k| k.sign(&th).to_bytes().to_vec()).collect();

    let mut stdin = SP1Stdin::new();
    stdin.write(&prev);
    stdin.write(&1u8);
    stdin.write(&boundary);
    stdin.write(&batch);
    stdin.write(&vec![[2u8; 32], [3u8; 32]]);
    stdin.write(&ring_keys);
    stdin.write(&sigs);

    let proof = client.prove(&pk, stdin).run().expect("proving failed");

    // Control: the untampered proof verifies.
    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("control verification failed — drills are meaningless");
    println!("control: untampered proof verifies");

    // Drill 1: corrupt one byte of the serialized proof.
    let mut bytes = bincode::serialize(&proof).expect("serialize proof");
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    let drill1_refused = match bincode::deserialize::<sp1_sdk::SP1ProofWithPublicValues>(&bytes) {
        Err(_) => {
            println!("drill 1: REFUSED at decode (corrupt byte broke the envelope)");
            true
        }
        Ok(tampered) => match client.verify(&tampered, pk.verifying_key(), None) {
            Err(e) => {
                println!("drill 1: REFUSED at verification ({e})");
                true
            }
            Ok(()) => {
                eprintln!("drill 1 FAILED: tampered proof verified");
                false
            }
        },
    };

    // Drill 2: foreign verifying key (byte-tampered vk).
    let mut vk_bytes = bincode::serialize(pk.verifying_key()).expect("serialize vk");
    let vmid = vk_bytes.len() / 2;
    vk_bytes[vmid] ^= 0x01;
    let drill2_refused = match bincode::deserialize::<SP1VerifyingKey>(&vk_bytes) {
        Err(_) => {
            println!("drill 2: REFUSED at vk decode (tampered key unparseable)");
            true
        }
        Ok(foreign_vk) => match client.verify(&proof, &foreign_vk, None) {
            Err(e) => {
                println!("drill 2: REFUSED at verification with foreign vkey ({e})");
                true
            }
            Ok(()) => {
                eprintln!("drill 2 FAILED: proof verified under a foreign vkey");
                false
            }
        },
    };

    if drill1_refused && drill2_refused {
        println!("DRILLS PASS: both tampers refused, control verified");
    } else {
        std::process::exit(1);
    }
}
