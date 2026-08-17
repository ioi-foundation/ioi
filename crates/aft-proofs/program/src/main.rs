//! AFT-CB P2.5 — the continuity guest.
//!
//! Proves one step of the collapse-continuity relation:
//!   - the step binds a previous step commitment (or genesis),
//!   - a Unanimous Boundary Close over (boundary_root, batch_root) is
//!     signature-verified in-guest: EVERY ring member's ed25519 signature
//!     over the domain-separated tuple must verify (n-of-n — no smaller
//!     quorum exists in this program),
//!   - the canonical-order relation binds order_root to the closed
//!     boundary by hash,
//!   - the step commits (as public values) the tuple that the NEXT step
//!     will bind: H(prev_commitment || boundary_root || batch_root ||
//!     order_root || ring_root).
//!
//! Chain shape (labeled honestly): each step is an independent SP1 CORE
//! proof; the host verifies every step proof and the hash chain links
//! step commitments. In-guest recursive verification (compressing the
//! chain into one proof) is the R4c follow-up and is NOT claimed here.

#![no_main]
sp1_zkvm::entrypoint!(main);

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub fn main() {
    // ---- inputs ---------------------------------------------------------
    let prev_commitment: [u8; 32] = sp1_zkvm::io::read();
    let is_genesis: u8 = sp1_zkvm::io::read();
    let boundary_root: [u8; 32] = sp1_zkvm::io::read();
    let batch_root: [u8; 32] = sp1_zkvm::io::read();
    let order_leaves: Vec<[u8; 32]> = sp1_zkvm::io::read();
    let ring_keys: Vec<[u8; 32]> = sp1_zkvm::io::read();
    let signatures: Vec<Vec<u8>> = sp1_zkvm::io::read();

    // ---- genesis binding ------------------------------------------------
    if is_genesis == 1 {
        assert_eq!(prev_commitment, [0u8; 32], "genesis must bind the zero commitment");
    }

    // ---- the signed tuple (domain-separated, spec §12.2 shape) ----------
    let mut h = Sha256::new();
    h.update(b"aft-cb/final-ack");
    h.update(prev_commitment);
    h.update(boundary_root);
    h.update(batch_root);
    let tuple_hash: [u8; 32] = h.finalize().into();

    // ---- UBC: n-of-n real ed25519 verification --------------------------
    assert!(!ring_keys.is_empty(), "empty ring");
    assert_eq!(
        ring_keys.len(),
        signatures.len(),
        "bitmap-complete: every member's share, no more, no fewer"
    );
    for (pk_bytes, sig_bytes) in ring_keys.iter().zip(signatures.iter()) {
        let vk = VerifyingKey::from_bytes(pk_bytes).expect("ring key");
        let sig = Signature::from_slice(sig_bytes).expect("share encoding");
        vk.verify(&tuple_hash, &sig).expect("share verification failed");
    }

    // ---- canonical-order relation: order_root = H(fold of leaves) over  --
    // ---- the closed boundary                                             --
    let mut oh = Sha256::new();
    oh.update(b"aft-cb/order");
    oh.update(boundary_root);
    for leaf in &order_leaves {
        oh.update(leaf);
    }
    let order_root: [u8; 32] = oh.finalize().into();

    // ---- ring commitment ------------------------------------------------
    let mut rh = Sha256::new();
    rh.update(b"aft-cb/ring");
    for k in &ring_keys {
        rh.update(k);
    }
    let ring_root: [u8; 32] = rh.finalize().into();

    // ---- the step commitment the next step binds ------------------------
    let mut ch = Sha256::new();
    ch.update(b"aft-cb/continuity");
    ch.update(prev_commitment);
    ch.update(boundary_root);
    ch.update(batch_root);
    ch.update(order_root);
    ch.update(ring_root);
    let commitment: [u8; 32] = ch.finalize().into();

    // ---- public values: (prev_commitment, commitment) -------------------
    sp1_zkvm::io::commit(&prev_commitment);
    sp1_zkvm::io::commit(&commitment);
}
