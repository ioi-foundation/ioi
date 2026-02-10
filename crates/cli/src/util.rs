// Path: crates/cli/src/util.rs

use anyhow::Result;
use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair};
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainTransaction, SignHeader, SignatureProof,
    SignatureSuite, SystemPayload, SystemTransaction,
};

pub fn titlecase(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

// Helper to sign tx for CLI
pub fn create_cli_tx(
    kp: &ioi_crypto::sign::eddsa::Ed25519KeyPair,
    payload: SystemPayload,
    nonce: u64,
) -> ChainTransaction {
    let pk = kp.public_key().to_bytes();

    // [FIX] Use canonical derivation instead of raw hashing
    // The previous implementation was:
    // let acc_id = ioi_types::app::AccountId(ioi_crypto::algorithms::hash::sha256(&pk).unwrap().try_into().unwrap());

    // We must use the exact same logic as the validator.
    // Since we are using Ed25519 raw bytes here, we need to wrap them as if they came from libp2p
    // OR just use the suite constant correctly.
    // The validator uses: `account_id_from_key_material(SignatureSuite::ED25519, &pk_bytes)`

    let acc_id_bytes = account_id_from_key_material(SignatureSuite::ED25519, &pk)
        .expect("Failed to derive account ID");
    let acc_id = AccountId(acc_id_bytes);

    let header = SignHeader {
        account_id: acc_id,
        nonce,
        chain_id: ioi_types::app::ChainId(0),
        tx_version: 1,
        session_auth: None,
    };

    let mut tx = SystemTransaction {
        header,
        payload,
        signature_proof: Default::default(),
    };

    let bytes = ioi_types::codec::to_bytes_canonical(&tx).unwrap();
    let sig = kp.private_key().sign(&bytes).unwrap();

    tx.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key: pk,
        signature: sig.to_bytes(),
    };

    ChainTransaction::System(Box::new(tx))
}
