// Path: crates/cli/src/util.rs

use anyhow::Result;
use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair};
use ioi_types::app::{ChainTransaction, SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction};

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
    // Hash PK to get AccountId (simplified)
    let acc_id = ioi_types::app::AccountId(
        ioi_crypto::algorithms::hash::sha256(&pk)
            .unwrap()
            .try_into()
            .unwrap(),
    );

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