// Path: crates/forge/tests/pqc_migration_e2e.rs

#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "tree-file",
    feature = "primitive-hash"
))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_api::crypto::{SerializableKey, SigningKeyPair};
use depin_sdk_crypto::security::SecurityLevel;
use depin_sdk_crypto::sign::dilithium::{DilithiumKeyPair, DilithiumScheme};
use depin_sdk_crypto::sign::eddsa::Ed25519KeyPair;
use depin_sdk_forge::testing::{submit_transaction, TestCluster};
use depin_sdk_types::{
    app::{
        account_id_from_pubkey, AccountId, ChainTransaction, Credential, RotationProof, SignHeader,
        SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
    },
    config::InitialServiceConfig,
    service_configs::MigrationConfig,
};
use serde_json::json; // --- FIX: Import the json! macro ---
use std::time::Duration;
use tokio::time::sleep;

// Trait to unify signing for different key types in tests
trait TestSigner {
    fn public_bytes(&self) -> Vec<u8>;
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn account_id(&self) -> AccountId;
}

impl TestSigner for Ed25519KeyPair {
    fn public_bytes(&self) -> Vec<u8> {
        SigningKeyPair::public_key(self).to_bytes()
    }
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        SigningKeyPair::sign(self, msg).to_bytes()
    }
    fn account_id(&self) -> AccountId {
        // --- FIX START: Perform explicit type conversion ---
        // 1. Get the raw bytes from our crypto crate's public key wrapper.
        let pk_bytes = self.public_key().to_bytes();

        // 2. Construct the specific libp2p Ed25519 public key type from the raw bytes.
        let libp2p_ed25519_pk = libp2p::identity::ed25519::PublicKey::try_from_bytes(&pk_bytes)
            .expect("Failed to create libp2p key from bytes");

        // 3. Convert the specific key type into the generic libp2p::identity::PublicKey.
        let libp2p_pk = libp2p::identity::PublicKey::from(libp2p_ed25519_pk);

        // 4. Now, call the canonical function with the correct type.
        account_id_from_pubkey(&libp2p_pk)
        // --- FIX END ---
    }
}

impl TestSigner for DilithiumKeyPair {
    fn public_bytes(&self) -> Vec<u8> {
        SigningKeyPair::public_key(self).to_bytes()
    }
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        SigningKeyPair::sign(self, msg).to_bytes()
    }
    fn account_id(&self) -> AccountId {
        let pk_hash = depin_sdk_crypto::algorithms::hash::sha256(&self.public_bytes());
        AccountId(pk_hash.try_into().unwrap())
    }
}

// Updated helper for creating signed transactions
fn create_signed_system_tx<S: TestSigner>(
    signer: &S,
    suite: SignatureSuite,
    header: SignHeader,
    payload: SystemPayload,
) -> Result<ChainTransaction> {
    let mut tx_to_sign = SystemTransaction {
        header,
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx_to_sign.to_sign_bytes()?;
    let signature = TestSigner::sign(signer, &sign_bytes);

    tx_to_sign.signature_proof = SignatureProof {
        suite,
        public_key: signer.public_bytes(),
        signature,
    };
    Ok(ChainTransaction::System(tx_to_sign))
}

#[tokio::test]
async fn test_pqc_identity_migration_lifecycle() -> Result<()> {
    // 1. SETUP
    let ed25519_key = Ed25519KeyPair::generate();
    let dilithium_scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let dilithium_key = dilithium_scheme.generate_keypair();
    let account_id = ed25519_key.account_id();
    let mut nonce = 0;
    let grace_period_blocks = 5u64;
    let chain_id = 1u32;

    // 2. LAUNCH CLUSTER
    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            grace_period_blocks,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519, SignatureSuite::Dilithium2],
            allow_downgrade: false,
            chain_id,
        }))
        .with_genesis_modifier(move |genesis, keys| {
            genesis["genesis_state"]["system::authorities"] =
                json!([keys[0].public().to_peer_id().to_bytes()]);
            let initial_cred = Credential {
                suite: SignatureSuite::Ed25519,
                public_key_hash: account_id.0,
                activation_height: 0,
                l2_location: None,
            };
            let creds: [Option<Credential>; 2] = [Some(initial_cred), None];
            let creds_bytes = serde_json::to_vec(&creds).unwrap();
            let creds_key = [b"identity::creds::", account_id.as_ref()].concat();
            genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&creds_key))] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes)));
        })
        .build()
        .await?;
    let rpc_addr = &cluster.validators[0].rpc_addr;

    // 3. INITIAL TX (Ed25519) - Verifies nonce=0 works
    sleep(Duration::from_secs(6)).await;
    let header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };
    let initial_tx = create_signed_system_tx(
        &ed25519_key,
        SignatureSuite::Ed25519,
        header,
        SystemPayload::Stake { amount: 10 },
    )?;
    submit_transaction(rpc_addr, &initial_tx).await?;
    nonce += 1;
    sleep(Duration::from_secs(6)).await;

    // 4. INITIATE ROTATION
    let challenge = {
        let mut preimage = b"DePIN-PQ-MIGRATE/v1".to_vec();
        preimage.extend_from_slice(&chain_id.to_le_bytes());
        preimage.extend_from_slice(account_id.as_ref());
        preimage.extend_from_slice(&0u64.to_le_bytes()); // First rotation nonce is 0
        depin_sdk_crypto::algorithms::hash::sha256(&preimage)
    };
    let rotation_proof = RotationProof {
        old_public_key: ed25519_key.public_bytes(),
        old_signature: TestSigner::sign(&ed25519_key, &challenge),
        new_public_key: dilithium_key.public_bytes(),
        new_signature: TestSigner::sign(&dilithium_key, &challenge),
        target_suite: SignatureSuite::Dilithium2,
        l2_location: None,
    };
    let rotate_header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };
    let rotate_tx = create_signed_system_tx(
        &ed25519_key,
        SignatureSuite::Ed25519,
        rotate_header,
        SystemPayload::RotateKey(rotation_proof),
    )?;
    submit_transaction(rpc_addr, &rotate_tx).await?;
    nonce += 1;
    sleep(Duration::from_secs(6)).await;

    // 5. TEST GRACE PERIOD (Both keys should work)
    for _ in 0..(grace_period_blocks - 2) {
        let ed_header = SignHeader {
            account_id,
            nonce,
            chain_id,
            tx_version: 1,
        };
        submit_transaction(
            rpc_addr,
            &create_signed_system_tx(
                &ed25519_key,
                SignatureSuite::Ed25519,
                ed_header,
                SystemPayload::Stake { amount: 1 },
            )?,
        )
        .await?;
        nonce += 1;

        let dil_header = SignHeader {
            account_id,
            nonce,
            chain_id,
            tx_version: 1,
        };
        submit_transaction(
            rpc_addr,
            &create_signed_system_tx(
                &dilithium_key,
                SignatureSuite::Dilithium2,
                dil_header,
                SystemPayload::Stake { amount: 1 },
            )?,
        )
        .await?;
        nonce += 1;
        sleep(Duration::from_secs(6)).await;
    }

    // 6. TEST POST-GRACE PERIOD (Wait for promotion to happen)
    sleep(Duration::from_secs(18)).await;

    let old_key_header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };
    let old_key_tx = create_signed_system_tx(
        &ed25519_key,
        SignatureSuite::Ed25519,
        old_key_header,
        SystemPayload::Stake { amount: 1 },
    )?;

    submit_transaction(rpc_addr, &old_key_tx).await?;

    let new_key_header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };
    let new_key_tx = create_signed_system_tx(
        &dilithium_key,
        SignatureSuite::Dilithium2,
        new_key_header,
        SystemPayload::Stake { amount: 1 },
    )?;
    submit_transaction(rpc_addr, &new_key_tx).await?;

    println!("--- PQC Identity Migration E2E Test Passed ---");
    Ok(())
}
