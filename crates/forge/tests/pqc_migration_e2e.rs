// Path: crates/forge/tests/pqc_migration_e2e.rs
#![cfg(all(
    feature = "consensus-pos",
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
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, poll::wait_for_height, submit_transaction,
    TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainTransaction, Credential,
        RotationProof, SignHeader, SignatureProof, SignatureSuite, SystemPayload,
        SystemTransaction,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX, STAKES_KEY_CURRENT,
        STAKES_KEY_NEXT,
    },
    service_configs::MigrationConfig,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

// Trait to unify signing for different key types in tests
trait TestSigner {
    fn public_bytes(&self) -> Vec<u8>;
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn account_id(&self) -> AccountId;
    fn suite(&self) -> SignatureSuite;
    fn libp2p_public_bytes(&self) -> Vec<u8>;
}

impl TestSigner for Ed25519KeyPair {
    fn public_bytes(&self) -> Vec<u8> {
        SigningKeyPair::public_key(self).to_bytes()
    }
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        SigningKeyPair::sign(self, msg).to_bytes()
    }
    fn account_id(&self) -> AccountId {
        let account_hash =
            account_id_from_key_material(self.suite(), &self.libp2p_public_bytes()).unwrap();
        AccountId(account_hash)
    }
    fn suite(&self) -> SignatureSuite {
        SignatureSuite::Ed25519
    }
    fn libp2p_public_bytes(&self) -> Vec<u8> {
        let pk_bytes = self.public_key().to_bytes();
        let libp2p_ed25519_pk =
            libp2p::identity::ed25519::PublicKey::try_from_bytes(&pk_bytes).unwrap();
        let libp2p_pk = libp2p::identity::PublicKey::from(libp2p_ed25519_pk);
        libp2p_pk.encode_protobuf()
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
        let account_hash =
            account_id_from_key_material(self.suite(), &self.public_bytes()).unwrap();
        AccountId(account_hash)
    }
    fn suite(&self) -> SignatureSuite {
        SignatureSuite::Dilithium2
    }
    fn libp2p_public_bytes(&self) -> Vec<u8> {
        self.public_bytes()
    }
}

// Updated helper for creating signed transactions
fn create_signed_system_tx<S: TestSigner>(
    signer: &S,
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
        suite: signer.suite(),
        public_key: signer.public_bytes(),
        signature,
    };
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

/// Helper function to add a full identity record for a key to the genesis state.
fn add_identity_to_genesis(
    genesis_state: &mut serde_json::Map<String, Value>,
    suite: SignatureSuite,
    account_id: AccountId,
    libp2p_pk_bytes: &[u8],
) {
    // B. Set the initial IdentityHub credentials
    let initial_cred = Credential {
        suite,
        public_key_hash: account_id.0,
        activation_height: 0,
        l2_location: None,
    };
    let creds_array: [Option<Credential>; 2] = [Some(initial_cred), None];
    let creds_bytes = serde_json::to_vec(&creds_array).unwrap();
    let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
    let creds_key_b64 = format!("b64:{}", BASE64_STANDARD.encode(&creds_key));
    genesis_state.insert(
        creds_key_b64,
        json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
    );

    // C. Set the ActiveKeyRecord for consensus verification
    let record = ActiveKeyRecord {
        suite,
        pubkey_hash: account_id.0,
        since_height: 0,
    };
    let record_key = [b"identity::key_record::", account_id.as_ref()].concat();
    let record_bytes = codec::to_bytes_canonical(&record);
    genesis_state.insert(
        format!("b64:{}", BASE64_STANDARD.encode(&record_key)),
        json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes))),
    );

    // D. Set the AccountId -> PublicKey mapping for consensus verification
    let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
    genesis_state.insert(
        format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key)),
        json!(format!("b64:{}", BASE64_STANDARD.encode(&libp2p_pk_bytes))),
    );
}

#[tokio::test]
async fn test_pqc_identity_migration_lifecycle() -> Result<()> {
    // Set a fast block time for the test environment.
    std::env::set_var("ORCH_BLOCK_INTERVAL_SECS", "2");

    // 1. SETUP
    build_test_artifacts("consensus-pos,vm-wasm,tree-file,primitive-hash");
    let ed25519_key = Ed25519KeyPair::generate();
    let dilithium_scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let dilithium_key = dilithium_scheme.generate_keypair();
    let account_id = ed25519_key.account_id();
    let mut nonce = 0;
    let grace_period_blocks = 5u64;
    let chain_id = 1u32;

    let ed25519_suite = ed25519_key.suite();
    let ed25519_account_id = ed25519_key.account_id();
    let ed25519_libp2p_pk = ed25519_key.libp2p_public_bytes();

    let validator_keypair = libp2p::identity::Keypair::generate_ed25519();

    // 2. LAUNCH CLUSTER
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_keypairs(vec![validator_keypair])
        .with_consensus_type("ProofOfStake")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            grace_period_blocks,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519, SignatureSuite::Dilithium2],
            allow_downgrade: false,
            chain_id,
        }))
        .with_genesis_modifier(move |genesis, _keys| {
            // Use the provided validator keypair from the cluster builder
            let validator_keypair = &_keys[0];
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();

            // Setup the validator node's identity
            add_identity_to_genesis(
                genesis_state,
                SignatureSuite::Ed25519,
                AccountId(
                    account_id_from_key_material(
                        SignatureSuite::Ed25519,
                        &validator_keypair.public().encode_protobuf(),
                    )
                    .unwrap(),
                ),
                &validator_keypair.public().encode_protobuf(),
            );

            // Setup the test account's identity
            add_identity_to_genesis(
                genesis_state,
                ed25519_suite,
                ed25519_account_id,
                &ed25519_libp2p_pk,
            );

            // Set initial stake for the validator to produce blocks, using the correct canonical encoding.
            let mut stakes = BTreeMap::new();
            stakes.insert(
                AccountId(
                    account_id_from_key_material(
                        SignatureSuite::Ed25519,
                        &validator_keypair.public().encode_protobuf(),
                    )
                    .unwrap(),
                ),
                100_000u64,
            );
            let stakes_bytes = codec::to_bytes_canonical(&stakes);
            let stakes_b64 = format!("b64:{}", BASE64_STANDARD.encode(stakes_bytes));
            genesis_state.insert(
                std::str::from_utf8(STAKES_KEY_CURRENT).unwrap().to_string(),
                json!(&stakes_b64),
            );
            genesis_state.insert(
                std::str::from_utf8(STAKES_KEY_NEXT).unwrap().to_string(),
                json!(&stakes_b64),
            );
        })
        .build()
        .await?;

    let node = &mut cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    let mut orch_logs = node.orch_log_stream.lock().await.take().unwrap();
    wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;

    // 3. INITIAL TX (Ed25519) - Verifies nonce=0 works
    let header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };
    let initial_tx =
        create_signed_system_tx(&ed25519_key, header, SystemPayload::Unstake { amount: 0 })?;
    submit_transaction(rpc_addr, &initial_tx).await?;
    nonce += 1; // Nonce is now 1
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Published transaction via gossip",
    )
    .await?;

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
        rotate_header,
        SystemPayload::RotateKey(rotation_proof),
    )?;
    submit_transaction(rpc_addr, &rotate_tx).await?;
    nonce += 1; // Nonce is now 2
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Published transaction via gossip",
    )
    .await?;

    // 5. TEST GRACE PERIOD (Both keys should work, sharing the same nonce sequence)
    // Send with old key (nonce=2)
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
            ed_header,
            SystemPayload::Unstake { amount: 0 },
        )?,
    )
    .await?;
    nonce += 1; // Nonce is now 3
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Published transaction via gossip",
    )
    .await?;

    // Send with new key (nonce=3)
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
            dil_header,
            SystemPayload::Unstake { amount: 0 },
        )?,
    )
    .await?;
    nonce += 1; // Nonce is now 4
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Published transaction via gossip",
    )
    .await?;

    // 6. TEST POST-GRACE PERIOD
    wait_for_height(rpc_addr, 8, Duration::from_secs(60)).await?;

    // Try to send with the old key. This should be rejected.
    let old_key_header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };
    let old_key_tx = create_signed_system_tx(
        &ed25519_key,
        old_key_header,
        SystemPayload::Unstake { amount: 1 },
    )?;
    let old_key_result = submit_transaction(rpc_addr, &old_key_tx).await;
    assert!(old_key_result.is_err());
    let err_string = old_key_result.unwrap_err().to_string();
    assert!(
        err_string.contains("ExpiredKey") || err_string.contains("UnauthorizedByCredentials"),
        "Expected ExpiredKey or Unauthorized error, but got: {}",
        err_string
    );

    // Send with the new key. This should succeed.
    let new_key_header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };
    let new_key_tx = create_signed_system_tx(
        &dilithium_key,
        new_key_header,
        SystemPayload::Unstake { amount: 0 },
    )?;
    submit_transaction(rpc_addr, &new_key_tx).await?;
    nonce += 1; // Nonce is now 5
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Published transaction via gossip",
    )
    .await?;

    // Verify the new key still works
    let final_header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };
    let final_tx = create_signed_system_tx(
        &dilithium_key,
        final_header,
        SystemPayload::Unstake { amount: 0 },
    )?;
    submit_transaction(rpc_addr, &final_tx).await?;
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Published transaction via gossip",
    )
    .await?;

    println!("--- PQC Identity Migration E2E Test Passed ---");
    Ok(())
}
