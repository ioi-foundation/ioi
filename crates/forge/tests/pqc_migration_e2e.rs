// Path: crates/forge/tests/pqc_migration_e2e.rs

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_api::crypto::{SerializableKey, SigningKeyPair};
use depin_sdk_crypto::security::SecurityLevel;
use depin_sdk_crypto::sign::dilithium::{DilithiumKeyPair, DilithiumScheme};
use depin_sdk_crypto::sign::eddsa::Ed25519KeyPair;
use depin_sdk_forge::testing::{
    build_test_artifacts,
    poll::wait_for_height,
    rpc::query_state_key, // Added for state assertions
    submit_transaction,
    TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainId, ChainTransaction,
        Credential, RotationProof, SignHeader, SignatureProof, SignatureSuite, SystemPayload,
        SystemTransaction, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX,
        IDENTITY_CREDENTIALS_PREFIX,
        ORACLE_PENDING_REQUEST_PREFIX, // Added for state assertions
        STAKES_KEY_CURRENT,
        VALIDATOR_SET_KEY,
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
        SigningKeyPair::sign(self, msg).unwrap().to_bytes()
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
        SigningKeyPair::sign(self, msg).unwrap().to_bytes()
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
        public_key_hash: account_id.0, // <-- FIX: Corrected field name from pubkey_hash to public_key_hash
        activation_height: 0,
        l2_location: None,
    };
    let creds_array: [Option<Credential>; 2] = [Some(initial_cred), None];
    let creds_bytes = codec::to_bytes_canonical(&creds_array).unwrap();
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
    let record_bytes = codec::to_bytes_canonical(&record).unwrap();
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
    build_test_artifacts();
    let ed25519_key = Ed25519KeyPair::generate().unwrap();
    let dilithium_scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let dilithium_key = dilithium_scheme.generate_keypair().unwrap();
    let account_id = ed25519_key.account_id();
    let mut nonce = 0;
    let grace_period_blocks = 5u64;
    let chain_id: ChainId = 1.into();

    let ed25519_suite = ed25519_key.suite();
    let ed25519_account_id = ed25519_key.account_id();
    let ed25519_libp2p_pk = ed25519_key.libp2p_public_bytes();

    let validator_keypair = libp2p::identity::Keypair::generate_ed25519();

    // 2. LAUNCH CLUSTER
    let node = TestCluster::builder()
        .with_validators(1)
        .with_keypairs(vec![validator_keypair.clone()])
        .with_consensus_type("ProofOfStake")
        .with_state_tree("IAVL")
        .with_chain_id(chain_id.into())
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            grace_period_blocks,
            chain_id: chain_id.into(),
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519, SignatureSuite::Dilithium2],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(move |genesis, _keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();

            // Setup identity for both the validator and the test account
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
            add_identity_to_genesis(
                genesis_state,
                ed25519_suite,
                ed25519_account_id,
                &ed25519_libp2p_pk,
            );

            // Create ValidatorV1 entry for ONLY the validator node
            let validator_account_id = AccountId(
                account_id_from_key_material(
                    SignatureSuite::Ed25519,
                    &validator_keypair.public().encode_protobuf(),
                )
                .unwrap(),
            );
            let initial_stake = 100_000u128;
            let validators = vec![ValidatorV1 {
                account_id: validator_account_id,
                weight: initial_stake,
                consensus_key: ActiveKeyRecord {
                    suite: SignatureSuite::Ed25519,
                    pubkey_hash: validator_account_id.0,
                    since_height: 0,
                },
            }];

            let validator_sets = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: initial_stake,
                    validators,
                },
                next: None,
            };

            let vs_bytes = depin_sdk_types::app::write_validator_sets(&validator_sets).unwrap();
            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&vs_bytes))),
            );

            // Set up stakes for both accounts for transaction validity
            let initial_stake = 100_000u64;
            let mut stakes = BTreeMap::new();
            stakes.insert(validator_account_id, initial_stake);
            stakes.insert(ed25519_account_id, initial_stake);
            let stakes_bytes = codec::to_bytes_canonical(&stakes).unwrap();
            genesis_state.insert(
                std::str::from_utf8(STAKES_KEY_CURRENT).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&stakes_bytes))),
            );
        })
        .build()
        .await?
        .validators
        .remove(0);

    let rpc_addr = &node.rpc_addr;
    wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;

    // 3. INITIATE ROTATION
    let challenge = {
        let mut preimage = b"DePIN-PQ-MIGRATE/v1".to_vec();
        preimage.extend_from_slice(&<ChainId as Into<u32>>::into(chain_id).to_le_bytes());
        preimage.extend_from_slice(account_id.as_ref());
        let rotation_nonce = 0u64;
        preimage.extend_from_slice(&rotation_nonce.to_le_bytes());
        depin_sdk_crypto::algorithms::hash::sha256(&preimage).unwrap()
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
    nonce += 1; // Nonce is now 1

    // Wait for the block containing the rotation to be committed, ensuring the chain state
    // is updated before we test the grace period logic.
    wait_for_height(rpc_addr, 2, Duration::from_secs(20)).await?;

    // 4. TEST GRACE PERIOD
    // Send with old key (nonce=1)
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
            SystemPayload::RequestOracleData {
                url: "grace-old".into(),
                request_id: 1,
            },
        )?,
    )
    .await?;
    nonce += 1; // Nonce is now 2

    // Assert the transaction was included in a block
    wait_for_height(rpc_addr, 3, Duration::from_secs(20)).await?;

    // Send with new key (nonce=2)
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
            SystemPayload::RequestOracleData {
                url: "grace-new".into(),
                request_id: 2,
            },
        )?,
    )
    .await?;
    nonce += 1; // Nonce is now 3

    // Assert the transaction was included in a block
    wait_for_height(rpc_addr, 4, Duration::from_secs(20)).await?;

    // 5. TEST POST-GRACE PERIOD
    // Wait for grace period to end (activation_height = 2 + 5 = 7). We wait for height 8.
    wait_for_height(rpc_addr, 8, Duration::from_secs(60)).await?;

    // 5a. Submit tx with OLD, EXPIRED key. It should be rejected by the chain. Nonce = 3.
    let old_key_header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };
    let old_key_tx = create_signed_system_tx(
        &ed25519_key,
        old_key_header,
        SystemPayload::RequestOracleData {
            url: "post-grace-old".into(),
            request_id: 3,
        },
    )?;
    // We don't care about the result, just that it gets into the mempool to be filtered.
    let _ = submit_transaction(rpc_addr, &old_key_tx).await;

    // 5b. Submit tx with NEW, ACTIVE key with the same nonce. This should succeed.
    let new_key_header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };
    let new_key_tx = create_signed_system_tx(
        &dilithium_key,
        new_key_header,
        SystemPayload::RequestOracleData {
            url: "post-grace-new".into(),
            request_id: 4,
        },
    )?;
    submit_transaction(rpc_addr, &new_key_tx).await?;
    nonce += 1; // This transaction should succeed, so we bump our local nonce counter

    // 5c. VERIFY THE STATE
    // Wait for a block to be produced that processes these transactions.
    let current_height = depin_sdk_forge::testing::rpc::get_chain_height(rpc_addr).await?;
    wait_for_height(rpc_addr, current_height + 2, Duration::from_secs(20)).await?;

    // The request from the OLD key should NOT exist in state.
    let old_req_key = [ORACLE_PENDING_REQUEST_PREFIX, &3u64.to_le_bytes()].concat();
    let old_req_val = query_state_key(rpc_addr, &old_req_key).await?;
    assert!(
        old_req_val.is_none(),
        "Request from expired key must not be present in state"
    );

    // The request from the NEW key SHOULD exist in state.
    let new_req_key = [ORACLE_PENDING_REQUEST_PREFIX, &4u64.to_le_bytes()].concat();
    let new_req_val = query_state_key(rpc_addr, &new_req_key).await?;
    assert!(
        new_req_val.is_some(),
        "Request from new active key must be present in state"
    );

    println!("SUCCESS: State correctly mutated by new PQC key post-grace period, and not by expired key.");

    // 5d. Final check that the new key can continue to submit transactions.
    let final_header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };
    let final_tx = create_signed_system_tx(
        &dilithium_key,
        final_header,
        SystemPayload::RequestOracleData {
            url: "post-grace-final".into(),
            request_id: 5,
        },
    )?;
    submit_transaction(rpc_addr, &final_tx).await?;
    let final_height = depin_sdk_forge::testing::rpc::get_chain_height(rpc_addr).await?;
    wait_for_height(rpc_addr, final_height + 1, Duration::from_secs(20)).await?;

    println!("--- PQC Identity Migration E2E Test Passed ---");
    Ok(())
}
