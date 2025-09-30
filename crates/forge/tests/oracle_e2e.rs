// Path: crates/forge/tests/oracle_e2e.rs
#![cfg(all(
    feature = "consensus-pos",
    feature = "vm-wasm",
    feature = "tree-iavl",
    feature = "primitive-hash"
))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
// [+] NEW: Import the new polling helper
use depin_sdk_forge::testing::poll::{wait_for_height, wait_for_oracle_data};
use depin_sdk_forge::testing::{build_test_artifacts, submit_transaction, TestCluster};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainId, ChainTransaction,
        Credential, SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY},
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use serde_json::json;
use tokio::task::JoinHandle;

// --- Simple local HTTP stub so the oracle has a deterministic, offline source ---
async fn start_local_price_stub() -> (String, JoinHandle<()>) {
    use axum::{routing::get, Router, Server};
    use std::net::SocketAddr;

    async fn price() -> &'static str {
        // Shape roughly mirrors the CoinGecko response used by the oracle.
        r#"{"bitcoin":{"usd":42000}}"#
    }

    let app = Router::new().route("/price", get(price));
    // Bind to an ephemeral port on localhost
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let url = format!("http://{addr}/price");

    let handle = tokio::spawn(async move {
        Server::from_tcp(listener.into_std().unwrap())
            .unwrap()
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    (url, handle)
}

// Helper function to create a signed system transaction
fn create_system_tx(
    keypair: &Keypair,
    payload: SystemPayload,
    nonce: u64,
    chain_id: ChainId,
) -> Result<ChainTransaction> {
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(SignatureSuite::Ed25519, &public_key_bytes)?;
    let account_id = AccountId(account_id_hash);

    let header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };

    let mut tx_to_sign = SystemTransaction {
        header,
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx_to_sign.to_sign_bytes()?;
    let signature = keypair.sign(&sign_bytes)?;

    tx_to_sign.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: public_key_bytes,
        signature,
    };
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

#[tokio::test]
async fn test_validator_native_oracle_e2e() -> Result<()> {
    // 1. SETUP: Build artifacts and launch a 4-node PoS cluster.
    build_test_artifacts();

    // Launch a local HTTP stub the oracle can call deterministically.
    let (stub_url, _stub_handle) = start_local_price_stub().await;

    let cluster = TestCluster::builder()
        .with_validators(4)
        .with_consensus_type("ProofOfStake")
        .with_state_tree("IAVL")
        .with_chain_id(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(|genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
            let initial_stake = 100_000u128;

            let validators: Vec<ValidatorV1> = keys
                .iter()
                .map(|k| {
                    let pk_bytes = k.public().encode_protobuf();
                    let account_hash =
                        account_id_from_key_material(SignatureSuite::Ed25519, &pk_bytes).unwrap();
                    ValidatorV1 {
                        account_id: AccountId(account_hash),
                        weight: initial_stake,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::Ed25519,
                            pubkey_hash: account_hash,
                            since_height: 0,
                        },
                    }
                })
                .collect();
            let total_weight = validators.iter().map(|v| v.weight).sum();
            let validator_sets = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight,
                    validators,
                },
                next: None,
            };

            let vs_bytes = depin_sdk_types::app::write_validator_sets(&validator_sets).unwrap();
            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&vs_bytes))),
            );

            // Populate identity records for all validators
            for keypair in keys {
                let suite = SignatureSuite::Ed25519;
                let pk_bytes = keypair.public().encode_protobuf();
                let account_id_hash = account_id_from_key_material(suite, &pk_bytes).unwrap();
                let account_id = AccountId(account_id_hash);

                // Add IdentityHub credentials
                let cred = Credential {
                    suite: SignatureSuite::Ed25519,
                    public_key_hash: account_id.0,
                    activation_height: 0,
                    l2_location: None,
                };
                let creds_array: [Option<Credential>; 2] = [Some(cred), None];
                let creds_bytes = codec::to_bytes_canonical(&creds_array).unwrap();
                let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
                genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&creds_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes)));

                // Add AccountId -> PublicKey mapping
                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
                genesis["genesis_state"]
                    [format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&pk_bytes)));

                // Add ActiveKeyRecord for consensus
                let record = ActiveKeyRecord {
                    suite,
                    pubkey_hash: account_id_hash,
                    since_height: 0,
                };
                let record_key = [b"identity::key_record::", account_id.as_ref()].concat();
                let record_bytes = codec::to_bytes_canonical(&record).unwrap();
                genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&record_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes)));
            }
        })
        .build()
        .await?;

    let node0_rpc = &cluster.validators[0].rpc_addr;

    // Wait for deterministic chain readiness.
    wait_for_height(node0_rpc, 2, std::time::Duration::from_secs(30)).await?;

    // 2. SUBMIT ORACLE REQUEST TRANSACTION
    let request_id = 101;
    let payload = SystemPayload::RequestOracleData {
        // Use our stable local stub instead of a flaky external dependency.
        url: stub_url,
        request_id,
    };

    let signer_keypair = &cluster.validators[0].keypair;
    let request_tx = create_system_tx(signer_keypair, payload, 0, 1.into())?;
    // Best-effort broadcast to all validators so at least one mempool admits it.
    for v in &cluster.validators {
        let _ = submit_transaction(&v.rpc_addr, &request_tx).await;
    }

    // 3. ASSERT ON-CHAIN FINALIZATION
    // This is the new, robust assertion. It replaces all previous log checks.
    // It polls the state of the chain until the oracle's final value is present
    // at the expected key, verifying the entire end-to-end flow.
    let expected_data = br#"{"bitcoin":{"usd":42000}}"#.to_vec();
    wait_for_oracle_data(
        node0_rpc,
        request_id,
        &expected_data,
        std::time::Duration::from_secs(45),
    )
    .await?;

    println!("--- Validator-Native Oracle E2E Test Passed ---");
    Ok(())
}
