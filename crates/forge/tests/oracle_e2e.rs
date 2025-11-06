// Path: crates/forge/tests/oracle_e2e.rs
#![cfg(all(
    feature = "consensus-pos",
    feature = "vm-wasm",
    feature = "tree-iavl",
    feature = "primitive-hash"
))]

use anyhow::{anyhow, Result};
use axum::{routing::get, serve, Router};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_forge::testing::{
    build_test_artifacts,
    poll::{wait_for_height, wait_for_oracle_data, wait_for_pending_oracle_request},
    submit_transaction, TestCluster,
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainId, ChainTransaction,
        Credential, SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    // [+] FIX: Add the missing import for OracleParams
    config::{InitialServiceConfig, OracleParams},
    keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY},
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use parity_scale_codec::Encode;
use serde_json::json;
use std::net::SocketAddr;
use tokio::task::JoinHandle;

// --- Simple local HTTP stub so the oracle has a deterministic, offline source ---
async fn start_local_price_stub() -> (String, JoinHandle<()>) {
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
        serve(listener, app.into_make_service()).await.unwrap();
    });
    (url, handle)
}

// Helper function to create a signed CallService transaction
fn create_call_service_tx<P: Encode>(
    signer_keypair: &Keypair,
    service_id: &str,
    method: &str,
    params: P,
    nonce: u64,
    chain_id: ChainId,
) -> Result<ChainTransaction> {
    let public_key_bytes = signer_keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(SignatureSuite::Ed25519, &public_key_bytes)?;
    let account_id = AccountId(account_id_hash);

    let payload = SystemPayload::CallService {
        service_id: service_id.to_string(),
        method: method.to_string(),
        params: codec::to_bytes_canonical(&params).map_err(|e| anyhow!(e))?,
    };

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
    let sign_bytes = tx_to_sign.to_sign_bytes().map_err(|e| anyhow!(e))?;
    let signature = signer_keypair.sign(&sign_bytes)?;

    tx_to_sign.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: public_key_bytes,
        signature,
    };
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

// ABI for request_data@v1
#[derive(Encode)]
struct RequestOracleDataParams {
    url: String,
    request_id: u64,
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
        .with_initial_service(InitialServiceConfig::Oracle(OracleParams::default()))
        .with_genesis_modifier(|genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
            let initial_stake = 100_000u128;

            // --- FIX START: Create a deterministically sorted list of validators ---
            let mut validators: Vec<ValidatorV1> = keys
                .iter()
                .map(|keypair| {
                    let pk_bytes = keypair.public().encode_protobuf();
                    let account_id_hash =
                        account_id_from_key_material(SignatureSuite::Ed25519, &pk_bytes).unwrap();
                    let account_id = AccountId(account_id_hash);

                    ValidatorV1 {
                        account_id,
                        weight: initial_stake,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::Ed25519,
                            public_key_hash: account_id_hash,
                            since_height: 0,
                        },
                    }
                })
                .collect();
            validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));
            // --- FIX END ---

            let total_weight = validators.iter().map(|v| v.weight).sum();
            let validator_sets = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight,
                    validators,
                },
                next: None,
            };

            let vs_bytes = ioi_types::app::write_validator_sets(&validator_sets).unwrap();
            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&vs_bytes))),
            );

            // Populate identity records for all validators using the original key order
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
                    public_key_hash: account_id.0,
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
    let signer_keypair = &cluster.validators[0].keypair;
    let request_tx = create_call_service_tx(
        signer_keypair,
        "oracle",
        "request_data@v1",
        RequestOracleDataParams {
            url: stub_url,
            request_id,
        },
        0,
        1.into(),
    )?;
    // Best-effort broadcast to all validators so at least one mempool admits it.
    for v in &cluster.validators {
        let _ = submit_transaction(&v.rpc_addr, &request_tx).await;
    }

    wait_for_pending_oracle_request(node0_rpc, request_id, std::time::Duration::from_secs(30))
        .await?;
    println!("SUCCESS: Oracle request tx was included in a block and is now pending.");

    // 3. ASSERT ON-CHAIN FINALIZATION
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
