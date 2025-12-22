// Path: crates/forge/tests/oracle_e2e.rs
#![cfg(all(
    feature = "consensus-pos",
    feature = "vm-wasm",
    feature = "state-iavl",
    feature = "commitment-hash"
))]

use anyhow::{anyhow, Result};
use axum::{routing::get, serve, Router};
use ioi_api::state::service_namespace_prefix;
use ioi_forge::testing::{
    build_test_artifacts, submit_transaction, wait_for_height, wait_for_oracle_data,
    wait_for_pending_oracle_request, TestCluster,
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, ChainId, ChainTransaction, SignHeader, SignatureProof, SignatureSuite,
        SystemPayload, SystemTransaction, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::{InitialServiceConfig, OracleParams},
    keys::{ORACLE_DATA_PREFIX, ORACLE_PENDING_REQUEST_PREFIX},
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use parity_scale_codec::Encode;
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
    let account_id_hash = account_id_from_key_material(SignatureSuite::ED25519, &public_key_bytes)?;
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
        suite: SignatureSuite::ED25519,
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
            allowed_target_suites: vec![SignatureSuite::ED25519],
            allow_downgrade: false,
        }))
        .with_initial_service(InitialServiceConfig::Oracle(OracleParams::default()))
        // --- UPDATED: Using GenesisBuilder API ---
        .with_genesis_modifier(|builder, keys| {
            let initial_stake = 100_000u128;

            // Create a deterministically sorted list of validators
            // The builder handles identity registration internally
            let mut validators: Vec<ValidatorV1> = keys
                .iter()
                .map(|keypair| {
                    // Use the builder to register identity (credentials, pubkey map)
                    let account_id = builder.add_identity(keypair);

                    // Re-derive hash for consensus key record
                    let pk_bytes = keypair.public().encode_protobuf();
                    let account_id_hash = account_id.0;

                    ValidatorV1 {
                        account_id,
                        weight: initial_stake,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::ED25519,
                            public_key_hash: account_id_hash,
                            since_height: 0,
                        },
                    }
                })
                .collect();

            validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

            let total_weight = validators.iter().map(|v| v.weight).sum();
            let validator_sets = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight,
                    validators,
                },
                next: None,
            };

            // Set canonical validator set
            builder.set_validators(&validator_sets);

            // Set block timing
            let timing_params = BlockTimingParams {
                base_interval_secs: 5,
                retarget_every_blocks: 0, // Disable adaptive timing for simplicity.
                ..Default::default()
            };
            let timing_runtime = BlockTimingRuntime {
                effective_interval_secs: timing_params.base_interval_secs,
                ..Default::default()
            };
            builder.set_block_timing(&timing_params, &timing_runtime);

            // Identities were already added in the map loop above.
            // However, the original code also added the ActiveKeyRecord to the identity namespace explicitly.
            // The `add_identity` helper does this automatically (creates `identity::key_record::{id}`).
            // So we don't need to duplicate that logic here.
        })
        .build()
        .await?;

    // --- FIX START: Wrap test logic in an async block to guarantee cleanup ---
    let test_result: Result<()> = async {
        let node0_rpc = &cluster.validators[0].validator().rpc_addr;

        // Wait for deterministic chain readiness.
        wait_for_height(node0_rpc, 2, std::time::Duration::from_secs(30)).await?;

        // 2. SUBMIT ORACLE REQUEST TRANSACTION
        let request_id = 101;
        let signer_keypair = &cluster.validators[0].validator().keypair;
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
            let _ = submit_transaction(&v.validator().rpc_addr, &request_tx).await;
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
        Ok(())
    }
    .await;

    // --- FIX START: Add explicit shutdown logic ---
    for guard in cluster.validators {
        guard.shutdown().await?;
    }
    test_result?;
    // --- FIX END ---

    println!("--- Validator-Native Oracle E2E Test Passed ---");
    Ok(())
}
