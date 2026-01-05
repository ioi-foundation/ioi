// Path: crates/cli/tests/infra_e2e.rs
#![cfg(all(
    any(feature = "consensus-admft", feature = "consensus-pos"),
    feature = "vm-wasm",
    feature = "state-iavl"
))]

use anyhow::{anyhow, Result};
use axum::{routing::get, serve, Router};
// [FIX] Import WorkloadClientApi to enable calling query_state_at
use ioi_api::chain::WorkloadClientApi;
use ioi_client::WorkloadClient;
use ioi_cli::testing::{
    build_test_artifacts,
    genesis::GenesisBuilder,
    rpc::{self, submit_transaction},
    wait_for_height, TestCluster,
};
use ioi_types::{
    app::{
        AccountId, ActiveKeyRecord, BlockTimingParams, BlockTimingRuntime, ChainId,
        ChainTransaction, SignHeader, SignatureProof, SignatureSuite, SystemPayload,
        SystemTransaction, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::{InitialServiceConfig, OracleParams},
    service_configs::MigrationConfig,
};
use parity_scale_codec::Encode;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::fs;

// --- Helper functions for metrics ---

// Helper to scrape a metrics endpoint and return the body as text.
async fn scrape_metrics(telemetry_addr: &str) -> Result<String> {
    let url = format!("http://{}/metrics", telemetry_addr);
    let response = reqwest::get(&url).await?.text().await?;
    Ok(response)
}

// Helper to parse a specific metric's value from the Prometheus text format.
fn get_metric_value(metrics_body: &str, metric_name: &str) -> Option<f64> {
    metrics_body
        .lines()
        .find(|line| line.starts_with(metric_name) && (line.contains(' ') || line.contains('{')))
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse::<f64>().ok())
}

#[derive(Encode)]
struct RequestOracleDataParams {
    url: String,
    request_id: u64,
}

// Helper function to create a correctly signed system transaction.
fn create_signed_system_tx(
    keypair: &libp2p::identity::Keypair,
    payload: SystemPayload,
    nonce: u64,
    chain_id: ChainId,
) -> Result<ChainTransaction> {
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash =
        ioi_types::app::account_id_from_key_material(SignatureSuite::ED25519, &public_key_bytes)?;
    let account_id = AccountId(account_id_hash);

    let header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
        session_auth: None, // [FIX] Initialize session_auth
    };

    let mut tx_to_sign = SystemTransaction {
        header,
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx_to_sign.to_sign_bytes().map_err(|e| anyhow!(e))?;
    let signature = keypair.sign(&sign_bytes)?;

    tx_to_sign.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key: public_key_bytes,
        signature,
    };
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

// A local HTTP stub for the oracle request to succeed in the crash test.
async fn start_local_http_stub() -> (String, tokio::task::JoinHandle<()>) {
    async fn handler() -> &'static str {
        "ok"
    }
    let app = Router::new().route("/recovery-test", get(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        serve(listener, app).await.unwrap();
    });
    (url, handle)
}

#[tokio::test]
async fn test_metrics_endpoint() -> Result<()> {
    use cfg_if::cfg_if;

    println!("\n--- Running Metrics Endpoint Test ---");

    let mut builder = TestCluster::builder()
        .with_validators(1)
        .with_state_tree("IAVL")
        .with_commitment_scheme("Hash")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![ioi_types::app::SignatureSuite::ED25519],
            allow_downgrade: false,
        }));

    cfg_if! {
        if #[cfg(feature = "consensus-admft")] {
            println!("--- Configuring for Proof of Authority ---");
            builder = builder.with_consensus_type("Admft")
                .with_genesis_modifier(|builder: &mut GenesisBuilder, keys| {
                    let keypair = &keys[0];
                    // 1. Identities (and get AccountId)
                    let account_id = builder.add_identity(keypair);
                    let account_hash = account_id.0;

                    // 2. Validator Set (PoA)
                    let vs = ValidatorSetV1 {
                        effective_from_height: 1,
                        total_weight: 1,
                        validators: vec![ValidatorV1 {
                            account_id,
                            weight: 1,
                            consensus_key: ActiveKeyRecord { suite: SignatureSuite::ED25519, public_key_hash: account_hash, since_height: 0 },
                        }],
                    };
                    let vs_blob = ValidatorSetsV1 { current: vs, next: None };
                    builder.set_validators(&vs_blob);

                    // 3. Block Timing
                    let timing_params = BlockTimingParams {
                        base_interval_secs: 5,
                        min_interval_secs: 2,
                        max_interval_secs: 10,
                        target_gas_per_block: 1_000_000,
                        ema_alpha_milli: 200,
                        interval_step_bps: 500,
                        retarget_every_blocks: 0,
                    };
                    let timing_runtime = BlockTimingRuntime {
                        ema_gas_used: 0,
                        effective_interval_secs: timing_params.base_interval_secs,
                    };
                    builder.set_block_timing(&timing_params, &timing_runtime);
                });
        } else if #[cfg(feature = "consensus-pos")] {
            println!("--- Configuring for Proof of Stake ---");
            builder = builder.with_consensus_type("ProofOfStake")
                .with_genesis_modifier(|builder: &mut GenesisBuilder, keys| {
                    let keypair = &keys[0];
                    // 1. Identities
                    let account_id = builder.add_identity(keypair);
                    let account_hash = account_id.0;

                    // 2. Validator Set (PoS)
                    let initial_stake = 100_000u128;
                    let vs = ValidatorSetV1 {
                        effective_from_height: 1,
                        total_weight: initial_stake,
                        validators: vec![ValidatorV1 {
                            account_id,
                            weight: initial_stake,
                            consensus_key: ActiveKeyRecord { suite: SignatureSuite::ED25519, public_key_hash: account_hash, since_height: 0 },
                        }],
                    };
                    let vs_blob = ValidatorSetsV1 { current: vs, next: None };
                    builder.set_validators(&vs_blob);

                    // 3. Block Timing
                    let timing_params = BlockTimingParams {
                        base_interval_secs: 5,
                        min_interval_secs: 2,
                        max_interval_secs: 10,
                        target_gas_per_block: 1_000_000,
                        ema_alpha_milli: 200,
                        interval_step_bps: 500,
                        retarget_every_blocks: 0,
                    };
                    let timing_runtime = BlockTimingRuntime {
                        ema_gas_used: 0,
                        effective_interval_secs: timing_params.base_interval_secs,
                    };
                    builder.set_block_timing(&timing_params, &timing_runtime);
                });
        }
    }

    let mut cluster = builder.build().await?;
    let node_guard = cluster.validators.remove(0);

    // Wrap the core test logic in an async block to ensure cleanup happens on failure.
    let test_result: Result<()> = async {
        let node = node_guard.validator();
        wait_for_height(&node.rpc_addr, 1, Duration::from_secs(30)).await?;

        // The orchestrator's telemetry address is now dynamically allocated and stored.
        let metrics_body = scrape_metrics(&node.orchestration_telemetry_addr).await?;

        assert!(metrics_body.contains("ioi_storage_disk_usage_bytes"));
        assert!(metrics_body.contains("ioi_networking_connected_peers"));
        assert!(metrics_body.contains("ioi_rpc_requests_total"));
        assert!(get_metric_value(&metrics_body, "ioi_mempool_size").is_some());
        Ok(())
    }
    .await;

    // Guaranteed cleanup
    node_guard.shutdown().await?;

    // Propagate the original error, if any.
    test_result?;

    println!("--- Metrics Endpoint Test Passed ---");
    Ok(())
}

#[tokio::test]
#[cfg(not(windows))]
async fn test_storage_crash_recovery() -> Result<()> {
    println!("\n--- Running Storage Crash Recovery Test ---");

    let (stub_url, _stub_handle) = start_local_http_stub().await;
    let cluster = TestCluster::builder()
        .with_validators(1)
        .use_docker_backend(false)
        .with_initial_service(InitialServiceConfig::Oracle(OracleParams::default()))
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![ioi_types::app::SignatureSuite::ED25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(|builder, keys| {
            let keypair = &keys[0];
            let suite = SignatureSuite::ED25519;

            // 1. Identity
            let account_id = builder.add_identity(keypair);
            let account_id_hash = account_id.0;

            // 2. Validator Set
            let vs = ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: 1,
                validators: vec![ValidatorV1 {
                    account_id,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite,
                        public_key_hash: account_id_hash,
                        since_height: 0,
                    },
                }],
            };
            let vs_blob = ValidatorSetsV1 {
                current: vs,
                next: None,
            };
            builder.set_validators(&vs_blob);

            // 3. Block Timing
            let timing_params = BlockTimingParams {
                base_interval_secs: 5,
                min_interval_secs: 2,
                max_interval_secs: 10,
                target_gas_per_block: 1_000_000,
                ema_alpha_milli: 200,
                interval_step_bps: 500,
                retarget_every_blocks: 0,
            };
            let timing_runtime = BlockTimingRuntime {
                ema_gas_used: 0,
                effective_interval_secs: timing_params.base_interval_secs,
            };
            builder.set_block_timing(&timing_params, &timing_runtime);
        })
        .build()
        .await?;

    let mut node_guard = cluster.validators.into_iter().next().unwrap();

    let test_logic_result: Result<(), anyhow::Error> = async {
        let rpc_addr = node_guard.validator().rpc_addr.clone();

        // [FIX] Use the provider_registry service which is registered as native by default.
        use ioi_services::provider_registry::{RegisterProviderParams, SupplyTier};
        let params = RegisterProviderParams {
            tier: SupplyTier::Community,
            endpoint: format!("{}/recovery-test", stub_url),
            capabilities: vec!["gpu".to_string()],
        };
        let params_bytes =
            ioi_types::codec::to_bytes_canonical(&params).map_err(anyhow::Error::msg)?;
        let payload = SystemPayload::CallService {
            service_id: "provider_registry".to_string(),
            method: "register@v1".to_string(),
            params: params_bytes,
        };
        let tx = create_signed_system_tx(&node_guard.validator().keypair, payload, 0, 1.into())?;
        submit_transaction(&rpc_addr, &tx).await?;

        // [FIX] Wait for block inclusion.
        wait_for_height(&rpc_addr, 2, Duration::from_secs(30)).await?;
        println!("State was successfully written before crash.");

        // --- NEW: Verify WAL Existence ---
        // Locate the WAL file based on the validator's config
        let workload_config_path = node_guard.validator().backend.as_any()
             .downcast_ref::<ioi_cli::testing::backend::ProcessBackend>()
             .map(|p| p.workload_config_path.clone())
             .ok_or(anyhow!("Could not get config path"))?;
             
        let config_str = fs::read_to_string(&workload_config_path)?;
        let cfg: ioi_types::config::WorkloadConfig = toml::from_str(&config_str)?;
        let db_path = std::path::Path::new(&cfg.state_file).with_extension("db");
        let wal_path = db_path.with_extension("wal");
        
        assert!(wal_path.exists(), "WAL file should exist before crash");
        let meta = fs::metadata(&wal_path)?;
        println!("WAL File Size: {} bytes", meta.len());
        assert!(meta.len() > 0, "WAL file should not be empty");
        // ---------------------------------

        println!("Killing workload process...");
        node_guard
            .validator_mut()
            .kill_workload()
            .await?;

        // Small sleep to ensure OS reclaims ports fully, though wait() in backend helps.
        tokio::time::sleep(Duration::from_secs(2)).await;

        println!("Restarting workload process...");
        node_guard
            .validator_mut()
            .restart_workload_process()
            .await?;

        ioi_cli::testing::assert::wait_for(
            "orchestration RPC to become responsive after workload restart",
            Duration::from_millis(500),
            Duration::from_secs(45),
            || async {
                match rpc::get_chain_height(&rpc_addr).await {
                    Ok(height) => {
                        println!(
                            "[DEBUG] get_chain_height succeeded after restart with height={}",
                            height
                        );
                        Ok(Some(()))
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        println!("[DEBUG] get_chain_height failed after restart: {}", msg);

                        if msg.contains("STATUS_KEY not found in state") {
                            println!(
                                "[DEBUG] treating STATUS_KEY-not-found as RPC-responsive for readiness check"
                            );
                            Ok(Some(()))
                        } else {
                            Ok(None)
                        }
                    }
                }
            },
        )
        .await?;
        println!("Workload process restarted and orchestrator reconnected.");

        // [FIX] Derive the correct key to check after recovery.
        let pk_bytes = node_guard.validator().keypair.public().encode_protobuf();
        let account_id = AccountId(ioi_types::app::account_id_from_key_material(
            SignatureSuite::ED25519,
            &pk_bytes,
        )?);

        let ns = ioi_api::state::service_namespace_prefix("provider_registry");
        let key_to_check = [
            ns.as_slice(),
            b"providers::",
            account_id.as_ref(),
        ]
        .concat();

        let state_after = rpc::query_state_key(&rpc_addr, &key_to_check).await?;
        assert!(state_after.is_some(), "State was lost after crash");

        Ok(())
    }
    .await;

    node_guard.shutdown().await?;
    test_logic_result?;

    println!("--- Storage Crash Recovery Test Passed ---");
    Ok(())
}

#[tokio::test]
async fn test_gc_respects_pinned_epochs() -> Result<()> {
    println!("\n--- Running Deterministic GC Pinning Test ---");
    // Set fast block times for this test
    std::env::set_var("ORCH_BLOCK_INTERVAL_SECS", "1");

    build_test_artifacts();

    // Configure aggressively small retention for testing
    let keep_recent = 10;
    let epoch_size = 5;

    // Disable auto-GC to control it manually
    // We'll just set a very long interval so it doesn't run automatically
    let gc_interval = 3600;

    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_state_tree("IAVL")
        .with_keep_recent_heights(keep_recent)
        .with_epoch_size(epoch_size)
        .with_gc_interval(gc_interval)
        // FIX: Ensure safety buffer doesn't prevent pruning in this short test
        .with_min_finality_depth(0)
        // --- UPDATED: Using GenesisBuilder API ---
        .with_genesis_modifier(|builder, keys| {
            let keypair = &keys[0];
            // 1. Identity
            let account_id = builder.add_identity(keypair);
            let acct_hash = account_id.0;

            // 2. Validator Set
            let vs = ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: 1,
                validators: vec![ValidatorV1 {
                    account_id,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        // FIX: Use ED25519 constant
                        suite: SignatureSuite::ED25519,
                        public_key_hash: acct_hash,
                        since_height: 0,
                    },
                }],
            };
            let vs_blob = ValidatorSetsV1 {
                current: vs,
                next: None,
            };
            builder.set_validators(&vs_blob);

            // 3. Block Timing (Fast)
            let timing_params = BlockTimingParams {
                base_interval_secs: 1,
                min_interval_secs: 1,
                max_interval_secs: 10,
                target_gas_per_block: 1_000_000,
                retarget_every_blocks: 0,
                ..Default::default()
            };
            let timing_runtime = BlockTimingRuntime {
                ema_gas_used: 0,
                effective_interval_secs: timing_params.base_interval_secs,
            };
            builder.set_block_timing(&timing_params, &timing_runtime);
        })
        .build()
        .await?;

    let mut node_guard = cluster.validators.remove(0);
    let rpc_addr = node_guard.validator().rpc_addr.clone();
    let ipc_addr = node_guard.validator().workload_ipc_addr.clone();

    // Wrap in async block for cleanup
    let test_logic = async {
        // Connect direct client for debug RPCs
        let certs_path = &node_guard.validator().certs_dir_path;
        let client = WorkloadClient::new(
            &ipc_addr,
            &certs_path.join("ca.pem").to_string_lossy(),
            &certs_path.join("orchestration.pem").to_string_lossy(),
            &certs_path.join("orchestration.key").to_string_lossy(),
        )
        .await?;

        // 1. Advance chain to make history available
        println!("Advancing chain to height 20...");
        wait_for_height(&rpc_addr, 20, Duration::from_secs(60)).await?;

        // 2. Pin a specific height that is about to fall out of retention
        let pinned_height = 12;
        println!("Pinning height {}...", pinned_height);
        client.debug_pin_height(pinned_height).await?;

        // Verify it exists currently
        let block_12 = client
            .get_block_by_height(pinned_height)
            .await?
            .expect("Block 12 should exist");
        let root_12 = block_12.header.state_root;
        let res = client
            .query_state_at(root_12.clone(), b"system::validators::current")
            .await;
        assert!(
            res.is_ok(),
            "State at 12 should be queryable before pruning"
        );

        // 3. Advance chain to push height 12 out of window
        // current > 12 + 10 = 22. Let's go to 35 to be safe.
        println!("Advancing chain to height 35...");
        wait_for_height(&rpc_addr, 35, Duration::from_secs(60)).await?;

        // 4. Trigger GC
        println!("Triggering GC...");
        let stats = client.debug_trigger_gc().await?;
        println!("GC Stats: {:?}", stats);

        // 5. Assert Existence (Pin should save it)
        let res_pinned = client
            .query_state_at(root_12.clone(), b"system::validators::current")
            .await;
        assert!(
            res_pinned.is_ok(),
            "Pinned state at 12 should still be available after GC"
        );

        // 6. Unpin
        println!("Unpinning height {}...", pinned_height);
        client.debug_unpin_height(pinned_height).await?;

        // 7. Trigger GC again
        println!("Triggering GC 2nd pass...");
        let stats2 = client.debug_trigger_gc().await?;
        println!("GC Stats 2: {:?}", stats2);

        // 8. Assert Pruned
        let res_pruned = client
            .query_state_at(root_12, b"system::validators::current")
            .await;
        assert!(
            res_pruned.is_err(),
            "State at 12 should be pruned after unpinning"
        );
        let err_str = res_pruned.unwrap_err().to_string();
        assert!(
            err_str.contains("Backend error")
                || err_str.contains("not known")
                || err_str.contains("anchor"),
            "Expected pruning error, got: {}",
            err_str
        );

        Ok::<(), anyhow::Error>(())
    };

    let res = test_logic.await;
    node_guard.shutdown().await?;
    res?;

    println!("--- GC Pinning Test Passed ---");
    Ok(())
}

#[tokio::test]
async fn test_storage_soak_test() -> Result<()> {
    println!("\n--- Running Storage Soak Test ---");
    // Speed up blocks
    std::env::set_var("ORCH_BLOCK_INTERVAL_SECS", "1");
    build_test_artifacts();

    // Fast GC to stress the system
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_state_tree("IAVL")
        .with_epoch_size(10)
        .with_keep_recent_heights(20)
        .with_gc_interval(1)
        // FIX: Ensure aggressive pruning occurs
        .with_min_finality_depth(0)
        // --- UPDATED: Using GenesisBuilder API ---
        .with_genesis_modifier(|builder, keys| {
            let keypair = &keys[0];
            // 1. Identity
            let account_id = builder.add_identity(keypair);
            let acct_hash = account_id.0;

            // 2. Validator Set
            let vs = ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: 1,
                validators: vec![ValidatorV1 {
                    account_id,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        // FIX: Use ED25519 constant
                        suite: SignatureSuite::ED25519,
                        public_key_hash: acct_hash,
                        since_height: 0,
                    },
                }],
            };
            let vs_blob = ValidatorSetsV1 {
                current: vs,
                next: None,
            };
            builder.set_validators(&vs_blob);

            // 3. Timing Params
            let timing_params = BlockTimingParams {
                base_interval_secs: 1,
                min_interval_secs: 1,
                max_interval_secs: 10,
                target_gas_per_block: 1_000_000,
                retarget_every_blocks: 0,
                ..Default::default()
            };
            let timing_runtime = BlockTimingRuntime {
                ema_gas_used: 0,
                effective_interval_secs: timing_params.base_interval_secs,
            };
            builder.set_block_timing(&timing_params, &timing_runtime);
        })
        .build()
        .await?;

    let node_guard = cluster.validators.remove(0);
    let telemetry_addr = node_guard.validator().workload_telemetry_addr.clone();
    let rpc_addr = node_guard.validator().rpc_addr.clone();
    let keypair = node_guard.validator().keypair.clone();
    let chain_id = 1.into();

    // Run logic in block for cleanup
    let test_logic = async {
        // Run load for 45 seconds
        let duration = Duration::from_secs(45);
        let start = Instant::now();

        println!("Waiting for chain to grow and GC to run...");

        let mut gc_ran = false;
        let mut last_height = 0;
        let mut nonce = 0;

        while start.elapsed() < duration {
            tokio::time::sleep(Duration::from_secs(1)).await;

            // Check height progress
            if let Ok(h) = rpc::get_chain_height(&rpc_addr).await {
                if h > last_height {
                    // println!("Height: {}", h);
                    last_height = h;
                }
            }

            // Keep chain moving with dummy transactions if needed
            // [FIX] Use provider_registry
            use ioi_services::provider_registry::{SupplyTier, RegisterProviderParams};
            let tx = create_signed_system_tx(
                &keypair,
                SystemPayload::CallService {
                    service_id: "provider_registry".to_string(),
                    method: "register@v1".to_string(),
                    params: codec::to_bytes_canonical(&RegisterProviderParams {
                        tier: SupplyTier::Community,
                        endpoint: format!("http://dummy/{}", nonce),
                        capabilities: vec![],
                    })
                    .unwrap(),
                },
                nonce,
                chain_id,
            )?;
            let _ = submit_transaction(&rpc_addr, &tx).await;
            nonce += 1;

            if let Ok(metrics) = scrape_metrics(&telemetry_addr).await {
                if let Some(val) = get_metric_value(&metrics, "ioi_storage_epochs_dropped_total") {
                    if val > 0.0 {
                        gc_ran = true;
                        println!("GC confirmed running: epochs_dropped = {}", val);
                        break; // Success!
                    }
                }
            }
        }

        if !gc_ran {
            // If we failed, check height
            println!("Final height: {}", last_height);
            if last_height < 30 {
                println!("WARN: Chain did not grow enough to trigger GC (needs > 30).");
            }
        }

        assert!(gc_ran, "GC did not drop any epochs during the soak test");
        Ok::<(), anyhow::Error>(())
    };

    let res = test_logic.await;
    node_guard.shutdown().await?;
    res?;

    println!("--- Storage Soak Test Passed ---");
    Ok(())
}