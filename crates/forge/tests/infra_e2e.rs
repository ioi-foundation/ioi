// Path: crates/forge/tests/infra_e2e.rs

#![cfg(all(
    feature = "consensus-poa",
    feature = "tree-iavl",
    feature = "primitive-hash"
))]

use anyhow::{anyhow, Result};
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts,
    poll::{wait_for, wait_for_height},
    rpc, submit_transaction, TestCluster,
};
use depin_sdk_types::app::{
    AccountId, ChainTransaction, SignHeader, SignatureSuite, SystemPayload, SystemTransaction,
};
use std::mem::ManuallyDrop;
use std::time::{Duration, Instant};

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
        .find(|line| line.starts_with(metric_name))
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse::<f64>().ok())
}

#[tokio::test]
async fn test_metrics_endpoint() -> Result<()> {
    build_test_artifacts();
    println!("\n--- Running Metrics Endpoint Test ---");

    // 1. Launch a single node. The test harness automatically starts its telemetry server.
    let cluster = TestCluster::builder().with_validators(1).build().await?;
    let node = &cluster.validators[0];

    // Wait for the node to be ready.
    wait_for_height(&node.rpc_addr, 1, Duration::from_secs(30)).await?;

    // 2. Scrape the /metrics endpoint.
    let metrics_body = scrape_metrics(&node.workload_telemetry_addr).await?;

    // 3. Assert that the response contains expected metric names.
    assert!(
        metrics_body.contains("depin_sdk_storage_disk_usage_bytes"),
        "Metrics should contain disk usage"
    );
    assert!(
        metrics_body.contains("depin_sdk_network_connected_peers"),
        "Metrics should contain connected peers count"
    );
    assert!(
        metrics_body.contains("depin_sdk_rpc_requests_total"),
        "Metrics should contain rpc request count"
    );
    assert!(
        get_metric_value(&metrics_body, "depin_sdk_mempool_size").is_some(),
        "Mempool size metric should be present"
    );

    println!("--- Metrics Endpoint Test Passed ---");
    Ok(())
}

/*
// FIXME: This test is disabled because it calls methods (`workload_process`, `restart_workload_process`)
// that are not defined on `TestValidator`. Implementing this functionality would require a significant
// refactoring to expose and manage process handles from the test harness backend.
#[tokio::test]
#[cfg(not(windows))] // `kill -9` is not applicable on Windows.
async fn test_storage_crash_recovery() -> Result<()> {
    use depin_sdk_client::WorkloadClient;

    build_test_artifacts();
    println!("\n--- Running Storage Crash Recovery Test ---");

    // 1. Setup: Launch a node using the local process backend.
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .use_docker_backend(false) // Must use processes to kill one
        .build()
        .await?;

    // Wrap the validator in ManuallyDrop to prevent its Drop handler from cleaning up prematurely.
    let mut node = ManuallyDrop::new(cluster.validators.remove(0));
    let rpc_addr = node.rpc_addr.clone();
    let account_id_bytes = node.keypair.public().to_peer_id().to_bytes();
    let account_id = AccountId(depin_sdk_types::app::account_id_from_key_material(
        SignatureSuite::Ed25519,
        &account_id_bytes,
    )?);

    // 2. Action: Submit a transaction to change state.
    let tx = ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id,
            nonce: 0,
            chain_id: 1.into(),
            tx_version: 1,
        },
        payload: SystemPayload::RequestOracleData {
            url: "http://example.com/recovery-test".to_string(),
            request_id: 12345,
        },
        signature_proof: Default::default(), // Signing not required for this specific test
    }));

    submit_transaction(&rpc_addr, &tx).await?;
    wait_for_height(&rpc_addr, 1, Duration::from_secs(30)).await?;

    // 3. Verify: Check that the state was updated before the crash.
    let key_to_check = [
        depin_sdk_types::keys::ORACLE_PENDING_REQUEST_PREFIX,
        &12345u64.to_le_bytes(),
    ]
    .concat();
    let state_before = rpc::query_state_key(&rpc_addr, &key_to_check).await?;
    assert!(state_before.is_some(), "State was not written before crash");

    // 4. Action: Forcefully kill the workload process.
    println!("Killing workload process...");
    let workload_pid = node
        .workload_process()
        .lock()
        .await
        .as_mut()
        .expect("Should have workload process handle")
        .id()
        .expect("Process should have an ID");
    let kill_output = std::process::Command::new("kill")
        .args(["-9", &workload_pid.to_string()])
        .output()?;

    if !kill_output.status.success() {
        return Err(anyhow!(
            "Failed to kill workload process: {}",
            String::from_utf8_lossy(&kill_output.stderr)
        ));
    }
    tokio::time::sleep(Duration::from_secs(2)).await; // Give time for the OS to kill it.

    // 5. Action: Restart the workload process.
    println!("Restarting workload process...");
    node.restart_workload_process().await?;

    // Wait for the workload to be ready again.
    let client = WorkloadClient::new(
        &node.workload_ipc_addr,
        &node.certs_dir_path.join("ca.pem").to_string_lossy(),
        &node
            .certs_dir_path
            .join("orchestration.pem")
            .to_string_lossy(),
        &node
            .certs_dir_path
            .join("orchestration.key")
            .to_string_lossy(),
    )
    .await?;
    wait_for(
        "workload genesis to be ready after restart",
        Duration::from_millis(500),
        Duration::from_secs(30),
        || async {
            match client.get_genesis_status().await {
                Ok(status) if status.ready => Ok(Some(())),
                _ => Ok(None),
            }
        },
    )
    .await?;
    println!("Workload process restarted and ready.");

    // 6. Assert: The state from the original transaction must still be present.
    let state_after = rpc::query_state_key(&rpc_addr, &key_to_check).await?;
    assert_eq!(
        state_before, state_after,
        "State after crash does not match state before"
    );

    // Manually clean up.
    unsafe { ManuallyDrop::drop(&mut node) };
    println!("--- Storage Crash Recovery Test Passed ---");
    Ok(())
}
*/

/*
// FIXME: This test is disabled because it calls methods (`with_gc_config`, `with_gc_interval_secs`)
// that are not defined on `TestClusterBuilder`.
#[tokio::test]
async fn test_gc_respects_pinned_epochs() -> Result<()> {
    // This test is a placeholder as its implementation requires a test-only RPC
    // to instruct the server to pin a version. The `PinGuard` is an internal server
    // mechanism and cannot be used from a client-side test.
    // The logic has been commented out to allow the rest of the suite to pass.
    println!(
        "\n--- SKIPPING GC Pinning Test (requires test-only RPC to be architecturally sound) ---"
    );
    Ok(())
    /*
    build_test_artifacts();
    println!("\n--- Running GC Pinning Test ---");

    // 1. Setup: Launch a node with aggressive GC settings.
    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_gc_config(5, 2, 10) // keep_recent=5, min_finality=2, epoch_size=10
        .with_gc_interval_secs(5) // Run GC frequently
        .build().await?;
    let node = &cluster.validators[0];
    let client = node.workload_client().await?;

    // 2. Action: Let the node produce enough blocks to make early ones prunable.
    wait_for_height(&node.rpc_addr, 15, Duration::from_secs(60)).await?;

    // 3. Action: Get the root for an early, prunable block (e.g., height 3) and pin it.
    let target_height = 3;
    let block3_header = rpc::get_block_by_height(&node.rpc_addr, target_height).await?
        .ok_or_else(|| anyhow!("Failed to get block header for height {}", target_height))?;
    let root_h3 = block3_header.state_root;
    let key_to_check = depin_sdk_types::keys::STATUS_KEY;

    println!("Pinning state for height {}...", target_height);
    // This needs to be replaced with a test-only RPC call to the workload
    // let _pin_guard = depin_sdk_api::state::PinGuard::new(node.pins.clone(), target_height).await;

    // 4. Action: Wait for GC to run.
    println!("Waiting for GC cycle...");
    tokio::time::sleep(Duration::from_secs(10)).await;

    // 5. Assert: GC has run.
    let metrics = scrape_metrics(&node.workload_telemetry_addr).await?;
    let dropped_count = get_metric_value(&metrics, "depin_sdk_storage_epochs_dropped_total").unwrap_or(0.0);
    assert!(dropped_count > 0.0, "GC should have run and dropped some state versions");

    // 6. Assert: The pinned state is still accessible.
    let result_while_pinned = client.query_state_at(root_h3.clone(), key_to_check).await;
    assert!(result_while_pinned.is_ok(), "Query for pinned state should succeed");
    println!("Successfully queried pinned state for height {}.", target_height);

    // 7. Action: Drop the pin and wait for another GC cycle.
    println!("Releasing pin for height {}...", target_height);
    // This needs to be replaced with an RPC call
    // drop(_pin_guard);
    tokio::time::sleep(Duration::from_secs(10)).await;

    // 8. Assert: The now-unpinned state is no longer accessible.
    let result_after_unpinned = client.query_state_at(root_h3, key_to_check).await;
    assert!(
        result_after_unpinned.is_err(),
        "Query for unpinned, pruned state should fail"
    );
    assert!(
        result_after_unpinned.unwrap_err().to_string().contains("StaleAnchor"),
        "Error should indicate the state version is missing"
    );

    println!("--- GC Pinning Test Passed ---");
    Ok(())
    */
}
*/

/*
// FIXME: This test is disabled because it calls methods (`with_gc_config`, `with_gc_interval_secs`)
// that are not defined on `TestClusterBuilder`.
#[tokio::test]
async fn test_storage_soak_test() -> Result<()> {
    build_test_artifacts();
    println!("\n--- Running Storage Soak Test ---");

    // 1. Setup: Node with aggressive GC.
    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_gc_config(20, 10, 50)
        .with_gc_interval_secs(5)
        .build()
        .await?;
    let node = &cluster.validators[0];
    let (mut orch_logs, _, _) = node.subscribe_logs();

    let test_duration = Duration::from_secs(90);
    let load_duration = Duration::from_secs(60);

    // 2. Action: Transaction firehose task.
    let rpc_addr_clone = node.rpc_addr.clone();
    let account_id_bytes = node.keypair.public().to_peer_id().to_bytes();
    let account_id = AccountId(depin_sdk_types::app::account_id_from_key_material(
        SignatureSuite::Ed25519,
        &account_id_bytes,
    )?);

    let tx_firehose_handle = tokio::spawn(async move {
        let start = Instant::now();
        let mut nonce = 0;
        let mut request_id_counter = 0;
        while start.elapsed() < load_duration {
            let payload = SystemPayload::RequestOracleData {
                url: format!("http://example.com/soak-{}", request_id_counter),
                request_id: request_id_counter,
            };
            let tx = ChainTransaction::System(Box::new(SystemTransaction {
                header: SignHeader {
                    account_id,
                    nonce,
                    chain_id: 1.into(),
                    tx_version: 1,
                },
                payload,
                signature_proof: Default::default(),
            }));
            let _ = submit_transaction(&rpc_addr_clone, &tx).await;
            nonce += 1;
            request_id_counter += 1;
            tokio::time::sleep(Duration::from_millis(100)).await; // Prevents overwhelming the mempool instantly
        }
    });

    // 3. Action: Metrics monitoring task.
    let telemetry_addr_clone = node.workload_telemetry_addr.clone();
    let monitor_handle = tokio::spawn(async move {
        let mut gc_counts = Vec::new();
        let mut disk_usages = Vec::new();
        let start = Instant::now();
        while start.elapsed() < test_duration {
            if let Ok(metrics) = scrape_metrics(&telemetry_addr_clone).await {
                if let Some(gc) =
                    get_metric_value(&metrics, "depin_sdk_storage_epochs_dropped_total")
                {
                    gc_counts.push(gc);
                }
                if let Some(disk) = get_metric_value(&metrics, "depin_sdk_storage_disk_usage_bytes")
                {
                    disk_usages.push(disk);
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        (gc_counts, disk_usages)
    });

    // Run the test.
    let _ = tx_firehose_handle.await;
    let (gc_counts, disk_usages) = monitor_handle.await?;

    // 4. Assertions
    println!("Collected GC Counts: {:?}", gc_counts);
    println!("Collected Disk Usages: {:?}", disk_usages);

    // Assertion 1: GC is active. The dropped count must be increasing after a warmup.
    let warmup_period = gc_counts.len() / 4;
    let gc_active_slice = &gc_counts[warmup_period..];
    assert!(
        gc_active_slice.windows(2).all(|w| w[0] <= w[1]),
        "GC dropped count should be monotonically increasing"
    );
    assert!(
        gc_active_slice.last().unwrap_or(&0.0) > &0.0,
        "GC should have dropped at least one epoch"
    );

    // Assertion 2: Disk usage plateaus.
    let n = disk_usages.len();
    assert!(n > 10, "Not enough data points for disk usage analysis");
    let midpoint = n / 2;
    let third_quarter_point = n * 3 / 4;
    let middle_slice = &disk_usages[midpoint..third_quarter_point];
    let last_slice = &disk_usages[third_quarter_point..];

    let avg_middle: f64 = middle_slice.iter().sum::<f64>() / middle_slice.len() as f64;
    let max_last: f64 = last_slice.iter().fold(0.0, |a, &b| a.max(b));

    // Allow for some fluctuation, but prevent unbounded growth.
    let tolerance_factor = 1.5;
    assert!(
        max_last < avg_middle * tolerance_factor,
        "Disk usage did not plateau. Avg middle usage: {}, Max last usage: {}",
        avg_middle,
        max_last
    );

    assert_log_contains(
        "Workload",
        &mut orch_logs.into(),
        "[GC] Dropped sealed epoch",
    )
    .await
    .ok();

    println!("--- Storage Soak Test Passed ---");
    Ok(())
}
*/
