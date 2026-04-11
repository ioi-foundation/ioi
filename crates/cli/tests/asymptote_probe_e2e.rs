#![cfg(all(feature = "consensus-aft", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::Result;
use ioi_cli::testing::{build_test_artifacts, rpc, TestCluster};
use ioi_types::config::AftSafetyMode;
use std::time::Duration;
use tokio::sync::broadcast::error::TryRecvError;

async fn fetch_metric(metrics_addr: &str, name: &str) -> String {
    let url = format!("http://{metrics_addr}/metrics");
    match reqwest::get(&url).await {
        Ok(resp) => match resp.text().await {
            Ok(body) => body
                .lines()
                .find_map(|line| {
                    line.starts_with(name)
                        .then(|| line.split_whitespace().last().unwrap_or("?").to_string())
                })
                .unwrap_or_else(|| "missing".to_string()),
            Err(_) => "Err".to_string(),
        },
        Err(_) => "Down".to_string(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn asymptote_probe_reports_status_and_tip_progress() -> Result<()> {
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(3)
        .with_consensus_type("Aft")
        .with_state_tree("IAVL")
        .with_chain_id(119)
        .with_aft_safety_mode(AftSafetyMode::Asymptote)
        .build()
        .await?;

    let rpc_addrs = cluster
        .validators
        .iter()
        .map(|guard| guard.validator().rpc_addr.clone())
        .collect::<Vec<_>>();
    let metrics_addrs = cluster
        .validators
        .iter()
        .map(|guard| guard.validator().orchestration_telemetry_addr.clone())
        .collect::<Vec<_>>();
    let mut orch_receivers = cluster
        .validators
        .iter()
        .map(|guard| guard.validator().subscribe_logs().0)
        .collect::<Vec<_>>();

    let result: Result<()> = async {
        for tick in 0..12u64 {
            for (index, rpc_addr) in rpc_addrs.iter().enumerate() {
                let status = rpc::get_status(rpc_addr).await?;
                let tip = rpc::tip_height_resilient(rpc_addr).await?;
                let peer_count =
                    fetch_metric(&metrics_addrs[index], "ioi_networking_connected_peers").await;
                let produced_blocks = fetch_metric(
                    &metrics_addrs[index],
                    "ioi_consensus_blocks_produced_total",
                )
                .await;
                eprintln!(
                    "[asymptote-probe] tick={} node={} status_height={} tip_height={} latest_timestamp={} peers={} produced_blocks={}",
                    tick,
                    index,
                    status.height,
                    tip,
                    status.latest_timestamp,
                    peer_count,
                    produced_blocks
                );
                if let Some(block) = rpc::get_block_by_height_resilient(rpc_addr, tip.max(1)).await? {
                    eprintln!(
                        "[asymptote-probe] tick={} node={} tip_block_height={} sealed={} guardian_cert={} order_cert={}",
                        tick,
                        index,
                        block.header.height,
                        block.header.sealed_finality_proof.is_some(),
                        block.header.guardian_certificate.is_some(),
                        block.header.canonical_order_certificate.is_some()
                    );
                }

                loop {
                    match orch_receivers[index].try_recv() {
                        Ok(line) => {
                            if line.contains("Consensus tick decided the next action")
                                || line.contains("Skipping block production because the node has no live peers")
                                || line.contains("Skipping consensus tick because the node is not yet synced")
                                || line.contains("Leader lacks a quorum certificate for the parent height")
                                || line.contains("Stalling block production until the canonical collapse extension certificate is available")
                                || line.contains("\"level\":\"WARN\"")
                                || line.contains("\"level\":\"ERROR\"")
                            {
                                eprintln!(
                                    "[asymptote-probe-log] tick={} node={} {}",
                                    tick, index, line
                                );
                            }
                        }
                        Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
                        Err(TryRecvError::Lagged(_)) => continue,
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Ok(())
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    result?;
    shutdown_result?;
    Ok(())
}
