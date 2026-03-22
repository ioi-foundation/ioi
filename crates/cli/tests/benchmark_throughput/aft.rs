#![cfg(all(
    feature = "consensus-aft",
    feature = "vm-wasm",
    any(feature = "state-iavl", feature = "state-jellyfish")
))]

use super::support::{
    create_transfer_tx, generate_accounts, render_markdown_table, summarize_latencies,
    BenchmarkAlignmentSummary, BenchmarkChurnSummary, BenchmarkSubmissionSummary, LatencySummary,
    PaperBenchmarkResult, BACKOFF_MS, BLOCK_TIME_MS, MAX_RETRIES,
};
use anyhow::{anyhow, Result};
use futures_util::stream::{self, StreamExt, TryStreamExt};
use ioi_cli::testing::{build_test_artifacts, rpc, TestCluster};
use ioi_ipc::public::{
    public_api_client::PublicApiClient, GetTransactionStatusRequest, SubmitTransactionRequest,
    TxStatus,
};
use ioi_types::{
    app::{
        account_id_from_key_material, aft_canonical_collapse_object_key,
        aft_canonical_order_abort_key, aft_order_certificate_key,
        interval_millis_to_legacy_seconds, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, ChainTransaction, SignatureSuite, ValidatorSetV1, ValidatorSetsV1,
        ValidatorV1,
    },
    codec,
    config::{AftSafetyMode, ValidatorRole},
    keys::ACCOUNT_NONCE_PREFIX,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::OsString;
use std::process::Command;
use std::sync::Arc;
use std::sync::{Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};
use tonic::transport::Channel;
use tonic::Code;

const LATENCY_SAMPLE_LIMIT: usize = 128;
const DEFAULT_SUBMIT_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_STATUS_TIMEOUT_MS: u64 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AftBenchmarkLane {
    BaseFinal,
    SealedFinal,
    CanonicalOrdering,
    DurableCollapse,
}

impl AftBenchmarkLane {
    fn as_str(self) -> &'static str {
        match self {
            Self::BaseFinal => "base_final",
            Self::SealedFinal => "sealed_final",
            Self::CanonicalOrdering => "canonical_ordering",
            Self::DurableCollapse => "durable_collapse",
        }
    }

    fn supports(self, safety_mode: AftSafetyMode) -> bool {
        match self {
            Self::BaseFinal | Self::CanonicalOrdering | Self::DurableCollapse => true,
            Self::SealedFinal => matches!(safety_mode, AftSafetyMode::Asymptote),
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "base_final" | "base" => Some(Self::BaseFinal),
            "sealed_final" | "sealed" => Some(Self::SealedFinal),
            "canonical_ordering" | "ordering" => Some(Self::CanonicalOrdering),
            "durable_collapse" | "canonical_collapse" | "collapse" => Some(Self::DurableCollapse),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct MetricsSnapshot {
    connected_peers: String,
    mempool_size: String,
    blocks_produced_total: String,
}

fn prebuilt_node_profiles() -> &'static StdMutex<BTreeSet<String>> {
    static PREBUILT: OnceLock<StdMutex<BTreeSet<String>>> = OnceLock::new();
    PREBUILT.get_or_init(|| StdMutex::new(BTreeSet::new()))
}

fn benchmark_rebuild_node_binary() -> bool {
    std::env::var("IOI_AFT_BENCH_REBUILD_NODE")
        .ok()
        .map(|value| !matches!(value.as_str(), "0" | "false" | "FALSE" | "False"))
        .unwrap_or(true)
}

fn ensure_benchmark_node_built(state_tree: &str) -> Result<()> {
    let features = format!(
        "validator-bins,consensus-aft,state-{},commitment-hash,vm-wasm",
        match state_tree {
            "IAVL" => "iavl",
            "Jellyfish" => "jellyfish",
            other => return Err(anyhow!("unsupported benchmark state tree: {}", other)),
        }
    );
    let build_profile =
        std::env::var("IOI_TEST_BUILD_PROFILE").unwrap_or_else(|_| "release".to_string());
    let cache_key = format!("{build_profile}|{features}");
    let rebuild_node_binary = benchmark_rebuild_node_binary();
    let first_build_for_profile = {
        let mut built = prebuilt_node_profiles()
            .lock()
            .expect("benchmark prebuild cache poisoned");
        built.insert(cache_key.clone())
    };
    if !first_build_for_profile {
        return Ok(());
    }

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root");
    let node_binary_dir = workspace_root.join("target").join(&build_profile);
    let benchmark_exe_mtime = std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::metadata(path).ok())
        .and_then(|metadata| metadata.modified().ok());
    let binaries_present = ["orchestration", "workload", "guardian"]
        .iter()
        .all(|bin| node_binary_dir.join(bin).exists());
    let stale_binaries = benchmark_exe_mtime
        .map(|benchmark_mtime| {
            ["orchestration", "workload", "guardian"].iter().any(|bin| {
                node_binary_dir
                    .join(bin)
                    .metadata()
                    .ok()
                    .and_then(|metadata| metadata.modified().ok())
                    .map(|binary_mtime| binary_mtime < benchmark_mtime)
                    .unwrap_or(true)
            })
        })
        .unwrap_or(false);
    if binaries_present && !rebuild_node_binary && !stale_binaries {
        return Ok(());
    }
    if stale_binaries && !rebuild_node_binary {
        return Err(anyhow!(
            "cached benchmark node binaries are older than the current benchmark executable while IOI_AFT_BENCH_REBUILD_NODE=0. Refresh the release node binaries first or set IOI_AFT_BENCH_REBUILD_NODE=1 intentionally."
        ));
    }
    if stale_binaries {
        println!(
            "--- Rebuilding benchmark node binaries because the current benchmark executable is newer than the cached node executables ---"
        );
    }

    let cargo_bin = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(cargo_bin);
    cmd.args([
        "build",
        "-p",
        "ioi-node",
        "--no-default-features",
        "--features",
        &features,
    ]);
    if build_profile.eq_ignore_ascii_case("release") {
        cmd.arg("--release");
    }
    if let Ok(home) = std::env::var("HOME") {
        let cargo_bin_dir = std::path::Path::new(&home).join(".cargo/bin");
        if cargo_bin_dir.exists() {
            let current_path = std::env::var("PATH").unwrap_or_default();
            let new_path = format!("{}:{}", cargo_bin_dir.display(), current_path);
            cmd.env("PATH", new_path);
        }
    }

    let status = cmd.status()?;
    if !status.success() {
        prebuilt_node_profiles()
            .lock()
            .expect("benchmark prebuild cache poisoned")
            .remove(&cache_key);
        return Err(anyhow!(
            "failed to prebuild benchmark node binary for features: {}",
            features
        ));
    }

    Ok(())
}

fn benchmark_fast_probe() -> bool {
    std::env::var("IOI_AFT_BENCH_FAST_PROBE")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
}

fn benchmark_trace_enabled() -> bool {
    std::env::var_os("IOI_AFT_BENCH_TRACE").is_some()
}

fn benchmark_skip_artifact_build() -> bool {
    std::env::var("IOI_AFT_BENCH_SKIP_ARTIFACT_BUILD")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(true)
}

#[derive(Debug, Clone, Copy)]
struct AftBenchmarkScenario {
    name: &'static str,
    validators: usize,
    safety_mode: AftSafetyMode,
    target_block_time_ms: u64,
    target_gas_per_block: u64,
    accounts: usize,
    txs_per_account: u64,
    rpc_connections_per_validator: usize,
    measurement_timeout_secs: u64,
}

impl AftBenchmarkScenario {
    const fn paper_guardian_majority_4v() -> Self {
        Self {
            name: "guardian_majority_4v",
            validators: 4,
            safety_mode: AftSafetyMode::GuardianMajority,
            target_block_time_ms: BLOCK_TIME_MS,
            target_gas_per_block: 1_000_000_000,
            accounts: 512,
            txs_per_account: 1,
            rpc_connections_per_validator: 24,
            measurement_timeout_secs: 60,
        }
    }

    const fn paper_guardian_majority_7v() -> Self {
        Self {
            name: "guardian_majority_7v",
            validators: 7,
            safety_mode: AftSafetyMode::GuardianMajority,
            target_block_time_ms: BLOCK_TIME_MS,
            target_gas_per_block: 1_000_000_000,
            accounts: 768,
            txs_per_account: 1,
            rpc_connections_per_validator: 16,
            measurement_timeout_secs: 75,
        }
    }

    const fn paper_asymptote_4v() -> Self {
        Self {
            name: "asymptote_4v",
            validators: 4,
            safety_mode: AftSafetyMode::Asymptote,
            target_block_time_ms: BLOCK_TIME_MS,
            target_gas_per_block: 1_000_000_000,
            accounts: 512,
            txs_per_account: 1,
            rpc_connections_per_validator: 24,
            measurement_timeout_secs: 75,
        }
    }

    const fn paper_asymptote_7v() -> Self {
        Self {
            name: "asymptote_7v",
            validators: 7,
            safety_mode: AftSafetyMode::Asymptote,
            target_block_time_ms: BLOCK_TIME_MS,
            target_gas_per_block: 1_000_000_000,
            accounts: 768,
            txs_per_account: 1,
            rpc_connections_per_validator: 16,
            measurement_timeout_secs: 90,
        }
    }
}

#[derive(Debug, Clone)]
struct SubmittedTx {
    tx_hash: String,
    chain_hash: String,
    submitted_at: Instant,
    admitted_at: Instant,
    status_channel_index: usize,
    submit_retries: u64,
    submit_timeout_retries: u64,
    duplicate_response: bool,
}

#[derive(Debug, Clone)]
struct CommittedTx {
    submitted_at: Instant,
    committed_at: Instant,
    block_height: u64,
}

#[derive(Debug, Clone)]
enum AftTerminalOutcome {
    Close,
    Abort,
}

#[derive(Debug, Clone)]
struct AftTerminalBlock {
    height: u64,
    terminal_at: Instant,
    outcome: AftTerminalOutcome,
}

struct ScopedEnv {
    saved: Vec<(String, Option<OsString>)>,
}

impl ScopedEnv {
    fn new() -> Self {
        Self { saved: Vec::new() }
    }

    fn set<K, V>(&mut self, key: K, value: V)
    where
        K: Into<String>,
        V: Into<OsString>,
    {
        let key = key.into();
        if !self.saved.iter().any(|(saved_key, _)| saved_key == &key) {
            self.saved.push((key.clone(), std::env::var_os(&key)));
        }
        std::env::set_var(&key, value.into());
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..).rev() {
            match value {
                Some(value) => std::env::set_var(&key, value),
                None => std::env::remove_var(&key),
            }
        }
    }
}

fn benchmark_override_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn benchmark_override_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn benchmark_override_u64_allow_zero(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_or_default(name: &str, default: impl Into<String>) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}

async fn build_channels(rpc_addrs: &[String], per_validator: usize) -> Result<Vec<Channel>> {
    let mut channels = Vec::new();
    // Interleave connections across validators so small and moderate submission sets
    // do not all land on the first RPC address in the list.
    for _ in 0..per_validator {
        for rpc_addr in rpc_addrs {
            channels.push(Channel::from_shared(format!("http://{}", rpc_addr))?.connect_lazy());
        }
    }
    Ok(channels)
}

async fn wait_for_next_height(rpc_addr: &str, start_height: u64, timeout: Duration) -> Result<u64> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);

    loop {
        let status = rpc::get_status(rpc_addr).await?;
        if status.height > start_height {
            return Ok(status.height);
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "timeout waiting for chain height to advance beyond {}",
                start_height
            ));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_first_committed_tip(
    rpc_addr: &str,
    start_height: u64,
    bootstrap_grace_secs: u64,
    target_block_time_secs_legacy: u64,
) -> Result<(u64, u64)> {
    let alignment_timeout_secs = bootstrap_grace_secs
        .saturating_add(target_block_time_secs_legacy.saturating_mul(4).max(4))
        .max(bootstrap_grace_secs.saturating_add(4));
    wait_for_next_height(
        rpc_addr,
        start_height,
        Duration::from_secs(alignment_timeout_secs),
    )
    .await
    .map_err(|error| {
        anyhow!("failed to observe the first committed height before submission: {error}")
    })?;

    let refreshed_status = rpc::get_status(rpc_addr).await?;
    if let Some(tip_block) =
        authoritative_tip_block_with_hint(rpc_addr, refreshed_status.height).await?
    {
        Ok((
            tip_block.header.height,
            tip_block.header.timestamp_ms_or_legacy(),
        ))
    } else {
        Ok((
            refreshed_status.height,
            refreshed_status.latest_timestamp.saturating_mul(1_000),
        ))
    }
}

async fn authoritative_tip_block_with_hint(
    rpc_addr: &str,
    status_hint_height: u64,
) -> Result<Option<ioi_types::app::Block<ioi_types::app::ChainTransaction>>> {
    let resilient_tip_height = rpc::tip_height_resilient(rpc_addr).await?;
    for tip_height in [resilient_tip_height, status_hint_height] {
        if tip_height == 0 {
            continue;
        }
        if let Some(block) = rpc::get_block_by_height_resilient(rpc_addr, tip_height).await? {
            return Ok(Some(block));
        }
    }
    Ok(None)
}

fn benchmark_primary_only() -> bool {
    std::env::var("IOI_AFT_BENCH_PRIMARY_ONLY")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
}

fn benchmark_lane_filter() -> Option<AftBenchmarkLane> {
    std::env::var("IOI_AFT_BENCH_LANE")
        .ok()
        .as_deref()
        .and_then(AftBenchmarkLane::parse)
}

fn benchmark_route_to_leaders_override() -> Option<bool> {
    std::env::var("IOI_AFT_BENCH_ROUTE_TO_LEADERS")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
}

fn benchmark_round_robin_by_tx_index_override() -> Option<bool> {
    std::env::var("IOI_AFT_BENCH_ROUND_ROBIN_BY_TX_INDEX")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
}

fn benchmark_prefer_target_height_leader() -> bool {
    std::env::var("IOI_AFT_BENCH_PREFER_TARGET_HEIGHT_LEADER")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
}

fn default_route_to_leaders(fast_probe: bool, benchmark_tx_total: usize) -> bool {
    fast_probe && benchmark_tx_total > 256
}

fn default_round_robin_by_tx_index(fast_probe: bool, txs_per_account: u64) -> bool {
    fast_probe && txs_per_account > 1
}

fn default_warm_first_committed_height(
    auto_future_genesis: bool,
    fast_probe: bool,
    benchmark_tx_total: usize,
) -> bool {
    auto_future_genesis && fast_probe && benchmark_tx_total > 256
}

fn default_ingress_leader_fanout(
    validators: usize,
    benchmark_tx_total: usize,
    benchmark_tx_select_max_bytes: u64,
    fast_probe: bool,
) -> usize {
    let approx_tx_capacity_per_leader =
        usize::max((benchmark_tx_select_max_bytes / 1_024) as usize, 1);
    let byte_based_fanout = usize::max(
        1,
        benchmark_tx_total.div_ceil(approx_tx_capacity_per_leader),
    );
    let burst_based_fanout = if fast_probe && benchmark_tx_total > 256 {
        usize::max(1, benchmark_tx_total.div_ceil(256))
    } else {
        1
    };

    usize::min(
        validators.max(1),
        usize::max(byte_based_fanout, burst_based_fanout),
    )
}

fn default_submit_lead_ms(
    target_block_time_ms: u64,
    fast_probe: bool,
    trace_mode: bool,
    benchmark_tx_total: usize,
) -> u64 {
    if fast_probe {
        if benchmark_tx_total > 256 {
            target_block_time_ms.saturating_div(4).clamp(100, 250)
        } else {
            target_block_time_ms.saturating_div(8).clamp(0, 50)
        }
    } else if trace_mode {
        target_block_time_ms.saturating_div(6).clamp(0, 75)
    } else {
        target_block_time_ms.saturating_div(4).clamp(10, 250)
    }
}

fn benchmark_block_time_ms(default_ms: u64) -> u64 {
    std::env::var("IOI_AFT_BENCH_BLOCK_TIME_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .or_else(|| {
            std::env::var("IOI_AFT_BENCH_BLOCK_TIME_SECS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .map(|secs| secs.saturating_mul(1_000))
        })
        .unwrap_or(default_ms)
}

fn benchmark_live_logs_enabled() -> bool {
    std::env::var("IOI_AFT_BENCH_LIVE_LOGS")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
}

fn default_submit_concurrency(
    total_expected_submissions: usize,
    submission_channel_count: usize,
    fast_probe: bool,
) -> usize {
    let baseline = usize::max(
        submission_channel_count
            .saturating_mul(if fast_probe { 4 } else { 8 })
            .max(1),
        128,
    );
    let capped = if fast_probe {
        baseline.min(256)
    } else {
        baseline
    };
    usize::min(total_expected_submissions.max(1), capped)
}

fn default_submit_wave_size(
    total_expected_submissions: usize,
    ingress_rpc_count: usize,
    fast_probe: bool,
) -> usize {
    if fast_probe && total_expected_submissions > 256 {
        usize::min(
            total_expected_submissions.max(1),
            usize::max(ingress_rpc_count.max(1).saturating_mul(64), 128).min(256),
        )
    } else {
        total_expected_submissions.max(1)
    }
}

fn default_submit_wave_pause_ms(
    target_block_time_ms: u64,
    ingress_rpc_count: usize,
    fast_probe: bool,
    total_expected_submissions: usize,
) -> u64 {
    if fast_probe && total_expected_submissions > 256 {
        target_block_time_ms
            .div_ceil((ingress_rpc_count.max(1) as u64).saturating_mul(16))
            .clamp(10, 100)
    } else {
        0
    }
}

fn default_alignment_safety_pad_ms(
    target_block_time_ms: u64,
    fast_probe: bool,
    total_expected_submissions: usize,
) -> u64 {
    if fast_probe && total_expected_submissions > 256 {
        target_block_time_ms.saturating_div(10).clamp(50, 100)
    } else {
        0
    }
}

fn alignment_pacing_budget_ms(
    total_expected_submissions: usize,
    submit_wave_size: usize,
    submit_wave_pause_ms: u64,
) -> u64 {
    let total_submission_waves = total_expected_submissions.div_ceil(submit_wave_size.max(1));
    submit_wave_pause_ms.saturating_mul(total_submission_waves.saturating_sub(1) as u64)
}

fn remaining_wave_pause_ms(
    elapsed_since_schedule_start: Duration,
    completed_wave_index: usize,
    submit_wave_pause_ms: u64,
) -> u64 {
    let target_elapsed_ms =
        submit_wave_pause_ms.saturating_mul(completed_wave_index.saturating_add(1) as u64);
    target_elapsed_ms.saturating_sub(
        elapsed_since_schedule_start
            .as_millis()
            .min(u128::from(u64::MAX)) as u64,
    )
}

fn alignment_ready_budget_ms(
    submit_lead_ms: u64,
    total_expected_submissions: usize,
    submit_wave_size: usize,
    submit_wave_pause_ms: u64,
    estimated_submission_service_budget_ms: u64,
    alignment_safety_pad_ms: u64,
) -> u64 {
    let pacing_budget_ms = alignment_pacing_budget_ms(
        total_expected_submissions,
        submit_wave_size,
        submit_wave_pause_ms,
    );

    submit_lead_ms
        .saturating_add(pacing_budget_ms)
        .saturating_add(estimated_submission_service_budget_ms)
        .saturating_add(alignment_safety_pad_ms)
}

fn alignment_start_lead_ms(
    submit_lead_ms: u64,
    total_expected_submissions: usize,
    submit_wave_size: usize,
    submit_wave_pause_ms: u64,
    estimated_submission_service_budget_ms: u64,
) -> u64 {
    submit_lead_ms
        .saturating_add(alignment_pacing_budget_ms(
            total_expected_submissions,
            submit_wave_size,
            submit_wave_pause_ms,
        ))
        .saturating_add(estimated_submission_service_budget_ms)
}

fn select_aligned_due_ms(
    base_due_ms: u64,
    now_ms: u64,
    target_block_time_ms: u64,
    ready_budget_ms: u64,
) -> u64 {
    let earliest_due_ms = now_ms.saturating_add(ready_budget_ms);
    if base_due_ms >= earliest_due_ms {
        base_due_ms
    } else {
        let skipped_due_slots = earliest_due_ms
            .saturating_sub(base_due_ms)
            .div_ceil(target_block_time_ms);
        base_due_ms.saturating_add(skipped_due_slots.saturating_mul(target_block_time_ms))
    }
}

fn aligned_target_height_for_due_ms(
    alignment_height: u64,
    base_due_ms: u64,
    next_due_ms: u64,
    target_block_time_ms: u64,
) -> u64 {
    let skipped_due_slots = next_due_ms
        .saturating_sub(base_due_ms)
        .checked_div(target_block_time_ms.max(1))
        .unwrap_or_default();
    alignment_height
        .saturating_add(skipped_due_slots)
        .saturating_add(1)
}

fn summarize_alignment_block_packing(
    per_block_tx_counts: &[(u64, usize)],
    target_height: Option<u64>,
) -> (Option<u64>, Option<u64>) {
    let Some(target_height) = target_height else {
        return (None, None);
    };

    let mut committed_before_target_height_txs = 0u64;
    let mut committed_at_target_height_txs = 0u64;
    for (height, matched_count) in per_block_tx_counts {
        if *height < target_height {
            committed_before_target_height_txs =
                committed_before_target_height_txs.saturating_add(*matched_count as u64);
        } else if *height == target_height {
            committed_at_target_height_txs =
                committed_at_target_height_txs.saturating_add(*matched_count as u64);
        }
    }

    (
        Some(committed_before_target_height_txs),
        Some(committed_at_target_height_txs),
    )
}

fn sampled_commit_visibility_lag_ms(
    authoritative_final_commit_instant: Instant,
    sampled_final_commit_instant: Option<Instant>,
) -> Option<i64> {
    sampled_final_commit_instant.map(|sampled_final_commit_instant| {
        if sampled_final_commit_instant >= authoritative_final_commit_instant {
            let lag_ms = sampled_final_commit_instant
                .duration_since(authoritative_final_commit_instant)
                .as_millis();
            lag_ms.min(i64::MAX as u128) as i64
        } else {
            let lag_ms = authoritative_final_commit_instant
                .duration_since(sampled_final_commit_instant)
                .as_millis();
            -(lag_ms.min(i64::MAX as u128) as i64)
        }
    })
}

fn sustained_commit_endpoint(
    fast_probe: bool,
    authoritative_final_commit_instant: Instant,
    sampled_final_commit_instant: Option<Instant>,
) -> Instant {
    if fast_probe {
        authoritative_final_commit_instant
    } else {
        sampled_final_commit_instant.unwrap_or(authoritative_final_commit_instant)
    }
}

async fn sample_status_latencies(rpc_addrs: &[String]) -> Result<LatencySummary> {
    let latency_samples = stream::iter(rpc_addrs.iter().cloned())
        .then(|rpc_addr| async move {
            let sample_started = Instant::now();
            rpc::get_status(&rpc_addr).await?;
            Ok::<Duration, anyhow::Error>(sample_started.elapsed())
        })
        .try_collect::<Vec<_>>()
        .await?;
    Ok(summarize_latencies(&latency_samples))
}

fn estimated_submission_service_budget_ms(
    total_expected_submissions: usize,
    submit_concurrency: usize,
    ingress_status_latency: LatencySummary,
) -> u64 {
    let submission_rounds = total_expected_submissions.div_ceil(submit_concurrency.max(1)) as u64;
    let round_trip_budget_ms = ingress_status_latency
        .p95_ms
        .ceil()
        .clamp(1.0, u64::MAX as f64) as u64;
    submission_rounds.saturating_mul(round_trip_budget_ms)
}

fn flatten_submissions(
    signed_account_txs: Vec<Vec<Vec<u8>>>,
    round_robin_by_tx_index: bool,
) -> Vec<(usize, usize, Vec<u8>)> {
    let total_expected_submissions = signed_account_txs.iter().map(Vec::len).sum();
    if !round_robin_by_tx_index {
        return signed_account_txs
            .into_iter()
            .enumerate()
            .flat_map(|(account_index, txs)| {
                txs.into_iter()
                    .enumerate()
                    .map(move |(tx_index, tx_bytes)| (account_index, tx_index, tx_bytes))
            })
            .collect::<Vec<_>>();
    }

    let mut flattened = Vec::with_capacity(total_expected_submissions);
    let mut per_account_iters = signed_account_txs
        .into_iter()
        .map(|txs| txs.into_iter())
        .collect::<Vec<_>>();
    let mut tx_index = 0usize;

    loop {
        let mut advanced = false;
        for (account_index, txs) in per_account_iters.iter_mut().enumerate() {
            if let Some(tx_bytes) = txs.next() {
                flattened.push((account_index, tx_index, tx_bytes));
                advanced = true;
            }
        }
        if !advanced {
            break;
        }
        tx_index = tx_index.saturating_add(1);
    }

    flattened
}

fn spawn_benchmark_live_log_drains(cluster: &TestCluster) {
    if !benchmark_live_logs_enabled() {
        return;
    }

    for (validator_index, guard) in cluster.validators.iter().enumerate() {
        let (mut orch_logs, mut workload_logs, guardian_logs) = guard.validator().subscribe_logs();
        tokio::spawn(async move {
            loop {
                match orch_logs.recv().await {
                    Ok(line) => {
                        println!("[BENCH-LIVE][v{validator_index}][orch] {line}");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        println!(
                            "[BENCH-LIVE][v{validator_index}][orch] <lagged {skipped} log lines>"
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        if benchmark_trace_enabled() {
            tokio::spawn(async move {
                loop {
                    match workload_logs.recv().await {
                        Ok(line) => {
                            println!("[BENCH-LIVE][v{validator_index}][workload] {line}");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            println!(
                                "[BENCH-LIVE][v{validator_index}][workload] <lagged {skipped} log lines>"
                            );
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });

            if let Some(mut guardian_logs) = guardian_logs {
                tokio::spawn(async move {
                    loop {
                        match guardian_logs.recv().await {
                            Ok(line) => {
                                println!("[BENCH-LIVE][v{validator_index}][guardian] {line}");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                println!(
                                    "[BENCH-LIVE][v{validator_index}][guardian] <lagged {skipped} log lines>"
                                );
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
struct PrepareBlockMetrics {
    height: u64,
    replay_mode: String,
    replay_debt: u64,
    validation_aborts: u64,
    execution_errors: u64,
}

#[derive(Debug, Default)]
struct BenchmarkChurnTracker {
    fallback_heights: BTreeSet<u64>,
    max_replay_debt: u64,
    max_validation_aborts: u64,
    max_execution_errors: u64,
}

impl BenchmarkChurnTracker {
    fn observe(&mut self, metrics: &PrepareBlockMetrics) {
        if metrics.replay_mode == "fallback_sequential" {
            self.fallback_heights.insert(metrics.height);
        }
        self.max_replay_debt = self.max_replay_debt.max(metrics.replay_debt);
        self.max_validation_aborts = self.max_validation_aborts.max(metrics.validation_aborts);
        self.max_execution_errors = self.max_execution_errors.max(metrics.execution_errors);
    }

    fn snapshot(&self) -> BenchmarkChurnSummary {
        BenchmarkChurnSummary {
            fallback_blocks: self.fallback_heights.len(),
            max_replay_debt: self.max_replay_debt,
            max_validation_aborts: self.max_validation_aborts,
            max_execution_errors: self.max_execution_errors,
        }
    }
}

fn parse_prepare_block_metrics(line: &str) -> Option<PrepareBlockMetrics> {
    let (_, payload) = line.split_once("[BENCH-EXEC] prepare_block")?;
    let mut metrics = PrepareBlockMetrics::default();
    let mut saw_height = false;
    let mut saw_replay_mode = false;

    for token in payload.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key {
            "height" => {
                metrics.height = value.parse().ok()?;
                saw_height = true;
            }
            "replay_mode" => {
                metrics.replay_mode = value.to_string();
                saw_replay_mode = true;
            }
            "replay_debt" => {
                metrics.replay_debt = value.parse().ok()?;
            }
            "validation_aborts" => {
                metrics.validation_aborts = value.parse().ok()?;
            }
            "execution_errors" => {
                metrics.execution_errors = value.parse().ok()?;
            }
            _ => {}
        }
    }

    if saw_height && saw_replay_mode {
        Some(metrics)
    } else {
        None
    }
}

fn spawn_benchmark_churn_collectors(cluster: &TestCluster) -> Arc<StdMutex<BenchmarkChurnTracker>> {
    let tracker = Arc::new(StdMutex::new(BenchmarkChurnTracker::default()));

    for guard in &cluster.validators {
        let mut workload_logs = guard.validator().subscribe_logs().1;
        let tracker = Arc::clone(&tracker);
        tokio::spawn(async move {
            loop {
                match workload_logs.recv().await {
                    Ok(line) => {
                        if let Some(metrics) = parse_prepare_block_metrics(&line) {
                            if let Ok(mut tracker) = tracker.lock() {
                                tracker.observe(&metrics);
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    tracker
}

fn leader_account_for_height(height: u64, validator_ids: &[Vec<u8>]) -> Option<AccountId> {
    if validator_ids.is_empty() {
        return None;
    }

    let target_height = height.max(1);
    let leader_index = ((target_height - 1) % validator_ids.len() as u64) as usize;
    let leader_bytes: [u8; 32] = validator_ids
        .get(leader_index)?
        .as_slice()
        .try_into()
        .ok()?;
    Some(AccountId(leader_bytes))
}

fn leader_accounts_from_height(
    start_height: u64,
    validator_ids: &[Vec<u8>],
    fanout: usize,
) -> Vec<AccountId> {
    if validator_ids.is_empty() || fanout == 0 {
        return Vec::new();
    }

    let mut leaders = Vec::new();
    let mut seen = HashSet::new();
    let validator_len = validator_ids.len() as u64;
    let steps = fanout.min(validator_ids.len());
    for offset in 0..steps {
        let target_height = start_height.saturating_add(offset as u64).max(1);
        let leader_index = ((target_height - 1) % validator_len) as usize;
        let Some(leader_bytes) = validator_ids.get(leader_index) else {
            continue;
        };
        let Ok(leader_bytes) = <[u8; 32]>::try_from(leader_bytes.as_slice()) else {
            continue;
        };
        let account = AccountId(leader_bytes);
        if seen.insert(account) {
            leaders.push(account);
        }
    }

    leaders
}

fn validator_rpc_addr_for_account_id(
    cluster: &TestCluster,
    account_id: AccountId,
) -> Option<String> {
    cluster.validators.iter().find_map(|guard| {
        let public_key = guard.validator().keypair.public().encode_protobuf();
        let validator_account_id =
            account_id_from_key_material(SignatureSuite::ED25519, &public_key)
                .ok()
                .map(AccountId)?;
        (validator_account_id == account_id).then(|| guard.validator().rpc_addr.clone())
    })
}

fn prioritize_rpc_addr(
    mut rpc_addrs: Vec<String>,
    preferred_rpc_addr: Option<&str>,
) -> Vec<String> {
    let Some(preferred_rpc_addr) = preferred_rpc_addr else {
        return rpc_addrs;
    };
    let Some(preferred_index) = rpc_addrs
        .iter()
        .position(|rpc_addr| rpc_addr == preferred_rpc_addr)
    else {
        return rpc_addrs;
    };
    if preferred_index > 0 {
        rpc_addrs.swap(0, preferred_index);
    }
    rpc_addrs
}

fn preferred_submission_channel_span(
    prefer_target_height_leader_submission: bool,
    connections_per_addr: usize,
    total_submission_channels: usize,
) -> usize {
    if prefer_target_height_leader_submission {
        connections_per_addr.min(total_submission_channels).max(1)
    } else {
        total_submission_channels.max(1)
    }
}

async fn submit_account_sequence(
    channels: Arc<Vec<Channel>>,
    preferred_channel_index: usize,
    status_channel_index: usize,
    txs: Vec<Vec<u8>>,
) -> Result<Vec<SubmittedTx>> {
    let mut submitted = Vec::with_capacity(txs.len());
    for tx_bytes in txs {
        submitted.push(
            submit_transaction_bytes(
                channels.as_ref(),
                preferred_channel_index,
                status_channel_index,
                tx_bytes,
            )
            .await?,
        );
    }

    Ok(submitted)
}

async fn submit_transaction_bytes(
    channels: &[Channel],
    preferred_channel_index: usize,
    status_channel_index: usize,
    tx_bytes: Vec<u8>,
) -> Result<SubmittedTx> {
    let submit_timeout = Duration::from_millis(benchmark_override_u64(
        "IOI_AFT_BENCH_SUBMIT_TIMEOUT_MS",
        DEFAULT_SUBMIT_TIMEOUT_MS,
    ));

    let chain_hash = codec::from_bytes_canonical::<ChainTransaction>(&tx_bytes)
        .ok()
        .and_then(|tx| tx.hash().ok())
        .map(hex::encode)
        .unwrap_or_default();
    let mut retries = 0u64;
    let mut timeout_retries = 0u64;
    loop {
        let channel_index = if channels.is_empty() {
            0
        } else {
            preferred_channel_index.saturating_add(retries as usize) % channels.len()
        };
        let mut client = PublicApiClient::new(
            channels
                .get(channel_index)
                .ok_or_else(|| anyhow!("no submission channels available"))?
                .clone(),
        );
        let request = tonic::Request::new(SubmitTransactionRequest {
            transaction_bytes: tx_bytes.clone(),
        });
        let submit_started = Instant::now();

        match timeout(submit_timeout, client.submit_transaction(request)).await {
            Err(_) => {
                retries += 1;
                timeout_retries += 1;
                if retries > MAX_RETRIES as u64 {
                    return Err(anyhow!(
                        "submit retries exceeded after timeout waiting {} ms",
                        submit_timeout.as_millis()
                    ));
                }
                sleep(Duration::from_millis(BACKOFF_MS)).await;
                continue;
            }
            Ok(Err(status)) => {
                let message = status.message().to_string();
                let retryable = matches!(
                    status.code(),
                    Code::ResourceExhausted | Code::Unavailable | Code::Internal
                ) || (status.code() == Code::InvalidArgument
                    && (message.contains("Nonce mismatch")
                        || message.contains("Nonce record not found")));

                if retryable {
                    retries += 1;
                    if retries > MAX_RETRIES as u64 {
                        return Err(anyhow!(
                            "submit retries exceeded: code={}, message={}",
                            status.code(),
                            message
                        ));
                    }
                    sleep(Duration::from_millis(BACKOFF_MS)).await;
                    continue;
                }

                if status.code() == Code::InvalidArgument
                    && (message.contains("already exists")
                        || message.contains("nonce too low")
                        || message.contains("Mempool"))
                {
                    let admitted_at = Instant::now();
                    return Ok(SubmittedTx {
                        tx_hash: String::new(),
                        chain_hash: String::new(),
                        submitted_at: submit_started,
                        admitted_at,
                        status_channel_index,
                        submit_retries: retries,
                        submit_timeout_retries: timeout_retries,
                        duplicate_response: true,
                    });
                }

                return Err(anyhow!(
                    "submit failed: code={}, message={}",
                    status.code(),
                    message
                ));
            }
            Ok(Ok(response)) => {
                let tx_hash = response.into_inner().tx_hash;
                let admitted_at = Instant::now();
                return Ok(SubmittedTx {
                    tx_hash,
                    chain_hash: chain_hash.clone(),
                    submitted_at: submit_started,
                    admitted_at,
                    status_channel_index,
                    submit_retries: retries,
                    submit_timeout_retries: timeout_retries,
                    duplicate_response: false,
                });
            }
        }
    }
}

async fn poll_committed_transaction(
    channels: &[Channel],
    submitted: SubmittedTx,
    timeout: Duration,
) -> Result<CommittedTx> {
    let deadline = submitted
        .submitted_at
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);

    loop {
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "timeout waiting for tx {} to commit",
                submitted.tx_hash
            ));
        }

        if let Some((status, error_message, block_height)) =
            query_transaction_status_any(channels, &submitted.tx_hash).await?
        {
            match status {
                TxStatus::Committed => {
                    return Ok(CommittedTx {
                        submitted_at: submitted.submitted_at,
                        committed_at: Instant::now(),
                        block_height,
                    });
                }
                TxStatus::Rejected => {
                    return Err(anyhow!(
                        "transaction {} rejected: {}",
                        submitted.tx_hash,
                        error_message
                    ));
                }
                _ => {}
            }
        }

        sleep(Duration::from_millis(100)).await;
    }
}

async fn query_state_key_any_rpc(rpc_addrs: &[String], key: &[u8]) -> Result<Option<Vec<u8>>> {
    for rpc_addr in rpc_addrs {
        if let Some(value) = rpc::query_state_key(rpc_addr, key).await? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

async fn wait_for_canonical_ordering_terminal_block(
    rpc_addrs: &[String],
    height: u64,
    timeout: Duration,
) -> Result<AftTerminalBlock> {
    let start = Instant::now();
    let close_key = aft_order_certificate_key(height);
    let abort_key = aft_canonical_order_abort_key(height);
    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "timeout waiting for canonical ordering terminal surface at height {}",
                height
            ));
        }

        if query_state_key_any_rpc(rpc_addrs, &abort_key)
            .await?
            .is_some()
        {
            return Ok(AftTerminalBlock {
                height,
                terminal_at: Instant::now(),
                outcome: AftTerminalOutcome::Abort,
            });
        }
        if query_state_key_any_rpc(rpc_addrs, &close_key)
            .await?
            .is_some()
        {
            return Ok(AftTerminalBlock {
                height,
                terminal_at: Instant::now(),
                outcome: AftTerminalOutcome::Close,
            });
        }
        if let Some(block) = get_block_by_height_any_rpc(rpc_addrs, height).await? {
            if block.header.canonical_order_certificate.is_some() {
                return Ok(AftTerminalBlock {
                    height,
                    terminal_at: Instant::now(),
                    outcome: AftTerminalOutcome::Close,
                });
            }
        }

        sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_durable_collapse_terminal_block(
    rpc_addrs: &[String],
    height: u64,
    timeout: Duration,
) -> Result<AftTerminalBlock> {
    let start = Instant::now();
    let collapse_key = aft_canonical_collapse_object_key(height);
    let abort_key = aft_canonical_order_abort_key(height);
    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "timeout waiting for durable collapse surface at height {}",
                height
            ));
        }

        if query_state_key_any_rpc(rpc_addrs, &collapse_key)
            .await?
            .is_some()
        {
            let outcome = if query_state_key_any_rpc(rpc_addrs, &abort_key)
                .await?
                .is_some()
            {
                AftTerminalOutcome::Abort
            } else {
                AftTerminalOutcome::Close
            };
            return Ok(AftTerminalBlock {
                height,
                terminal_at: Instant::now(),
                outcome,
            });
        }

        sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_sealed_terminal_block(
    rpc_addrs: &[String],
    height: u64,
    timeout: Duration,
) -> Result<AftTerminalBlock> {
    let start = Instant::now();
    let abort_key = aft_canonical_order_abort_key(height);
    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "timeout waiting for sealed AFT terminal surface at height {}",
                height
            ));
        }

        if query_state_key_any_rpc(rpc_addrs, &abort_key)
            .await?
            .is_some()
        {
            return Ok(AftTerminalBlock {
                height,
                terminal_at: Instant::now(),
                outcome: AftTerminalOutcome::Abort,
            });
        }

        if let Some(block) = get_block_by_height_any_rpc(rpc_addrs, height).await? {
            if block.header.sealed_finality_proof.is_some() {
                return Ok(AftTerminalBlock {
                    height,
                    terminal_at: Instant::now(),
                    outcome: AftTerminalOutcome::Close,
                });
            }
        }

        sleep(Duration::from_millis(200)).await;
    }
}

async fn query_transaction_status_any(
    channels: &[Channel],
    tx_hash: &str,
) -> Result<Option<(TxStatus, String, u64)>> {
    let status_timeout = Duration::from_millis(benchmark_override_u64(
        "IOI_AFT_BENCH_STATUS_TIMEOUT_MS",
        DEFAULT_STATUS_TIMEOUT_MS,
    ));
    let responses = stream::iter(channels.iter().cloned())
        .map(|channel| {
            let tx_hash = tx_hash.to_string();
            let status_timeout = status_timeout;
            async move {
                let mut client = PublicApiClient::new(channel);
                timeout(
                    status_timeout,
                    client.get_transaction_status(tonic::Request::new(
                        GetTransactionStatusRequest { tx_hash },
                    )),
                )
                .await
                .ok()
                .and_then(|result| result.ok())
                .map(|response| response.into_inner())
            }
        })
        .buffer_unordered(channels.len().max(1))
        .collect::<Vec<_>>()
        .await;

    let mut first_rejection = None;
    let mut first_pending = None;
    let mut first_unknown = None;

    for response in responses.into_iter().flatten() {
        let decoded = TxStatus::try_from(response.status).unwrap_or(TxStatus::Unknown);
        match decoded {
            TxStatus::Committed => {
                return Ok(Some((
                    TxStatus::Committed,
                    response.error_message,
                    response.block_height,
                )))
            }
            TxStatus::Rejected => {
                if first_rejection.is_none() {
                    first_rejection = Some((
                        TxStatus::Rejected,
                        response.error_message,
                        response.block_height,
                    ));
                }
            }
            TxStatus::InMempool | TxStatus::Pending => {
                if first_pending.is_none() {
                    first_pending = Some((decoded, response.error_message, response.block_height));
                }
            }
            TxStatus::Unknown => {
                if first_unknown.is_none() {
                    first_unknown = Some((
                        TxStatus::Unknown,
                        response.error_message,
                        response.block_height,
                    ));
                }
            }
        }
    }

    Ok(first_pending.or(first_unknown).or(first_rejection))
}

async fn get_block_by_height_any_rpc(
    rpc_addrs: &[String],
    height: u64,
) -> Result<Option<ioi_types::app::Block<ioi_types::app::ChainTransaction>>> {
    for rpc_addr in rpc_addrs {
        if let Some(block) = rpc::get_block_by_height_resilient(rpc_addr, height).await? {
            return Ok(Some(block));
        }
    }
    Ok(None)
}

#[derive(Debug, Clone)]
struct ChainCommitScan {
    committed: u64,
    scanned_tip_height: u64,
    committed_heights: BTreeSet<u64>,
    per_block_tx_counts: Vec<(u64, usize)>,
}

async fn scan_committed_hashes_from_chain(
    rpc_addrs: &[String],
    initial_height: u64,
    expected_hashes: &HashSet<String>,
    timeout: Duration,
) -> Result<ChainCommitScan> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut seen_hashes = HashSet::<String>::with_capacity(expected_hashes.len());
    let mut committed_heights = BTreeSet::new();
    let mut per_block_tx_counts = Vec::new();
    let mut next_height = initial_height.saturating_add(1);
    let mut last_progress_log = Instant::now()
        .checked_sub(Duration::from_secs(5))
        .unwrap_or_else(Instant::now);
    let mut last_scanned_tip = initial_height;

    loop {
        while let Some(block) = get_block_by_height_any_rpc(rpc_addrs, next_height).await? {
            let mut matched_in_block = 0usize;
            for tx in &block.transactions {
                if let Ok(hash) = tx.hash() {
                    let hash_hex = hex::encode(hash);
                    if expected_hashes.contains(&hash_hex) && seen_hashes.insert(hash_hex) {
                        matched_in_block += 1;
                    }
                }
            }
            per_block_tx_counts.push((next_height, matched_in_block));
            if matched_in_block > 0 {
                committed_heights.insert(next_height);
            }
            last_scanned_tip = next_height;
            next_height = next_height.saturating_add(1);
        }

        if last_progress_log.elapsed() >= Duration::from_secs(5) {
            println!(
                "chain scan progress: scanned_tip={} committed={}/{} scanned_blocks={}",
                last_scanned_tip,
                seen_hashes.len(),
                expected_hashes.len(),
                per_block_tx_counts.len()
            );
            last_progress_log = Instant::now();
        }

        if seen_hashes.len() >= expected_hashes.len() {
            return Ok(ChainCommitScan {
                committed: seen_hashes.len() as u64,
                scanned_tip_height: last_scanned_tip,
                committed_heights,
                per_block_tx_counts,
            });
        }

        if Instant::now() >= deadline {
            return Ok(ChainCommitScan {
                committed: seen_hashes.len() as u64,
                scanned_tip_height: last_scanned_tip,
                committed_heights,
                per_block_tx_counts,
            });
        }

        sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_committed_hashes_on_chain(
    rpc_addrs: &[String],
    initial_height: u64,
    expected_hashes: &HashSet<String>,
    timeout: Duration,
) -> Result<(Instant, ChainCommitScan)> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut seen_hashes = HashSet::<String>::with_capacity(expected_hashes.len());
    let mut committed_heights = BTreeSet::new();
    let mut per_block_tx_counts = Vec::new();
    let mut next_height = initial_height.saturating_add(1);
    let mut last_progress_log = Instant::now()
        .checked_sub(Duration::from_secs(5))
        .unwrap_or_else(Instant::now);
    let mut last_scanned_tip = initial_height;

    loop {
        while let Some(block) = get_block_by_height_any_rpc(rpc_addrs, next_height).await? {
            let mut matched_in_block = 0usize;
            for tx in &block.transactions {
                if let Ok(hash) = tx.hash() {
                    let hash_hex = hex::encode(hash);
                    if expected_hashes.contains(&hash_hex) && seen_hashes.insert(hash_hex) {
                        matched_in_block += 1;
                    }
                }
            }
            per_block_tx_counts.push((next_height, matched_in_block));
            if matched_in_block > 0 {
                committed_heights.insert(next_height);
            }
            last_scanned_tip = next_height;
            next_height = next_height.saturating_add(1);
        }

        if last_progress_log.elapsed() >= Duration::from_secs(5) {
            println!(
                "chain commit progress: scanned_tip={} committed={}/{} scanned_blocks={}",
                last_scanned_tip,
                seen_hashes.len(),
                expected_hashes.len(),
                per_block_tx_counts.len()
            );
            last_progress_log = Instant::now();
        }

        if seen_hashes.len() >= expected_hashes.len() {
            return Ok((
                Instant::now(),
                ChainCommitScan {
                    committed: seen_hashes.len() as u64,
                    scanned_tip_height: last_scanned_tip,
                    committed_heights,
                    per_block_tx_counts,
                },
            ));
        }

        if Instant::now() >= deadline {
            return Err(anyhow!(
                "timeout waiting for {} committed transaction hashes; observed {} before deadline (scanned_tip={})",
                expected_hashes.len(),
                seen_hashes.len(),
                last_scanned_tip,
            ));
        }

        sleep(Duration::from_millis(250)).await;
    }
}

async fn capture_cluster_commit_view(rpc_addrs: &[String]) -> String {
    let mut rows = Vec::with_capacity(rpc_addrs.len());
    for rpc_addr in rpc_addrs {
        match rpc::get_status(rpc_addr).await {
            Ok(status) => rows.push(format!(
                "{} => height={} total_transactions={}",
                rpc_addr, status.height, status.total_transactions
            )),
            Err(error) => rows.push(format!("{} => status_error={}", rpc_addr, error)),
        }
    }
    rows.join(" | ")
}

async fn fetch_metric(metrics_addr: &str, name: &str) -> String {
    let url = format!("http://{metrics_addr}/metrics");
    match reqwest::get(&url).await {
        Ok(resp) => match resp.text().await {
            Ok(text) => text
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

async fn capture_cluster_metrics_view(cluster: &TestCluster) -> String {
    let mut rows = Vec::with_capacity(cluster.validators.len());
    for validator in &cluster.validators {
        let rpc_addr = &validator.validator().rpc_addr;
        let metrics_addr = &validator.validator().orchestration_telemetry_addr;
        let snapshot = MetricsSnapshot {
            connected_peers: fetch_metric(metrics_addr, "ioi_networking_connected_peers").await,
            mempool_size: fetch_metric(metrics_addr, "ioi_mempool_size").await,
            blocks_produced_total: fetch_metric(
                metrics_addr,
                "ioi_consensus_blocks_produced_total",
            )
            .await,
        };
        rows.push(format!(
            "{} => peers={} mempool={} blocks_produced={}",
            rpc_addr,
            snapshot.connected_peers,
            snapshot.mempool_size,
            snapshot.blocks_produced_total,
        ));
    }
    rows.join(" | ")
}

fn summarize_block_tx_counts(per_block_tx_counts: &[(u64, usize)]) -> String {
    if per_block_tx_counts.is_empty() {
        return "no scanned blocks".to_string();
    }

    let non_zero = per_block_tx_counts
        .iter()
        .filter(|(_, count)| *count > 0)
        .cloned()
        .collect::<Vec<_>>();
    let recent = per_block_tx_counts
        .iter()
        .rev()
        .take(12)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|(height, count)| format!("{height}:{count}"))
        .collect::<Vec<_>>()
        .join(",");

    let max_block = per_block_tx_counts
        .iter()
        .map(|(_, count)| *count)
        .max()
        .unwrap_or(0);
    let non_zero_avg = if non_zero.is_empty() {
        0.0
    } else {
        non_zero.iter().map(|(_, count)| *count as f64).sum::<f64>() / non_zero.len() as f64
    };

    format!(
        "scanned_blocks={} non_zero_blocks={} max_block_match={} avg_non_zero_block_match={:.2} recent=[{}]",
        per_block_tx_counts.len(),
        non_zero.len(),
        max_block,
        non_zero_avg,
        recent
    )
}

fn canonicalize_submitted_records(submitted_records: &[SubmittedTx]) -> Vec<SubmittedTx> {
    let mut unique = BTreeMap::<String, SubmittedTx>::new();
    for submitted in submitted_records {
        if submitted.tx_hash.is_empty() {
            continue;
        }
        unique
            .entry(submitted.tx_hash.clone())
            .and_modify(|existing| {
                if submitted.submitted_at < existing.submitted_at {
                    *existing = submitted.clone();
                }
            })
            .or_insert_with(|| submitted.clone());
    }
    unique.into_values().collect()
}

fn sample_submitted_records_for_latency(
    submitted_records: &[SubmittedTx],
    limit: usize,
) -> Vec<SubmittedTx> {
    let mut buckets = BTreeMap::<usize, Vec<SubmittedTx>>::new();
    for submitted in submitted_records.iter().cloned() {
        buckets
            .entry(submitted.status_channel_index)
            .or_default()
            .push(submitted);
    }

    let mut sampled = Vec::with_capacity(limit.min(submitted_records.len()));
    loop {
        let mut progressed = false;
        for bucket in buckets.values_mut() {
            if sampled.len() >= limit {
                return sampled;
            }
            if !bucket.is_empty() {
                sampled.push(bucket.remove(0));
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    sampled
}

fn summarize_submissions(submitted_records: &[SubmittedTx]) -> BenchmarkSubmissionSummary {
    let submit_latencies = submitted_records
        .iter()
        .map(|submitted| {
            submitted
                .admitted_at
                .saturating_duration_since(submitted.submitted_at)
        })
        .collect::<Vec<_>>();

    BenchmarkSubmissionSummary {
        submit_retries: submitted_records
            .iter()
            .map(|submitted| submitted.submit_retries)
            .sum(),
        submit_timeout_retries: submitted_records
            .iter()
            .map(|submitted| submitted.submit_timeout_retries)
            .sum(),
        submit_duplicates: submitted_records
            .iter()
            .filter(|submitted| submitted.duplicate_response)
            .count() as u64,
        submit_latency: summarize_latencies(&submit_latencies),
    }
}

async fn collect_final_transaction_statuses(
    channels: &[Channel],
    submitted_records: &[SubmittedTx],
) -> Result<(u64, BTreeSet<u64>, BTreeMap<String, u64>)> {
    let results = stream::iter(
        submitted_records
            .iter()
            .filter(|submitted| !submitted.tx_hash.is_empty())
            .cloned(),
    )
    .map(|submitted| {
        let channels = channels.to_vec();
        async move { query_transaction_status_any(&channels, &submitted.tx_hash).await }
    })
    .buffer_unordered(usize::max(
        channels.len(),
        usize::min(submitted_records.len(), 256),
    ))
    .collect::<Vec<_>>()
    .await;

    let mut committed = 0u64;
    let mut committed_heights = BTreeSet::new();
    let mut status_buckets = BTreeMap::new();
    for result in results {
        if let Some((decoded, _error_message, block_height)) = result? {
            let bucket_name = match decoded {
                TxStatus::Pending => "pending",
                TxStatus::InMempool => "in_mempool",
                TxStatus::Committed => "committed",
                TxStatus::Rejected => "rejected",
                TxStatus::Unknown => "unknown",
            };
            *status_buckets.entry(bucket_name.to_string()).or_insert(0) += 1;
            if decoded == TxStatus::Committed {
                committed += 1;
                committed_heights.insert(block_height);
            }
        }
    }

    Ok((committed, committed_heights, status_buckets))
}

async fn run_scenario(
    scenario: AftBenchmarkScenario,
    lane: AftBenchmarkLane,
) -> Result<PaperBenchmarkResult> {
    if !lane.supports(scenario.safety_mode) {
        return Err(anyhow!(
            "benchmark lane {} is not supported for {:?}",
            lane.as_str(),
            scenario.safety_mode
        ));
    }

    let accounts = benchmark_override_usize("IOI_AFT_BENCH_ACCOUNTS", scenario.accounts);
    let txs_per_account =
        benchmark_override_u64("IOI_AFT_BENCH_TXS_PER_ACCOUNT", scenario.txs_per_account);
    let target_block_time_ms = benchmark_block_time_ms(scenario.target_block_time_ms);
    let target_block_time_secs_legacy = interval_millis_to_legacy_seconds(target_block_time_ms);
    let benchmark_tx_total = accounts.saturating_mul(txs_per_account as usize);
    let fast_probe = benchmark_fast_probe();
    let state_tree = std::env::var("IOI_AFT_BENCH_STATE_TREE").unwrap_or_else(|_| {
        if cfg!(feature = "state-iavl") {
            "IAVL".to_string()
        } else if cfg!(feature = "state-jellyfish") {
            "Jellyfish".to_string()
        } else {
            "IAVL".to_string()
        }
    });
    ensure_benchmark_node_built(&state_tree)?;
    let measurement_timeout_secs = benchmark_override_u64(
        "IOI_AFT_BENCH_TIMEOUT_SECS",
        scenario.measurement_timeout_secs,
    );
    let target_gas_per_block = benchmark_override_u64(
        "IOI_AFT_BENCH_TARGET_GAS_PER_BLOCK",
        scenario.target_gas_per_block,
    );
    let benchmark_tx_select_max_bytes = benchmark_override_u64(
        "IOI_AFT_BENCH_TX_SELECT_MAX_BYTES",
        (benchmark_tx_total as u64)
            .saturating_mul(1_024)
            .clamp(8 * 1024 * 1024, 64 * 1024 * 1024),
    );

    println!(
        "--- Running AFT paper benchmark scenario: {} [{}] ({:?}, {} validators, {} accounts x {} tx/account, gas/block {}, block_time_ms {}, state {}) ---",
        scenario.name,
        lane.as_str(),
        scenario.safety_mode,
        scenario.validators,
        accounts,
        txs_per_account,
        target_gas_per_block,
        target_block_time_ms,
        state_tree
    );

    let chain_id = 10_000 + scenario.validators as u32;
    let accounts = generate_accounts(accounts)?;
    let accounts_for_genesis = accounts.clone();
    let mut signed_account_txs = Vec::with_capacity(accounts.len());
    for (key, account_id) in &accounts {
        let mut txs = Vec::with_capacity(txs_per_account as usize);
        for nonce in 0..txs_per_account {
            let tx = create_transfer_tx(key, *account_id, *account_id, 1, nonce, chain_id);
            txs.push(ioi_types::codec::to_bytes_canonical(&tx).map_err(|e| anyhow!(e))?);
        }
        signed_account_txs.push(txs);
    }

    let target_batch = benchmark_tx_total.clamp(1_024, 32_768);
    let default_kick_debounce_ms = if benchmark_tx_total >= 8_192 {
        150
    } else if benchmark_tx_total >= 4_096 {
        100
    } else {
        25
    };
    let adaptive_view_timeout_ms = benchmark_override_u64(
        "IOI_AFT_BENCH_VIEW_TIMEOUT_MS",
        target_block_time_ms.saturating_mul(4).clamp(100, 2_000),
    );
    let trace_mode = benchmark_trace_enabled();
    let startup_buffer_secs = benchmark_override_u64(
        "IOI_AFT_BENCH_STARTUP_BUFFER_SECS",
        if trace_mode || fast_probe {
            // Benchmark nodes take materially longer than a few seconds to boot, especially when
            // we wait for multiple validator/workload pairs. Keep genesis far enough in the future
            // that submission setup still happens close to height 0.
            std::cmp::max(45, scenario.validators as u64 * 8)
        } else {
            std::cmp::max(60, scenario.validators as u64 * 10)
        },
    );
    let bootstrap_grace_secs = benchmark_override_u64(
        "IOI_AFT_BOOTSTRAP_GRACE_SECS",
        if trace_mode || fast_probe {
            startup_buffer_secs
                .saturating_add(target_block_time_secs_legacy.saturating_mul(2).max(5))
        } else {
            startup_buffer_secs
                .saturating_add(target_block_time_secs_legacy.saturating_mul(4).max(10))
        },
    );
    let mut benchmark_env = ScopedEnv::new();
    if benchmark_trace_enabled() {
        let trace_dir = std::env::var_os("IOI_AFT_BENCH_TRACE_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "ioi-aft-bench-trace-{}-{}",
                    std::process::id(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|duration| duration.as_millis())
                        .unwrap_or_default()
                ))
            });
        std::fs::create_dir_all(&trace_dir)?;
        println!("--- Benchmark trace dir: {} ---", trace_dir.display());
        benchmark_env.set(
            "IOI_AFT_BENCH_TRACE_DIR",
            trace_dir.to_string_lossy().to_string(),
        );
    }
    benchmark_env.set(
        "IOI_INGESTION_BATCH_SIZE",
        env_or_default("IOI_INGESTION_BATCH_SIZE", target_batch.to_string()),
    );
    benchmark_env.set(
        "IOI_INGESTION_BATCH_TIMEOUT_MS",
        env_or_default("IOI_INGESTION_BATCH_TIMEOUT_MS", "5"),
    );
    benchmark_env.set(
        "IOI_INGESTION_CONSENSUS_KICK_DEBOUNCE_MS",
        env_or_default(
            "IOI_INGESTION_CONSENSUS_KICK_DEBOUNCE_MS",
            default_kick_debounce_ms.to_string(),
        ),
    );
    benchmark_env.set(
        "IOI_RPC_FAST_ADMIT_MAX_MEMPOOL",
        env_or_default("IOI_RPC_FAST_ADMIT_MAX_MEMPOOL", "0"),
    );
    benchmark_env.set(
        "IOI_AFT_TX_RELAY_FANOUT",
        env_or_default(
            "IOI_AFT_TX_RELAY_FANOUT",
            scenario.validators.saturating_sub(1).max(1).to_string(),
        ),
    );
    benchmark_env.set(
        "IOI_AFT_POST_COMMIT_RELAY_LIMIT",
        env_or_default("IOI_AFT_POST_COMMIT_RELAY_LIMIT", target_batch.to_string()),
    );
    benchmark_env.set(
        "IOI_AFT_POST_COMMIT_LEADER_FANOUT",
        env_or_default(
            "IOI_AFT_POST_COMMIT_LEADER_FANOUT",
            scenario.validators.saturating_sub(1).max(1).to_string(),
        ),
    );
    benchmark_env.set(
        "IOI_CONSENSUS_TX_SELECT_LIMIT",
        env_or_default(
            "IOI_CONSENSUS_TX_SELECT_LIMIT",
            benchmark_tx_total.max(target_batch).to_string(),
        ),
    );
    benchmark_env.set(
        "IOI_CONSENSUS_TX_SELECT_MAX_BYTES",
        env_or_default(
            "IOI_CONSENSUS_TX_SELECT_MAX_BYTES",
            benchmark_tx_select_max_bytes.to_string(),
        ),
    );
    benchmark_env.set(
        "IOI_TEST_FULL_MESH_BOOTNODES",
        env_or_default(
            "IOI_TEST_FULL_MESH_BOOTNODES",
            // The AFT throughput matrix depends on successive leaders staying directly connected.
            // A star bootnode topology can strand later leaders behind a single peer and turn
            // dense multi-block runs into liveness artifacts instead of throughput measurements.
            "1",
        ),
    );
    benchmark_env.set(
        "ORCH_BLOCK_INTERVAL_MS",
        env_or_default("ORCH_BLOCK_INTERVAL_MS", "50"),
    );
    benchmark_env.set(
        "ORCH_CONSENSUS_MIN_TICK_MS",
        env_or_default("ORCH_CONSENSUS_MIN_TICK_MS", "10"),
    );
    benchmark_env.set(
        "IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS",
        env_or_default(
            "IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS",
            interval_millis_to_legacy_seconds(adaptive_view_timeout_ms).to_string(),
        ),
    );
    benchmark_env.set(
        "IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_MS",
        env_or_default(
            "IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_MS",
            adaptive_view_timeout_ms.to_string(),
        ),
    );
    benchmark_env.set(
        "IOI_AFT_BOOTSTRAP_GRACE_SECS",
        bootstrap_grace_secs.to_string(),
    );
    if let Some(interval_ms) = std::env::var("IOI_AFT_BENCH_TICK_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
    {
        benchmark_env.set("ORCH_BLOCK_INTERVAL_MS", interval_ms.to_string());
    }
    let auto_future_genesis = std::env::var("IOI_GENESIS_TIMESTAMP_SECS").is_err()
        && std::env::var("IOI_GENESIS_TIMESTAMP_MS").is_err();
    let warm_first_committed_height =
        default_warm_first_committed_height(auto_future_genesis, fast_probe, benchmark_tx_total);
    let benchmark_genesis_anchor_ms = if let Ok(ms) = std::env::var("IOI_GENESIS_TIMESTAMP_MS") {
        ms.parse::<u64>()
            .map_err(|error| anyhow!("invalid IOI_GENESIS_TIMESTAMP_MS override: {error}"))?
    } else if let Ok(secs) = std::env::var("IOI_GENESIS_TIMESTAMP_SECS") {
        secs.parse::<u64>()
            .map_err(|error| anyhow!("invalid IOI_GENESIS_TIMESTAMP_SECS override: {error}"))?
            .saturating_mul(1_000)
    } else {
        let block_time_floor = target_block_time_secs_legacy.max(1);
        let required_future_offset_secs = startup_buffer_secs
            .saturating_add(block_time_floor.saturating_mul(2))
            .saturating_add((scenario.validators as u64).div_ceil(2))
            .max(
                bootstrap_grace_secs
                    .saturating_add(block_time_floor)
                    .saturating_add(1),
            );
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| {
                duration.as_millis().min(u128::from(u64::MAX)) as u64
                    + required_future_offset_secs.saturating_mul(1_000)
            })
            .unwrap_or_else(|_| required_future_offset_secs.saturating_mul(1_000))
    };
    let benchmark_genesis_timestamp_secs = (benchmark_genesis_anchor_ms / 1_000).to_string();
    benchmark_env.set(
        "IOI_GENESIS_TIMESTAMP_SECS",
        benchmark_genesis_timestamp_secs.clone(),
    );
    let benchmark_genesis_timestamp_ms = benchmark_genesis_anchor_ms.to_string();
    benchmark_env.set(
        "IOI_GENESIS_TIMESTAMP_MS",
        benchmark_genesis_timestamp_ms.clone(),
    );
    if let Ok(allow_zero_height_ready) = std::env::var("IOI_TEST_ALLOW_ZERO_HEIGHT_READY") {
        benchmark_env.set("IOI_TEST_ALLOW_ZERO_HEIGHT_READY", allow_zero_height_ready);
    } else if auto_future_genesis {
        benchmark_env.set("IOI_TEST_ALLOW_ZERO_HEIGHT_READY", "1");
    }

    println!(
        "--- Benchmark startup barrier: genesis_ts={} genesis_ts_ms={} startup_buffer_secs={} bootstrap_grace_secs={} ---",
        benchmark_genesis_timestamp_secs,
        benchmark_genesis_timestamp_ms,
        startup_buffer_secs,
        bootstrap_grace_secs
    );

    let keep_recent_heights = benchmark_override_u64(
        "IOI_AFT_BENCH_KEEP_RECENT_HEIGHTS",
        if fast_probe {
            24
        } else if trace_mode {
            32
        } else {
            64
        },
    );
    let min_finality_depth = benchmark_override_u64_allow_zero(
        "IOI_AFT_BENCH_MIN_FINALITY_DEPTH",
        if fast_probe {
            12
        } else if trace_mode {
            16
        } else {
            32
        },
    );
    let gc_interval_secs = benchmark_override_u64(
        "IOI_AFT_BENCH_GC_INTERVAL_SECS",
        if fast_probe || trace_mode { 1 } else { 2 },
    );

    let cluster = TestCluster::builder()
        .with_validators(scenario.validators)
        .with_consensus_type("Aft")
        .with_state_tree(&state_tree)
        .with_chain_id(chain_id)
        .with_aft_safety_mode(scenario.safety_mode)
        .with_epoch_size(100_000)
        .with_keep_recent_heights(keep_recent_heights)
        .with_min_finality_depth(min_finality_depth)
        .with_gc_interval(gc_interval_secs)
        .with_genesis_modifier(move |builder, keys| {
            let mut validators = Vec::new();
            for key in keys {
                let account_id = builder.add_identity(key);
                let pk = key.public().encode_protobuf();
                let hash = account_id_from_key_material(SignatureSuite::ED25519, &pk).unwrap();
                validators.push(ValidatorV1 {
                    account_id,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ED25519,
                        public_key_hash: hash,
                        since_height: 0,
                    },
                });
            }
            validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

            for (account_key, _) in &accounts_for_genesis {
                let account_id = builder.add_identity(account_key);
                builder.insert_typed([ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat(), &0u64);
                builder.insert_typed(
                    [b"balance::".as_ref(), account_id.as_ref()].concat(),
                    &(1_000_000u128),
                );
            }

            builder.set_validators(&ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: validators.len() as u128,
                    validators,
                },
                next: None,
            });

            let timing = BlockTimingParams {
                base_interval_secs: target_block_time_secs_legacy,
                min_interval_secs: target_block_time_secs_legacy,
                max_interval_secs: target_block_time_secs_legacy.saturating_mul(4),
                target_gas_per_block,
                retarget_every_blocks: 0,
                base_interval_ms: target_block_time_ms,
                min_interval_ms: target_block_time_ms,
                max_interval_ms: target_block_time_ms.saturating_mul(4),
                ..Default::default()
            };
            builder.set_block_timing(
                &timing,
                &BlockTimingRuntime {
                    effective_interval_secs: timing.base_interval_secs,
                    effective_interval_ms: target_block_time_ms,
                    ..Default::default()
                },
            );
        })
        .with_role(0, ValidatorRole::Consensus)
        .build()
        .await?;

    spawn_benchmark_live_log_drains(&cluster);
    let benchmark_churn = spawn_benchmark_churn_collectors(&cluster);

    let run_result = async {
        let rpc_addrs = cluster
            .validators
            .iter()
            .map(|guard| guard.validator().rpc_addr.clone())
            .collect::<Vec<_>>();
        let primary_rpc_addr = rpc_addrs[0].clone();
        let primary_only = benchmark_primary_only();
        let route_to_leaders_override = benchmark_route_to_leaders_override();
        let route_to_leaders =
            route_to_leaders_override.unwrap_or_else(|| default_route_to_leaders(fast_probe, benchmark_tx_total));
        let prefer_target_height_leader = benchmark_prefer_target_height_leader();
        if route_to_leaders_override.is_none() && route_to_leaders {
            println!(
                "--- Auto-enabling leader-targeted ingress for fast probe above the clean 256 frontier (tx_total={}) ---",
                benchmark_tx_total
            );
        }
        let default_ingress_leader_fanout = default_ingress_leader_fanout(
            scenario.validators,
            benchmark_tx_total,
            benchmark_tx_select_max_bytes,
            fast_probe,
        );
        let ingress_leader_fanout = benchmark_override_usize(
            "IOI_AFT_BENCH_INGRESS_LEADER_FANOUT",
            default_ingress_leader_fanout,
        );
        let connections_per_addr = benchmark_override_usize(
            "IOI_AFT_BENCH_RPC_CONNECTIONS_PER_ADDR",
            scenario.rpc_connections_per_validator.max(1),
        );
        let align_to_next_block = std::env::var("IOI_AFT_BENCH_ALIGN_TO_NEXT_BLOCK")
            .ok()
            .map(|value| !matches!(value.as_str(), "0" | "false" | "FALSE" | "False"))
            .unwrap_or(true);
        let default_submit_lead_ms =
            default_submit_lead_ms(target_block_time_ms, fast_probe, trace_mode, benchmark_tx_total);
        if fast_probe && benchmark_tx_total > 256 {
            println!(
                "--- Auto-scaling submit lead for large fast probe: tx_total={} submit_lead_ms={} ---",
                benchmark_tx_total,
                default_submit_lead_ms
            );
        }
        let submit_lead_ms = benchmark_override_u64_allow_zero(
            "IOI_AFT_BENCH_SUBMIT_LEAD_MS",
            if align_to_next_block {
                default_submit_lead_ms.min(target_block_time_ms.saturating_sub(1))
            } else {
                default_submit_lead_ms
            },
        );
        let alignment_expected_submissions = benchmark_tx_total;
        let alignment_ingress_rpc_count = if primary_only {
            1
        } else if route_to_leaders {
            ingress_leader_fanout.max(1)
        } else {
            rpc_addrs.len().max(1)
        };
        let alignment_submit_wave_size = benchmark_override_usize(
            "IOI_AFT_BENCH_SUBMIT_WAVE_SIZE",
            default_submit_wave_size(
                alignment_expected_submissions,
                alignment_ingress_rpc_count,
                fast_probe,
            ),
        )
        .clamp(1, alignment_expected_submissions.max(1));
        let alignment_submit_wave_pause_ms = benchmark_override_u64_allow_zero(
            "IOI_AFT_BENCH_SUBMIT_WAVE_PAUSE_MS",
            default_submit_wave_pause_ms(
                target_block_time_ms,
                alignment_ingress_rpc_count,
                fast_probe,
                alignment_expected_submissions,
            ),
        );
        let alignment_safety_pad_ms = benchmark_override_u64_allow_zero(
            "IOI_AFT_BENCH_ALIGNMENT_SAFETY_PAD_MS",
            default_alignment_safety_pad_ms(
                target_block_time_ms,
                fast_probe,
                alignment_expected_submissions,
            ),
        );
        let alignment_submission_channel_count =
            alignment_ingress_rpc_count.saturating_mul(connections_per_addr).max(1);
        let alignment_submit_concurrency = benchmark_override_usize(
            "IOI_AFT_BENCH_SUBMIT_CONCURRENCY",
            default_submit_concurrency(
                alignment_expected_submissions,
                alignment_submission_channel_count,
                fast_probe,
            ),
        );
        let alignment_ingress_status_latency = sample_status_latencies(&rpc_addrs).await?;
        let alignment_estimated_submission_service_budget_ms =
            estimated_submission_service_budget_ms(
                alignment_expected_submissions,
                alignment_submit_concurrency,
                alignment_ingress_status_latency,
            );
        println!(
            "--- Alignment ingress preflight: ingress_status_p50_ms={:.2} ingress_status_p95_ms={:.2} estimated_submission_service_budget_ms={} ---",
            alignment_ingress_status_latency.p50_ms,
            alignment_ingress_status_latency.p95_ms,
            alignment_estimated_submission_service_budget_ms
        );
        let alignment_required_ready_ms = alignment_ready_budget_ms(
            submit_lead_ms,
            alignment_expected_submissions,
            alignment_submit_wave_size,
            alignment_submit_wave_pause_ms,
            alignment_estimated_submission_service_budget_ms,
            alignment_safety_pad_ms,
        );
        let mut alignment_due_ms = None;
        let mut alignment_target_height = None;
        let mut alignment_actual_start_lead_ms = submit_lead_ms;
        if align_to_next_block {
            let current_status = rpc::get_status(&primary_rpc_addr).await?;
            let authoritative_tip_block = if current_status.height > 0 {
                authoritative_tip_block_with_hint(&primary_rpc_addr, current_status.height).await?
            } else {
                None
            };
            let (alignment_height, latest_timestamp_ms) =
                if let Some(tip_block) = authoritative_tip_block.as_ref() {
                    (
                        tip_block.header.height,
                        tip_block.header.timestamp_ms_or_legacy(),
                    )
                } else if auto_future_genesis
                    && current_status.height == 0
                    && !warm_first_committed_height
                {
                    (current_status.height, benchmark_genesis_anchor_ms)
                } else if current_status.height == 0 {
                    if warm_first_committed_height {
                        println!(
                            "--- Warming benchmark past the first committed height before aligned submission (tx_total={}) ---",
                            benchmark_tx_total
                        );
                    }
                    wait_for_first_committed_tip(
                        &primary_rpc_addr,
                        current_status.height,
                        bootstrap_grace_secs,
                        target_block_time_secs_legacy,
                    )
                    .await?
                } else {
                    (
                        current_status.height,
                        current_status.latest_timestamp.saturating_mul(1_000),
                    )
                };
            if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let base_due_ms = latest_timestamp_ms.saturating_add(target_block_time_ms);
                let now_ms = now.as_millis().min(u128::from(u64::MAX)) as u64;
                let next_due_ms = select_aligned_due_ms(
                    base_due_ms,
                    now_ms,
                    target_block_time_ms,
                    alignment_required_ready_ms,
                );
                let due_at = Duration::from_millis(next_due_ms);
                let actual_start_lead_ms = alignment_start_lead_ms(
                    submit_lead_ms,
                    alignment_expected_submissions,
                    alignment_submit_wave_size,
                    alignment_submit_wave_pause_ms,
                    alignment_estimated_submission_service_budget_ms,
                );
                alignment_due_ms = Some(next_due_ms);
                alignment_target_height = Some(aligned_target_height_for_due_ms(
                    alignment_height,
                    base_due_ms,
                    next_due_ms,
                    target_block_time_ms,
                ));
                alignment_actual_start_lead_ms = actual_start_lead_ms;
                let target_start =
                    due_at.saturating_sub(Duration::from_millis(actual_start_lead_ms));
                let wait_for = target_start.saturating_sub(now);
                if !wait_for.is_zero() {
                    println!(
                        "--- Aligning submission burst to {} ms before next due block (height={}, base_due_ms={}, next_due_ms={}, actual_start_lead_ms={}, ready_budget_ms={}, wave_size={}, wave_pause_ms={}, safety_pad_ms={}) ---",
                        submit_lead_ms,
                        alignment_height,
                        base_due_ms,
                        next_due_ms,
                        actual_start_lead_ms,
                        alignment_required_ready_ms,
                        alignment_submit_wave_size,
                        alignment_submit_wave_pause_ms,
                        alignment_safety_pad_ms
                    );
                    sleep(wait_for).await;
                }
            }
        }
        let (channel_addrs, prefer_target_height_leader_submission) = if primary_only {
            (vec![primary_rpc_addr.clone()], false)
        } else if route_to_leaders {
            let current_status = rpc::get_status(&primary_rpc_addr).await?;
            let authoritative_tip_block =
                authoritative_tip_block_with_hint(&primary_rpc_addr, current_status.height).await?;
            let authoritative_tip_height = authoritative_tip_block
                .as_ref()
                .map(|tip_block| tip_block.header.height)
                .unwrap_or(current_status.height);
            if fast_probe && benchmark_tx_total > 256 && default_ingress_leader_fanout > 1 {
                println!(
                    "--- Auto-scaling leader-targeted ingress fanout for large fast probe: tx_total={} ingress_leader_fanout={} ---",
                    benchmark_tx_total,
                    default_ingress_leader_fanout
                );
            }
            let ingress_start_height = alignment_target_height
                .unwrap_or_else(|| authoritative_tip_height.saturating_add(1).max(1));
            let preferred_target_leader_rpc = if prefer_target_height_leader {
                authoritative_tip_block.as_ref().and_then(|tip_block| {
                    alignment_target_height.and_then(|target_height| {
                        leader_account_for_height(target_height, &tip_block.header.validator_set)
                            .and_then(|account_id| {
                                validator_rpc_addr_for_account_id(&cluster, account_id)
                            })
                    })
                })
            } else {
                None
            };
            let ingress_leader_rpcs = authoritative_tip_block
                .as_ref()
                .map(|tip_block| {
                    leader_accounts_from_height(
                        ingress_start_height,
                        &tip_block.header.validator_set,
                        ingress_leader_fanout,
                    )
                })
                .map(|leader_accounts| {
                    leader_accounts
                        .into_iter()
                        .filter_map(|leader_account_id| {
                            validator_rpc_addr_for_account_id(&cluster, leader_account_id)
                        })
                        .collect::<Vec<_>>()
                })
                .filter(|rpc_addrs| !rpc_addrs.is_empty())
                .unwrap_or_else(|| {
                    rpc_addrs
                        .iter()
                        .take(ingress_leader_fanout.max(1))
                        .cloned()
                        .collect::<Vec<_>>()
                });
            let ingress_leader_rpcs =
                prioritize_rpc_addr(ingress_leader_rpcs, preferred_target_leader_rpc.as_deref());

            println!(
                "--- Leader-targeted ingress RPCs (fanout={}): {} ---",
                ingress_leader_fanout,
                ingress_leader_rpcs.join(", ")
            );
            if let (Some(target_height), Some(preferred_target_leader_rpc)) =
                (alignment_target_height, preferred_target_leader_rpc.as_deref())
            {
                println!(
                    "--- Prioritizing target-height leader RPC for aligned submission: target_height={} rpc={} ---",
                    target_height,
                    preferred_target_leader_rpc
                );
            }
            (ingress_leader_rpcs, preferred_target_leader_rpc.is_some())
        } else {
            (rpc_addrs.clone(), false)
        };
        let status_channels = build_channels(&rpc_addrs, 1).await?;
        let submission_channels = build_channels(&channel_addrs, connections_per_addr).await?;
        let pre_submission_status = rpc::get_status(&primary_rpc_addr).await?;
        let pre_submission_tip_height =
            authoritative_tip_block_with_hint(&primary_rpc_addr, pre_submission_status.height)
                .await?
                .map(|tip_block| tip_block.header.height)
                .unwrap_or(pre_submission_status.height);
        let max_pre_submission_height = benchmark_override_u64(
            "IOI_AFT_BENCH_MAX_PRESUBMISSION_HEIGHT",
            if auto_future_genesis { 2 } else { u64::MAX },
        );
        if pre_submission_status.height > max_pre_submission_height {
            return Err(anyhow!(
                "benchmark startup drifted to height {} before submission (allowed <= {}). Adjust genesis/grace alignment before trusting this run.",
                pre_submission_status.height,
                max_pre_submission_height
            ));
        }
        let injection_started = Instant::now();
        let submitted_records = Arc::new(Mutex::new(Vec::new()));
        let total_expected_submissions = benchmark_tx_total;
        let submit_concurrency = benchmark_override_usize(
            "IOI_AFT_BENCH_SUBMIT_CONCURRENCY",
            default_submit_concurrency(
                total_expected_submissions,
                submission_channels.len(),
                fast_probe,
            ),
        );
        println!(
            "--- Submission fanout: ingress_rpcs={} connections_per_addr={} submission_channels={} status_channels={} submit_concurrency={} route_to_leaders={} primary_only={} ---",
            channel_addrs.len(),
            connections_per_addr,
            submission_channels.len(),
            status_channels.len(),
            submit_concurrency,
            route_to_leaders,
            primary_only
        );
        let preferred_submission_channel_span = preferred_submission_channel_span(
            prefer_target_height_leader_submission,
            connections_per_addr,
            submission_channels.len(),
        );
        println!(
            "--- Submission target leader preference: enabled={} preferred_channel_span={} ---",
            prefer_target_height_leader_submission,
            preferred_submission_channel_span
        );
        let submit_wave_size = benchmark_override_usize(
            "IOI_AFT_BENCH_SUBMIT_WAVE_SIZE",
            default_submit_wave_size(total_expected_submissions, channel_addrs.len(), fast_probe),
        )
        .clamp(1, total_expected_submissions.max(1));
        let submit_wave_pause_ms = benchmark_override_u64_allow_zero(
            "IOI_AFT_BENCH_SUBMIT_WAVE_PAUSE_MS",
            default_submit_wave_pause_ms(
                target_block_time_ms,
                channel_addrs.len(),
                fast_probe,
                total_expected_submissions,
            ),
        );
        println!(
            "--- Submission pacing: wave_size={} wave_pause_ms={} ---",
            submit_wave_size,
            submit_wave_pause_ms
        );
        let round_robin_by_tx_index = benchmark_round_robin_by_tx_index_override()
            .unwrap_or_else(|| default_round_robin_by_tx_index(fast_probe, txs_per_account));
        println!(
            "--- Submission order: round_robin_by_tx_index={} ---",
            round_robin_by_tx_index
        );
        let flattened_submissions =
            flatten_submissions(signed_account_txs, round_robin_by_tx_index);
        let total_submission_waves = flattened_submissions
            .len()
            .div_ceil(submit_wave_size.max(1));
        let submission_channels = Arc::new(submission_channels);
        let submission_schedule_started = Instant::now();

        for (wave_index, wave) in flattened_submissions
            .chunks(submit_wave_size.max(1))
            .enumerate()
        {
            let mut submission_stream = stream::iter(wave.iter().cloned())
                .map(|(account_index, tx_index, tx_bytes)| {
                    let channels = Arc::clone(&submission_channels);
                    let preferred_channel_index = account_index.saturating_add(tx_index)
                        % preferred_submission_channel_span.max(1);
                    let status_channel_index = account_index % status_channels.len().max(1);
                    async move {
                        submit_transaction_bytes(
                            channels.as_ref(),
                            preferred_channel_index,
                            status_channel_index,
                            tx_bytes,
                        )
                        .await
                    }
                })
                .buffer_unordered(submit_concurrency.min(wave.len()).max(1));

            while let Some(submitted) = submission_stream.next().await {
                let submitted = submitted?;
                let accepted_so_far = {
                    let mut submitted_records = submitted_records.lock().await;
                    submitted_records.push(submitted);
                    submitted_records.len()
                };
                if accepted_so_far % 512 == 0 || accepted_so_far >= total_expected_submissions {
                    println!(
                        "submission progress: accepted_txs={}/{} accepted_so_far={}",
                        accepted_so_far,
                        total_expected_submissions,
                        accepted_so_far
                    );
                }
            }

            if submit_wave_pause_ms > 0 && wave_index + 1 < total_submission_waves {
                let elapsed_since_schedule_start = submission_schedule_started.elapsed();
                let remaining_pause_ms = remaining_wave_pause_ms(
                    elapsed_since_schedule_start,
                    wave_index,
                    submit_wave_pause_ms,
                );
                if remaining_pause_ms > 0 {
                    println!(
                        "--- Submission wave {}/{} complete; pausing {} ms to hold paced schedule ---",
                        wave_index + 1,
                        total_submission_waves,
                        remaining_pause_ms
                    );
                    sleep(Duration::from_millis(remaining_pause_ms)).await;
                } else {
                    println!(
                        "--- Submission wave {}/{} complete; no extra pause because wave execution already consumed the paced schedule budget ---",
                        wave_index + 1,
                        total_submission_waves
                    );
                }
            }
        }
        let submitted_records = submitted_records.lock().await.clone();
        let submission = summarize_submissions(&submitted_records);
        let unique_submitted_records = canonicalize_submitted_records(&submitted_records);

        let injection_duration = injection_started.elapsed();
        let accepted = unique_submitted_records.len() as u64;
        let injection_tps = accepted as f64 / injection_duration.as_secs_f64().max(f64::EPSILON);
        println!(
            "--- Submission summary: retries={} timeout_retries={} duplicates={} submit_p50_ms={:.2} submit_p95_ms={:.2} ---",
            submission.submit_retries,
            submission.submit_timeout_retries,
            submission.submit_duplicates,
            submission.submit_latency.p50_ms,
            submission.submit_latency.p95_ms,
        );
        let submission_completed_wallclock_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok());
        let alignment_submit_complete_vs_due_ms = alignment_due_ms
            .zip(submission_completed_wallclock_ms)
            .map(|(due_ms, completed_ms)| {
                let delta_ms = i128::from(due_ms) - i128::from(completed_ms);
                delta_ms.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
            });
        println!(
            "--- Alignment outcome: requested_submit_lead_ms={} actual_start_lead_ms={} ready_budget_ms={} submit_complete_vs_due_ms={} ---",
            submit_lead_ms,
            alignment_actual_start_lead_ms,
            alignment_required_ready_ms,
            alignment_submit_complete_vs_due_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
        );
        let expected_hashes = unique_submitted_records
            .iter()
            .filter(|submitted| !submitted.chain_hash.is_empty())
            .map(|submitted| submitted.chain_hash.clone())
            .collect::<HashSet<_>>();

        let commit_timeout = Duration::from_secs(measurement_timeout_secs);
        let rpc_addrs_for_commit = rpc_addrs.clone();
        let expected_hashes_for_commit = expected_hashes.clone();
        let initial_height_for_commit = pre_submission_tip_height;
        let authoritative_commit_handle = tokio::spawn(async move {
            wait_for_committed_hashes_on_chain(
                &rpc_addrs_for_commit,
                initial_height_for_commit,
                &expected_hashes_for_commit,
                commit_timeout,
            )
            .await
        });
        let latency_sample_limit = if fast_probe {
            usize::min(LATENCY_SAMPLE_LIMIT, 32)
        } else {
            LATENCY_SAMPLE_LIMIT
        };
        let sampled_submitted_records =
            sample_submitted_records_for_latency(&unique_submitted_records, latency_sample_limit);
        let commit_poll_concurrency = usize::max(
            status_channels.len(),
            usize::min(sampled_submitted_records.len(), LATENCY_SAMPLE_LIMIT),
        );
        let commit_results = stream::iter(sampled_submitted_records.into_iter())
            .map(|submitted| {
                let channels = status_channels.clone();
                async move { poll_committed_transaction(&channels, submitted, commit_timeout).await }
            })
            .buffer_unordered(commit_poll_concurrency)
            .collect::<Vec<_>>()
            .await;

        let mut committed_records = Vec::new();
        let mut commit_failures = Vec::new();
        for result in commit_results {
            match result {
                Ok(record) => committed_records.push(record),
                Err(error) => commit_failures.push(error.to_string()),
            }
        }

        let no_sampled_commits_error = if committed_records.is_empty() {
            Some(
                commit_failures
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "unknown commit failure".to_string()),
            )
        } else {
            None
        };

        if !commit_failures.is_empty() {
            println!(
                "scenario {} observed {} sampled commit timeout/rejection(s) out of {} latency-sampled submissions",
                scenario.name,
                commit_failures.len(),
                usize::min(accepted as usize, latency_sample_limit)
            );
        }

        let (final_commit_instant, authoritative_chain_scan) =
            match authoritative_commit_handle.await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                let cluster_view = capture_cluster_commit_view(&rpc_addrs).await;
                let chain_scan = scan_committed_hashes_from_chain(
                    &rpc_addrs,
                    pre_submission_tip_height,
                    &expected_hashes,
                    Duration::from_secs(5),
                )
                .await
                .unwrap_or(ChainCommitScan {
                    committed: 0,
                    scanned_tip_height: 0,
                    committed_heights: BTreeSet::new(),
                    per_block_tx_counts: Vec::new(),
                });
                let block_tx_summary =
                    summarize_block_tx_counts(&chain_scan.per_block_tx_counts);
                let metrics_view = capture_cluster_metrics_view(&cluster).await;
                let (final_committed, final_heights, status_buckets) =
                    collect_final_transaction_statuses(
                        &status_channels,
                        &unique_submitted_records,
                    )
                        .await
                        .unwrap_or((0, BTreeSet::new(), BTreeMap::new()));
                return Err(anyhow!(
                    "{error}; cluster_view: {cluster_view}; metrics_view: {metrics_view}; final_status_scan: committed={final_committed} heights={:?} status_buckets={:?}; chain_scan: committed={} tip={} heights={:?}; block_tx_summary: {}",
                    final_heights,
                    status_buckets,
                    chain_scan.committed,
                    chain_scan.scanned_tip_height,
                    chain_scan.committed_heights,
                    block_tx_summary,
                ));
            }
            Err(join_error) => {
                return Err(anyhow!("authoritative chain-commit task join failure: {}", join_error));
            }
        };

        let (committed, committed_heights, final_status_buckets) = if fast_probe {
            (
                authoritative_chain_scan.committed.max(accepted),
                if authoritative_chain_scan.committed_heights.is_empty() {
                    let current_height = rpc::get_status(&primary_rpc_addr).await?.height;
                    std::iter::once(current_height).collect()
                } else {
                    authoritative_chain_scan.committed_heights.clone()
                },
                BTreeMap::new(),
            )
        } else {
            let (status_committed, status_committed_heights, status_buckets) =
                collect_final_transaction_statuses(&status_channels, &unique_submitted_records)
                    .await?;
            (
                authoritative_chain_scan.committed.max(status_committed),
                if authoritative_chain_scan.committed_heights.is_empty() {
                    status_committed_heights
                } else {
                    authoritative_chain_scan.committed_heights.clone()
                },
                status_buckets,
            )
        };

        if let Some(sample_failure) = no_sampled_commits_error {
            if committed == 0 {
                let cluster_view = capture_cluster_commit_view(&rpc_addrs).await;
                let metrics_view = capture_cluster_metrics_view(&cluster).await;
                let chain_scan = scan_committed_hashes_from_chain(
                    &rpc_addrs,
                    pre_submission_tip_height,
                    &expected_hashes,
                    Duration::from_secs(5),
                )
                .await
                .unwrap_or(ChainCommitScan {
                    committed: 0,
                    scanned_tip_height: 0,
                    committed_heights: BTreeSet::new(),
                    per_block_tx_counts: Vec::new(),
                });
                let block_tx_summary =
                    summarize_block_tx_counts(&chain_scan.per_block_tx_counts);
                return Err(anyhow!(
                    "no committed records observed; sample failure: {sample_failure}; cluster_view: {cluster_view}; metrics_view: {metrics_view}; final_status_scan: committed={committed} heights={:?} status_buckets={:?}; chain_scan: committed={} tip={} heights={:?}; block_tx_summary: {}",
                    committed_heights,
                    final_status_buckets,
                    chain_scan.committed,
                    chain_scan.scanned_tip_height,
                    chain_scan.committed_heights,
                    block_tx_summary,
                ));
            }
        };

        let sampled_final_commit_instant = committed_heights
            .iter()
            .next_back()
            .and_then(|highest_committed_height| {
                committed_records
                    .iter()
                    .filter(|record| record.block_height == *highest_committed_height)
                    .map(|record| record.committed_at)
                    .max()
            });
        let sampled_commit_visibility_lag_ms = sampled_commit_visibility_lag_ms(
            final_commit_instant,
            sampled_final_commit_instant,
        );
        let measured_final_commit_instant = sustained_commit_endpoint(
            fast_probe,
            final_commit_instant,
            sampled_final_commit_instant,
        );

        let sustained_tps = committed as f64
            / measured_final_commit_instant
                .duration_since(injection_started)
                .as_secs_f64()
                .max(f64::EPSILON);
        let commit_latencies = committed_records
            .iter()
            .map(|record| record.committed_at.duration_since(record.submitted_at))
            .collect::<Vec<_>>();
        let commit_latency = summarize_latencies(&commit_latencies);
        let alignment_first_committed_height = committed_heights.iter().next().copied();
        let alignment_first_committed_height_delta = alignment_target_height
            .zip(alignment_first_committed_height)
            .map(|(target_height, first_committed_height)| {
                let delta_blocks = i128::from(first_committed_height) - i128::from(target_height);
                delta_blocks.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
            });
        let alignment_committed_on_target_height =
            alignment_first_committed_height_delta.map(|delta_blocks| delta_blocks == 0);
        let (
            alignment_committed_before_target_height_txs,
            alignment_committed_at_target_height_txs,
        ) = summarize_alignment_block_packing(
            &authoritative_chain_scan.per_block_tx_counts,
            alignment_target_height,
        );
        println!(
            "--- Alignment commit outcome: target_height={} committed_on_target_height={} first_commit_height_delta={} committed_before_target_height_txs={} committed_at_target_height_txs={} ---",
            alignment_target_height
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            alignment_committed_on_target_height
                .map(|value| {
                    if value {
                        "yes".to_string()
                    } else {
                        "no".to_string()
                    }
                })
                .unwrap_or_else(|| "n/a".to_string()),
            alignment_first_committed_height_delta
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            alignment_committed_before_target_height_txs
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            alignment_committed_at_target_height_txs
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
        );
        println!(
            "--- Commit observation lag: sampled_commit_visibility_lag_ms={} sustained_endpoint={} ---",
            sampled_commit_visibility_lag_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            if fast_probe {
                "authoritative_chain_scan"
            } else {
                "sampled_status_or_authoritative_fallback"
            }
        );

        let terminal_result = if committed_heights.is_empty() || matches!(lane, AftBenchmarkLane::BaseFinal) {
            None
        } else {
            let mut earliest_commit_by_height = BTreeMap::new();
            for record in &committed_records {
                earliest_commit_by_height
                    .entry(record.block_height)
                    .and_modify(|current: &mut Instant| {
                        if record.committed_at < *current {
                            *current = record.committed_at;
                        }
                    })
                    .or_insert(record.committed_at);
            }

            let terminal_blocks = stream::iter(committed_heights.iter().copied())
                .map(|height| {
                    let rpc_addrs = rpc_addrs.clone();
                    let lane = lane;
                    async move {
                        match lane {
                            AftBenchmarkLane::BaseFinal => unreachable!("base-final lane should not wait for terminal blocks"),
                            AftBenchmarkLane::SealedFinal => {
                                wait_for_sealed_terminal_block(&rpc_addrs, height, commit_timeout)
                                    .await
                            }
                            AftBenchmarkLane::CanonicalOrdering => {
                                wait_for_canonical_ordering_terminal_block(
                                    &rpc_addrs,
                                    height,
                                    commit_timeout,
                                )
                                .await
                            }
                            AftBenchmarkLane::DurableCollapse => {
                                wait_for_durable_collapse_terminal_block(
                                    &rpc_addrs,
                                    height,
                                    commit_timeout,
                                )
                                .await
                            }
                        }
                    }
                })
                .buffer_unordered(usize::min(committed_heights.len(), 8))
                .try_collect::<Vec<_>>()
                .await?;

            let collapse_latencies = terminal_blocks
                .iter()
                .filter_map(|terminal| {
                    earliest_commit_by_height
                        .get(&terminal.height)
                        .map(|committed_at| terminal.terminal_at.duration_since(*committed_at))
                })
                .collect::<Vec<_>>();
            Some((
                summarize_latencies(&collapse_latencies),
                terminal_blocks
                    .iter()
                    .filter(|terminal| matches!(terminal.outcome, AftTerminalOutcome::Close))
                    .count(),
                terminal_blocks
                    .iter()
                    .filter(|terminal| matches!(terminal.outcome, AftTerminalOutcome::Abort))
                    .count(),
            ))
        };

        let (terminal_latency, terminal_close_blocks, terminal_abort_blocks) = terminal_result
            .map(|(latency, close_blocks, abort_blocks)| {
                (Some(latency), close_blocks, abort_blocks)
            })
            .unwrap_or((None, 0, 0));
        let churn = benchmark_churn
            .lock()
            .expect("benchmark churn tracker poisoned")
            .snapshot();
        let alignment = BenchmarkAlignmentSummary {
            requested_submit_lead_ms: submit_lead_ms,
            actual_start_lead_ms: alignment_actual_start_lead_ms,
            ready_budget_ms: alignment_required_ready_ms,
            submit_complete_vs_due_ms: alignment_submit_complete_vs_due_ms,
            target_height: alignment_target_height,
            committed_on_target_height: alignment_committed_on_target_height,
            first_committed_height_delta: alignment_first_committed_height_delta,
            committed_before_target_height_txs: alignment_committed_before_target_height_txs,
            committed_at_target_height_txs: alignment_committed_at_target_height_txs,
        };

        Ok(PaperBenchmarkResult {
            scenario: scenario.name.to_string(),
            validators: scenario.validators,
            safety_mode: format!("{:?}", scenario.safety_mode),
            lane: lane.as_str().to_string(),
            attempted: accounts.len() * txs_per_account as usize,
            accepted,
            committed,
            committed_blocks: committed_heights.len(),
            injection_tps,
            sustained_tps,
            commit_latency,
            sampled_commit_visibility_lag_ms,
            terminal_latency,
            terminal_close_blocks,
            terminal_abort_blocks,
            churn,
            submission,
            alignment,
        })
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    match (run_result, shutdown_result) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(run_error), Err(shutdown_error)) => Err(anyhow!(
            "benchmark failed: {}; cluster shutdown also failed: {}",
            run_error,
            shutdown_error
        )),
    }
}

fn benchmark_lanes_for_scenario(
    scenario: AftBenchmarkScenario,
    lane_filter: Option<AftBenchmarkLane>,
) -> Vec<AftBenchmarkLane> {
    let supported = [
        AftBenchmarkLane::BaseFinal,
        AftBenchmarkLane::CanonicalOrdering,
        AftBenchmarkLane::DurableCollapse,
        AftBenchmarkLane::SealedFinal,
    ]
    .into_iter()
    .filter(|lane| lane.supports(scenario.safety_mode))
    .collect::<Vec<_>>();

    match lane_filter {
        Some(lane) if lane.supports(scenario.safety_mode) => vec![lane],
        Some(_) => Vec::new(),
        None => supported,
    }
}

async fn run_benchmark_matrix(lane_filter: Option<AftBenchmarkLane>) -> Result<()> {
    if std::env::var_os("IOI_TEST_BUILD_PROFILE").is_none() {
        std::env::set_var("IOI_TEST_BUILD_PROFILE", "release");
    }

    if !benchmark_skip_artifact_build() {
        build_test_artifacts();
    }

    let scenario_filter = std::env::var("IOI_AFT_BENCH_SCENARIO").ok();
    let scenarios = [
        AftBenchmarkScenario::paper_guardian_majority_4v(),
        AftBenchmarkScenario::paper_guardian_majority_7v(),
        AftBenchmarkScenario::paper_asymptote_4v(),
        AftBenchmarkScenario::paper_asymptote_7v(),
    ]
    .into_iter()
    .filter(|scenario| {
        scenario_filter
            .as_deref()
            .map(|selected| selected == scenario.name)
            .unwrap_or(true)
    })
    .collect::<Vec<_>>();

    let mut results = Vec::new();
    for scenario in scenarios {
        for lane in benchmark_lanes_for_scenario(scenario, lane_filter) {
            results.push(run_scenario(scenario, lane).await?);
        }
    }

    println!("\n--- AFT Paper Benchmark Matrix ---");
    println!("{}", render_markdown_table(&results));

    Ok(())
}

#[test]
fn parse_prepare_block_metrics_extracts_churn_fields() {
    let line = "[BENCH-EXEC] prepare_block height=10 tx_count=212 replay_mode=fallback_sequential replay_gate=parallel_execution_error_fallback nonce_chain_edges=0 replay_debt=5128 validation_aborts=4972 validation_errors=0 validation_rewinds=156 execution_errors=2926 snapshot_ms=29 parallel_exec_ms=114 fallback_exec_ms=5 overlay_ms=0 collect_results_ms=0 roots_ms=0 total_ms=149";
    let metrics = parse_prepare_block_metrics(line).expect("parse benchmark metrics");

    assert_eq!(metrics.height, 10);
    assert_eq!(metrics.replay_mode, "fallback_sequential");
    assert_eq!(metrics.replay_debt, 5128);
    assert_eq!(metrics.validation_aborts, 4972);
    assert_eq!(metrics.execution_errors, 2926);
}

#[test]
fn benchmark_churn_tracker_counts_unique_fallback_heights() {
    let mut tracker = BenchmarkChurnTracker::default();
    tracker.observe(&PrepareBlockMetrics {
        height: 10,
        replay_mode: "fallback_sequential".to_string(),
        replay_debt: 9,
        validation_aborts: 8,
        execution_errors: 7,
    });
    tracker.observe(&PrepareBlockMetrics {
        height: 10,
        replay_mode: "fallback_sequential".to_string(),
        replay_debt: 4,
        validation_aborts: 3,
        execution_errors: 2,
    });
    tracker.observe(&PrepareBlockMetrics {
        height: 11,
        replay_mode: "parallel".to_string(),
        replay_debt: 12,
        validation_aborts: 1,
        execution_errors: 5,
    });

    let summary = tracker.snapshot();
    assert_eq!(summary.fallback_blocks, 1);
    assert_eq!(summary.max_replay_debt, 12);
    assert_eq!(summary.max_validation_aborts, 8);
    assert_eq!(summary.max_execution_errors, 7);
}

#[test]
fn default_submit_concurrency_caps_fast_probe_depth_per_channel() {
    assert_eq!(default_submit_concurrency(16, 64, true), 16);
    assert_eq!(default_submit_concurrency(256, 64, true), 256);
    assert_eq!(default_submit_concurrency(512, 64, true), 256);
    assert_eq!(default_submit_concurrency(512, 96, true), 256);
    assert_eq!(default_submit_concurrency(512, 64, false), 512);
}

#[test]
fn default_submit_wave_size_only_splits_large_fast_probes() {
    assert_eq!(default_submit_wave_size(128, 1, true), 128);
    assert_eq!(default_submit_wave_size(256, 2, true), 256);
    assert_eq!(default_submit_wave_size(512, 1, true), 128);
    assert_eq!(default_submit_wave_size(512, 2, true), 128);
    assert_eq!(default_submit_wave_size(1_024, 4, true), 256);
    assert_eq!(default_submit_wave_size(512, 2, false), 512);
}

#[test]
fn default_submit_wave_pause_ms_only_applies_to_large_fast_probes() {
    assert_eq!(default_submit_wave_pause_ms(1_000, 1, true, 128), 0);
    assert_eq!(default_submit_wave_pause_ms(1_000, 1, true, 512), 63);
    assert_eq!(default_submit_wave_pause_ms(1_000, 2, true, 512), 32);
    assert_eq!(default_submit_wave_pause_ms(1_000, 4, true, 1_024), 16);
    assert_eq!(default_submit_wave_pause_ms(1_000, 2, false, 512), 0);
}

#[test]
fn default_alignment_safety_pad_ms_only_applies_to_large_fast_probes() {
    assert_eq!(default_alignment_safety_pad_ms(1_000, true, 128), 0);
    assert_eq!(default_alignment_safety_pad_ms(1_000, true, 512), 100);
    assert_eq!(default_alignment_safety_pad_ms(400, true, 512), 50);
    assert_eq!(default_alignment_safety_pad_ms(1_000, false, 512), 0);
}

#[test]
fn alignment_ready_budget_ms_includes_wave_pause_and_safety_pad() {
    assert_eq!(alignment_ready_budget_ms(250, 1_024, 256, 8, 80, 100), 454);
    assert_eq!(alignment_ready_budget_ms(50, 128, 128, 0, 0, 0), 50);
}

#[test]
fn remaining_wave_pause_ms_only_sleeps_until_the_scheduled_wave_deadline() {
    assert_eq!(remaining_wave_pause_ms(Duration::from_millis(0), 0, 8), 8);
    assert_eq!(remaining_wave_pause_ms(Duration::from_millis(8), 0, 8), 0);
    assert_eq!(remaining_wave_pause_ms(Duration::from_millis(20), 0, 8), 0);
    assert_eq!(remaining_wave_pause_ms(Duration::from_millis(10), 1, 8), 6);
}

#[test]
fn alignment_start_lead_ms_accounts_for_wave_pause_without_safety_pad() {
    assert_eq!(alignment_start_lead_ms(250, 1_024, 256, 8, 80), 354);
    assert_eq!(alignment_start_lead_ms(250, 128, 128, 0, 0), 250);
}

#[test]
fn select_aligned_due_ms_skips_tight_due_slots() {
    assert_eq!(select_aligned_due_ms(1_000, 500, 1_000, 374), 1_000);
    assert_eq!(select_aligned_due_ms(1_000, 700, 1_000, 374), 2_000);
}

#[test]
fn aligned_target_height_for_due_ms_tracks_skipped_slots() {
    assert_eq!(aligned_target_height_for_due_ms(0, 1_000, 1_000, 1_000), 1);
    assert_eq!(aligned_target_height_for_due_ms(1, 2_000, 4_000, 1_000), 4);
}

#[test]
fn leader_account_for_height_tracks_validator_rotation() {
    let validator_ids = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]];
    assert_eq!(
        leader_account_for_height(1, &validator_ids),
        Some(AccountId([1u8; 32]))
    );
    assert_eq!(
        leader_account_for_height(2, &validator_ids),
        Some(AccountId([2u8; 32]))
    );
    assert_eq!(
        leader_account_for_height(4, &validator_ids),
        Some(AccountId([1u8; 32]))
    );
}

#[test]
fn prioritize_rpc_addr_moves_the_target_to_the_front() {
    let rpc_addrs = vec![
        "127.0.0.1:20101".to_string(),
        "127.0.0.1:20201".to_string(),
        "127.0.0.1:20301".to_string(),
    ];
    assert_eq!(
        prioritize_rpc_addr(rpc_addrs.clone(), Some("127.0.0.1:20201")),
        vec![
            "127.0.0.1:20201".to_string(),
            "127.0.0.1:20101".to_string(),
            "127.0.0.1:20301".to_string(),
        ]
    );
    assert_eq!(
        prioritize_rpc_addr(rpc_addrs.clone(), Some("127.0.0.1:20101")),
        rpc_addrs
    );
}

#[test]
fn preferred_submission_channel_span_limits_first_attempts_to_the_target_leader_bucket() {
    assert_eq!(preferred_submission_channel_span(true, 48, 96), 48);
    assert_eq!(preferred_submission_channel_span(true, 48, 24), 24);
    assert_eq!(preferred_submission_channel_span(false, 48, 96), 96);
}

#[test]
fn estimated_submission_service_budget_scales_with_rounds_and_observed_rtt() {
    assert_eq!(
        estimated_submission_service_budget_ms(
            1_024,
            256,
            LatencySummary {
                p95_ms: 5.2,
                ..LatencySummary::default()
            }
        ),
        24
    );
    assert_eq!(
        estimated_submission_service_budget_ms(
            128,
            256,
            LatencySummary {
                p95_ms: 0.4,
                ..LatencySummary::default()
            }
        ),
        1
    );
}

#[test]
fn summarize_alignment_block_packing_counts_target_and_preceding_matches() {
    assert_eq!(
        summarize_alignment_block_packing(&[(2, 64), (3, 192), (4, 32)], Some(3)),
        (Some(64), Some(192))
    );
    assert_eq!(
        summarize_alignment_block_packing(&[(3, 192), (4, 32)], Some(2)),
        (Some(0), Some(0))
    );
    assert_eq!(
        summarize_alignment_block_packing(&[(2, 64), (3, 192)], None),
        (None, None)
    );
}

#[test]
fn sampled_commit_visibility_lag_ms_tracks_signed_visibility_drift() {
    let start = Instant::now();
    assert_eq!(
        sampled_commit_visibility_lag_ms(start, Some(start + Duration::from_millis(37))),
        Some(37)
    );
    assert_eq!(
        sampled_commit_visibility_lag_ms(start, Some(start - Duration::from_millis(12))),
        Some(-12)
    );
    assert_eq!(sampled_commit_visibility_lag_ms(start, None), None);
}

#[test]
fn sustained_commit_endpoint_prefers_authoritative_scan_for_fast_probes() {
    let authoritative = Instant::now();
    let sampled = authoritative + Duration::from_millis(125);
    assert_eq!(
        sustained_commit_endpoint(true, authoritative, Some(sampled)),
        authoritative
    );
    assert_eq!(
        sustained_commit_endpoint(false, authoritative, Some(sampled)),
        sampled
    );
    assert_eq!(
        sustained_commit_endpoint(false, authoritative, None),
        authoritative
    );
}

#[test]
fn summarize_submissions_counts_retries_timeouts_and_duplicates() {
    let now = Instant::now();
    let summary = summarize_submissions(&[
        SubmittedTx {
            tx_hash: "tx-a".to_string(),
            chain_hash: "chain-a".to_string(),
            submitted_at: now,
            admitted_at: now + Duration::from_millis(12),
            status_channel_index: 0,
            submit_retries: 3,
            submit_timeout_retries: 2,
            duplicate_response: false,
        },
        SubmittedTx {
            tx_hash: String::new(),
            chain_hash: String::new(),
            submitted_at: now,
            admitted_at: now + Duration::from_millis(48),
            status_channel_index: 1,
            submit_retries: 1,
            submit_timeout_retries: 0,
            duplicate_response: true,
        },
    ]);

    assert_eq!(summary.submit_retries, 4);
    assert_eq!(summary.submit_timeout_retries, 2);
    assert_eq!(summary.submit_duplicates, 1);
    assert_eq!(summary.submit_latency.p50_ms, 48.0);
    assert_eq!(summary.submit_latency.p95_ms, 48.0);
}

#[test]
fn default_route_to_leaders_auto_enables_only_for_large_fast_probes() {
    assert!(!default_route_to_leaders(false, 512));
    assert!(!default_route_to_leaders(true, 256));
    assert!(default_route_to_leaders(true, 257));
}

#[test]
fn default_round_robin_by_tx_index_only_enables_for_multi_tx_fast_probes() {
    assert!(!default_round_robin_by_tx_index(false, 2));
    assert!(!default_round_robin_by_tx_index(true, 1));
    assert!(default_round_robin_by_tx_index(true, 2));
}

#[test]
fn flatten_submissions_round_robins_by_tx_index_when_enabled() {
    let flattened = flatten_submissions(
        vec![
            vec![vec![10], vec![11]],
            vec![vec![20], vec![21]],
            vec![vec![30]],
        ],
        true,
    );

    assert_eq!(
        flattened,
        vec![
            (0, 0, vec![10]),
            (1, 0, vec![20]),
            (2, 0, vec![30]),
            (0, 1, vec![11]),
            (1, 1, vec![21]),
        ]
    );
}

#[test]
fn flatten_submissions_preserves_account_major_order_when_disabled() {
    let flattened = flatten_submissions(
        vec![vec![vec![10], vec![11]], vec![vec![20], vec![21]]],
        false,
    );

    assert_eq!(
        flattened,
        vec![
            (0, 0, vec![10]),
            (0, 1, vec![11]),
            (1, 0, vec![20]),
            (1, 1, vec![21]),
        ]
    );
}

#[test]
fn default_ingress_leader_fanout_scales_up_only_for_large_fast_probes() {
    assert_eq!(
        default_ingress_leader_fanout(4, 256, 8 * 1024 * 1024, true),
        1
    );
    assert_eq!(
        default_ingress_leader_fanout(4, 512, 8 * 1024 * 1024, true),
        2
    );
    assert_eq!(
        default_ingress_leader_fanout(4, 1_024, 8 * 1024 * 1024, true),
        4
    );
    assert_eq!(
        default_ingress_leader_fanout(4, 512, 8 * 1024 * 1024, false),
        1
    );
    assert_eq!(
        default_ingress_leader_fanout(4, 16_384, 8 * 1024 * 1024, false),
        2
    );
}

#[test]
fn default_submit_lead_ms_scales_up_only_for_large_fast_probes() {
    assert_eq!(default_submit_lead_ms(1_000, true, false, 128), 50);
    assert_eq!(default_submit_lead_ms(1_000, true, false, 512), 250);
    assert_eq!(default_submit_lead_ms(1_000, false, true, 512), 75);
    assert_eq!(default_submit_lead_ms(1_000, false, false, 512), 250);
}

#[test]
fn default_warm_first_committed_height_only_applies_to_large_fast_auto_future_genesis_probes() {
    assert!(default_warm_first_committed_height(true, true, 512));
    assert!(!default_warm_first_committed_height(true, true, 256));
    assert!(!default_warm_first_committed_height(true, false, 512));
    assert!(!default_warm_first_committed_height(false, true, 512));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs the paper-grade AFT throughput benchmark matrix"]
async fn test_aft_paper_benchmark_matrix() -> Result<()> {
    run_benchmark_matrix(benchmark_lane_filter()).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs the base-final AFT throughput benchmark matrix"]
async fn test_aft_base_final_benchmark_matrix() -> Result<()> {
    run_benchmark_matrix(Some(AftBenchmarkLane::BaseFinal)).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs the canonical-ordering AFT throughput benchmark matrix"]
async fn test_aft_canonical_ordering_benchmark_matrix() -> Result<()> {
    run_benchmark_matrix(Some(AftBenchmarkLane::CanonicalOrdering)).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs the durable-collapse AFT throughput benchmark matrix"]
async fn test_aft_durable_collapse_benchmark_matrix() -> Result<()> {
    run_benchmark_matrix(Some(AftBenchmarkLane::DurableCollapse)).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs the sealed-final AFT throughput benchmark matrix"]
async fn test_aft_sealed_final_benchmark_matrix() -> Result<()> {
    run_benchmark_matrix(Some(AftBenchmarkLane::SealedFinal)).await
}
