#![cfg(all(
    feature = "consensus-aft",
    feature = "vm-wasm",
    any(feature = "state-iavl", feature = "state-jellyfish")
))]

use super::support::{
    create_transfer_tx, generate_accounts, render_markdown_table, summarize_latencies,
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
    let binaries_present = ["orchestration", "workload", "guardian"]
        .iter()
        .all(|bin| node_binary_dir.join(bin).exists());
    if binaries_present && !rebuild_node_binary {
        return Ok(());
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
    status_channel_index: usize,
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
    for rpc_addr in rpc_addrs {
        for _ in 0..per_validator {
            channels.push(
                Channel::from_shared(format!("http://{}", rpc_addr))?
                    .connect()
                    .await?,
            );
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

fn benchmark_route_to_leaders() -> bool {
    std::env::var("IOI_AFT_BENCH_ROUTE_TO_LEADERS")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
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

fn leader_account_for_next_height(
    local_height: u64,
    validator_ids: &[Vec<u8>],
) -> Option<AccountId> {
    if validator_ids.is_empty() {
        return None;
    }

    let next_height = local_height.saturating_add(1).max(1);
    let leader_index = ((next_height - 1) % validator_ids.len() as u64) as usize;
    let leader_bytes: [u8; 32] = validator_ids
        .get(leader_index)?
        .as_slice()
        .try_into()
        .ok()?;
    Some(AccountId(leader_bytes))
}

fn leader_accounts_for_upcoming_heights(
    local_height: u64,
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
    for offset in 1..=steps {
        let target_height = local_height.saturating_add(offset as u64).max(1);
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

async fn submit_account_sequence(
    channels: Arc<Vec<Channel>>,
    preferred_channel_index: usize,
    status_channel_index: usize,
    txs: Vec<Vec<u8>>,
) -> Result<Vec<SubmittedTx>> {
    let mut submitted = Vec::with_capacity(txs.len());
    let submit_timeout = Duration::from_millis(benchmark_override_u64(
        "IOI_AFT_BENCH_SUBMIT_TIMEOUT_MS",
        DEFAULT_SUBMIT_TIMEOUT_MS,
    ));

    for tx_bytes in txs {
        let chain_hash = codec::from_bytes_canonical::<ChainTransaction>(&tx_bytes)
            .ok()
            .and_then(|tx| tx.hash().ok())
            .map(hex::encode)
            .unwrap_or_default();
        let mut retries = 0usize;
        loop {
            let channel_index = if channels.is_empty() {
                0
            } else {
                preferred_channel_index.saturating_add(retries) % channels.len()
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
                    if retries > MAX_RETRIES {
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
                        if retries > MAX_RETRIES {
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
                        submitted.push(SubmittedTx {
                            tx_hash: String::new(),
                            chain_hash: String::new(),
                            submitted_at: submit_started,
                            status_channel_index,
                        });
                        break;
                    }

                    return Err(anyhow!(
                        "submit failed: code={}, message={}",
                        status.code(),
                        message
                    ));
                }
                Ok(Ok(response)) => {
                    let tx_hash = response.into_inner().tx_hash;
                    submitted.push(SubmittedTx {
                        tx_hash,
                        chain_hash: chain_hash.clone(),
                        submitted_at: submit_started,
                        status_channel_index,
                    });
                    break;
                }
            }
        }
    }

    Ok(submitted)
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

async fn select_highest_tip_rpc<'a>(rpc_addrs: &'a [String]) -> Result<(&'a str, u64)> {
    let mut best: Option<(&'a str, u64)> = None;
    let mut last_error = None;

    for rpc_addr in rpc_addrs {
        match rpc::get_status(rpc_addr).await {
            Ok(status) => {
                let height = status.height;
                let rpc_addr = rpc_addr.as_str();
                if best
                    .map(|(_, best_height)| height > best_height)
                    .unwrap_or(true)
                {
                    best = Some((rpc_addr, height));
                }
            }
            Err(error) => last_error = Some(error),
        }
    }

    best.ok_or_else(|| {
        anyhow!(
            "failed to fetch status from any benchmark rpc endpoint{}",
            last_error
                .map(|error| format!(": {error}"))
                .unwrap_or_default()
        )
    })
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
        let (_scan_rpc_addr, tip_height) = select_highest_tip_rpc(rpc_addrs).await?;

        while next_height <= tip_height {
            match get_block_by_height_any_rpc(rpc_addrs, next_height).await? {
                Some(block) => {
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
                    next_height = next_height.saturating_add(1);
                    last_scanned_tip = tip_height;
                }
                None => break,
            }
        }

        if last_progress_log.elapsed() >= Duration::from_secs(5) {
            println!(
                "chain scan progress: tip={} committed={}/{} scanned_blocks={}",
                tip_height,
                seen_hashes.len(),
                expected_hashes.len(),
                per_block_tx_counts.len()
            );
            last_progress_log = Instant::now();
        }

        if seen_hashes.len() >= expected_hashes.len() {
            return Ok(ChainCommitScan {
                committed: seen_hashes.len() as u64,
                scanned_tip_height: tip_height,
                committed_heights,
                per_block_tx_counts,
            });
        }

        if Instant::now() >= deadline {
            return Ok(ChainCommitScan {
                committed: seen_hashes.len() as u64,
                scanned_tip_height: last_scanned_tip.max(tip_height),
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
        let (_scan_rpc_addr, tip_height) = select_highest_tip_rpc(rpc_addrs).await?;

        while next_height <= tip_height {
            match get_block_by_height_any_rpc(rpc_addrs, next_height).await? {
                Some(block) => {
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
                    next_height = next_height.saturating_add(1);
                    last_scanned_tip = tip_height;
                }
                None => break,
            }
        }

        if last_progress_log.elapsed() >= Duration::from_secs(5) {
            println!(
                "chain commit progress: tip={} committed={}/{} scanned_blocks={}",
                tip_height,
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
                    scanned_tip_height: tip_height,
                    committed_heights,
                    per_block_tx_counts,
                },
            ));
        }

        if Instant::now() >= deadline {
            return Err(anyhow!(
                "timeout waiting for {} committed transaction hashes; observed {} before deadline (tip={} scanned_tip={})",
                expected_hashes.len(),
                seen_hashes.len(),
                tip_height,
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
    let fast_admit_limit = benchmark_tx_total
        .saturating_add(target_batch / 2)
        .clamp(1_024, 65_536);
    let default_kick_debounce_ms = if benchmark_tx_total >= 8_192 {
        150
    } else if benchmark_tx_total >= 4_096 {
        100
    } else {
        25
    };
    let adaptive_view_timeout_ms = benchmark_override_u64(
        "IOI_AFT_BENCH_VIEW_TIMEOUT_MS",
        target_block_time_ms.saturating_mul(4).clamp(500, 2_000),
    );
    let trace_mode = benchmark_trace_enabled();
    let startup_buffer_secs = benchmark_override_u64(
        "IOI_AFT_BENCH_STARTUP_BUFFER_SECS",
        if trace_mode || fast_probe {
            std::cmp::max(3, scenario.validators as u64)
        } else {
            std::cmp::max(5, scenario.validators as u64 * 2)
        },
    );
    let bootstrap_grace_secs = benchmark_override_u64(
        "IOI_AFT_BOOTSTRAP_GRACE_SECS",
        if trace_mode || fast_probe {
            startup_buffer_secs
                .saturating_add(target_block_time_secs_legacy.max(1))
                .max(5)
        } else {
            startup_buffer_secs.saturating_add(target_block_time_secs_legacy.saturating_mul(2))
        },
    );
    let mut benchmark_env = ScopedEnv::new();
    if benchmark_trace_enabled() && std::env::var_os("IOI_AFT_BENCH_TRACE_DIR").is_none() {
        let trace_dir = std::env::temp_dir().join(format!(
            "ioi-aft-bench-trace-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_millis())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&trace_dir)?;
        println!("--- Benchmark trace dir: {} ---", trace_dir.display());
        benchmark_env.set("IOI_AFT_BENCH_TRACE_DIR", trace_dir.to_string_lossy().to_string());
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
        env_or_default(
            "IOI_RPC_FAST_ADMIT_MAX_MEMPOOL",
            fast_admit_limit.to_string(),
        ),
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
            "0",
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

    let cluster = TestCluster::builder()
        .with_validators(scenario.validators)
        .with_consensus_type("Aft")
        .with_state_tree(&state_tree)
        .with_chain_id(chain_id)
        .with_aft_safety_mode(scenario.safety_mode)
        .with_epoch_size(100_000)
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

    let run_result = async {
        let rpc_addrs = cluster
            .validators
            .iter()
            .map(|guard| guard.validator().rpc_addr.clone())
            .collect::<Vec<_>>();
        let primary_rpc_addr = rpc_addrs[0].clone();
        let primary_only = benchmark_primary_only();
        let route_to_leaders = benchmark_route_to_leaders();
        let align_to_next_block = std::env::var("IOI_AFT_BENCH_ALIGN_TO_NEXT_BLOCK")
            .ok()
            .map(|value| !matches!(value.as_str(), "0" | "false" | "FALSE" | "False"))
            .unwrap_or(!(trace_mode || fast_probe));
        let submit_lead_ms =
            benchmark_override_u64_allow_zero("IOI_AFT_BENCH_SUBMIT_LEAD_MS", 0);
        if align_to_next_block {
            let current_status = rpc::get_status(&primary_rpc_addr).await?;
            let refreshed_status = if auto_future_genesis && current_status.height == 0 {
                current_status
            } else {
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs())
                    .unwrap_or_default();
                let alignment_timeout_secs = if current_status.height == 0 {
                    current_status
                        .latest_timestamp
                        .saturating_sub(now_secs)
                        .saturating_add(bootstrap_grace_secs)
                        .saturating_add(target_block_time_secs_legacy.saturating_mul(4).max(4))
                        .max(bootstrap_grace_secs.saturating_add(4))
                } else {
                    current_status
                        .latest_timestamp
                        .saturating_sub(now_secs)
                        .saturating_add(target_block_time_secs_legacy.saturating_mul(3))
                        .max(target_block_time_secs_legacy.saturating_mul(3).max(3))
                };
                let alignment_result = wait_for_next_height(
                    &primary_rpc_addr,
                    current_status.height,
                    Duration::from_secs(alignment_timeout_secs),
                )
                .await;
                if let Err(error) = alignment_result {
                    if current_status.height == 0 {
                        return Err(anyhow!(
                            "failed to observe the first committed height before submission: {error}"
                        ));
                    }
                    println!(
                        "alignment warning: failed to observe next height before submission (height={}, error={}); continuing benchmark",
                        current_status.height, error
                    );
                }
                rpc::get_status(&primary_rpc_addr).await?
            };
            if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let latest_timestamp_ms = if refreshed_status.height == 0 {
                    benchmark_genesis_anchor_ms
                } else {
                    refreshed_status.latest_timestamp.saturating_mul(1_000)
                };
                let next_due_ms = latest_timestamp_ms.saturating_add(target_block_time_ms);
                let due_at = Duration::from_millis(next_due_ms);
                let lead = Duration::from_millis(submit_lead_ms);
                let target_start = due_at.saturating_sub(lead);
                let wait_for = target_start.saturating_sub(now);
                if !wait_for.is_zero() {
                    println!(
                        "--- Aligning submission burst to {} ms before next due block (height={}, next_due_ms={}) ---",
                        submit_lead_ms,
                        refreshed_status.height,
                        next_due_ms
                    );
                    sleep(wait_for).await;
                }
            }
        }
        let channel_addrs = if primary_only {
            vec![primary_rpc_addr.clone()]
        } else if route_to_leaders {
            let current_status = rpc::get_status(&primary_rpc_addr).await?;
            let approx_tx_capacity_per_leader =
                usize::max((benchmark_tx_select_max_bytes / 1_024) as usize, 1);
            let default_ingress_leader_fanout = usize::min(
                scenario.validators.max(1),
                usize::max(
                    1,
                    benchmark_tx_total.div_ceil(approx_tx_capacity_per_leader),
                ),
            );
            let ingress_leader_fanout = benchmark_override_usize(
                "IOI_AFT_BENCH_INGRESS_LEADER_FANOUT",
                default_ingress_leader_fanout,
            );
            let ingress_leader_rpcs = rpc::get_block_by_height_resilient(
                &primary_rpc_addr,
                current_status.height,
            )
            .await?
            .map(|tip_block| {
                leader_accounts_for_upcoming_heights(
                    current_status.height,
                    &tip_block.header.validator_set,
                    ingress_leader_fanout,
                )
            })
            .map(|leader_accounts| {
                leader_accounts
                    .into_iter()
                    .filter_map(|leader_account_id| {
                        cluster.validators.iter().find_map(|guard| {
                            let public_key = guard.validator().keypair.public().encode_protobuf();
                            let account_id = account_id_from_key_material(
                                SignatureSuite::ED25519,
                                &public_key,
                            )
                            .ok()
                            .map(AccountId)?;
                            (account_id == leader_account_id)
                                .then(|| guard.validator().rpc_addr.clone())
                        })
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

            println!(
                "--- Leader-targeted ingress RPCs: {} ---",
                ingress_leader_rpcs.join(", ")
            );
            ingress_leader_rpcs
        } else {
            rpc_addrs.clone()
        };
        let pre_submission_status = rpc::get_status(&primary_rpc_addr).await?;
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
        let connections_per_addr = scenario.rpc_connections_per_validator.max(1);
        let status_channels = build_channels(&rpc_addrs, 1).await?;
        let submission_channels = build_channels(&channel_addrs, connections_per_addr).await?;
        let injection_started = Instant::now();
        let submitted_records = Arc::new(Mutex::new(Vec::new()));
        let total_accounts = signed_account_txs.len();
        let submit_concurrency = benchmark_override_usize(
            "IOI_AFT_BENCH_SUBMIT_CONCURRENCY",
            usize::min(
                total_accounts.max(1),
                usize::max(submission_channels.len().saturating_mul(8), 128),
            ),
        );
        let submission_channels = Arc::new(submission_channels);
        let mut submission_stream = stream::iter(
            signed_account_txs
                .into_iter()
                .enumerate()
                .map(|(index, txs)| (index, txs)),
        )
        .map(|(index, txs)| {
            let channels = Arc::clone(&submission_channels);
            let preferred_channel_index = index % channels.len().max(1);
            let status_channel_index = index % status_channels.len().max(1);
            async move {
                submit_account_sequence(
                    channels,
                    preferred_channel_index,
                    status_channel_index,
                    txs,
                )
                .await
            }
        })
        .buffer_unordered(submit_concurrency);

        while let Some(batch) = submission_stream.next().await {
            let mut batch = batch?;
            let accepted_so_far = {
                let mut submitted_records = submitted_records.lock().await;
                submitted_records.append(&mut batch);
                submitted_records.len()
            };
            if accepted_so_far % 512 == 0 || accepted_so_far >= total_accounts {
                println!(
                    "submission progress: accepted_accounts={}/{} accepted_so_far={}",
                    accepted_so_far,
                    total_accounts,
                    accepted_so_far
                );
            }
        }
        let submitted_records = submitted_records.lock().await.clone();
        let unique_submitted_records = canonicalize_submitted_records(&submitted_records);

        let injection_duration = injection_started.elapsed();
        let accepted = unique_submitted_records.len() as u64;
        let injection_tps = accepted as f64 / injection_duration.as_secs_f64().max(f64::EPSILON);
        let expected_hashes = unique_submitted_records
            .iter()
            .filter(|submitted| !submitted.chain_hash.is_empty())
            .map(|submitted| submitted.chain_hash.clone())
            .collect::<HashSet<_>>();

        let commit_timeout = Duration::from_secs(measurement_timeout_secs);
        let rpc_addrs_for_commit = rpc_addrs.clone();
        let expected_hashes_for_commit = expected_hashes.clone();
        let initial_height_for_commit = pre_submission_status.height;
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
                    pre_submission_status.height,
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
                    pre_submission_status.height,
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

        let sustained_tps = committed as f64
            / final_commit_instant
                .duration_since(injection_started)
                .as_secs_f64()
                .max(f64::EPSILON);
        let commit_latencies = committed_records
            .iter()
            .map(|record| record.committed_at.duration_since(record.submitted_at))
            .collect::<Vec<_>>();
        let commit_latency = summarize_latencies(&commit_latencies);

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
            terminal_latency,
            terminal_close_blocks,
            terminal_abort_blocks,
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
