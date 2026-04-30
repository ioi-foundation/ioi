use super::support::{
    create_transfer_tx, generate_accounts, render_markdown_table, summarize_latencies,
    BenchmarkAlignmentSummary, BenchmarkChurnSummary, BenchmarkSubmissionSummary, LatencySummary,
    PaperBenchmarkResult, BACKOFF_MS, BLOCK_TIME_MS, MAX_RETRIES,
};
use anyhow::{anyhow, Result};
use futures_util::stream::{self, StreamExt, TryStreamExt};
use ioi_cli::testing::{
    build::{test_node_binary_dir, test_node_target_dir},
    build_test_artifacts, rpc, TestCluster,
};
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

    let node_target_dir = test_node_target_dir(&build_profile, &features);
    let node_binary_dir = test_node_binary_dir(&build_profile, &features);
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
    cmd.env("CARGO_TARGET_DIR", &node_target_dir);
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
