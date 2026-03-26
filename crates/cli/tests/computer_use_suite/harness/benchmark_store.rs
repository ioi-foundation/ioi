use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::benchmark_refresh::{self, RefreshMode};
use super::benchmark_summary::{publish_case_summary, PublishedCaseSummary};
use super::support::repo_root;
use crate::computer_use_suite::types::{
    AgentBackend, ComputerUseCase, ComputerUseCaseResult, ComputerUseMode, SuiteConfig, TaskSet,
};

const STORE_VERSION: u32 = 3;
const RUN_WINDOW_LIMIT: usize = 12;

#[derive(Serialize, Deserialize, Default)]
struct BenchmarkStore {
    version: u32,
    updated_at_ms: u64,
    runs: Vec<BenchmarkRunRecord>,
}

#[derive(Serialize, Deserialize)]
struct BenchmarkRunRecord {
    run_id: String,
    mode: String,
    task_set: String,
    artifact_root: String,
    updated_at_ms: u64,
    #[serde(default = "default_run_status")]
    status: String,
    #[serde(default)]
    active_case_id: Option<String>,
    #[serde(default)]
    total_cases: usize,
    #[serde(default)]
    completed_cases: usize,
    cases: Vec<BenchmarkCaseRecord>,
}

#[derive(Serialize, Deserialize)]
struct BenchmarkCaseRecord {
    suite: String,
    case_id: String,
    env_id: String,
    case_dir: String,
    summary_json_path: String,
    summary_markdown_path: String,
    diagnostic_json_path: Option<String>,
    diagnostic_markdown_path: Option<String>,
    inference_calls_path: Option<String>,
    inference_trace_path: Option<String>,
    bridge_state_path: Option<String>,
    trace_bundle_path: Option<String>,
    trace_analysis_path: Option<String>,
}

struct RunProgress<'a> {
    status: &'static str,
    active_case_id: Option<&'a str>,
    total_cases: usize,
    completed_cases: usize,
}

impl<'a> RunProgress<'a> {
    fn running(
        active_case_id: Option<&'a str>,
        total_cases: usize,
        completed_cases: usize,
    ) -> Self {
        Self {
            status: "running",
            active_case_id,
            total_cases,
            completed_cases,
        }
    }

    fn completed(total_cases: usize, completed_cases: usize) -> Self {
        Self {
            status: "completed",
            active_case_id: None,
            total_cases,
            completed_cases,
        }
    }
}

pub(super) fn publish_live_run_started(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    task_set: TaskSet,
    cases: &[ComputerUseCase],
) -> Result<()> {
    if !live_publish_enabled(config, mode) {
        return Ok(());
    }

    merge_published_cases_into_store(
        config,
        mode,
        task_set,
        &[],
        RunProgress::running(cases.first().map(|case| case.id.as_str()), cases.len(), 0),
        RefreshMode::StoreOnly,
    )
}

pub(super) fn publish_live_case_started(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    task_set: TaskSet,
    case: &ComputerUseCase,
    completed_cases: usize,
    total_cases: usize,
) -> Result<()> {
    if !live_publish_enabled(config, mode) {
        return Ok(());
    }

    merge_published_cases_into_store(
        config,
        mode,
        task_set,
        &[],
        RunProgress::running(Some(case.id.as_str()), total_cases, completed_cases),
        RefreshMode::StoreOnly,
    )
}

pub(super) fn publish_live_run(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    task_set: TaskSet,
    results: &[ComputerUseCaseResult],
) -> Result<()> {
    if !live_publish_enabled(config, mode) {
        return Ok(());
    }

    let mut published_cases = Vec::new();
    for result in results.iter().filter(is_live_result) {
        published_cases.push(publish_case_summary(
            result,
            mode,
            &run_id_for_artifact_root(&config.artifact_root),
        )?);
    }

    if published_cases.is_empty() {
        return Ok(());
    }

    merge_published_cases_into_store(
        config,
        mode,
        task_set,
        &published_cases,
        RunProgress::completed(results.len(), published_cases.len()),
        RefreshMode::FullBlocking,
    )
}

pub(super) fn publish_live_case(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    task_set: TaskSet,
    result: &ComputerUseCaseResult,
    completed_cases: usize,
    total_cases: usize,
) -> Result<()> {
    if !live_publish_enabled(config, mode) || !is_live_result(&result) {
        return Ok(());
    }

    let published_case = publish_case_summary(
        result,
        mode,
        &run_id_for_artifact_root(&config.artifact_root),
    )?;
    let progress = if completed_cases >= total_cases {
        RunProgress::completed(total_cases, completed_cases)
    } else {
        RunProgress::running(None, total_cases, completed_cases)
    };
    merge_published_cases_into_store(
        config,
        mode,
        task_set,
        &[published_case],
        progress,
        RefreshMode::StoreOnly,
    )
}

fn is_live_result(result: &&ComputerUseCaseResult) -> bool {
    result.mode == ComputerUseMode::Agent && result.agent_backend == Some(AgentBackend::LiveHttp)
}

fn live_publish_enabled(config: &SuiteConfig, mode: ComputerUseMode) -> bool {
    mode == ComputerUseMode::Agent && config.agent_backend == AgentBackend::LiveHttp
}

fn read_store(path: &PathBuf) -> Result<BenchmarkStore> {
    if !path.exists() {
        return Ok(BenchmarkStore::default());
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("read benchmark store {}", path.display()))?;
    let mut store: BenchmarkStore = serde_json::from_str(&raw)
        .with_context(|| format!("parse benchmark store {}", path.display()))?;
    if store.version == 0 {
        store.version = STORE_VERSION;
    }
    Ok(store)
}

fn merge_published_cases_into_store(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    task_set: TaskSet,
    published_cases: &[PublishedCaseSummary],
    progress: RunProgress<'_>,
    refresh_mode: RefreshMode,
) -> Result<()> {
    let store_paths = benchmark_store_paths();
    let store_path = store_paths
        .first()
        .cloned()
        .context("benchmark store path is not configured")?;
    if let Some(parent) = store_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create benchmark store dir {}", parent.display()))?;
    }

    let mut store = read_store(&store_path)?;
    let run_id = run_id_for_artifact_root(&config.artifact_root);
    let updated_at_ms = now_ms();
    store.version = STORE_VERSION;
    store.updated_at_ms = updated_at_ms;

    if let Some(existing_run) = store.runs.iter_mut().find(|run| run.run_id == run_id) {
        existing_run.mode = mode.as_str().to_string();
        existing_run.task_set = task_set.as_str().to_string();
        existing_run.artifact_root = config.artifact_root.to_string_lossy().to_string();
        existing_run.updated_at_ms = updated_at_ms;
        existing_run.status = progress.status.to_string();
        existing_run.active_case_id = progress.active_case_id.map(str::to_string);
        existing_run.total_cases = progress.total_cases;
        existing_run.completed_cases = progress.completed_cases;
        for published_case in published_cases {
            let case_record = to_case_record(published_case);
            existing_run
                .cases
                .retain(|case| case.case_id != published_case.case_id);
            existing_run.cases.push(case_record);
        }
    } else {
        store.runs.push(BenchmarkRunRecord {
            run_id,
            mode: mode.as_str().to_string(),
            task_set: task_set.as_str().to_string(),
            artifact_root: config.artifact_root.to_string_lossy().to_string(),
            updated_at_ms,
            status: progress.status.to_string(),
            active_case_id: progress.active_case_id.map(str::to_string),
            total_cases: progress.total_cases,
            completed_cases: progress.completed_cases,
            cases: published_cases
                .iter()
                .map(to_case_record)
                .collect::<Vec<_>>(),
        });
    }

    store.runs.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| right.run_id.cmp(&left.run_id))
    });
    store.runs.truncate(RUN_WINDOW_LIMIT);

    for store_path in &store_paths {
        write_json_atomically(store_path, &store)?;
    }
    benchmark_refresh::request_generated_data_refresh(refresh_mode)?;
    Ok(())
}

fn benchmark_store_paths() -> Vec<PathBuf> {
    let root = repo_root();
    vec![
        root.join("apps")
            .join("benchmarks")
            .join("src")
            .join("generated")
            .join("benchmark-store.json"),
        root.join("apps")
            .join("benchmarks")
            .join("public")
            .join("generated")
            .join("benchmark-store.json"),
    ]
}

fn write_json_atomically(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("benchmark store has no parent {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create benchmark store dir {}", parent.display()))?;

    let temp_path = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .unwrap_or("benchmark-store.json"),
        std::process::id(),
        now_ms()
    ));
    fs::write(&temp_path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("write benchmark store temp {}", temp_path.display()))?;
    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "replace benchmark store {} from {}",
            path.display(),
            temp_path.display()
        )
    })?;
    Ok(())
}

fn to_case_record(case: &PublishedCaseSummary) -> BenchmarkCaseRecord {
    BenchmarkCaseRecord {
        suite: case.suite.clone(),
        case_id: case.case_id.clone(),
        env_id: case.env_id.clone(),
        case_dir: case.case_dir.to_string_lossy().to_string(),
        summary_json_path: case.summary_json_path.to_string_lossy().to_string(),
        summary_markdown_path: case.summary_markdown_path.to_string_lossy().to_string(),
        diagnostic_json_path: case
            .diagnostic_json_path
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
        diagnostic_markdown_path: case
            .diagnostic_markdown_path
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
        inference_calls_path: case
            .inference_calls_path
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
        inference_trace_path: case
            .inference_trace_path
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
        bridge_state_path: case
            .bridge_state_path
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
        trace_bundle_path: Some(case.trace_bundle_path.to_string_lossy().to_string()),
        trace_analysis_path: Some(case.trace_analysis_path.to_string_lossy().to_string()),
    }
}

fn run_id_for_artifact_root(artifact_root: &PathBuf) -> String {
    artifact_root
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "run-local".to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn default_run_status() -> String {
    "completed".to_string()
}
