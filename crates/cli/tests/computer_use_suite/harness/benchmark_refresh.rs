use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use super::benchmark_trace;
use super::repo_root;

const STORE_VERSION: u32 = 3;

#[derive(Clone, Copy)]
pub(super) enum RefreshMode {
    Background,
    Blocking,
}

#[derive(Default)]
struct RefreshState {
    running: bool,
    pending: bool,
}

struct RefreshScheduler {
    state: Mutex<RefreshState>,
    cv: Condvar,
}

fn refresh_scheduler() -> Arc<RefreshScheduler> {
    static SCHEDULER: OnceLock<Arc<RefreshScheduler>> = OnceLock::new();
    SCHEDULER
        .get_or_init(|| {
            Arc::new(RefreshScheduler {
                state: Mutex::new(RefreshState::default()),
                cv: Condvar::new(),
            })
        })
        .clone()
}

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

pub(super) fn request_generated_data_refresh(mode: RefreshMode) -> Result<()> {
    match mode {
        RefreshMode::Background => schedule_background_refresh(),
        RefreshMode::Blocking => run_blocking_refresh(),
    }
}

fn schedule_background_refresh() -> Result<()> {
    let scheduler = refresh_scheduler();
    let should_spawn = {
        let mut state = scheduler
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("benchmark refresh scheduler mutex poisoned"))?;
        state.pending = true;
        if state.running {
            false
        } else {
            state.running = true;
            true
        }
    };

    if should_spawn {
        let scheduler = scheduler.clone();
        thread::spawn(move || {
            if let Err(err) = drain_refresh_requests(&scheduler) {
                eprintln!("warning: benchmark data refresh failed: {err:#}");
            }
        });
    }

    Ok(())
}

fn run_blocking_refresh() -> Result<()> {
    let scheduler = refresh_scheduler();
    loop {
        let should_run = {
            let mut state = scheduler
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("benchmark refresh scheduler mutex poisoned"))?;
            state.pending = true;
            if state.running {
                while state.running {
                    state = scheduler.cv.wait(state).map_err(|_| {
                        anyhow::anyhow!("benchmark refresh scheduler mutex poisoned")
                    })?;
                }
            }
            if state.pending {
                state.running = true;
                true
            } else {
                false
            }
        };

        if !should_run {
            return Ok(());
        }

        drain_refresh_requests(&scheduler)?;
    }
}

fn drain_refresh_requests(scheduler: &RefreshScheduler) -> Result<()> {
    loop {
        {
            let mut state = scheduler
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("benchmark refresh scheduler mutex poisoned"))?;
            state.pending = false;
        }

        let result = refresh_generated_data_once();

        let mut state = scheduler
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("benchmark refresh scheduler mutex poisoned"))?;
        if state.pending {
            drop(state);
            result?;
            continue;
        }
        state.running = false;
        scheduler.cv.notify_all();
        drop(state);
        result?;
        return Ok(());
    }
}

fn refresh_generated_data_once() -> Result<()> {
    let repo_root = repo_root();
    backfill_retained_case_traces(&repo_root)?;

    let package_path = repo_root.join("apps/benchmarks/package.json");
    if !package_path.exists() {
        return Ok(());
    }

    let output = match Command::new("npm")
        .args(["run", "generate:data", "--workspace=apps/benchmarks"])
        .current_dir(&repo_root)
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            eprintln!(
                "warning: benchmark data refresh skipped: failed to launch npm: {}",
                err
            );
            return Ok(());
        }
    };

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "warning: benchmark data refresh failed:\nstdout:\n{}\nstderr:\n{}",
        stdout.trim(),
        stderr.trim()
    );
    Ok(())
}

fn backfill_retained_case_traces(repo_root: &Path) -> Result<()> {
    let store_path = benchmark_store_path(repo_root);
    if !store_path.exists() {
        return Ok(());
    }

    let mut store = read_store(&store_path)?;
    let mut store_changed = store.version != STORE_VERSION;
    store.version = STORE_VERSION;

    for run in &mut store.runs {
        for case in &mut run.cases {
            if normalize_case_paths(case, repo_root) {
                store_changed = true;
            }

            let summary_json_path = resolve_workspace_path(repo_root, &case.summary_json_path);
            let published_trace =
                match benchmark_trace::publish_case_trace_from_summary_artifact(&summary_json_path)
                {
                    Ok(Some(published)) => published,
                    Ok(None) => continue,
                    Err(err) => {
                        eprintln!(
                            "warning: benchmark trace backfill skipped for {}: {}",
                            summary_json_path.display(),
                            err
                        );
                        continue;
                    }
                };

            let trace_bundle_path =
                relativize_repo_path(repo_root, &published_trace.trace_bundle_path);
            let trace_analysis_path =
                relativize_repo_path(repo_root, &published_trace.trace_analysis_path);

            if case.trace_bundle_path.as_deref() != Some(trace_bundle_path.as_str()) {
                case.trace_bundle_path = Some(trace_bundle_path);
                store_changed = true;
            }
            if case.trace_analysis_path.as_deref() != Some(trace_analysis_path.as_str()) {
                case.trace_analysis_path = Some(trace_analysis_path);
                store_changed = true;
            }
        }
    }

    if !store_changed {
        return Ok(());
    }

    store.updated_at_ms = now_ms();
    write_store(&store_path, &store)
}

fn benchmark_store_path(repo_root: &Path) -> PathBuf {
    repo_root
        .join("apps")
        .join("benchmarks")
        .join("src")
        .join("generated")
        .join("benchmark-store.json")
}

fn read_store(path: &Path) -> Result<BenchmarkStore> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read benchmark store {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse benchmark store {}", path.display()))
}

fn write_store(path: &Path, store: &BenchmarkStore) -> Result<()> {
    write_json_atomically(path, store)
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
    })
}

fn normalize_case_paths(case: &mut BenchmarkCaseRecord, repo_root: &Path) -> bool {
    let mut changed = false;

    changed |= normalize_path_field(&mut case.case_dir, repo_root);
    changed |= normalize_path_field(&mut case.summary_json_path, repo_root);
    changed |= normalize_path_field(&mut case.summary_markdown_path, repo_root);
    changed |= normalize_optional_path_field(&mut case.diagnostic_json_path, repo_root);
    changed |= normalize_optional_path_field(&mut case.diagnostic_markdown_path, repo_root);
    changed |= normalize_optional_path_field(&mut case.inference_calls_path, repo_root);
    changed |= normalize_optional_path_field(&mut case.inference_trace_path, repo_root);
    changed |= normalize_optional_path_field(&mut case.bridge_state_path, repo_root);
    changed |= normalize_optional_path_field(&mut case.trace_bundle_path, repo_root);
    changed |= normalize_optional_path_field(&mut case.trace_analysis_path, repo_root);

    changed
}

fn normalize_path_field(value: &mut String, repo_root: &Path) -> bool {
    let resolved = resolve_workspace_path(repo_root, value);
    let normalized = relativize_repo_path(repo_root, &resolved);
    if *value != normalized {
        *value = normalized;
        true
    } else {
        false
    }
}

fn normalize_optional_path_field(value: &mut Option<String>, repo_root: &Path) -> bool {
    let Some(current) = value.as_ref() else {
        return false;
    };
    let resolved = resolve_workspace_path(repo_root, current);
    let normalized = relativize_repo_path(repo_root, &resolved);
    if current != &normalized {
        *value = Some(normalized);
        true
    } else {
        false
    }
}

fn resolve_workspace_path(repo_root: &Path, path: &str) -> PathBuf {
    let raw = PathBuf::from(path);
    if raw.is_absolute() {
        return raw;
    }

    let repo_candidate = repo_root.join(&raw);
    if repo_candidate.exists() {
        return repo_candidate;
    }

    let cli_candidate = repo_root.join("crates").join("cli").join(&raw);
    if cli_candidate.exists() {
        return cli_candidate;
    }

    if raw
        .components()
        .next()
        .is_some_and(|component| component.as_os_str() == "target")
    {
        cli_candidate
    } else {
        repo_candidate
    }
}

fn relativize_repo_path(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_refresh_backfills_trace_artifacts() -> Result<()> {
        let repo_root = repo_root();
        let store_path = benchmark_store_path(&repo_root);
        if !store_path.exists() {
            return Ok(());
        }

        backfill_retained_case_traces(&repo_root)?;

        let store = read_store(&store_path)?;
        assert!(store.version >= STORE_VERSION);

        for run in &store.runs {
            for case in &run.cases {
                let summary_path = resolve_workspace_path(&repo_root, &case.summary_json_path);
                if !summary_path.exists() {
                    continue;
                }

                let trace_bundle_path = case
                    .trace_bundle_path
                    .as_deref()
                    .map(|path| resolve_workspace_path(&repo_root, path))
                    .context("trace bundle path should be populated after backfill")?;
                let trace_analysis_path = case
                    .trace_analysis_path
                    .as_deref()
                    .map(|path| resolve_workspace_path(&repo_root, path))
                    .context("trace analysis path should be populated after backfill")?;

                assert!(
                    trace_bundle_path.exists(),
                    "expected trace bundle at {}",
                    trace_bundle_path.display()
                );
                assert!(
                    trace_analysis_path.exists(),
                    "expected trace analysis at {}",
                    trace_analysis_path.display()
                );
            }
        }

        Ok(())
    }
}
