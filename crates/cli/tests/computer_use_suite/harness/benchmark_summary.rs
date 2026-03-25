use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::benchmark_trace;
use crate::computer_use_suite::types::{AgentBackend, ComputerUseCaseResult, ComputerUseMode};

#[derive(Clone)]
pub(super) struct PublishedCaseSummary {
    pub suite: String,
    pub case_id: String,
    pub env_id: String,
    pub case_dir: PathBuf,
    pub summary_json_path: PathBuf,
    pub summary_markdown_path: PathBuf,
    pub diagnostic_json_path: Option<PathBuf>,
    pub diagnostic_markdown_path: Option<PathBuf>,
    pub inference_calls_path: Option<PathBuf>,
    pub inference_trace_path: Option<PathBuf>,
    pub bridge_state_path: Option<PathBuf>,
    pub trace_bundle_path: PathBuf,
    pub trace_analysis_path: PathBuf,
}

#[derive(Serialize)]
struct BenchmarkCaseSummary<'a> {
    case_id: &'a str,
    env_id: &'a str,
    suite: &'a str,
    mode: &'a str,
    task_set: &'a str,
    run_id: &'a str,
    generated_at_ms: u64,
    summary: Value,
    findings: Vec<String>,
    timing: Value,
    links: Value,
}

pub(super) fn publish_case_summary(
    result: &ComputerUseCaseResult,
    mode: ComputerUseMode,
    run_id: &str,
) -> Result<PublishedCaseSummary> {
    let case_dir = PathBuf::from(&result.artifacts.artifact_root);
    fs::create_dir_all(&case_dir).with_context(|| {
        format!(
            "create benchmark summary artifact dir {}",
            case_dir.display()
        )
    })?;

    let suite = infer_suite(&result.case_id).to_string();
    let diagnostic_json_path = path_from_option(result.artifacts.json_report_path.as_ref());
    let diagnostic_markdown_path =
        path_from_option(result.artifacts.markdown_summary_path.as_ref());
    let inference_calls_path = path_from_option(result.artifacts.inference_calls_path.as_ref());
    let inference_trace_path = path_from_option(result.artifacts.inference_trace_path.as_ref());
    let bridge_state_path = path_from_option(result.artifacts.bridge_state_path.as_ref());
    let diagnostic = read_json(diagnostic_json_path.as_deref())?;
    let phase_timing = diagnostic
        .as_ref()
        .and_then(|value| value.get("phase_timing"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut summary = diagnostic
        .as_ref()
        .and_then(|value| value.get("summary"))
        .cloned()
        .unwrap_or_else(|| fallback_summary(result));
    enrich_case_outcome_summary(&mut summary, result);
    let findings = diagnostic
        .as_ref()
        .and_then(|value| value.get("findings"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| fallback_findings(result));

    let summary_json_path = case_dir.join("benchmark_summary.json");
    let summary_markdown_path = case_dir.join("benchmark_summary.md");
    let payload = BenchmarkCaseSummary {
        case_id: &result.case_id,
        env_id: &result.env_id,
        suite: &suite,
        mode: mode.as_str(),
        task_set: result.task_set.as_str(),
        run_id,
        generated_at_ms: now_ms(),
        summary,
        findings: findings.clone(),
        timing: phase_timing,
        links: json!({
            "case_dir": case_dir,
            "diagnostic_json": diagnostic_json_path.as_ref().map(|path| path.to_string_lossy()),
            "diagnostic_markdown": diagnostic_markdown_path.as_ref().map(|path| path.to_string_lossy()),
            "inference_calls": inference_calls_path.as_ref().map(|path| path.to_string_lossy()),
            "inference_trace": inference_trace_path.as_ref().map(|path| path.to_string_lossy()),
            "bridge_state": bridge_state_path.as_ref().map(|path| path.to_string_lossy()),
        }),
    };

    write_json(&summary_json_path, &payload)?;
    write_markdown(
        &summary_markdown_path,
        &suite,
        run_id,
        &payload.summary,
        &payload.findings,
    )?;
    let published_trace = benchmark_trace::publish_case_trace(
        result,
        &suite,
        run_id,
        &case_dir,
        &payload.summary,
        &payload.findings,
        diagnostic.as_ref(),
        &summary_json_path,
        &summary_markdown_path,
        diagnostic_json_path.as_deref(),
        diagnostic_markdown_path.as_deref(),
        inference_calls_path.as_deref(),
        inference_trace_path.as_deref(),
        bridge_state_path.as_deref(),
    )?;

    Ok(PublishedCaseSummary {
        suite,
        case_id: result.case_id.clone(),
        env_id: result.env_id.clone(),
        case_dir,
        summary_json_path,
        summary_markdown_path,
        diagnostic_json_path,
        diagnostic_markdown_path,
        inference_calls_path,
        inference_trace_path,
        bridge_state_path,
        trace_bundle_path: published_trace.trace_bundle_path,
        trace_analysis_path: published_trace.trace_analysis_path,
    })
}

fn infer_suite(case_id: &str) -> &'static str {
    if case_id.starts_with("miniwob_") {
        "MiniWoB++"
    } else if case_id.starts_with("osworld_") {
        "OSWorld"
    } else if case_id.starts_with("workarena_") {
        "WorkArena"
    } else {
        "Unknown"
    }
}

fn fallback_summary(result: &ComputerUseCaseResult) -> Value {
    json!({
        "env_id": result.env_id,
        "backend": result.agent_backend.map(AgentBackend::as_str),
        "provider_calls": 0,
        "reward": result.final_reward,
        "raw_reward": result.bridge_state.info.raw_reward,
        "terminated": result.terminated,
        "truncated": result.truncated,
        "episode_step": result.bridge_state.episode_step,
        "final_trigger": result.bridge_state.info.trigger,
        "query_text": result.bridge_state.info.query_text.clone().unwrap_or_else(|| result.utterance.clone()),
        "elapsed_ms": result.elapsed_ms,
        "failure_class": result.failure_class,
        "mode": match result.mode {
            ComputerUseMode::Oracle => "oracle",
            ComputerUseMode::Runtime => "runtime",
            ComputerUseMode::Agent => "agent",
        },
    })
}

fn enrich_case_outcome_summary(summary: &mut Value, result: &ComputerUseCaseResult) {
    let effective_reward = result
        .bridge_state
        .info
        .raw_reward
        .unwrap_or(result.final_reward);
    let reward_floor_met =
        super::reward_meets_floor(effective_reward, result.expected_reward_floor);
    let result_label = if reward_floor_met {
        "pass"
    } else if effective_reward > 0.0 {
        "near-miss"
    } else {
        "red"
    };

    let Some(summary_object) = summary.as_object_mut() else {
        *summary = fallback_summary(result);
        return enrich_case_outcome_summary(summary, result);
    };
    summary_object.insert(
        "expected_reward_floor".to_string(),
        json!(result.expected_reward_floor),
    );
    summary_object.insert("effective_reward".to_string(), json!(effective_reward));
    summary_object.insert("reward_floor_met".to_string(), json!(reward_floor_met));
    summary_object.insert("result_label".to_string(), json!(result_label));
}

fn fallback_findings(result: &ComputerUseCaseResult) -> Vec<String> {
    let mut findings = Vec::new();
    let effective_reward = result
        .bridge_state
        .info
        .raw_reward
        .unwrap_or(result.final_reward);
    if let Some(failure_class) = &result.failure_class {
        findings.push(format!("failure_class: {}", failure_class));
    }
    if !result.terminated {
        findings.push("run ended without a terminal benchmark state".to_string());
    }
    if !super::reward_meets_floor(effective_reward, result.expected_reward_floor) {
        findings.push(format!(
            "effective reward {:.3} stayed below floor {:.3}",
            effective_reward, result.expected_reward_floor
        ));
    }
    if result.tool_steps.is_empty() {
        findings.push("no tool steps were recorded".to_string());
    }
    findings
}

fn read_json(path: Option<&Path>) -> Result<Option<Value>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read benchmark summary source {}", path.display()))?;
    Ok(Some(serde_json::from_str(&raw).with_context(|| {
        format!("parse benchmark summary source {}", path.display())
    })?))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("write benchmark summary json {}", path.display()))
}

fn write_markdown(
    path: &Path,
    suite: &str,
    run_id: &str,
    summary: &Value,
    findings: &[String],
) -> Result<()> {
    let reward = summary
        .get("reward")
        .and_then(Value::as_f64)
        .unwrap_or_default();
    let provider_calls = summary
        .get("provider_calls")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let query = summary
        .get("query_text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let markdown = format!(
        "# Benchmark Summary\n\n- suite: `{suite}`\n- run: `{run_id}`\n- reward: `{reward:.3}`\n- provider_calls: `{provider_calls}`\n- query: `{query}`\n\n## Findings\n{}\n",
        findings
            .iter()
            .map(|finding| format!("- {}", finding))
            .collect::<Vec<_>>()
            .join("\n")
    );
    fs::write(path, markdown)
        .with_context(|| format!("write benchmark summary markdown {}", path.display()))
}

fn path_from_option(path: Option<&String>) -> Option<PathBuf> {
    path.map(PathBuf::from)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
