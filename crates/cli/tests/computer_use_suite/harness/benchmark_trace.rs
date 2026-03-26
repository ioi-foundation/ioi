use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::support::repo_root;
use crate::computer_use_suite::types::ComputerUseCaseResult;

const TRACE_BUNDLE_VERSION: u32 = 1;
const TRACE_ANALYSIS_VERSION: u32 = 1;
const REWARD_FLOOR_EPSILON: f64 = 1e-4;

pub(super) struct PublishedCaseTrace {
    pub trace_bundle_path: PathBuf,
    pub trace_analysis_path: PathBuf,
}

#[derive(Deserialize)]
struct PersistedBenchmarkCaseSummary {
    case_id: String,
    env_id: String,
    suite: String,
    run_id: String,
    summary: Value,
    findings: Vec<String>,
    links: PersistedBenchmarkCaseLinks,
}

#[derive(Deserialize, Default)]
struct PersistedBenchmarkCaseLinks {
    case_dir: Option<String>,
    diagnostic_json: Option<String>,
    diagnostic_markdown: Option<String>,
    inference_calls: Option<String>,
    inference_trace: Option<String>,
    bridge_state: Option<String>,
}

#[derive(Serialize)]
struct TraceBundle {
    version: u32,
    trace_id: String,
    run_id: String,
    case_id: String,
    env_id: String,
    suite: String,
    generated_at_ms: u64,
    summary: Value,
    findings: Vec<String>,
    source_artifacts: Value,
    spans: Vec<TraceSpan>,
    bookmarks: Vec<TraceBookmark>,
}

#[derive(Serialize, Clone)]
struct TraceSpan {
    id: String,
    lane: String,
    parent_span_id: Option<String>,
    step_index: Option<u32>,
    capability_tags: Vec<String>,
    ts_start_ms: Option<u64>,
    ts_end_ms: Option<u64>,
    duration_ms: Option<u64>,
    status: String,
    summary: String,
    attributes: Value,
    artifact_refs: Vec<String>,
}

#[derive(Serialize, Clone)]
struct TraceBookmark {
    id: String,
    label: String,
    span_id: String,
    kind: String,
}

#[derive(Serialize)]
struct TraceAnalysis {
    version: u32,
    trace_id: String,
    run_id: String,
    case_id: String,
    generated_at_ms: u64,
    metrics: Vec<TraceMetric>,
    findings: Vec<String>,
    bookmarks: Vec<TraceBookmark>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TraceMetric {
    metric_id: String,
    label: String,
    status: String,
    summary: String,
    supporting_span_ids: Vec<String>,
    supporting_artifacts: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn publish_case_trace(
    result: &ComputerUseCaseResult,
    suite: &str,
    run_id: &str,
    case_dir: &Path,
    summary: &Value,
    findings: &[String],
    diagnostic: Option<&Value>,
    benchmark_summary_json_path: &Path,
    benchmark_summary_markdown_path: &Path,
    diagnostic_json_path: Option<&Path>,
    diagnostic_markdown_path: Option<&Path>,
    inference_calls_path: Option<&Path>,
    inference_trace_path: Option<&Path>,
    bridge_state_path: Option<&Path>,
) -> Result<PublishedCaseTrace> {
    publish_case_trace_payload(
        &result.case_id,
        &result.env_id,
        suite,
        run_id,
        case_dir,
        summary,
        findings,
        diagnostic,
        benchmark_summary_json_path,
        benchmark_summary_markdown_path,
        diagnostic_json_path,
        diagnostic_markdown_path,
        inference_calls_path,
        inference_trace_path,
        bridge_state_path,
    )
}

pub(super) fn publish_case_trace_from_summary_artifact(
    summary_json_path: &Path,
) -> Result<Option<PublishedCaseTrace>> {
    if !summary_json_path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(summary_json_path).with_context(|| {
        format!(
            "read persisted benchmark summary {}",
            summary_json_path.display()
        )
    })?;
    let persisted: PersistedBenchmarkCaseSummary =
        serde_json::from_str(&raw).with_context(|| {
            format!(
                "parse persisted benchmark summary {}",
                summary_json_path.display()
            )
        })?;

    let case_dir = persisted
        .links
        .case_dir
        .as_deref()
        .map(resolve_workspace_path_str)
        .unwrap_or_else(|| {
            summary_json_path
                .parent()
                .unwrap_or(summary_json_path)
                .to_path_buf()
        });
    let benchmark_summary_markdown_path = summary_json_path
        .parent()
        .unwrap_or(summary_json_path)
        .join("benchmark_summary.md");
    let diagnostic_json_path = persisted
        .links
        .diagnostic_json
        .as_deref()
        .map(resolve_workspace_path_str);
    let diagnostic_markdown_path = persisted
        .links
        .diagnostic_markdown
        .as_deref()
        .map(resolve_workspace_path_str);
    let inference_calls_path = persisted
        .links
        .inference_calls
        .as_deref()
        .map(resolve_workspace_path_str);
    let inference_trace_path = persisted
        .links
        .inference_trace
        .as_deref()
        .map(resolve_workspace_path_str);
    let bridge_state_path = persisted
        .links
        .bridge_state
        .as_deref()
        .map(resolve_workspace_path_str);
    let diagnostic = read_json_file(diagnostic_json_path.as_deref())?;

    Ok(Some(publish_case_trace_payload(
        &persisted.case_id,
        &persisted.env_id,
        &persisted.suite,
        &persisted.run_id,
        &case_dir,
        &persisted.summary,
        &persisted.findings,
        diagnostic.as_ref(),
        summary_json_path,
        &benchmark_summary_markdown_path,
        diagnostic_json_path.as_deref(),
        diagnostic_markdown_path.as_deref(),
        inference_calls_path.as_deref(),
        inference_trace_path.as_deref(),
        bridge_state_path.as_deref(),
    )?))
}

#[allow(clippy::too_many_arguments)]
fn publish_case_trace_payload(
    case_id: &str,
    env_id: &str,
    suite: &str,
    run_id: &str,
    case_dir: &Path,
    summary: &Value,
    findings: &[String],
    diagnostic: Option<&Value>,
    benchmark_summary_json_path: &Path,
    benchmark_summary_markdown_path: &Path,
    diagnostic_json_path: Option<&Path>,
    diagnostic_markdown_path: Option<&Path>,
    inference_calls_path: Option<&Path>,
    inference_trace_path: Option<&Path>,
    bridge_state_path: Option<&Path>,
) -> Result<PublishedCaseTrace> {
    let case_dir = resolve_workspace_path(case_dir);
    let benchmark_summary_json_path = resolve_workspace_path(benchmark_summary_json_path);
    let benchmark_summary_markdown_path = resolve_workspace_path(benchmark_summary_markdown_path);
    let diagnostic_json_path = diagnostic_json_path.map(resolve_workspace_path);
    let diagnostic_markdown_path = diagnostic_markdown_path.map(resolve_workspace_path);
    let inference_calls_path = inference_calls_path.map(resolve_workspace_path);
    let inference_trace_path = inference_trace_path.map(resolve_workspace_path);
    let bridge_state_path = bridge_state_path.map(resolve_workspace_path);

    fs::create_dir_all(&case_dir)
        .with_context(|| format!("create trace case dir {}", case_dir.display()))?;

    let trace_id = format!("{run_id}:{case_id}");
    let source_artifacts = json!({
        "case_dir": display_workspace_path(&case_dir),
        "benchmark_summary_json": display_workspace_path(&benchmark_summary_json_path),
        "benchmark_summary_markdown": display_workspace_path(&benchmark_summary_markdown_path),
        "diagnostic_json": diagnostic_json_path.as_deref().map(display_workspace_path),
        "diagnostic_markdown": diagnostic_markdown_path.as_deref().map(display_workspace_path),
        "inference_calls": inference_calls_path.as_deref().map(display_workspace_path),
        "inference_trace": inference_trace_path.as_deref().map(display_workspace_path),
        "bridge_state": bridge_state_path.as_deref().map(display_workspace_path),
    });

    let spans = build_spans(diagnostic, &source_artifacts, summary, findings);
    let bookmarks = build_bookmarks(&spans);
    let metrics = build_metrics(summary, diagnostic, &spans, &source_artifacts);

    let trace_bundle_path = case_dir.join("trace_bundle.json");
    let trace_analysis_path = case_dir.join("trace_analysis.json");
    write_json(
        &trace_bundle_path,
        &TraceBundle {
            version: TRACE_BUNDLE_VERSION,
            trace_id: trace_id.clone(),
            run_id: run_id.to_string(),
            case_id: case_id.to_string(),
            env_id: env_id.to_string(),
            suite: suite.to_string(),
            generated_at_ms: now_ms(),
            summary: summary.clone(),
            findings: findings.to_vec(),
            source_artifacts: source_artifacts.clone(),
            spans: spans.clone(),
            bookmarks: bookmarks.clone(),
        },
    )?;
    write_json(
        &trace_analysis_path,
        &TraceAnalysis {
            version: TRACE_ANALYSIS_VERSION,
            trace_id,
            run_id: run_id.to_string(),
            case_id: case_id.to_string(),
            generated_at_ms: now_ms(),
            metrics,
            findings: findings.to_vec(),
            bookmarks,
        },
    )?;

    Ok(PublishedCaseTrace {
        trace_bundle_path,
        trace_analysis_path,
    })
}

fn build_spans(
    diagnostic: Option<&Value>,
    source_artifacts: &Value,
    summary: &Value,
    findings: &[String],
) -> Vec<TraceSpan> {
    let case_refs = artifact_refs(
        source_artifacts,
        &["benchmark_summary_json", "diagnostic_json"],
    );
    let mut spans = Vec::new();
    let phase_timing = diagnostic
        .and_then(|value| value.get("phase_timing"))
        .and_then(Value::as_object);
    let case_start = phase_timing
        .and_then(|timing| timing.get("browser_launch_started_at_ms"))
        .and_then(Value::as_u64)
        .or_else(|| {
            phase_timing
                .and_then(|timing| timing.get("bootstrap_sync_ms"))
                .and_then(Value::as_u64)
        });
    let case_end = phase_timing
        .and_then(|timing| timing.get("case_finished_at_ms"))
        .and_then(Value::as_u64);
    spans.push(trace_span(
        "case",
        "case",
        None,
        None,
        vec!["overall_case_outcome".to_string()],
        case_start,
        case_end,
        trace_status_from_summary(summary),
        summary_line(summary, findings),
        json!({}),
        case_refs,
    ));

    for (id, label, lane, tags, start_key, end_key) in [
        (
            "phase:browser_launch",
            "Browser launch",
            "runtime",
            &["startup_latency"][..],
            "browser_launch_started_at_ms",
            "browser_launch_finished_at_ms",
        ),
        (
            "phase:browser_navigation",
            "Browser navigation",
            "browser",
            &["bridge_sync_observability"][..],
            "browser_navigation_started_at_ms",
            "browser_navigation_finished_at_ms",
        ),
        (
            "phase:agent_start_service",
            "Agent start service",
            "executor",
            &["execution_runtime"][..],
            "agent_start_service_started_at_ms",
            "agent_start_service_finished_at_ms",
        ),
        (
            "phase:first_step_service",
            "First step service",
            "executor",
            &["execution_runtime"][..],
            "first_step_service_started_at_ms",
            "first_step_service_finished_at_ms",
        ),
        (
            "phase:first_inference",
            "First inference",
            "inference",
            &["planning_contract"][..],
            "first_inference_started_at_ms",
            "first_inference_finished_at_ms",
        ),
    ] {
        if let Some(span) = phase_span(
            id,
            label,
            lane,
            &tags,
            phase_timing,
            start_key,
            end_key,
            source_artifacts,
        ) {
            spans.push(span);
        }
    }

    if let Some(calls) = diagnostic
        .and_then(|value| value.get("inference_calls"))
        .and_then(Value::as_array)
    {
        for (index, call) in calls.iter().enumerate() {
            spans.push(trace_span(
                format!("inference:{index}"),
                "inference",
                Some("case".to_string()),
                None,
                vec!["planning_contract".to_string()],
                call.get("started_at_ms").and_then(Value::as_u64),
                call.get("finished_at_ms").and_then(Value::as_u64),
                status_string("completed"),
                compact(format!(
                    "{} {}",
                    call.get("method")
                        .and_then(Value::as_str)
                        .unwrap_or("inference"),
                    call.get("output_utf8")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim()
                )),
                json!({
                    "tool_name": call.get("tool_name").cloned().unwrap_or(Value::Null),
                    "elapsed_ms": call.get("elapsed_ms").cloned().unwrap_or(Value::Null),
                }),
                artifact_refs(source_artifacts, &["inference_calls", "inference_trace"]),
            ));
        }
    }

    if let Some(timeline) = diagnostic
        .and_then(|value| value.get("timeline"))
        .and_then(Value::as_array)
    {
        for step in timeline {
            let step_index = step
                .get("step_index")
                .and_then(Value::as_u64)
                .map(|value| value as u32);
            let receipt_times = step
                .get("execution_receipts")
                .and_then(Value::as_array)
                .map(|receipts| {
                    receipts
                        .iter()
                        .filter_map(|receipt| receipt.get("timestamp_ms").and_then(Value::as_u64))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let step_start = step
                .get("inference_started_at_ms")
                .and_then(Value::as_u64)
                .or_else(|| receipt_times.first().copied());
            let step_end = receipt_times
                .last()
                .copied()
                .or_else(|| step.get("inference_finished_at_ms").and_then(Value::as_u64));
            let step_id = format!("step:{}", step_index.unwrap_or(0));
            spans.push(trace_span(
                step_id,
                "step",
                Some("case".to_string()),
                step_index,
                vec![
                    "observation_surface".to_string(),
                    "verification_signal".to_string(),
                ],
                step_start,
                step_end,
                trace_status_from_step(step),
                compact(format!(
                    "{} {}",
                    step.get("chosen_name").and_then(Value::as_str).unwrap_or("step"),
                    step.get("requested_id").and_then(Value::as_str).unwrap_or("")
                )),
                json!({
                    "action_error_class": step.get("action_error_class").cloned().unwrap_or(Value::Null),
                    "routing_failure_class": step.get("routing_failure_class").cloned().unwrap_or(Value::Null),
                    "observation_targets": step.get("observation_targets").cloned().unwrap_or(Value::Null),
                }),
                artifact_refs(source_artifacts, &["diagnostic_json", "inference_calls"]),
            ));
        }
    }

    if let Some(receipts) = diagnostic
        .and_then(|value| value.get("execution_receipts"))
        .and_then(Value::as_array)
    {
        for (index, receipt) in receipts.iter().enumerate() {
            let observed = receipt.get("observed_value").and_then(Value::as_object);
            let start_ms = observed
                .and_then(|value| value.get("started_at_ms"))
                .and_then(Value::as_u64)
                .or_else(|| receipt.get("timestamp_ms").and_then(Value::as_u64));
            let end_ms = observed
                .and_then(|value| value.get("finished_at_ms"))
                .and_then(Value::as_u64)
                .or_else(|| receipt.get("timestamp_ms").and_then(Value::as_u64));
            let key = receipt
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or("receipt");
            let observed_status = observed
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str)
                .unwrap_or(
                    if receipt
                        .get("satisfied")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    {
                        "completed"
                    } else {
                        "failed"
                    },
                );
            spans.push(trace_span(
                format!("receipt:{key}:{index}"),
                receipt
                    .get("stage")
                    .and_then(Value::as_str)
                    .unwrap_or("receipt"),
                Some("case".to_string()),
                receipt
                    .get("step_index")
                    .and_then(Value::as_u64)
                    .map(|value| value as u32),
                metric_tags_for_receipt(key),
                start_ms,
                end_ms,
                status_string(observed_status),
                compact(format!(
                    "{} {}",
                    receipt
                        .get("stage")
                        .and_then(Value::as_str)
                        .unwrap_or("receipt"),
                    key
                )),
                json!({
                    "probe_source": receipt.get("probe_source").cloned().unwrap_or(Value::Null),
                    "observed_value": receipt.get("observed_value").cloned().unwrap_or(Value::Null),
                }),
                artifact_refs(source_artifacts, &["diagnostic_json"]),
            ));
        }
    }

    if let Some(sync_history) = diagnostic
        .and_then(|value| value.get("sync_history"))
        .and_then(Value::as_array)
    {
        for sync in sync_history {
            let sync_index = sync
                .get("sync_index")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            let trigger = sync
                .get("trigger")
                .and_then(Value::as_str)
                .unwrap_or("sync");
            spans.push(trace_span(
                format!("bridge_sync:{sync_index}"),
                "bridge",
                Some("case".to_string()),
                sync.get("episode_step").and_then(Value::as_u64).map(|value| value as u32),
                vec!["bridge_sync_observability".to_string()],
                sync.get("last_sync_ms").and_then(Value::as_u64),
                sync.get("last_sync_ms").and_then(Value::as_u64),
                status_string("observed"),
                compact(format!(
                    "{} reward={} terminated={}",
                    trigger,
                    sync.get("reward").and_then(Value::as_f64).unwrap_or_default(),
                    sync.get("terminated").and_then(Value::as_bool).unwrap_or(false)
                )),
                json!({
                    "visible_text_excerpt": sync.get("visible_text_excerpt").cloned().unwrap_or(Value::Null),
                }),
                artifact_refs(source_artifacts, &["bridge_state", "diagnostic_json"]),
            ));
        }
    }

    spans
}

fn build_bookmarks(spans: &[TraceSpan]) -> Vec<TraceBookmark> {
    let mut bookmarks = Vec::new();
    for (bookmark_id, label, kind, predicate) in [
        (
            "first_inference",
            "First inference",
            "milestone",
            "inference:0",
        ),
        (
            "executor_timeout",
            "Executor timeout",
            "failure",
            "receipt:service_executor_dispatch",
        ),
        (
            "terminal_sync",
            "Terminal sync",
            "milestone",
            "bridge_sync:",
        ),
    ] {
        if let Some(span) = spans.iter().find(|span| span.id.starts_with(predicate)) {
            bookmarks.push(TraceBookmark {
                id: bookmark_id.to_string(),
                label: label.to_string(),
                span_id: span.id.clone(),
                kind: kind.to_string(),
            });
        }
    }
    if let Some(span) = spans.iter().rev().find(|span| span.id == "case") {
        bookmarks.push(TraceBookmark {
            id: "case_outcome".to_string(),
            label: "Case outcome".to_string(),
            span_id: span.id.clone(),
            kind: "summary".to_string(),
        });
    }
    bookmarks
}

fn build_metrics(
    summary: &Value,
    diagnostic: Option<&Value>,
    spans: &[TraceSpan],
    source_artifacts: &Value,
) -> Vec<TraceMetric> {
    let mut metrics = Vec::new();
    metrics.push(TraceMetric {
        metric_id: "overall_case_outcome".to_string(),
        label: "Overall case outcome".to_string(),
        status: trace_status_from_summary(summary),
        summary: compact(format!(
            "effective_reward={} reward={} floor_met={} terminated={} provider_calls={}",
            summary_effective_reward(summary).unwrap_or_default(),
            summary
                .get("reward")
                .and_then(Value::as_f64)
                .unwrap_or_default(),
            summary_reward_floor_met(summary).unwrap_or(false),
            summary
                .get("terminated")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            summary
                .get("provider_calls")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        )),
        supporting_span_ids: vec!["case".to_string()],
        supporting_artifacts: artifact_refs(source_artifacts, &["benchmark_summary_json"]),
    });
    metrics.push(trace_metric(
        "observation_surface",
        "Observation surface",
        if diagnostic
            .and_then(|value| value.get("timeline"))
            .and_then(Value::as_array)
            .is_some_and(|timeline| {
                timeline.iter().any(|step| {
                    step.get("observation_targets")
                        .and_then(Value::as_array)
                        .is_some_and(|targets| !targets.is_empty())
                })
            })
        {
            "pass"
        } else {
            "unknown"
        },
        "Grounded observation targets were recorded for at least one agent step.",
        spans_with_tag(spans, "observation_surface"),
        artifact_refs(source_artifacts, &["diagnostic_json"]),
    ));
    metrics.push(trace_metric(
        "execution_runtime",
        "Execution runtime",
        if spans.iter().any(|span| {
            span.id.starts_with("receipt:service_executor_dispatch") && span.status != "completed"
        }) {
            "red"
        } else if spans
            .iter()
            .any(|span| span.id.starts_with("receipt:service_executor_dispatch"))
        {
            "pass"
        } else {
            "unknown"
        },
        "Service executor dispatch is the current canonical runtime bottleneck surface.",
        spans
            .iter()
            .filter(|span| span.id.starts_with("receipt:service_executor_dispatch"))
            .map(|span| span.id.clone())
            .collect(),
        artifact_refs(source_artifacts, &["diagnostic_json"]),
    ));
    metrics.push(trace_metric(
        "verification_signal",
        "Verification signal",
        if diagnostic
            .and_then(|value| value.get("timeline"))
            .and_then(Value::as_array)
            .is_some_and(|timeline| {
                timeline
                    .iter()
                    .any(|step| step.get("action_error_class").is_some())
            })
        {
            "red"
        } else if spans_with_tag(spans, "verification_signal").is_empty() {
            "unknown"
        } else {
            "pass"
        },
        "Post-action verification is derived from per-step execution receipts and action outcomes.",
        spans_with_tag(spans, "verification_signal"),
        artifact_refs(source_artifacts, &["diagnostic_json"]),
    ));
    metrics.push(trace_metric(
        "bridge_sync_observability",
        "Bridge sync observability",
        if spans.iter().any(|span| span.lane == "bridge") {
            "pass"
        } else {
            "unknown"
        },
        "Bridge sync history is available for replay and capability correlation.",
        spans
            .iter()
            .filter(|span| span.lane == "bridge")
            .take(4)
            .map(|span| span.id.clone())
            .collect(),
        artifact_refs(source_artifacts, &["bridge_state", "diagnostic_json"]),
    ));
    metrics
}

fn phase_span(
    id: &str,
    label: &str,
    lane: &str,
    tags: &[&str],
    phase_timing: Option<&serde_json::Map<String, Value>>,
    start_key: &str,
    end_key: &str,
    source_artifacts: &Value,
) -> Option<TraceSpan> {
    let start_ms = phase_timing
        .and_then(|timing| timing.get(start_key))
        .and_then(Value::as_u64)?;
    let end_ms = phase_timing
        .and_then(|timing| timing.get(end_key))
        .and_then(Value::as_u64)
        .or(Some(start_ms))?;
    Some(trace_span(
        id,
        lane,
        Some("case".to_string()),
        None,
        tags.iter().map(|tag| (*tag).to_string()).collect(),
        Some(start_ms),
        Some(end_ms),
        status_string("completed"),
        label.to_string(),
        json!({ "source": "phase_timing" }),
        artifact_refs(source_artifacts, &["diagnostic_json", "inference_trace"]),
    ))
}

fn trace_span(
    id: impl Into<String>,
    lane: impl Into<String>,
    parent_span_id: Option<String>,
    step_index: Option<u32>,
    capability_tags: Vec<String>,
    ts_start_ms: Option<u64>,
    ts_end_ms: Option<u64>,
    status: String,
    summary: String,
    attributes: Value,
    artifact_refs: Vec<String>,
) -> TraceSpan {
    TraceSpan {
        id: id.into(),
        lane: lane.into(),
        parent_span_id,
        step_index,
        capability_tags,
        ts_start_ms,
        ts_end_ms,
        duration_ms: ts_start_ms
            .zip(ts_end_ms)
            .map(|(start, end)| end.saturating_sub(start)),
        status,
        summary,
        attributes,
        artifact_refs,
    }
}

fn trace_metric(
    metric_id: &str,
    label: &str,
    status: &str,
    summary: &str,
    supporting_span_ids: Vec<String>,
    supporting_artifacts: Vec<String>,
) -> TraceMetric {
    TraceMetric {
        metric_id: metric_id.to_string(),
        label: label.to_string(),
        status: status.to_string(),
        summary: summary.to_string(),
        supporting_span_ids,
        supporting_artifacts,
    }
}

fn artifact_refs(source_artifacts: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .filter_map(|key| source_artifacts.get(*key).and_then(Value::as_str))
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn spans_with_tag(spans: &[TraceSpan], tag: &str) -> Vec<String> {
    spans
        .iter()
        .filter(|span| span.capability_tags.iter().any(|entry| entry == tag))
        .map(|span| span.id.clone())
        .collect()
}

fn metric_tags_for_receipt(key: &str) -> Vec<String> {
    if key.contains("executor") || key.contains("action_complete") {
        vec!["execution_runtime".to_string()]
    } else if key.contains("policy") || key.contains("determinism") {
        vec!["planning_contract".to_string()]
    } else {
        vec!["verification_signal".to_string()]
    }
}

fn summary_effective_reward(summary: &Value) -> Option<f64> {
    summary
        .get("effective_reward")
        .and_then(Value::as_f64)
        .or_else(|| summary.get("raw_reward").and_then(Value::as_f64))
        .or_else(|| summary.get("reward").and_then(Value::as_f64))
}

fn summary_reward_floor_met(summary: &Value) -> Option<bool> {
    summary
        .get("reward_floor_met")
        .and_then(Value::as_bool)
        .or_else(|| {
            let effective_reward = summary_effective_reward(summary)?;
            let expected_reward_floor = summary
                .get("expected_reward_floor")
                .and_then(Value::as_f64)
                .unwrap_or(1.0);
            Some(effective_reward + REWARD_FLOOR_EPSILON >= expected_reward_floor)
        })
}

fn trace_status_from_summary(summary: &Value) -> String {
    if summary_reward_floor_met(summary).unwrap_or(false) {
        return "pass".to_string();
    }
    match summary_effective_reward(summary) {
        Some(value) if value > 0.0 => "near_miss".to_string(),
        Some(_) => "red".to_string(),
        None => "unknown".to_string(),
    }
}

fn trace_status_from_step(step: &Value) -> String {
    if step.get("action_error_class").is_some() || step.get("routing_failure_class").is_some() {
        "failed".to_string()
    } else {
        "completed".to_string()
    }
}

fn status_string(status: &str) -> String {
    status.trim().to_string()
}

fn summary_line(summary: &Value, findings: &[String]) -> String {
    compact(format!(
        "{} | reward={} effective_reward={} floor_met={} | {}",
        summary
            .get("query_text")
            .and_then(Value::as_str)
            .unwrap_or("computer-use case"),
        summary
            .get("reward")
            .and_then(Value::as_f64)
            .unwrap_or_default(),
        summary_effective_reward(summary).unwrap_or_default(),
        summary_reward_floor_met(summary).unwrap_or(false),
        findings
            .first()
            .cloned()
            .unwrap_or_else(|| "no findings".to_string()),
    ))
}

fn compact(value: String) -> String {
    let text = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.len() <= 220 {
        text
    } else {
        format!("{}...", &text[..217])
    }
}

fn read_json_file(path: Option<&Path>) -> Result<Option<Value>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read trace source json {}", path.display()))?;
    Ok(Some(serde_json::from_str(&raw).with_context(|| {
        format!("parse trace source json {}", path.display())
    })?))
}

fn resolve_workspace_path_str(path: &str) -> PathBuf {
    resolve_workspace_path(Path::new(path))
}

fn resolve_workspace_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    let repo = repo_root();
    let repo_candidate = repo.join(path);
    if repo_candidate.exists() {
        return repo_candidate;
    }

    let cli_candidate = repo.join("crates").join("cli").join(path);
    if cli_candidate.exists() {
        return cli_candidate;
    }

    if path
        .components()
        .next()
        .is_some_and(|component| component.as_os_str() == "target")
    {
        cli_candidate
    } else {
        repo_candidate
    }
}

fn display_workspace_path(path: &Path) -> String {
    resolve_workspace_path(path).display().to_string()
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("write trace artifact {}", path.display()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
