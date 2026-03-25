use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkTraceFeedView {
    pub generated_at: Option<String>,
    pub repo_root: Option<String>,
    pub cases: Vec<BenchmarkTraceCaseView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkTraceCaseView {
    pub suite: String,
    pub case_id: String,
    pub run_id: String,
    pub run_sort: u64,
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub summary: BenchmarkTraceSummaryView,
    #[serde(default)]
    pub findings: Vec<String>,
    #[serde(default)]
    pub trace_metrics: Vec<BenchmarkTraceMetricView>,
    #[serde(default)]
    pub trace: Option<BenchmarkTraceReplayView>,
    #[serde(default)]
    pub links: BenchmarkTraceLinkSetView,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BenchmarkTraceSummaryView {
    #[serde(default)]
    pub env_id: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub provider_calls: u64,
    #[serde(default)]
    pub reward: f64,
    #[serde(default)]
    pub terminated: bool,
    #[serde(default)]
    pub query_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkTraceMetricView {
    #[serde(default)]
    pub metric_id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub supporting_span_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkTraceReplayView {
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub range_start_ms: u64,
    #[serde(default)]
    pub range_end_ms: u64,
    #[serde(default)]
    pub span_count: usize,
    #[serde(default)]
    pub lanes: Vec<BenchmarkTraceLaneView>,
    #[serde(default)]
    pub bookmarks: Vec<BenchmarkTraceBookmarkView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkTraceLaneView {
    #[serde(default)]
    pub lane: String,
    #[serde(default)]
    pub spans: Vec<BenchmarkTraceSpanView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkTraceSpanView {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub lane: String,
    #[serde(default)]
    pub parent_span_id: Option<String>,
    #[serde(default)]
    pub step_index: Option<u64>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub start_ms: u64,
    #[serde(default)]
    pub end_ms: u64,
    #[serde(default)]
    pub duration_ms: Option<u64>,
    #[serde(default)]
    pub capability_tags: Vec<String>,
    #[serde(default)]
    pub attributes_summary: String,
    #[serde(default)]
    pub artifact_links: Vec<BenchmarkTraceArtifactLinkView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkTraceArtifactLinkView {
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub href: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkTraceBookmarkView {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub span_id: String,
    #[serde(default)]
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkTraceLinkSetView {
    #[serde(default)]
    pub trace_bundle: Option<String>,
    #[serde(default)]
    pub trace_analysis: Option<String>,
    #[serde(default)]
    pub benchmark_summary: Option<String>,
    #[serde(default)]
    pub diagnostic_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct GeneratedBenchmarkDataFile {
    #[serde(default)]
    generated_at: Option<String>,
    #[serde(default)]
    repo_root: Option<String>,
    #[serde(default)]
    latest_cases: Vec<BenchmarkTraceCaseView>,
}

fn benchmark_data_file_path() -> Result<PathBuf, String> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .map_err(|error| format!("Failed to resolve repo root: {}", error))?;
    let path = repo_root.join("apps/benchmarks/src/generated/benchmark-data.json");
    if path.exists() {
        Ok(path)
    } else {
        Err(format!(
            "Benchmark trace data not found at '{}'. Run `npm run generate:data --workspace=apps/benchmarks`.",
            path.display()
        ))
    }
}

fn case_priority(case: &BenchmarkTraceCaseView) -> u8 {
    if case.result.eq_ignore_ascii_case("pass") {
        1
    } else {
        0
    }
}

#[tauri::command]
pub fn get_local_benchmark_trace_feed(
    limit: Option<usize>,
) -> Result<BenchmarkTraceFeedView, String> {
    let path = benchmark_data_file_path()?;
    let payload = fs::read_to_string(&path)
        .map_err(|error| format!("Failed to read '{}': {}", path.display(), error))?;
    let mut data: GeneratedBenchmarkDataFile = serde_json::from_str(&payload)
        .map_err(|error| format!("Failed to parse '{}': {}", path.display(), error))?;

    let max_cases = limit.unwrap_or(8).clamp(1, 32);
    data.latest_cases.retain(|case| {
        case.trace
            .as_ref()
            .map(|trace| !trace.lanes.is_empty())
            .unwrap_or(false)
    });
    data.latest_cases.sort_by(|left, right| {
        case_priority(left)
            .cmp(&case_priority(right))
            .then_with(|| right.run_sort.cmp(&left.run_sort))
            .then_with(|| left.case_id.cmp(&right.case_id))
    });
    data.latest_cases.truncate(max_cases);

    Ok(BenchmarkTraceFeedView {
        generated_at: data.generated_at,
        repo_root: data.repo_root,
        cases: data.latest_cases,
    })
}
