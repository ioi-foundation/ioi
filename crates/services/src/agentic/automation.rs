use ioi_crypto::algorithms::hash::sha256;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const AUTOMATION_ROOT_ENV_VAR: &str = "IOI_AUTOMATION_ROOT_PATH";

const AUTOMATION_REGISTRY_FILE: &str = "workflow_registry.json";
const AUTOMATION_SPEC_VERSION: &str = "workflow.v1";
const AUTOMATION_REGISTRY_VERSION: u32 = 1;
const AUTOMATION_STATE_VERSION: u32 = 1;
const AUTOMATION_RECEIPT_VERSION: u32 = 1;
const HACKER_NEWS_FRONT_PAGE_URL: &str = "https://news.ycombinator.com/";
const HACKER_NEWS_SOURCE_KIND: &str = "hacker_news_front_page";
const HACKER_NEWS_EXTRACTOR_KIND: &str = "hacker_news_front_page_titles";
const CONTAINS_ANY_PREDICATE_KIND: &str = "contains_any_title";
const ASSISTANT_NOTIFICATION_SINK_KIND: &str = "assistant_notification";
const SEEN_KEY_LIMIT: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowKind {
    Monitor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStatus {
    Active,
    Paused,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowProvenance {
    pub created_via: String,
    pub authoring_tool: String,
    #[serde(default)]
    pub source_prompt: Option<String>,
    #[serde(default)]
    pub source_prompt_hash: Option<String>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowTrigger {
    #[serde(rename = "type")]
    pub trigger_type: String,
    pub every_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowNode {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub config: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowEdge {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowGraph {
    #[serde(default)]
    pub nodes: Vec<WorkflowNode>,
    #[serde(default)]
    pub edges: Vec<WorkflowEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowStateSchema {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub seen_keys: Vec<String>,
    #[serde(default)]
    pub last_run_ms: Option<u64>,
    #[serde(default)]
    pub last_success_ms: Option<u64>,
    #[serde(default)]
    pub last_emission_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowPolicy {
    #[serde(default)]
    pub network_allowlist: Vec<String>,
    #[serde(default)]
    pub notification_policy: String,
    #[serde(default)]
    pub human_gate_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorSource {
    #[serde(rename = "type")]
    pub source_type: String,
    pub url: String,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorExtractor {
    #[serde(rename = "type")]
    pub extractor_type: String,
    #[serde(default)]
    pub selector: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorPredicate {
    #[serde(rename = "type")]
    pub predicate_type: String,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub case_sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorDedupe {
    pub strategy: String,
    #[serde(default)]
    pub state_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationSink {
    #[serde(rename = "type")]
    pub sink_type: String,
    pub notification_class: String,
    pub rail: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorDefinition {
    pub source: MonitorSource,
    pub extractor: MonitorExtractor,
    pub predicate: MonitorPredicate,
    pub dedupe: MonitorDedupe,
    pub sink: NotificationSink,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowArtifact {
    pub spec_version: String,
    pub workflow_id: String,
    pub kind: WorkflowKind,
    pub title: String,
    pub description: String,
    pub provenance: WorkflowProvenance,
    pub trigger: WorkflowTrigger,
    pub graph: WorkflowGraph,
    pub state_schema: WorkflowStateSchema,
    pub policy: WorkflowPolicy,
    pub monitor: MonitorDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowRuntimeState {
    pub schema_version: u32,
    pub workflow_id: String,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub seen_keys: Vec<String>,
    #[serde(default)]
    pub last_run_ms: Option<u64>,
    #[serde(default)]
    pub last_success_ms: Option<u64>,
    #[serde(default)]
    pub last_emission_hash: Option<String>,
    #[serde(default)]
    pub updated_at_ms: u64,
    #[serde(default)]
    pub failure_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledWorkflowSummary {
    pub workflow_id: String,
    pub kind: WorkflowKind,
    pub status: WorkflowStatus,
    pub title: String,
    pub description: String,
    pub artifact_hash: String,
    pub spec_version: String,
    pub poll_interval_seconds: u64,
    pub source_label: String,
    #[serde(default)]
    pub keywords: Vec<String>,
    pub installed_at_ms: u64,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub next_run_at_ms: Option<u64>,
    #[serde(default)]
    pub last_run_at_ms: Option<u64>,
    #[serde(default)]
    pub last_success_at_ms: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    pub run_count: u64,
    pub failure_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowInstallReceipt {
    pub receipt_version: u32,
    pub workflow_id: String,
    pub installed_at_ms: u64,
    pub artifact_hash: String,
    pub policy_hash: String,
    pub authoring_tool: String,
    pub trigger_kind: String,
    pub valid: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateMonitorRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub keywords: Vec<String>,
    #[serde(default)]
    pub interval_seconds: Option<u64>,
    #[serde(default)]
    pub source_prompt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkflowRegistryRecord {
    workflow_id: String,
    kind: WorkflowKind,
    status: WorkflowStatus,
    title: String,
    description: String,
    artifact_hash: String,
    spec_version: String,
    artifact_path: String,
    poll_interval_seconds: u64,
    source_label: String,
    #[serde(default)]
    keywords: Vec<String>,
    installed_at_ms: u64,
    updated_at_ms: u64,
    #[serde(default)]
    next_run_at_ms: Option<u64>,
    #[serde(default)]
    last_run_at_ms: Option<u64>,
    #[serde(default)]
    last_success_at_ms: Option<u64>,
    #[serde(default)]
    last_error: Option<String>,
    #[serde(default)]
    last_run_id: Option<String>,
    #[serde(default)]
    run_count: u64,
    #[serde(default)]
    failure_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WorkflowRegistry {
    version: u32,
    #[serde(default)]
    workflows: Vec<WorkflowRegistryRecord>,
}

pub fn automation_root_path_from_env() -> Option<PathBuf> {
    std::env::var_os(AUTOMATION_ROOT_ENV_VAR).map(PathBuf::from)
}

pub fn automation_root_path_from_workspace(workspace_path: &str) -> Option<PathBuf> {
    let trimmed = workspace_path.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(root_path_for(Path::new(trimmed)))
}

pub fn resolve_automation_root_path(workspace_path: Option<&str>) -> Option<PathBuf> {
    automation_root_path_from_env()
        .or_else(|| workspace_path.and_then(automation_root_path_from_workspace))
}

pub fn install_monitor_request(
    root_dir: &Path,
    request: CreateMonitorRequest,
    authoring_tool: &str,
) -> Result<InstalledWorkflowSummary, String> {
    let artifact = compile_monitor_request(request, authoring_tool)?;
    install_workflow_artifact(root_dir, artifact, authoring_tool)
}

pub fn compile_monitor_request(
    request: CreateMonitorRequest,
    authoring_tool: &str,
) -> Result<WorkflowArtifact, String> {
    let keywords = normalize_keywords(&request.keywords);
    if keywords.is_empty() {
        return Err("Monitor keyword list is empty after normalization.".to_string());
    }

    let interval_seconds = request.interval_seconds.unwrap_or(300).max(60);
    let workflow_id = monitor_workflow_id_from_keywords(&keywords)?;
    let title = request.title.unwrap_or_else(|| {
        format!(
            "Monitor Hacker News for {}",
            keywords
                .iter()
                .map(|value| format!("\"{}\"", value))
                .collect::<Vec<_>>()
                .join(" or ")
        )
    });
    let description = request.description.unwrap_or_else(|| {
        format!(
            "Poll the Hacker News front page every {} seconds and notify on new matches.",
            interval_seconds
        )
    });
    let source_prompt_hash = request
        .source_prompt
        .as_ref()
        .map(|prompt| {
            sha256(prompt.as_bytes())
                .map(hex::encode)
                .map_err(|error| error.to_string())
        })
        .transpose()?;

    Ok(WorkflowArtifact {
        spec_version: AUTOMATION_SPEC_VERSION.to_string(),
        workflow_id,
        kind: WorkflowKind::Monitor,
        title,
        description,
        provenance: WorkflowProvenance {
            created_via: "chat".to_string(),
            authoring_tool: authoring_tool.to_string(),
            source_prompt: request.source_prompt,
            source_prompt_hash,
            created_at_ms: now(),
        },
        trigger: WorkflowTrigger {
            trigger_type: "interval".to_string(),
            every_seconds: interval_seconds,
        },
        graph: monitor_graph_for_keywords(&keywords, interval_seconds),
        state_schema: WorkflowStateSchema {
            cursor: None,
            seen_keys: Vec::new(),
            last_run_ms: None,
            last_success_ms: None,
            last_emission_hash: None,
        },
        policy: WorkflowPolicy {
            network_allowlist: vec!["news.ycombinator.com".to_string()],
            notification_policy: "assistant".to_string(),
            human_gate_required: false,
        },
        monitor: MonitorDefinition {
            source: MonitorSource {
                source_type: HACKER_NEWS_SOURCE_KIND.to_string(),
                url: HACKER_NEWS_FRONT_PAGE_URL.to_string(),
                scope: Some("front_page".to_string()),
            },
            extractor: MonitorExtractor {
                extractor_type: HACKER_NEWS_EXTRACTOR_KIND.to_string(),
                selector: Some("span.titleline > a".to_string()),
            },
            predicate: MonitorPredicate {
                predicate_type: CONTAINS_ANY_PREDICATE_KIND.to_string(),
                keywords,
                case_sensitive: false,
            },
            dedupe: MonitorDedupe {
                strategy: "state.seen_set".to_string(),
                state_key: Some("href".to_string()),
            },
            sink: NotificationSink {
                sink_type: ASSISTANT_NOTIFICATION_SINK_KIND.to_string(),
                notification_class: "digest".to_string(),
                rail: "assistant".to_string(),
                severity: "informational".to_string(),
            },
        },
    })
}

pub fn install_workflow_artifact(
    root_dir: &Path,
    artifact: WorkflowArtifact,
    authoring_tool: &str,
) -> Result<InstalledWorkflowSummary, String> {
    validate_artifact(&artifact)?;
    ensure_runtime_dirs(root_dir)?;

    let installed_at_ms = now();
    let artifact_hash = json_sha256_hex(&artifact)?;
    let policy_hash = json_sha256_hex(&artifact.policy)?;
    let artifact_path = artifact_path_for(root_dir, &artifact.workflow_id);
    write_json_atomic(&artifact_path, &artifact)?;

    let state = WorkflowRuntimeState {
        schema_version: AUTOMATION_STATE_VERSION,
        workflow_id: artifact.workflow_id.clone(),
        cursor: artifact.state_schema.cursor.clone(),
        seen_keys: artifact.state_schema.seen_keys.clone(),
        last_run_ms: artifact.state_schema.last_run_ms,
        last_success_ms: artifact.state_schema.last_success_ms,
        last_emission_hash: artifact.state_schema.last_emission_hash.clone(),
        updated_at_ms: installed_at_ms,
        failure_count: 0,
    };
    write_json_atomic(&state_path_for(root_dir, &artifact.workflow_id), &state)?;

    let mut registry =
        load_json::<WorkflowRegistry>(&registry_path_for(root_dir)).unwrap_or(WorkflowRegistry {
            version: AUTOMATION_REGISTRY_VERSION,
            workflows: Vec::new(),
        });
    let next_run_at_ms = Some(installed_at_ms);
    let summary = if let Some(existing) = registry
        .workflows
        .iter_mut()
        .find(|record| record.workflow_id == artifact.workflow_id)
    {
        existing.kind = artifact.kind.clone();
        existing.status = WorkflowStatus::Active;
        existing.title = artifact.title.clone();
        existing.description = artifact.description.clone();
        existing.artifact_hash = artifact_hash.clone();
        existing.spec_version = artifact.spec_version.clone();
        existing.artifact_path = artifact_path.to_string_lossy().to_string();
        existing.poll_interval_seconds = artifact.trigger.every_seconds.max(60);
        existing.source_label = artifact.monitor.source.url.clone();
        existing.keywords = artifact.monitor.predicate.keywords.clone();
        existing.updated_at_ms = installed_at_ms;
        existing.next_run_at_ms = next_run_at_ms;
        existing.last_error = None;
        summary_from_record(existing)
    } else {
        let record = WorkflowRegistryRecord {
            workflow_id: artifact.workflow_id.clone(),
            kind: artifact.kind.clone(),
            status: WorkflowStatus::Active,
            title: artifact.title.clone(),
            description: artifact.description.clone(),
            artifact_hash: artifact_hash.clone(),
            spec_version: artifact.spec_version.clone(),
            artifact_path: artifact_path.to_string_lossy().to_string(),
            poll_interval_seconds: artifact.trigger.every_seconds.max(60),
            source_label: artifact.monitor.source.url.clone(),
            keywords: artifact.monitor.predicate.keywords.clone(),
            installed_at_ms,
            updated_at_ms: installed_at_ms,
            next_run_at_ms,
            last_run_at_ms: None,
            last_success_at_ms: None,
            last_error: None,
            last_run_id: None,
            run_count: 0,
            failure_count: 0,
        };
        registry.workflows.push(record.clone());
        summary_from_record(&record)
    };
    persist_registry(root_dir, &registry)?;

    let install_receipt = WorkflowInstallReceipt {
        receipt_version: AUTOMATION_RECEIPT_VERSION,
        workflow_id: artifact.workflow_id.clone(),
        installed_at_ms,
        artifact_hash,
        policy_hash,
        authoring_tool: authoring_tool.to_string(),
        trigger_kind: artifact.trigger.trigger_type.clone(),
        valid: true,
    };
    append_install_receipt(root_dir, &artifact.workflow_id, &install_receipt)?;

    Ok(summary)
}

pub fn root_path_for(data_dir: &Path) -> PathBuf {
    data_dir.join("automation")
}

pub fn registry_path_for(root_dir: &Path) -> PathBuf {
    root_dir.join(AUTOMATION_REGISTRY_FILE)
}

pub fn artifact_path_for(root_dir: &Path, workflow_id: &str) -> PathBuf {
    artifacts_dir_for(root_dir).join(format!("{}.json", workflow_id))
}

pub fn state_path_for(root_dir: &Path, workflow_id: &str) -> PathBuf {
    states_dir_for(root_dir).join(format!("{}.json", workflow_id))
}

pub fn ensure_runtime_dirs(root_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(root_dir).map_err(|error| error.to_string())?;
    fs::create_dir_all(artifacts_dir_for(root_dir)).map_err(|error| error.to_string())?;
    fs::create_dir_all(states_dir_for(root_dir)).map_err(|error| error.to_string())?;
    fs::create_dir_all(receipts_root_for(root_dir)).map_err(|error| error.to_string())?;
    Ok(())
}

pub fn validate_artifact(artifact: &WorkflowArtifact) -> Result<(), String> {
    if artifact.spec_version != AUTOMATION_SPEC_VERSION {
        return Err(format!(
            "Unsupported workflow spec version '{}'.",
            artifact.spec_version
        ));
    }
    if artifact.trigger.trigger_type != "interval" {
        return Err(format!(
            "Unsupported workflow trigger '{}'.",
            artifact.trigger.trigger_type
        ));
    }
    if artifact.trigger.every_seconds < 60 {
        return Err("Workflow trigger interval must be at least 60 seconds.".to_string());
    }
    if artifact.monitor.source.source_type != HACKER_NEWS_SOURCE_KIND {
        return Err(format!(
            "Unsupported workflow source '{}'.",
            artifact.monitor.source.source_type
        ));
    }
    if artifact.monitor.source.url != HACKER_NEWS_FRONT_PAGE_URL {
        return Err(
            "The current monitor runtime only supports the Hacker News front page URL.".to_string(),
        );
    }
    if artifact.monitor.extractor.extractor_type != HACKER_NEWS_EXTRACTOR_KIND {
        return Err(format!(
            "Unsupported workflow extractor '{}'.",
            artifact.monitor.extractor.extractor_type
        ));
    }
    if artifact.monitor.predicate.predicate_type != CONTAINS_ANY_PREDICATE_KIND {
        return Err(format!(
            "Unsupported workflow predicate '{}'.",
            artifact.monitor.predicate.predicate_type
        ));
    }
    if artifact.monitor.predicate.keywords.is_empty() {
        return Err("Workflow predicates must include at least one keyword.".to_string());
    }
    if artifact.monitor.sink.sink_type != ASSISTANT_NOTIFICATION_SINK_KIND {
        return Err(format!(
            "Unsupported workflow sink '{}'.",
            artifact.monitor.sink.sink_type
        ));
    }
    let domain_allowed = artifact
        .policy
        .network_allowlist
        .iter()
        .any(|entry| entry.trim().eq_ignore_ascii_case("news.ycombinator.com"));
    if !domain_allowed {
        return Err("Workflow policy must explicitly allow news.ycombinator.com.".to_string());
    }
    Ok(())
}

pub fn render_installation_summary(summary: &InstalledWorkflowSummary) -> String {
    let keywords = if summary.keywords.is_empty() {
        "none".to_string()
    } else {
        summary.keywords.join(", ")
    };
    format!(
        "Scheduled workflow: {}\nWorkflow ID: {}\nPoll interval: {} seconds\nSource: {}\nKeywords: {}",
        summary.title,
        summary.workflow_id,
        summary.poll_interval_seconds,
        summary.source_label,
        keywords
    )
}

fn artifacts_dir_for(root_dir: &Path) -> PathBuf {
    root_dir.join("artifacts")
}

fn states_dir_for(root_dir: &Path) -> PathBuf {
    root_dir.join("state")
}

fn receipts_root_for(root_dir: &Path) -> PathBuf {
    root_dir.join("receipts")
}

fn receipt_dir_for(root_dir: &Path, workflow_id: &str) -> PathBuf {
    receipts_root_for(root_dir).join(workflow_id)
}

fn append_install_receipt(
    root_dir: &Path,
    workflow_id: &str,
    receipt: &WorkflowInstallReceipt,
) -> Result<(), String> {
    let path = receipt_dir_for(root_dir, workflow_id).join("install.json");
    write_json_atomic(&path, receipt)
}

fn persist_registry(root_dir: &Path, registry: &WorkflowRegistry) -> Result<(), String> {
    write_json_atomic(&registry_path_for(root_dir), registry)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let temp_path = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(&temp_path, bytes).map_err(|error| error.to_string())?;
    fs::rename(&temp_path, path).map_err(|error| error.to_string())?;
    Ok(())
}

fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn summary_from_record(record: &WorkflowRegistryRecord) -> InstalledWorkflowSummary {
    InstalledWorkflowSummary {
        workflow_id: record.workflow_id.clone(),
        kind: record.kind.clone(),
        status: record.status.clone(),
        title: record.title.clone(),
        description: record.description.clone(),
        artifact_hash: record.artifact_hash.clone(),
        spec_version: record.spec_version.clone(),
        poll_interval_seconds: record.poll_interval_seconds,
        source_label: record.source_label.clone(),
        keywords: record.keywords.clone(),
        installed_at_ms: record.installed_at_ms,
        updated_at_ms: record.updated_at_ms,
        next_run_at_ms: record.next_run_at_ms,
        last_run_at_ms: record.last_run_at_ms,
        last_success_at_ms: record.last_success_at_ms,
        last_error: record.last_error.clone(),
        run_count: record.run_count,
        failure_count: record.failure_count,
    }
}

fn normalize_keywords(keywords: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = keywords
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .filter(|value| seen.insert(value.clone()))
        .collect::<Vec<_>>();
    normalized.sort();
    normalized
}

fn monitor_workflow_id_from_keywords(keywords: &[String]) -> Result<String, String> {
    let digest = hash_strings_hex(
        &keywords
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect::<Vec<_>>(),
    )?;
    Ok(format!("monitor_hacker_news_{}", &digest[..12]))
}

fn monitor_graph_for_keywords(keywords: &[String], every_seconds: u64) -> WorkflowGraph {
    WorkflowGraph {
        nodes: vec![
            WorkflowNode {
                id: "trigger".to_string(),
                kind: "trigger.interval".to_string(),
                config: json!({ "everySeconds": every_seconds }),
            },
            WorkflowNode {
                id: "fetch".to_string(),
                kind: "source.web.read".to_string(),
                config: json!({ "url": HACKER_NEWS_FRONT_PAGE_URL }),
            },
            WorkflowNode {
                id: "extract".to_string(),
                kind: "extract.hacker_news_front_page".to_string(),
                config: json!({ "selector": "span.titleline > a" }),
            },
            WorkflowNode {
                id: "match".to_string(),
                kind: "predicate.contains_any".to_string(),
                config: json!({ "keywords": keywords }),
            },
            WorkflowNode {
                id: "dedupe".to_string(),
                kind: "state.seen_set".to_string(),
                config: json!({ "limit": SEEN_KEY_LIMIT }),
            },
            WorkflowNode {
                id: "notify".to_string(),
                kind: "sink.notification.send".to_string(),
                config: json!({ "rail": "assistant" }),
            },
        ],
        edges: vec![
            WorkflowEdge {
                from: "trigger".to_string(),
                to: "fetch".to_string(),
            },
            WorkflowEdge {
                from: "fetch".to_string(),
                to: "extract".to_string(),
            },
            WorkflowEdge {
                from: "extract".to_string(),
                to: "match".to_string(),
            },
            WorkflowEdge {
                from: "match".to_string(),
                to: "dedupe".to_string(),
            },
            WorkflowEdge {
                from: "dedupe".to_string(),
                to: "notify".to_string(),
            },
        ],
    }
}

fn json_sha256_hex<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let digest = sha256(bytes).map_err(|error| error.to_string())?;
    Ok(hex::encode(digest))
}

fn hash_strings_hex(values: &[String]) -> Result<String, String> {
    let joined = values.join("|");
    let digest = sha256(joined.as_bytes()).map_err(|error| error.to_string())?;
    Ok(hex::encode(digest))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
#[path = "automation/tests.rs"]
mod tests;
