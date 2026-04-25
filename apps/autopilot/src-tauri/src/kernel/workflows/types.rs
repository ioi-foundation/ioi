use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    #[serde(default)]
    pub every_seconds: u64,
    #[serde(default)]
    pub remote_trigger_id: Option<String>,
    #[serde(default)]
    pub wait_until_ms: Option<u64>,
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
    pub trigger_kind: String,
    pub trigger_label: String,
    #[serde(default)]
    pub remote_trigger_id: Option<String>,
    #[serde(default)]
    pub wait_until_ms: Option<u64>,
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
pub(super) struct WorkflowRegistryRecord {
    pub(super) workflow_id: String,
    pub(super) kind: WorkflowKind,
    pub(super) status: WorkflowStatus,
    #[serde(default)]
    pub(super) trigger_kind: String,
    #[serde(default)]
    pub(super) trigger_label: String,
    #[serde(default)]
    pub(super) remote_trigger_id: Option<String>,
    #[serde(default)]
    pub(super) wait_until_ms: Option<u64>,
    pub(super) title: String,
    pub(super) description: String,
    pub(super) artifact_hash: String,
    pub(super) spec_version: String,
    pub(super) artifact_path: String,
    pub(super) poll_interval_seconds: u64,
    pub(super) source_label: String,
    #[serde(default)]
    pub(super) keywords: Vec<String>,
    pub(super) installed_at_ms: u64,
    pub(super) updated_at_ms: u64,
    #[serde(default)]
    pub(super) next_run_at_ms: Option<u64>,
    #[serde(default)]
    pub(super) last_run_at_ms: Option<u64>,
    #[serde(default)]
    pub(super) last_success_at_ms: Option<u64>,
    #[serde(default)]
    pub(super) last_error: Option<String>,
    #[serde(default)]
    pub(super) last_run_id: Option<String>,
    #[serde(default)]
    pub(super) run_count: u64,
    #[serde(default)]
    pub(super) failure_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(super) struct WorkflowRegistry {
    pub(super) version: u32,
    #[serde(default)]
    pub(super) workflows: Vec<WorkflowRegistryRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowRunReceipt {
    pub receipt_version: u32,
    pub workflow_id: String,
    pub run_id: String,
    pub trigger_kind: String,
    pub status: String,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub artifact_hash: String,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub settlement_refs: Vec<String>,
    #[serde(default)]
    pub projection_only: bool,
    #[serde(default)]
    pub simulation_only: bool,
    pub workflow_status: WorkflowStatus,
    pub next_run_at_ms: Option<u64>,
    #[serde(default)]
    pub observation: Value,
    #[serde(default)]
    pub notification_ids: Vec<String>,
    #[serde(default)]
    pub error: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledWorkflowDetail {
    pub summary: InstalledWorkflowSummary,
    pub artifact: WorkflowArtifact,
    pub state: WorkflowRuntimeState,
    #[serde(default)]
    pub recent_receipts: Vec<WorkflowRunReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowProjectFile {
    pub version: String,
    pub nodes: Vec<Value>,
    pub edges: Vec<Value>,
    #[serde(rename = "global_config")]
    pub global_config: Value,
}

#[derive(Debug, Clone, Deserialize)]
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
