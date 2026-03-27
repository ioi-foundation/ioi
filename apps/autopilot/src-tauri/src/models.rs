// apps/autopilot/src-tauri/src/models.rs
use ioi_api::vm::inference::InferenceRuntime;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_memory::MemoryRuntime;
use ioi_types::app::agentic::{LlmToolDefinition, PiiTarget};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tonic::transport::Channel;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentPhase {
    Idle,
    Running,
    Gate,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateInfo {
    pub title: String,
    pub description: String,
    pub risk: String,
    #[serde(default)]
    pub approve_label: Option<String>,
    #[serde(default)]
    pub deny_label: Option<String>,
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    #[serde(default)]
    pub surface_label: Option<String>,
    #[serde(default)]
    pub scope_label: Option<String>,
    #[serde(default)]
    pub operation_label: Option<String>,
    #[serde(default)]
    pub target_label: Option<String>,
    #[serde(default)]
    pub operator_note: Option<String>,
    #[serde(default)]
    pub pii: Option<PiiReviewInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiReviewInfo {
    pub decision_hash: String,
    pub target_label: String,
    pub span_summary: String,
    #[serde(default)]
    pub class_counts: std::collections::BTreeMap<String, u32>,
    #[serde(default)]
    pub severity_counts: std::collections::BTreeMap<String, u32>,
    pub stage2_prompt: String,
    pub deadline_ms: u64,
    #[serde(default)]
    pub target_id: Option<PiiTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineCapabilityFamily {
    pub id: String,
    pub label: String,
    pub description: String,
    pub status: String,
    pub available_count: usize,
    pub tool_names: Vec<String>,
    pub operator_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineControlAction {
    pub item_id: String,
    pub title: String,
    pub summary: String,
    pub status: String,
    pub severity: String,
    pub requested_at_ms: u64,
    #[serde(default)]
    pub due_at_ms: Option<u64>,
    #[serde(default)]
    pub approval_scope: Option<String>,
    #[serde(default)]
    pub sensitive_action_type: Option<String>,
    #[serde(default)]
    pub recommended_action: Option<String>,
    #[serde(default)]
    pub recovery_hint: Option<String>,
    #[serde(default)]
    pub request_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineActivityRecord {
    pub event_id: String,
    pub session_id: String,
    pub family: String,
    pub title: String,
    pub tool_name: String,
    pub timestamp_ms: u64,
    pub success: bool,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub subject_kind: Option<String>,
    #[serde(default)]
    pub subject_id: Option<String>,
    #[serde(default)]
    pub backend_id: Option<String>,
    #[serde(default)]
    pub error_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineCompatRoute {
    pub id: String,
    pub label: String,
    pub path: String,
    pub url: String,
    pub enabled: bool,
    pub compatibility_tier: String,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineJobRecord {
    pub job_id: String,
    pub title: String,
    pub summary: String,
    pub status: String,
    pub origin: String,
    pub subject_kind: String,
    pub operation: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub progress_percent: u8,
    #[serde(default)]
    pub source_uri: Option<String>,
    #[serde(default)]
    pub subject_id: Option<String>,
    #[serde(default)]
    pub backend_id: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub approval_scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineModelRecord {
    pub model_id: String,
    pub status: String,
    pub residency: String,
    pub installed_at_ms: u64,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub source_uri: Option<String>,
    #[serde(default)]
    pub backend_id: Option<String>,
    #[serde(default)]
    pub hardware_profile: Option<String>,
    #[serde(default)]
    pub job_id: Option<String>,
    #[serde(default)]
    pub bytes_transferred: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineBackendRecord {
    pub backend_id: String,
    pub status: String,
    pub health: String,
    pub installed_at_ms: u64,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub source_uri: Option<String>,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub hardware_profile: Option<String>,
    #[serde(default)]
    pub job_id: Option<String>,
    #[serde(default)]
    pub install_path: Option<String>,
    #[serde(default)]
    pub entrypoint: Option<String>,
    #[serde(default)]
    pub health_endpoint: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub last_started_at_ms: Option<u64>,
    #[serde(default)]
    pub last_health_check_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineGalleryEntryPreview {
    pub entry_id: String,
    pub label: String,
    pub summary: String,
    #[serde(default)]
    pub source_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineGalleryCatalogRecord {
    pub gallery_id: String,
    pub kind: String,
    pub label: String,
    pub source_uri: String,
    pub sync_status: String,
    pub compatibility_tier: String,
    pub enabled: bool,
    pub entry_count: u32,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub last_job_id: Option<String>,
    #[serde(default)]
    pub last_synced_at_ms: Option<u64>,
    #[serde(default)]
    pub catalog_path: Option<String>,
    #[serde(default)]
    pub sample_entries: Vec<LocalEngineGalleryEntryPreview>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineRegistryState {
    #[serde(default)]
    pub registry_models: Vec<LocalEngineModelRecord>,
    #[serde(default)]
    pub managed_backends: Vec<LocalEngineBackendRecord>,
    #[serde(default)]
    pub gallery_catalogs: Vec<LocalEngineGalleryCatalogRecord>,
    #[serde(default)]
    pub activity_history: Vec<LocalEngineActivityRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineWorkerCompletionContract {
    pub success_criteria: String,
    pub expected_output: String,
    pub merge_mode: String,
    #[serde(default)]
    pub verification_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineWorkerWorkflowRecord {
    pub workflow_id: String,
    pub label: String,
    pub summary: String,
    pub goal_template: String,
    #[serde(default)]
    pub trigger_intents: Vec<String>,
    #[serde(default)]
    pub default_budget: Option<u64>,
    #[serde(default)]
    pub max_retries: Option<u8>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub completion_contract: Option<LocalEngineWorkerCompletionContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineWorkerTemplateRecord {
    pub template_id: String,
    pub label: String,
    pub role: String,
    pub summary: String,
    pub default_budget: u64,
    pub max_retries: u8,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    pub completion_contract: LocalEngineWorkerCompletionContract,
    #[serde(default)]
    pub workflows: Vec<LocalEngineWorkerWorkflowRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineAgentPlaybookStepRecord {
    pub step_id: String,
    pub label: String,
    pub summary: String,
    pub worker_template_id: String,
    pub worker_workflow_id: String,
    pub goal_template: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineAgentPlaybookRecord {
    pub playbook_id: String,
    pub label: String,
    pub summary: String,
    pub goal_template: String,
    #[serde(default)]
    pub trigger_intents: Vec<String>,
    #[serde(default)]
    pub recommended_for: Vec<String>,
    pub default_budget: u64,
    pub completion_contract: LocalEngineWorkerCompletionContract,
    #[serde(default)]
    pub steps: Vec<LocalEngineAgentPlaybookStepRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineParentPlaybookReceiptRecord {
    pub event_id: String,
    pub timestamp_ms: u64,
    pub phase: String,
    pub status: String,
    pub success: bool,
    pub summary: String,
    #[serde(default)]
    pub receipt_ref: Option<String>,
    #[serde(default)]
    pub child_session_id: Option<String>,
    #[serde(default)]
    pub template_id: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub error_class: Option<String>,
    #[serde(default)]
    pub artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineParentPlaybookStepRunRecord {
    pub step_id: String,
    pub label: String,
    pub summary: String,
    pub status: String,
    #[serde(default)]
    pub child_session_id: Option<String>,
    #[serde(default)]
    pub template_id: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub updated_at_ms: Option<u64>,
    #[serde(default)]
    pub completed_at_ms: Option<u64>,
    #[serde(default)]
    pub error_class: Option<String>,
    #[serde(default)]
    pub receipts: Vec<LocalEngineParentPlaybookReceiptRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineParentPlaybookRunRecord {
    pub run_id: String,
    pub parent_session_id: String,
    pub playbook_id: String,
    pub playbook_label: String,
    pub status: String,
    pub latest_phase: String,
    pub summary: String,
    #[serde(default)]
    pub current_step_id: Option<String>,
    #[serde(default)]
    pub current_step_label: Option<String>,
    #[serde(default)]
    pub active_child_session_id: Option<String>,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub completed_at_ms: Option<u64>,
    #[serde(default)]
    pub error_class: Option<String>,
    #[serde(default)]
    pub steps: Vec<LocalEngineParentPlaybookStepRunRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineSnapshot {
    pub generated_at_ms: u64,
    pub total_native_tools: usize,
    pub pending_control_count: usize,
    pub pending_approval_count: usize,
    pub active_issue_count: usize,
    pub capabilities: Vec<LocalEngineCapabilityFamily>,
    pub compatibility_routes: Vec<LocalEngineCompatRoute>,
    pub pending_controls: Vec<LocalEngineControlAction>,
    pub jobs: Vec<LocalEngineJobRecord>,
    pub recent_activity: Vec<LocalEngineActivityRecord>,
    pub registry_models: Vec<LocalEngineModelRecord>,
    pub managed_backends: Vec<LocalEngineBackendRecord>,
    pub gallery_catalogs: Vec<LocalEngineGalleryCatalogRecord>,
    pub worker_templates: Vec<LocalEngineWorkerTemplateRecord>,
    pub agent_playbooks: Vec<LocalEngineAgentPlaybookRecord>,
    #[serde(default)]
    pub parent_playbook_runs: Vec<LocalEngineParentPlaybookRunRecord>,
    pub control_plane: LocalEngineControlPlane,
    pub staged_operations: Vec<LocalEngineStagedOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineRuntimeProfile {
    pub mode: String,
    pub endpoint: String,
    pub default_model: String,
    pub baseline_role: String,
    pub kernel_authority: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineStorageConfig {
    pub models_path: String,
    pub backends_path: String,
    pub artifacts_path: String,
    pub cache_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineWatchdogConfig {
    pub enabled: bool,
    pub idle_check_enabled: bool,
    pub idle_timeout: String,
    pub busy_check_enabled: bool,
    pub busy_timeout: String,
    pub check_interval: String,
    pub force_eviction_when_busy: bool,
    pub lru_eviction_max_retries: u32,
    pub lru_eviction_retry_interval: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineMemoryConfig {
    pub reclaimer_enabled: bool,
    pub threshold_percent: u8,
    pub prefer_gpu: bool,
    pub target_resource: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineBackendPolicyConfig {
    pub max_concurrency: u32,
    pub max_queued_requests: u32,
    pub parallel_backend_loads: u32,
    pub allow_parallel_requests: bool,
    pub health_probe_interval: String,
    pub log_level: String,
    pub auto_shutdown_on_idle: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineResponseConfig {
    pub retain_receipts_days: u32,
    pub persist_artifacts: bool,
    pub allow_streaming: bool,
    pub store_request_previews: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineApiConfig {
    pub bind_address: String,
    pub remote_access_enabled: bool,
    pub expose_compat_routes: bool,
    pub cors_mode: String,
    pub auth_mode: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineLauncherConfig {
    pub auto_start_on_boot: bool,
    pub reopen_studio_on_launch: bool,
    pub auto_check_updates: bool,
    pub release_channel: String,
    pub show_kernel_console: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineGallerySource {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub uri: String,
    pub enabled: bool,
    pub sync_status: String,
    pub compatibility_tier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineEnvironmentBinding {
    pub key: String,
    pub value: String,
    pub secret: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineStagedOperation {
    pub operation_id: String,
    pub subject_kind: String,
    pub operation: String,
    pub title: String,
    #[serde(default)]
    pub source_uri: Option<String>,
    #[serde(default)]
    pub subject_id: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    pub created_at_ms: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineControlPlane {
    pub runtime: LocalEngineRuntimeProfile,
    pub storage: LocalEngineStorageConfig,
    pub watchdog: LocalEngineWatchdogConfig,
    pub memory: LocalEngineMemoryConfig,
    pub backend_policy: LocalEngineBackendPolicyConfig,
    pub responses: LocalEngineResponseConfig,
    pub api: LocalEngineApiConfig,
    #[serde(default)]
    pub launcher: LocalEngineLauncherConfig,
    pub galleries: Vec<LocalEngineGallerySource>,
    pub environment: Vec<LocalEngineEnvironmentBinding>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub duration: String,
    pub actions: u32,
    pub cost: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    CommandRun,
    CommandStream,
    CodeSearch,
    FileRead,
    FileEdit,
    DiffCreated,
    TestRun,
    BrowserNavigate,
    BrowserSnapshot,
    Receipt,
    InfoNote,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventStatus {
    Success,
    Failure,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactType {
    Diff,
    File,
    Web,
    RunBundle,
    Report,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
pub struct ArtifactRef {
    pub artifact_id: String,
    pub artifact_type: ArtifactType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptDigest {
    pub receipt_id: String,
    pub policy_hash: String,
    pub decision: String,
    pub tier: String,
    pub reason_code: String,
    pub tool_name: String,
    pub budgets: Value,
    pub step_index: u32,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AgentEvent {
    pub event_id: String,
    pub timestamp: String,
    pub thread_id: String,
    pub step_index: u32,
    pub event_type: EventType,
    pub title: String,
    pub digest: Value,
    pub details: Value,
    #[serde(default)]
    pub artifact_refs: Vec<ArtifactRef>,
    pub receipt_ref: Option<String>,
    #[serde(default)]
    pub input_refs: Vec<String>,
    pub status: EventStatus,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Artifact {
    pub artifact_id: String,
    pub created_at: String,
    pub thread_id: String,
    pub artifact_type: ArtifactType,
    pub title: String,
    pub description: String,
    pub content_ref: String,
    pub metadata: Value,
    pub version: Option<u32>,
    pub parent_artifact_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SkillCatalogEntry {
    pub skill_hash: String,
    pub name: String,
    pub description: String,
    pub lifecycle_state: String,
    pub source_type: String,
    pub success_rate_bps: u32,
    pub sample_size: u32,
    pub archival_record_id: i64,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub source_evidence_hash: Option<String>,
    #[serde(default)]
    pub relative_path: Option<String>,
    pub stale: bool,
    #[ts(type = "{ name: string; description: string; parameters: string }")]
    pub definition: LlmToolDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeCollectionSourceRecord {
    pub source_id: String,
    pub kind: String,
    pub uri: String,
    #[serde(default)]
    pub poll_interval_minutes: Option<u64>,
    pub enabled: bool,
    pub sync_status: String,
    #[serde(default)]
    pub last_synced_at_ms: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeCollectionEntryRecord {
    pub entry_id: String,
    pub title: String,
    pub kind: String,
    pub scope: String,
    pub artifact_id: String,
    pub byte_count: usize,
    pub chunk_count: usize,
    #[serde(default)]
    pub archival_record_ids: Vec<i64>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub content_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeCollectionRecord {
    pub collection_id: String,
    pub label: String,
    #[serde(default)]
    pub description: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub active: bool,
    #[serde(default)]
    pub entries: Vec<KnowledgeCollectionEntryRecord>,
    #[serde(default)]
    pub sources: Vec<KnowledgeCollectionSourceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeCollectionEntryContent {
    pub collection_id: String,
    pub entry_id: String,
    pub title: String,
    pub kind: String,
    pub artifact_id: String,
    pub byte_count: usize,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeCollectionSearchHit {
    pub collection_id: String,
    pub entry_id: String,
    pub title: String,
    pub scope: String,
    pub score: f32,
    pub lexical_score: f32,
    #[serde(default)]
    pub semantic_score: Option<f32>,
    pub trust_level: String,
    pub snippet: String,
    pub archival_record_id: i64,
    #[serde(default)]
    pub inspect_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ActiveContextItem {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub summary: String,
    #[serde(default)]
    pub badge: Option<String>,
    #[serde(default)]
    pub secondary_badge: Option<String>,
    #[serde(default)]
    pub success_rate_bps: Option<u32>,
    #[serde(default)]
    pub sample_size: Option<u32>,
    #[serde(default)]
    pub focus_id: Option<String>,
    #[serde(default)]
    pub skill_hash: Option<String>,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub source_evidence_hash: Option<String>,
    #[serde(default)]
    pub relative_path: Option<String>,
    #[serde(default)]
    pub stale: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SkillSourceDiscoveredSkill {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub relative_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SkillSourceRecord {
    pub source_id: String,
    pub label: String,
    pub uri: String,
    pub kind: String,
    pub enabled: bool,
    pub sync_status: String,
    #[serde(default)]
    pub last_synced_at_ms: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub discovered_skills: Vec<SkillSourceDiscoveredSkill>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ContextConstraint {
    pub id: String,
    pub label: String,
    pub value: String,
    pub severity: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AtlasNode {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub summary: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub emphasis: Option<f32>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AtlasEdge {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub relation: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub weight: f32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AtlasNeighborhood {
    pub lens: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub focus_id: Option<String>,
    #[serde(default)]
    pub nodes: Vec<AtlasNode>,
    #[serde(default)]
    pub edges: Vec<AtlasEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillMacroStepView {
    pub index: u32,
    pub tool_name: String,
    pub target: String,
    pub params_json: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillBenchmarkView {
    pub sample_size: u32,
    pub success_rate_bps: u32,
    pub intervention_rate_bps: u32,
    pub policy_incident_rate_bps: u32,
    pub avg_cost: u64,
    pub avg_latency_ms: u64,
    pub passed: bool,
    pub last_evaluated_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillDetailView {
    pub skill_hash: String,
    pub name: String,
    pub description: String,
    pub lifecycle_state: String,
    pub source_type: String,
    pub archival_record_id: i64,
    pub success_rate_bps: u32,
    pub sample_size: u32,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub source_evidence_hash: Option<String>,
    #[serde(default)]
    pub relative_path: Option<String>,
    #[serde(default)]
    pub source_registry_id: Option<String>,
    #[serde(default)]
    pub source_registry_label: Option<String>,
    #[serde(default)]
    pub source_registry_uri: Option<String>,
    #[serde(default)]
    pub source_registry_kind: Option<String>,
    #[serde(default)]
    pub source_registry_sync_status: Option<String>,
    #[serde(default)]
    pub source_registry_relative_path: Option<String>,
    pub stale: bool,
    #[serde(default)]
    pub used_tools: Vec<String>,
    #[serde(default)]
    pub steps: Vec<SkillMacroStepView>,
    #[serde(default)]
    pub benchmark: SkillBenchmarkView,
    #[serde(default)]
    pub markdown: Option<String>,
    #[serde(default)]
    pub neighborhood: AtlasNeighborhood,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SubstrateProofReceipt {
    pub event_id: String,
    pub timestamp: String,
    pub step_index: u32,
    pub tool_name: String,
    pub query_hash: String,
    pub index_root: String,
    pub k: u32,
    pub ef_search: u32,
    pub candidate_limit: u32,
    pub candidate_total: u32,
    pub candidate_reranked: u32,
    pub candidate_truncated: bool,
    pub distance_metric: String,
    pub embedding_normalized: bool,
    #[serde(default)]
    pub proof_hash: Option<String>,
    #[serde(default)]
    pub proof_ref: Option<String>,
    #[serde(default)]
    pub certificate_mode: Option<String>,
    pub success: bool,
    #[serde(default)]
    pub error_class: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SubstrateProofView {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub skill_hash: Option<String>,
    pub summary: String,
    #[serde(default)]
    pub index_roots: Vec<String>,
    #[serde(default)]
    pub receipts: Vec<SubstrateProofReceipt>,
    #[serde(default)]
    pub neighborhood: AtlasNeighborhood,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ActiveContextSnapshot {
    pub session_id: String,
    pub goal: String,
    pub status: String,
    pub mode: String,
    pub current_tier: String,
    #[serde(default)]
    pub focus_id: String,
    #[serde(default)]
    pub active_skill_id: Option<String>,
    #[serde(default)]
    pub skills: Vec<ActiveContextItem>,
    #[serde(default)]
    pub tools: Vec<ActiveContextItem>,
    #[serde(default)]
    pub evidence: Vec<ActiveContextItem>,
    #[serde(default)]
    pub constraints: Vec<ContextConstraint>,
    #[serde(default)]
    pub recent_actions: Vec<String>,
    pub neighborhood: AtlasNeighborhood,
    #[serde(default)]
    pub substrate: Option<SubstrateProofView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasSearchResult {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub summary: String,
    pub score: f32,
    pub lens: String,
}

// Structured chat message for persistent history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String, // "user", "agent", "system", "tool"

    // We map backend `content` to frontend `text` for compatibility with UI components
    #[serde(alias = "content")]
    pub text: String,

    pub timestamp: u64,
}

// Represents a node in the hierarchical swarm visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmAgent {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub role: String,
    pub status: String, // "running", "completed", "failed", "requisition"
    pub budget_used: f64,
    pub budget_cap: f64,
    pub current_thought: Option<String>,
    #[serde(default)]
    pub artifacts_produced: u32,
    #[serde(default)]
    pub estimated_cost: f64,
    #[serde(default)]
    pub policy_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    pub kind: String,
    pub prompt: String,
    #[serde(default)]
    pub one_time: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClarificationOption {
    pub id: String,
    pub label: String,
    pub description: String,
    #[serde(default)]
    pub recommended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClarificationRequest {
    pub kind: String,
    pub question: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub failure_class: Option<String>,
    #[serde(default)]
    pub evidence_snippet: Option<String>,
    #[serde(default)]
    pub context_hint: Option<String>,
    #[serde(default)]
    pub options: Vec<ClarificationOption>,
    #[serde(default)]
    pub allow_other: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    pub id: String,
    pub intent: String,
    pub agent: String,
    pub phase: AgentPhase,
    pub progress: u32,
    pub total_steps: u32,
    pub current_step: String,
    pub gate_info: Option<GateInfo>,
    pub receipt: Option<Receipt>,
    pub visual_hash: Option<String>,
    pub pending_request_hash: Option<String>,
    pub session_id: Option<String>,
    #[serde(default)]
    pub credential_request: Option<CredentialRequest>,
    #[serde(default)]
    pub clarification_request: Option<ClarificationRequest>,

    // History source of truth.
    // This is populated by hydrating from the blockchain state (Audit Log).
    #[serde(default)]
    pub history: Vec<ChatMessage>,

    // New immutable event stream (canonical for new runs).
    #[serde(default)]
    pub events: Vec<AgentEvent>,

    // Macro artifacts for this thread.
    #[serde(default)]
    pub artifacts: Vec<Artifact>,

    // Run bundle artifact pointer (if created).
    #[serde(default)]
    pub run_bundle_id: Option<String>,

    // Track processed steps using a composite key "{step}:{tool}"
    #[serde(skip, default)]
    pub processed_steps: HashSet<String>,

    // The hierarchical swarm state for SwarmViz
    #[serde(default)]
    pub swarm_tree: Vec<SwarmAgent>,

    // Evolutionary Metadata (Genetics)
    #[serde(default)]
    pub generation: u64,

    #[serde(default = "default_lineage")]
    pub lineage_id: String,

    #[serde(default)]
    pub fitness_score: f32,
}

fn default_lineage() -> String {
    "genesis".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResponse {
    pub responded: bool,
    pub approved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum NotificationRail {
    Control,
    Assistant,
}

impl Default for NotificationRail {
    fn default() -> Self {
        Self::Assistant
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum NotificationSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Default for NotificationSeverity {
    fn default() -> Self {
        Self::Medium
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum InterventionStatus {
    New,
    Seen,
    Pending,
    Responded,
    Resolved,
    Expired,
    Cancelled,
}

impl Default for InterventionStatus {
    fn default() -> Self {
        Self::New
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum AssistantNotificationStatus {
    New,
    Seen,
    Acknowledged,
    Snoozed,
    Resolved,
    Dismissed,
    Expired,
    Archived,
}

impl Default for AssistantNotificationStatus {
    fn default() -> Self {
        Self::New
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum InterventionType {
    ApprovalGate,
    PiiReviewGate,
    ClarificationGate,
    CredentialGate,
    ReauthGate,
    DecisionGate,
    InterventionOutcome,
}

impl Default for InterventionType {
    fn default() -> Self {
        Self::ApprovalGate
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum AssistantNotificationClass {
    FollowUpRisk,
    DeadlineRisk,
    MeetingPrep,
    StalledWorkflow,
    ValuableCompletion,
    Digest,
    AutomationOpportunity,
    HabitualFriction,
    AuthAttention,
}

impl Default for AssistantNotificationClass {
    fn default() -> Self {
        Self::Digest
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum NotificationActionStyle {
    Primary,
    Secondary,
    Danger,
    Quiet,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum NotificationPreviewMode {
    Redacted,
    Compact,
    Full,
}

impl Default for NotificationPreviewMode {
    fn default() -> Self {
        Self::Redacted
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum ObservationTier {
    WorkflowState,
    ConnectorMetadata,
    RedactedConnectorContent,
    CoarseHostContext,
    DeepAmbientBehavior,
}

impl Default for ObservationTier {
    fn default() -> Self {
        Self::WorkflowState
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct NotificationAction {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub style: Option<NotificationActionStyle>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct NotificationDeliveryState {
    #[serde(default)]
    pub toast_sent: bool,
    #[serde(default)]
    pub inbox_visible: bool,
    #[serde(default)]
    pub badge_counted: bool,
    #[serde(default)]
    pub pill_visible: bool,
    #[serde(default)]
    pub last_toast_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPrivacy {
    #[serde(default)]
    pub preview_mode: NotificationPreviewMode,
    #[serde(default)]
    pub contains_sensitive_data: bool,
    #[serde(default)]
    pub observation_tier: ObservationTier,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct NotificationSource {
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub workflow_name: String,
    #[serde(default)]
    pub step_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPolicyRefs {
    #[serde(default)]
    pub policy_hash: Option<String>,
    #[serde(default)]
    pub request_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NotificationTarget {
    GmailThread {
        connector_id: String,
        thread_id: String,
        #[serde(default)]
        message_id: Option<String>,
    },
    CalendarEvent {
        connector_id: String,
        calendar_id: String,
        event_id: String,
    },
    ConnectorAuth {
        connector_id: String,
    },
    ConnectorSubscription {
        connector_id: String,
        subscription_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DetectorPolicyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub min_score: Option<f32>,
    #[serde(default)]
    pub min_age_minutes: Option<u32>,
    #[serde(default)]
    pub lead_time_minutes: Option<u32>,
    #[serde(default)]
    pub toast_min_score: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantAttentionGlobalPolicy {
    pub toasts_enabled: bool,
    pub badge_enabled: bool,
    pub digest_enabled: bool,
    #[serde(default)]
    pub hosted_inference_allowed: bool,
}

impl Default for AssistantAttentionGlobalPolicy {
    fn default() -> Self {
        Self {
            toasts_enabled: true,
            badge_enabled: true,
            digest_enabled: true,
            hosted_inference_allowed: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorAttentionPolicy {
    #[serde(default)]
    pub scan_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantUserProfile {
    pub version: u32,
    pub display_name: String,
    #[serde(default)]
    pub preferred_name: Option<String>,
    #[serde(default)]
    pub role_label: Option<String>,
    pub timezone: String,
    pub locale: String,
    #[serde(default)]
    pub primary_email: Option<String>,
    #[serde(default)]
    pub avatar_seed: String,
    #[serde(default)]
    pub grounding_allowed: bool,
}

impl Default for AssistantUserProfile {
    fn default() -> Self {
        let timezone = std::env::var("TZ")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| chrono::Local::now().offset().to_string());
        Self {
            version: 1,
            display_name: "Operator".to_string(),
            preferred_name: None,
            role_label: Some("Private Operator".to_string()),
            timezone,
            locale: "en-US".to_string(),
            primary_email: None,
            avatar_seed: "OP".to_string(),
            grounding_allowed: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantAttentionPolicy {
    pub version: u32,
    #[serde(default)]
    pub global: AssistantAttentionGlobalPolicy,
    #[serde(default)]
    pub detectors: HashMap<String, DetectorPolicyConfig>,
    #[serde(default)]
    pub connectors: HashMap<String, ConnectorAttentionPolicy>,
}

impl Default for AssistantAttentionPolicy {
    fn default() -> Self {
        let mut detectors = HashMap::new();
        detectors.insert(
            "valuable_completion".to_string(),
            DetectorPolicyConfig {
                enabled: true,
                min_score: Some(0.75),
                min_age_minutes: None,
                lead_time_minutes: None,
                toast_min_score: Some(0.9),
            },
        );
        detectors.insert(
            "deadline_risk".to_string(),
            DetectorPolicyConfig {
                enabled: true,
                min_score: Some(0.7),
                min_age_minutes: None,
                lead_time_minutes: Some(30),
                toast_min_score: Some(0.8),
            },
        );
        detectors.insert(
            "auth_attention".to_string(),
            DetectorPolicyConfig {
                enabled: true,
                min_score: Some(0.65),
                min_age_minutes: None,
                lead_time_minutes: None,
                toast_min_score: Some(0.85),
            },
        );
        detectors.insert(
            "follow_up_risk".to_string(),
            DetectorPolicyConfig {
                enabled: true,
                min_score: Some(0.72),
                min_age_minutes: Some(180),
                lead_time_minutes: None,
                toast_min_score: Some(0.9),
            },
        );
        detectors.insert(
            "meeting_prep".to_string(),
            DetectorPolicyConfig {
                enabled: true,
                min_score: Some(0.74),
                min_age_minutes: None,
                lead_time_minutes: Some(45),
                toast_min_score: Some(0.88),
            },
        );
        detectors.insert(
            "stalled_workflow".to_string(),
            DetectorPolicyConfig {
                enabled: true,
                min_score: Some(0.78),
                min_age_minutes: Some(10),
                lead_time_minutes: None,
                toast_min_score: Some(0.9),
            },
        );
        let mut connectors = HashMap::new();
        connectors.insert(
            "gmail".to_string(),
            ConnectorAttentionPolicy {
                scan_mode: Some("metadata_only".to_string()),
            },
        );
        connectors.insert(
            "calendar".to_string(),
            ConnectorAttentionPolicy {
                scan_mode: Some("metadata_only".to_string()),
            },
        );
        Self {
            version: 1,
            global: AssistantAttentionGlobalPolicy::default(),
            detectors,
            connectors,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantAttentionProfile {
    pub version: u32,
    #[serde(default)]
    pub preferred_surfaces: Vec<String>,
    #[serde(default)]
    pub high_value_contacts: Vec<String>,
    #[serde(default)]
    pub focus_windows: Vec<String>,
    #[serde(default)]
    pub notification_feedback: HashMap<String, HashMap<String, u32>>,
}

impl Default for AssistantAttentionProfile {
    fn default() -> Self {
        Self {
            version: 1,
            preferred_surfaces: vec!["inbox".to_string(), "pill".to_string()],
            high_value_contacts: Vec::new(),
            focus_windows: Vec::new(),
            notification_feedback: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct InterventionRecord {
    pub item_id: String,
    #[serde(default = "control_rail")]
    pub rail: NotificationRail,
    pub intervention_type: InterventionType,
    #[serde(default)]
    pub status: InterventionStatus,
    #[serde(default)]
    pub severity: NotificationSeverity,
    #[serde(default)]
    pub blocking: bool,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub recommended_action: Option<String>,
    #[serde(default)]
    pub consequence_if_ignored: Option<String>,
    #[serde(default)]
    pub created_at_ms: u64,
    #[serde(default)]
    pub updated_at_ms: u64,
    #[serde(default)]
    pub due_at_ms: Option<u64>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub snoozed_until_ms: Option<u64>,
    #[serde(default)]
    pub dedupe_key: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub delivery_state: NotificationDeliveryState,
    #[serde(default)]
    pub privacy: NotificationPrivacy,
    #[serde(default)]
    pub source: NotificationSource,
    #[serde(default)]
    pub artifact_refs: Vec<ArtifactRef>,
    #[serde(default)]
    pub source_event_ids: Vec<String>,
    #[serde(default)]
    pub policy_refs: NotificationPolicyRefs,
    #[serde(default)]
    pub actions: Vec<NotificationAction>,
    #[serde(default)]
    pub target: Option<NotificationTarget>,
    #[serde(default)]
    pub request_hash: Option<String>,
    #[serde(default)]
    pub policy_hash: Option<String>,
    #[serde(default)]
    pub approval_scope: Option<String>,
    #[serde(default)]
    pub sensitive_action_type: Option<String>,
    #[serde(default)]
    pub error_class: Option<String>,
    #[serde(default)]
    pub blocked_stage: Option<String>,
    #[serde(default)]
    pub retry_available: Option<bool>,
    #[serde(default)]
    pub recovery_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct AssistantNotificationRecord {
    pub item_id: String,
    #[serde(default)]
    pub rail: NotificationRail,
    pub notification_class: AssistantNotificationClass,
    #[serde(default)]
    pub status: AssistantNotificationStatus,
    #[serde(default)]
    pub severity: NotificationSeverity,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub recommended_action: Option<String>,
    #[serde(default)]
    pub consequence_if_ignored: Option<String>,
    #[serde(default)]
    pub created_at_ms: u64,
    #[serde(default)]
    pub updated_at_ms: u64,
    #[serde(default)]
    pub due_at_ms: Option<u64>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub snoozed_until_ms: Option<u64>,
    #[serde(default)]
    pub dedupe_key: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub delivery_state: NotificationDeliveryState,
    #[serde(default)]
    pub privacy: NotificationPrivacy,
    #[serde(default)]
    pub source: NotificationSource,
    #[serde(default)]
    pub artifact_refs: Vec<ArtifactRef>,
    #[serde(default)]
    pub source_event_ids: Vec<String>,
    #[serde(default)]
    pub policy_refs: NotificationPolicyRefs,
    #[serde(default)]
    pub actions: Vec<NotificationAction>,
    #[serde(default)]
    pub target: Option<NotificationTarget>,
    #[serde(default)]
    pub priority_score: f32,
    #[serde(default)]
    pub confidence_score: f32,
    #[serde(default)]
    pub ranking_reason: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn control_rail() -> NotificationRail {
    NotificationRail::Control
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextBlob {
    pub data_base64: String,
    pub mime_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostInputEvent {
    pub device: String,
    pub description: String,
}

// Struct for persistent session history index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String, // Hex encoded
    pub title: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetAutopilotDataResult {
    pub data_dir: String,
    pub removed_paths: Vec<String>,
    pub identity_preserved: bool,
    pub remote_history_may_persist: bool,
}

#[derive(Default)]
pub struct AppState {
    pub current_task: Option<AgentTask>,
    pub gate_response: Option<GateResponse>,
    pub is_simulating: bool,
    pub rpc_client: Option<PublicApiClient<Channel>>,
    pub event_index: HashMap<String, Vec<String>>,
    pub artifact_index: HashMap<String, Vec<String>>,

    // Shared kernel-owned runtime for inference, embeddings, and adjacent
    // absorbed model/media capability calls.
    pub inference_runtime: Option<Arc<dyn InferenceRuntime>>,

    // Primary local runtime for checkpoints, memory, events, artifacts, and cache state.
    pub memory_runtime: Option<Arc<MemoryRuntime>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serializes_agent_event_shape() {
        let event = AgentEvent {
            event_id: "evt-1".to_string(),
            timestamp: "2026-02-13T00:00:00Z".to_string(),
            thread_id: "thread-1".to_string(),
            step_index: 7,
            event_type: EventType::CommandRun,
            title: "Ran cargo test".to_string(),
            digest: json!({"tool":"cargo test"}),
            details: json!({"output":"ok"}),
            artifact_refs: vec![ArtifactRef {
                artifact_id: "art-1".to_string(),
                artifact_type: ArtifactType::Log,
            }],
            receipt_ref: Some("receipt-1".to_string()),
            input_refs: vec!["evt-0".to_string()],
            status: EventStatus::Success,
            duration_ms: Some(12),
        };

        let value = serde_json::to_value(&event).expect("serialize event");
        assert_eq!(value["event_id"], "evt-1");
        assert_eq!(value["event_type"], "COMMAND_RUN");
        assert_eq!(value["status"], "SUCCESS");
        assert_eq!(value["artifact_refs"][0]["artifact_type"], "LOG");
    }

    #[test]
    fn serializes_artifact_shape() {
        let artifact = Artifact {
            artifact_id: "art-1".to_string(),
            created_at: "2026-02-13T00:00:00Z".to_string(),
            thread_id: "thread-1".to_string(),
            artifact_type: ArtifactType::Diff,
            title: "Large diff".to_string(),
            description: "Diff exceeded threshold".to_string(),
            content_ref: "ioi-memory://artifact/art-1".to_string(),
            metadata: json!({"files_touched": 4}),
            version: Some(1),
            parent_artifact_id: None,
        };
        let value = serde_json::to_value(&artifact).expect("serialize artifact");
        assert_eq!(value["artifact_type"], "DIFF");
        assert_eq!(value["metadata"]["files_touched"], 4);
    }
}
