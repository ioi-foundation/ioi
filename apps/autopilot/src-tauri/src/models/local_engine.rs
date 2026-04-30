use serde::{Deserialize, Serialize};
use ts_rs::TS;

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
    #[serde(default)]
    pub harness_workflow_id: Option<String>,
    #[serde(default)]
    pub harness_activation_id: Option<String>,
    #[serde(default)]
    pub harness_hash: Option<String>,
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
    pub route_family: String,
    pub topology: String,
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
    pub control_plane_schema_version: u32,
    pub control_plane_profile_id: String,
    #[serde(default)]
    pub control_plane_migrations: Vec<LocalEngineConfigMigrationRecord>,
    pub control_plane: LocalEngineControlPlane,
    pub managed_settings: LocalEngineManagedSettingsSnapshot,
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
    pub cors_mode: String,
    pub auth_mode: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineLauncherConfig {
    pub auto_start_on_boot: bool,
    pub reopen_chat_on_launch: bool,
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
#[serde(rename_all = "camelCase")]
pub struct LocalEngineConfigMigrationRecord {
    pub migration_id: String,
    pub from_version: u32,
    pub to_version: u32,
    pub applied_at_ms: u64,
    pub summary: String,
    #[serde(default)]
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineControlPlaneDocument {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub profile_id: String,
    #[serde(default)]
    pub migrations: Vec<LocalEngineConfigMigrationRecord>,
    pub control_plane: LocalEngineControlPlane,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineManagedSettingsChannelRecord {
    pub channel_id: String,
    pub label: String,
    pub source_uri: String,
    pub status: String,
    pub verification_status: String,
    pub summary: String,
    #[serde(default)]
    pub precedence: i32,
    #[serde(default)]
    pub authority_label: Option<String>,
    #[serde(default)]
    pub signature_algorithm: Option<String>,
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub schema_version: Option<u32>,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub refreshed_at_ms: Option<u64>,
    #[serde(default)]
    pub local_override_count: usize,
    #[serde(default)]
    pub overridden_fields: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineManagedSettingsSnapshot {
    pub sync_status: String,
    pub summary: String,
    #[serde(default)]
    pub active_channel_id: Option<String>,
    #[serde(default)]
    pub active_channel_label: Option<String>,
    #[serde(default)]
    pub active_source_uri: Option<String>,
    #[serde(default)]
    pub last_refreshed_at_ms: Option<u64>,
    #[serde(default)]
    pub last_successful_refresh_at_ms: Option<u64>,
    #[serde(default)]
    pub last_failed_refresh_at_ms: Option<u64>,
    #[serde(default)]
    pub refresh_error: Option<String>,
    #[serde(default)]
    pub local_override_count: usize,
    #[serde(default)]
    pub local_override_fields: Vec<String>,
    #[serde(default)]
    pub channels: Vec<LocalEngineManagedSettingsChannelRecord>,
}
