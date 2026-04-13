// apps/autopilot/src-tauri/src/models.rs
use crate::kernel::connectors::{ConnectorCatalogEntry, ShieldPolicyState};
use ioi_api::studio::{
    ExecutionEnvelope, ExecutionStage, StudioArtifactBlueprint, StudioArtifactBrief,
    StudioArtifactCandidateSummary, StudioArtifactEditIntent, StudioArtifactExemplar,
    StudioArtifactIR, StudioArtifactJudgeResult, StudioArtifactOutputOrigin,
    StudioArtifactPreparationNeeds, StudioArtifactPreparedContextResolution,
    StudioArtifactRenderEvaluation, StudioArtifactRuntimeNarrationEvent,
    StudioArtifactSelectedSkill, StudioArtifactSelectionTarget,
    StudioArtifactSkillDiscoveryResolution, StudioArtifactTasteMemory, StudioArtifactUxLifecycle,
    SwarmChangeReceipt, SwarmExecutionSummary, SwarmMergeReceipt, SwarmPlan,
    SwarmVerificationReceipt, SwarmWorkerReceipt,
};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_memory::MemoryRuntime;
use ioi_types::app::agentic::{LlmToolDefinition, PiiTarget};
pub use ioi_types::app::{
    StudioArtifactClass, StudioArtifactDeliverableShape, StudioArtifactFailure,
    StudioArtifactFailureKind, StudioArtifactFileRole, StudioArtifactLifecycleState,
    StudioArtifactManifest, StudioArtifactManifestFile, StudioArtifactManifestStorage,
    StudioArtifactManifestTab, StudioArtifactManifestVerification, StudioArtifactPersistenceMode,
    StudioArtifactTabKind, StudioArtifactVerificationStatus, StudioExecutionSubstrate,
    StudioOutcomeArtifactRequest, StudioOutcomeArtifactScope,
    StudioOutcomeArtifactVerificationRequest, StudioOutcomeKind, StudioOutcomeRequest,
    StudioPresentationSurface, StudioRendererKind, StudioRuntimeProvenance,
    StudioRuntimeProvenanceKind, StudioVerifiedReply,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::transport::Channel;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
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
    pub control_plane_schema_version: u32,
    pub control_plane_profile_id: String,
    #[serde(default)]
    pub control_plane_migrations: Vec<LocalEngineConfigMigrationRecord>,
    pub control_plane: LocalEngineControlPlane,
    pub managed_settings: LocalEngineManagedSettingsSnapshot,
    pub staged_operations: Vec<LocalEngineStagedOperation>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityAuthorityDescriptor {
    pub tier_id: String,
    pub tier_label: String,
    #[serde(default)]
    pub governed_profile_id: Option<String>,
    #[serde(default)]
    pub governed_profile_label: Option<String>,
    pub summary: String,
    pub detail: String,
    #[serde(default)]
    pub signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityLeaseDescriptor {
    pub availability: String,
    pub availability_label: String,
    #[serde(default)]
    pub runtime_target_id: Option<String>,
    #[serde(default)]
    pub runtime_target_label: Option<String>,
    #[serde(default)]
    pub mode_id: Option<String>,
    #[serde(default)]
    pub mode_label: Option<String>,
    pub summary: String,
    pub detail: String,
    #[serde(default)]
    pub requires_auth: bool,
    #[serde(default)]
    pub signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityRegistryEntry {
    pub entry_id: String,
    pub kind: String,
    pub label: String,
    pub summary: String,
    pub source_kind: String,
    pub source_label: String,
    #[serde(default)]
    pub source_uri: Option<String>,
    pub trust_posture: String,
    #[serde(default)]
    pub governed_profile: Option<String>,
    pub availability: String,
    pub status_label: String,
    pub why_selectable: String,
    #[serde(default)]
    pub governing_family_id: Option<String>,
    #[serde(default)]
    pub related_governing_entry_ids: Vec<String>,
    #[serde(default)]
    pub governing_family_hints: Vec<String>,
    #[serde(default)]
    pub runtime_target: Option<String>,
    #[serde(default)]
    pub lease_mode: Option<String>,
    pub authority: CapabilityAuthorityDescriptor,
    pub lease: CapabilityLeaseDescriptor,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityRegistrySummary {
    pub generated_at_ms: u64,
    pub total_entries: usize,
    pub connector_count: usize,
    pub connected_connector_count: usize,
    pub runtime_skill_count: usize,
    pub tracked_source_count: usize,
    pub filesystem_skill_count: usize,
    pub extension_count: usize,
    pub model_count: usize,
    pub backend_count: usize,
    pub native_family_count: usize,
    pub pending_engine_control_count: usize,
    pub active_issue_count: usize,
    pub authoritative_source_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityRegistrySnapshot {
    pub generated_at_ms: u64,
    pub summary: CapabilityRegistrySummary,
    pub entries: Vec<CapabilityRegistryEntry>,
    pub connectors: Vec<ConnectorCatalogEntry>,
    pub skill_catalog: Vec<SkillCatalogEntry>,
    pub skill_sources: Vec<SkillSourceRecord>,
    pub extension_manifests: Vec<ExtensionManifestRecord>,
    pub local_engine: LocalEngineSnapshot,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantWorkbenchActivityRecord {
    pub activity_id: String,
    pub session_kind: String,
    pub surface: String,
    pub action: String,
    pub status: String,
    pub message: String,
    pub timestamp_ms: u64,
    #[serde(default)]
    pub source_notification_id: Option<String>,
    #[serde(default)]
    pub connector_id: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub evidence_thread_id: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
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
#[serde(rename_all = "camelCase")]
pub struct ExtensionContributionRecord {
    pub kind: String,
    pub label: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub item_count: Option<u32>,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionManifestRecord {
    pub extension_id: String,
    pub manifest_kind: String,
    pub manifest_path: String,
    pub root_path: String,
    pub source_label: String,
    pub source_uri: String,
    pub source_kind: String,
    pub enabled: bool,
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub developer_name: Option<String>,
    #[serde(default)]
    pub author_name: Option<String>,
    #[serde(default)]
    pub author_email: Option<String>,
    #[serde(default)]
    pub author_url: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    pub trust_posture: String,
    pub governed_profile: String,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub default_prompts: Vec<String>,
    #[serde(default)]
    pub contributions: Vec<ExtensionContributionRecord>,
    #[serde(default)]
    pub filesystem_skills: Vec<SkillSourceDiscoveredSkill>,
    #[serde(default)]
    pub marketplace_name: Option<String>,
    #[serde(default)]
    pub marketplace_display_name: Option<String>,
    #[serde(default)]
    pub marketplace_category: Option<String>,
    #[serde(default)]
    pub marketplace_installation_policy: Option<String>,
    #[serde(default)]
    pub marketplace_authentication_policy: Option<String>,
    #[serde(default)]
    pub marketplace_products: Vec<String>,
    #[serde(default)]
    pub marketplace_available_version: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_catalog_expires_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_catalog_refreshed_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_catalog_refresh_source: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_channel: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_source_id: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_source_label: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_source_uri: Option<String>,
    #[serde(default)]
    pub marketplace_package_url: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_refresh_bundle_id: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_refresh_bundle_label: Option<String>,
    #[serde(default)]
    pub marketplace_catalog_refresh_bundle_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_catalog_refresh_bundle_expires_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_catalog_refresh_available_version: Option<String>,
    #[serde(default)]
    pub marketplace_verification_status: Option<String>,
    #[serde(default)]
    pub marketplace_signature_algorithm: Option<String>,
    #[serde(default)]
    pub marketplace_signer_identity: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_id: Option<String>,
    #[serde(default)]
    pub marketplace_signing_key_id: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_label: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_trust_status: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_trust_source: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_root_id: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_root_label: Option<String>,
    #[serde(default)]
    pub marketplace_authority_bundle_id: Option<String>,
    #[serde(default)]
    pub marketplace_authority_bundle_label: Option<String>,
    #[serde(default)]
    pub marketplace_authority_bundle_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_authority_trust_bundle_id: Option<String>,
    #[serde(default)]
    pub marketplace_authority_trust_bundle_label: Option<String>,
    #[serde(default)]
    pub marketplace_authority_trust_bundle_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_authority_trust_bundle_expires_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_authority_trust_bundle_status: Option<String>,
    #[serde(default)]
    pub marketplace_authority_trust_issuer_id: Option<String>,
    #[serde(default)]
    pub marketplace_authority_trust_issuer_label: Option<String>,
    #[serde(default)]
    pub marketplace_authority_id: Option<String>,
    #[serde(default)]
    pub marketplace_authority_label: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_statement_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_publisher_trust_detail: Option<String>,
    #[serde(default)]
    pub marketplace_publisher_revoked_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_verification_error: Option<String>,
    #[serde(default)]
    pub marketplace_verified_at_ms: Option<u64>,
    #[serde(default)]
    pub marketplace_verification_source: Option<String>,
    #[serde(default)]
    pub marketplace_verified_digest_sha256: Option<String>,
    #[serde(default)]
    pub marketplace_trust_score_label: Option<String>,
    #[serde(default)]
    pub marketplace_trust_score_source: Option<String>,
    #[serde(default)]
    pub marketplace_trust_recommendation: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactNavigatorNode {
    pub id: String,
    pub label: String,
    pub kind: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub badge: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub lens: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub children: Vec<StudioArtifactNavigatorNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactMaterializationFileWrite {
    pub path: String,
    pub kind: String,
    #[serde(default)]
    pub content_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactMaterializationCommandIntent {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactMaterializationPreviewIntent {
    pub label: String,
    pub url: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactMaterializationVerificationStep {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactPipelineStep {
    pub id: String,
    pub stage: ExecutionStage,
    pub label: String,
    pub status: String,
    pub summary: String,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub verification_gate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactMaterializationContract {
    pub version: u32,
    pub request_kind: String,
    pub normalized_intent: String,
    pub summary: String,
    #[serde(default)]
    pub artifact_brief: Option<StudioArtifactBrief>,
    #[serde(default)]
    pub preparation_needs: Option<StudioArtifactPreparationNeeds>,
    #[serde(default)]
    pub prepared_context_resolution: Option<StudioArtifactPreparedContextResolution>,
    #[serde(default)]
    pub skill_discovery_resolution: Option<StudioArtifactSkillDiscoveryResolution>,
    #[serde(default)]
    pub blueprint: Option<StudioArtifactBlueprint>,
    #[serde(default)]
    pub artifact_ir: Option<StudioArtifactIR>,
    #[serde(default)]
    pub selected_skills: Vec<StudioArtifactSelectedSkill>,
    #[serde(default)]
    pub retrieved_exemplars: Vec<StudioArtifactExemplar>,
    #[serde(default)]
    pub edit_intent: Option<StudioArtifactEditIntent>,
    #[serde(default)]
    pub candidate_summaries: Vec<StudioArtifactCandidateSummary>,
    #[serde(default)]
    pub winning_candidate_id: Option<String>,
    #[serde(default)]
    pub winning_candidate_rationale: Option<String>,
    #[serde(default)]
    pub execution_envelope: Option<ExecutionEnvelope>,
    #[serde(default)]
    pub swarm_plan: Option<SwarmPlan>,
    #[serde(default)]
    pub swarm_execution: Option<SwarmExecutionSummary>,
    #[serde(default)]
    pub swarm_worker_receipts: Vec<SwarmWorkerReceipt>,
    #[serde(default, alias = "swarmPatchReceipts")]
    pub swarm_change_receipts: Vec<SwarmChangeReceipt>,
    #[serde(default)]
    pub swarm_merge_receipts: Vec<SwarmMergeReceipt>,
    #[serde(default)]
    pub swarm_verification_receipts: Vec<SwarmVerificationReceipt>,
    #[serde(default)]
    pub render_evaluation: Option<StudioArtifactRenderEvaluation>,
    #[serde(default)]
    pub judge: Option<StudioArtifactJudgeResult>,
    #[serde(default)]
    pub output_origin: Option<StudioArtifactOutputOrigin>,
    #[serde(default)]
    pub production_provenance: Option<StudioRuntimeProvenance>,
    #[serde(default)]
    pub acceptance_provenance: Option<StudioRuntimeProvenance>,
    #[serde(default)]
    pub fallback_used: bool,
    #[serde(default)]
    pub ux_lifecycle: Option<StudioArtifactUxLifecycle>,
    #[serde(default)]
    pub failure: Option<StudioArtifactFailure>,
    #[serde(default)]
    pub navigator_nodes: Vec<StudioArtifactNavigatorNode>,
    #[serde(default)]
    pub file_writes: Vec<StudioArtifactMaterializationFileWrite>,
    #[serde(default)]
    pub command_intents: Vec<StudioArtifactMaterializationCommandIntent>,
    #[serde(default)]
    pub preview_intent: Option<StudioArtifactMaterializationPreviewIntent>,
    #[serde(default)]
    pub verification_steps: Vec<StudioArtifactMaterializationVerificationStep>,
    #[serde(default)]
    pub pipeline_steps: Vec<StudioArtifactPipelineStep>,
    #[serde(default)]
    pub runtime_narration_events: Vec<StudioArtifactRuntimeNarrationEvent>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactRevision {
    pub revision_id: String,
    #[serde(default)]
    pub parent_revision_id: Option<String>,
    pub branch_id: String,
    pub branch_label: String,
    pub prompt: String,
    pub created_at: String,
    pub ux_lifecycle: StudioArtifactUxLifecycle,
    pub artifact_manifest: StudioArtifactManifest,
    #[serde(default)]
    pub artifact_brief: Option<StudioArtifactBrief>,
    #[serde(default)]
    pub preparation_needs: Option<StudioArtifactPreparationNeeds>,
    #[serde(default)]
    pub prepared_context_resolution: Option<StudioArtifactPreparedContextResolution>,
    #[serde(default)]
    pub skill_discovery_resolution: Option<StudioArtifactSkillDiscoveryResolution>,
    #[serde(default)]
    pub blueprint: Option<StudioArtifactBlueprint>,
    #[serde(default)]
    pub artifact_ir: Option<StudioArtifactIR>,
    #[serde(default)]
    pub selected_skills: Vec<StudioArtifactSelectedSkill>,
    #[serde(default)]
    pub retrieved_exemplars: Vec<StudioArtifactExemplar>,
    #[serde(default)]
    pub edit_intent: Option<StudioArtifactEditIntent>,
    #[serde(default)]
    pub candidate_summaries: Vec<StudioArtifactCandidateSummary>,
    #[serde(default)]
    pub winning_candidate_id: Option<String>,
    #[serde(default)]
    pub execution_envelope: Option<ExecutionEnvelope>,
    #[serde(default)]
    pub swarm_plan: Option<SwarmPlan>,
    #[serde(default)]
    pub swarm_execution: Option<SwarmExecutionSummary>,
    #[serde(default)]
    pub swarm_worker_receipts: Vec<SwarmWorkerReceipt>,
    #[serde(default, alias = "swarmPatchReceipts")]
    pub swarm_change_receipts: Vec<SwarmChangeReceipt>,
    #[serde(default)]
    pub swarm_merge_receipts: Vec<SwarmMergeReceipt>,
    #[serde(default)]
    pub swarm_verification_receipts: Vec<SwarmVerificationReceipt>,
    #[serde(default)]
    pub render_evaluation: Option<StudioArtifactRenderEvaluation>,
    #[serde(default)]
    pub judge: Option<StudioArtifactJudgeResult>,
    #[serde(default)]
    pub output_origin: Option<StudioArtifactOutputOrigin>,
    #[serde(default)]
    pub production_provenance: Option<StudioRuntimeProvenance>,
    #[serde(default)]
    pub acceptance_provenance: Option<StudioRuntimeProvenance>,
    #[serde(default)]
    pub failure: Option<StudioArtifactFailure>,
    #[serde(default)]
    pub file_writes: Vec<StudioArtifactMaterializationFileWrite>,
    #[serde(default)]
    pub taste_memory: Option<StudioArtifactTasteMemory>,
    #[serde(default)]
    pub selected_targets: Vec<StudioArtifactSelectionTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StudioBuildReceipt {
    pub receipt_id: String,
    pub kind: String,
    pub title: String,
    pub status: String,
    pub summary: String,
    pub started_at: String,
    #[serde(default)]
    pub finished_at: Option<String>,
    #[serde(default)]
    pub artifact_ids: Vec<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub duration_ms: Option<u64>,
    #[serde(default)]
    pub failure_class: Option<String>,
    #[serde(default)]
    pub replay_classification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StudioCodeWorkerLease {
    pub backend: String,
    pub planner_authority: String,
    #[serde(default)]
    pub allowed_mutation_scope: Vec<String>,
    #[serde(default)]
    pub allowed_command_classes: Vec<String>,
    pub execution_state: String,
    #[serde(default)]
    pub retry_classification: Option<String>,
    #[serde(default)]
    pub last_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StudioRendererSession {
    pub session_id: String,
    pub studio_session_id: String,
    pub renderer: StudioRendererKind,
    pub workspace_root: String,
    pub entry_document: String,
    #[serde(default)]
    pub preview_url: Option<String>,
    #[serde(default)]
    pub preview_process_id: Option<u32>,
    #[serde(default)]
    pub scaffold_recipe_id: Option<String>,
    #[serde(default)]
    pub presentation_variant_id: Option<String>,
    #[serde(default)]
    pub package_manager: Option<String>,
    pub status: String,
    pub verification_status: String,
    #[serde(default)]
    pub receipts: Vec<StudioBuildReceipt>,
    #[serde(default)]
    pub current_worker_execution: Option<StudioCodeWorkerLease>,
    pub current_tab: String,
    #[serde(default)]
    pub available_tabs: Vec<String>,
    #[serde(default)]
    pub ready_tabs: Vec<String>,
    pub retry_count: u32,
    #[serde(default)]
    pub last_failure_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactSession {
    pub session_id: String,
    pub thread_id: String,
    pub artifact_id: String,
    pub title: String,
    pub summary: String,
    pub current_lens: String,
    pub navigator_backing_mode: String,
    #[serde(default)]
    pub navigator_nodes: Vec<StudioArtifactNavigatorNode>,
    #[serde(default)]
    pub attached_artifact_ids: Vec<String>,
    #[serde(default)]
    pub available_lenses: Vec<String>,
    pub materialization: StudioArtifactMaterializationContract,
    pub outcome_request: StudioOutcomeRequest,
    pub artifact_manifest: StudioArtifactManifest,
    pub verified_reply: StudioVerifiedReply,
    pub lifecycle_state: StudioArtifactLifecycleState,
    pub status: String,
    #[serde(default)]
    pub active_revision_id: Option<String>,
    #[serde(default)]
    pub revisions: Vec<StudioArtifactRevision>,
    #[serde(default)]
    pub taste_memory: Option<StudioArtifactTasteMemory>,
    #[serde(default)]
    pub retrieved_exemplars: Vec<StudioArtifactExemplar>,
    #[serde(default)]
    pub selected_targets: Vec<StudioArtifactSelectionTarget>,
    #[serde(default)]
    pub ux_lifecycle: Option<StudioArtifactUxLifecycle>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub build_session_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub renderer_session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildArtifactSession {
    pub session_id: String,
    pub studio_session_id: String,
    pub workspace_root: String,
    pub entry_document: String,
    #[serde(default)]
    pub preview_url: Option<String>,
    #[serde(default)]
    pub preview_process_id: Option<u32>,
    pub scaffold_recipe_id: String,
    #[serde(default)]
    pub presentation_variant_id: Option<String>,
    pub package_manager: String,
    pub build_status: String,
    pub verification_status: String,
    #[serde(default)]
    pub receipts: Vec<StudioBuildReceipt>,
    pub current_worker_execution: StudioCodeWorkerLease,
    pub current_lens: String,
    #[serde(default)]
    pub available_lenses: Vec<String>,
    #[serde(default)]
    pub ready_lenses: Vec<String>,
    pub retry_count: u32,
    #[serde(default)]
    pub last_failure_summary: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionChecklistItem {
    pub item_id: String,
    pub label: String,
    pub status: String,
    #[serde(default)]
    pub detail: Option<String>,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionBackgroundTaskRecord {
    pub task_id: String,
    #[serde(default)]
    pub session_id: Option<String>,
    pub label: String,
    pub status: String,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub latest_output: Option<String>,
    #[serde(default)]
    pub can_stop: bool,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionFileContext {
    #[serde(default)]
    pub session_id: Option<String>,
    pub workspace_root: String,
    #[serde(default)]
    pub pinned_files: Vec<String>,
    #[serde(default)]
    pub recent_files: Vec<String>,
    #[serde(default)]
    pub explicit_includes: Vec<String>,
    #[serde(default)]
    pub explicit_excludes: Vec<String>,
    pub updated_at_ms: u64,
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

    #[serde(default)]
    pub session_checklist: Vec<SessionChecklistItem>,

    #[serde(default)]
    pub background_tasks: Vec<SessionBackgroundTaskRecord>,

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

    #[serde(default)]
    pub studio_session: Option<StudioArtifactSession>,

    #[serde(default)]
    pub studio_outcome: Option<StudioOutcomeRequest>,

    #[serde(default)]
    pub renderer_session: Option<StudioRendererSession>,

    #[serde(default)]
    pub build_session: Option<BuildArtifactSession>,

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

fn runtime_view_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn truncated_runtime_detail(value: &str, max_chars: usize) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut chars = trimmed.chars();
    let shortened: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        Some(format!("{}...", shortened))
    } else {
        Some(trimmed.to_string())
    }
}

fn latest_task_output_excerpt(task: &AgentTask) -> Option<String> {
    task.history
        .iter()
        .rev()
        .find(|message| {
            !message.text.trim().is_empty()
                && matches!(message.role.as_str(), "assistant" | "agent" | "system")
        })
        .and_then(|message| truncated_runtime_detail(&message.text, 120))
        .or_else(|| truncated_runtime_detail(&task.current_step, 120))
}

fn checklist_request_item(task: &AgentTask, updated_at_ms: u64) -> SessionChecklistItem {
    SessionChecklistItem {
        item_id: "request".to_string(),
        label: "Request captured".to_string(),
        status: "completed".to_string(),
        detail: truncated_runtime_detail(&task.intent, 96),
        updated_at_ms,
    }
}

fn checklist_execution_item(task: &AgentTask, updated_at_ms: u64) -> SessionChecklistItem {
    let is_blocked = task.clarification_request.is_some()
        || task.credential_request.is_some()
        || task.phase == AgentPhase::Gate
        || task.pending_request_hash.is_some();
    let status = if is_blocked {
        "blocked"
    } else {
        match task.phase {
            AgentPhase::Idle => "pending",
            AgentPhase::Running => "in_progress",
            AgentPhase::Gate => "blocked",
            AgentPhase::Complete => "completed",
            AgentPhase::Failed => "failed",
        }
    };

    let detail = if matches!(task.phase, AgentPhase::Complete | AgentPhase::Failed) {
        truncated_runtime_detail(&task.current_step, 120)
            .or_else(|| latest_task_output_excerpt(task))
    } else {
        truncated_runtime_detail(&task.current_step, 120)
    };

    SessionChecklistItem {
        item_id: "execution".to_string(),
        label: if is_blocked {
            "Resolve blocker".to_string()
        } else {
            match task.phase {
                AgentPhase::Failed => "Execution failed".to_string(),
                AgentPhase::Complete => "Execution complete".to_string(),
                _ => "Continue execution".to_string(),
            }
        },
        status: status.to_string(),
        detail,
        updated_at_ms,
    }
}

fn checklist_interruption_item(
    task: &AgentTask,
    updated_at_ms: u64,
) -> Option<SessionChecklistItem> {
    if let Some(request) = task.clarification_request.as_ref() {
        return Some(SessionChecklistItem {
            item_id: "clarification".to_string(),
            label: "Resolve clarification".to_string(),
            status: "blocked".to_string(),
            detail: truncated_runtime_detail(&request.question, 120),
            updated_at_ms,
        });
    }

    if let Some(request) = task.credential_request.as_ref() {
        return Some(SessionChecklistItem {
            item_id: "credential".to_string(),
            label: "Provide runtime credential".to_string(),
            status: "blocked".to_string(),
            detail: truncated_runtime_detail(&request.prompt, 120)
                .or_else(|| truncated_runtime_detail(&request.kind, 80)),
            updated_at_ms,
        });
    }

    if task.phase == AgentPhase::Gate || task.pending_request_hash.is_some() {
        return Some(SessionChecklistItem {
            item_id: "approval".to_string(),
            label: "Review approval".to_string(),
            status: "blocked".to_string(),
            detail: task
                .gate_info
                .as_ref()
                .and_then(|gate| {
                    truncated_runtime_detail(&gate.description, 120)
                        .or_else(|| truncated_runtime_detail(&gate.title, 80))
                })
                .or_else(|| Some("Execution is waiting on operator approval.".to_string())),
            updated_at_ms,
        });
    }

    None
}

fn checklist_review_item(task: &AgentTask, updated_at_ms: u64) -> SessionChecklistItem {
    let latest_output = latest_task_output_excerpt(task);
    let is_blocked = task.clarification_request.is_some()
        || task.credential_request.is_some()
        || task.phase == AgentPhase::Gate
        || task.pending_request_hash.is_some();
    let (label, status, detail) = match task.phase {
        AgentPhase::Complete => (
            "Review latest output",
            "completed",
            latest_output
                .or_else(|| Some("Run finished without a retained output excerpt.".to_string())),
        ),
        AgentPhase::Failed => (
            "Decide next step",
            "blocked",
            Some("Retry the run or start a new session once the blocker is addressed.".to_string()),
        ),
        AgentPhase::Running | AgentPhase::Gate => (
            if is_blocked {
                "Resume execution"
            } else {
                "Review emerging output"
            },
            if is_blocked { "blocked" } else { "pending" },
            if is_blocked {
                checklist_interruption_item(task, updated_at_ms)
                    .and_then(|item| item.detail)
                    .or_else(|| Some("Answer the blocker so the runtime can continue.".to_string()))
            } else {
                latest_output.or_else(|| {
                    Some("Waiting for the next retained output from the runtime.".to_string())
                })
            },
        ),
        AgentPhase::Idle => (
            "Await next request",
            "pending",
            Some("Start or resume a session to produce output.".to_string()),
        ),
    };

    SessionChecklistItem {
        item_id: "review".to_string(),
        label: label.to_string(),
        status: status.to_string(),
        detail,
        updated_at_ms,
    }
}

fn build_session_checklist(task: &AgentTask, updated_at_ms: u64) -> Vec<SessionChecklistItem> {
    let mut items = vec![checklist_request_item(task, updated_at_ms)];

    if let Some(interruption) = checklist_interruption_item(task, updated_at_ms) {
        items.push(interruption);
    }

    items.push(checklist_execution_item(task, updated_at_ms));
    items.push(checklist_review_item(task, updated_at_ms));
    items
}

fn build_background_tasks(
    task: &AgentTask,
    updated_at_ms: u64,
) -> Vec<SessionBackgroundTaskRecord> {
    let session_id = task.session_id.clone().or_else(|| Some(task.id.clone()));
    let is_blocked = task.clarification_request.is_some()
        || task.credential_request.is_some()
        || task.phase == AgentPhase::Gate
        || task.pending_request_hash.is_some();

    let status = if is_blocked {
        "blocked"
    } else {
        match task.phase {
            AgentPhase::Idle => "pending",
            AgentPhase::Running => "running",
            AgentPhase::Gate => "blocked",
            AgentPhase::Complete => "completed",
            AgentPhase::Failed => "failed",
        }
    };

    let detail = if is_blocked {
        checklist_interruption_item(task, updated_at_ms).and_then(|item| item.detail)
    } else {
        truncated_runtime_detail(&task.current_step, 120)
    };

    vec![SessionBackgroundTaskRecord {
        task_id: task.id.clone(),
        session_id,
        label: truncated_runtime_detail(&task.intent, 72)
            .unwrap_or_else(|| "Session run".to_string()),
        status: status.to_string(),
        detail,
        latest_output: latest_task_output_excerpt(task),
        can_stop: matches!(task.phase, AgentPhase::Running | AgentPhase::Gate) || is_blocked,
        updated_at_ms,
    }]
}

impl AgentTask {
    pub fn sync_runtime_views(&mut self) {
        let updated_at_ms = runtime_view_now_ms();
        self.session_checklist = build_session_checklist(self, updated_at_ms);
        self.background_tasks = build_background_tasks(self, updated_at_ms);
    }
}

#[cfg(test)]
mod runtime_view_tests {
    use super::*;
    use std::collections::HashSet;

    fn sample_task(phase: AgentPhase) -> AgentTask {
        AgentTask {
            id: "task-1".to_string(),
            intent: "Prepare release checklist".to_string(),
            agent: "Autopilot".to_string(),
            phase,
            progress: 0,
            total_steps: 3,
            current_step: "Inspecting retained output".to_string(),
            gate_info: None,
            receipt: None,
            visual_hash: None,
            pending_request_hash: None,
            session_id: Some("task-1".to_string()),
            credential_request: None,
            clarification_request: None,
            session_checklist: Vec::new(),
            background_tasks: Vec::new(),
            history: vec![ChatMessage {
                role: "agent".to_string(),
                text: "Drafted the first pass of the checklist.".to_string(),
                timestamp: 0,
            }],
            events: Vec::new(),
            artifacts: Vec::new(),
            studio_session: None,
            studio_outcome: None,
            renderer_session: None,
            build_session: None,
            run_bundle_id: None,
            processed_steps: HashSet::new(),
            swarm_tree: Vec::new(),
            generation: 0,
            lineage_id: "genesis".to_string(),
            fitness_score: 0.0,
        }
    }

    #[test]
    fn sync_runtime_views_marks_clarification_as_blocked() {
        let mut task = sample_task(AgentPhase::Complete);
        task.clarification_request = Some(ClarificationRequest {
            kind: "intent_resolution".to_string(),
            question: "Which release branch should I target?".to_string(),
            tool_name: "AskUserQuestion".to_string(),
            failure_class: None,
            evidence_snippet: None,
            context_hint: None,
            options: Vec::new(),
            allow_other: true,
        });

        task.sync_runtime_views();

        assert!(task
            .session_checklist
            .iter()
            .any(|item| item.item_id == "clarification" && item.status == "blocked"));
        assert_eq!(task.background_tasks[0].status, "blocked");
    }

    #[test]
    fn sync_runtime_views_exposes_latest_output_for_completed_tasks() {
        let mut task = sample_task(AgentPhase::Complete);
        task.sync_runtime_views();

        assert!(task
            .session_checklist
            .iter()
            .any(|item| item.item_id == "review" && item.status == "completed"));
        assert_eq!(
            task.background_tasks[0].latest_output.as_deref(),
            Some("Drafted the first pass of the checklist.")
        );
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StudioLaunchReceipt {
    pub timestamp_ms: u64,
    pub stage: String,
    pub detail: Value,
}

// Struct for persistent session history index
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionSummary {
    pub session_id: String, // Hex encoded
    pub title: String,
    pub timestamp: u64,
    #[serde(default)]
    pub phase: Option<AgentPhase>,
    #[serde(default)]
    pub current_step: Option<String>,
    #[serde(default)]
    pub resume_hint: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum SessionMemoryClass {
    Ephemeral,
    CarryForward,
    Pinned,
    GovernanceCritical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum SessionCompactionMode {
    Manual,
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionPolicy {
    #[serde(default)]
    pub carry_pinned_only: bool,
    #[serde(default = "session_compaction_policy_true")]
    pub preserve_checklist_state: bool,
    #[serde(default = "session_compaction_policy_true")]
    pub preserve_background_tasks: bool,
    #[serde(default = "session_compaction_policy_true")]
    pub preserve_latest_output_excerpt: bool,
    #[serde(default = "session_compaction_policy_true")]
    pub preserve_governance_blockers: bool,
    #[serde(default)]
    pub aggressive_transcript_pruning: bool,
}

fn session_compaction_policy_true() -> bool {
    true
}

impl Default for SessionCompactionPolicy {
    fn default() -> Self {
        Self {
            carry_pinned_only: false,
            preserve_checklist_state: true,
            preserve_background_tasks: true,
            preserve_latest_output_excerpt: true,
            preserve_governance_blockers: true,
            aggressive_transcript_pruning: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum SessionCompactionDisposition {
    CarryForward,
    RetainedSummary,
    Pruned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum SessionCompactionResumeSafetyStatus {
    Protected,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionResumeSafetyReceipt {
    pub status: SessionCompactionResumeSafetyStatus,
    #[serde(default)]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionMemoryItem {
    pub key: String,
    pub label: String,
    pub memory_class: SessionMemoryClass,
    #[serde(default)]
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionPruneDecision {
    pub key: String,
    pub label: String,
    pub disposition: SessionCompactionDisposition,
    pub detail_count: usize,
    pub rationale: String,
    pub summary: String,
    #[serde(default)]
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionCarryForwardState {
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub pinned_files: Vec<String>,
    #[serde(default)]
    pub explicit_includes: Vec<String>,
    #[serde(default)]
    pub explicit_excludes: Vec<String>,
    #[serde(default)]
    pub checklist_labels: Vec<String>,
    #[serde(default)]
    pub background_task_labels: Vec<String>,
    #[serde(default)]
    pub blocked_on: Option<String>,
    #[serde(default)]
    pub pending_decision_context: Option<String>,
    #[serde(default)]
    pub latest_artifact_outcome: Option<String>,
    #[serde(default)]
    pub execution_targets: Vec<String>,
    #[serde(default)]
    pub latest_output_excerpt: Option<String>,
    #[serde(default)]
    pub memory_items: Vec<SessionCompactionMemoryItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionPreview {
    pub session_id: String,
    pub title: String,
    #[serde(default)]
    pub phase: Option<AgentPhase>,
    pub policy: SessionCompactionPolicy,
    pub pre_compaction_span: String,
    pub summary: String,
    pub resume_anchor: String,
    pub carried_forward_state: SessionCompactionCarryForwardState,
    pub resume_safety: SessionCompactionResumeSafetyReceipt,
    #[serde(default)]
    pub prune_decisions: Vec<SessionCompactionPruneDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionRecord {
    pub compaction_id: String,
    pub session_id: String,
    pub title: String,
    pub compacted_at_ms: u64,
    pub mode: SessionCompactionMode,
    #[serde(default)]
    pub phase: Option<AgentPhase>,
    #[serde(default)]
    pub policy: SessionCompactionPolicy,
    pub pre_compaction_span: String,
    pub summary: String,
    pub resume_anchor: String,
    pub carried_forward_state: SessionCompactionCarryForwardState,
    pub resume_safety: SessionCompactionResumeSafetyReceipt,
    #[serde(default)]
    pub prune_decisions: Vec<SessionCompactionPruneDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionRecommendation {
    pub should_compact: bool,
    #[serde(default)]
    pub reason_labels: Vec<String>,
    #[serde(default)]
    pub recommended_policy: SessionCompactionPolicy,
    #[serde(default)]
    pub recommended_policy_label: String,
    #[serde(default)]
    pub recommended_policy_reason_labels: Vec<String>,
    #[serde(default)]
    pub resume_safeguard_labels: Vec<String>,
    pub history_count: usize,
    pub event_count: usize,
    pub artifact_count: usize,
    pub pinned_file_count: usize,
    pub explicit_include_count: usize,
    pub idle_age_ms: u64,
    #[serde(default)]
    pub blocked_age_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionDurabilityPortfolio {
    pub retained_session_count: usize,
    pub compacted_session_count: usize,
    pub replay_ready_session_count: usize,
    pub uncompacted_session_count: usize,
    pub stale_compaction_count: usize,
    pub degraded_compaction_count: usize,
    pub recommended_compaction_count: usize,
    pub compacted_without_team_memory_count: usize,
    pub team_memory_entry_count: usize,
    pub team_memory_covered_session_count: usize,
    pub team_memory_redacted_session_count: usize,
    pub team_memory_review_required_session_count: usize,
    #[serde(default)]
    pub coverage_summary: String,
    #[serde(default)]
    pub team_memory_summary: String,
    #[serde(default)]
    pub attention_summary: String,
    #[serde(default)]
    pub attention_labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionSnapshot {
    pub generated_at_ms: u64,
    #[serde(default)]
    pub active_session_id: Option<String>,
    #[serde(default)]
    pub active_session_title: Option<String>,
    pub policy_for_active: SessionCompactionPolicy,
    pub record_count: usize,
    #[serde(default)]
    pub latest_for_active: Option<SessionCompactionRecord>,
    #[serde(default)]
    pub preview_for_active: Option<SessionCompactionPreview>,
    #[serde(default)]
    pub recommendation_for_active: Option<SessionCompactionRecommendation>,
    #[serde(default)]
    pub durability_portfolio: SessionDurabilityPortfolio,
    #[serde(default)]
    pub records: Vec<SessionCompactionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum TeamMemoryScopeKind {
    Workspace,
    Session,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum TeamMemorySyncStatus {
    Synced,
    Redacted,
    ReviewRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemoryRedactionSummary {
    pub redaction_count: usize,
    #[serde(default)]
    pub redacted_fields: Vec<String>,
    pub redaction_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemorySyncEntry {
    pub entry_id: String,
    pub session_id: String,
    pub session_title: String,
    pub synced_at_ms: u64,
    pub scope_kind: TeamMemoryScopeKind,
    pub scope_id: String,
    pub scope_label: String,
    pub actor_id: String,
    pub actor_label: String,
    pub actor_role: String,
    pub sync_status: TeamMemorySyncStatus,
    pub review_summary: String,
    pub omitted_governance_item_count: usize,
    pub resume_anchor: String,
    pub pre_compaction_span: String,
    pub summary: String,
    #[serde(default)]
    pub shared_memory_items: Vec<SessionCompactionMemoryItem>,
    pub redaction: TeamMemoryRedactionSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemorySyncSnapshot {
    pub generated_at_ms: u64,
    #[serde(default)]
    pub active_session_id: Option<String>,
    #[serde(default)]
    pub active_scope_id: Option<String>,
    #[serde(default)]
    pub active_scope_kind: Option<TeamMemoryScopeKind>,
    #[serde(default)]
    pub active_scope_label: Option<String>,
    pub entry_count: usize,
    pub redacted_entry_count: usize,
    pub review_required_count: usize,
    pub summary: String,
    #[serde(default)]
    pub entries: Vec<TeamMemorySyncEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionProjection {
    pub task: Option<AgentTask>,
    pub sessions: Vec<SessionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRewindCandidate {
    pub session_id: String,
    pub title: String,
    pub timestamp: u64,
    #[serde(default)]
    pub phase: Option<AgentPhase>,
    #[serde(default)]
    pub current_step: Option<String>,
    #[serde(default)]
    pub resume_hint: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    pub is_current: bool,
    pub is_last_stable: bool,
    pub action_label: String,
    pub preview_headline: String,
    pub preview_detail: String,
    pub discard_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRewindSnapshot {
    #[serde(default)]
    pub active_session_id: Option<String>,
    #[serde(default)]
    pub active_session_title: Option<String>,
    #[serde(default)]
    pub last_stable_session_id: Option<String>,
    pub candidates: Vec<SessionRewindCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionHookReceiptSummary {
    pub title: String,
    pub timestamp_ms: u64,
    pub tool_name: String,
    pub status: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionHookRecord {
    pub hook_id: String,
    #[serde(default)]
    pub entry_id: Option<String>,
    pub label: String,
    pub owner_label: String,
    pub source_label: String,
    pub source_kind: String,
    #[serde(default)]
    pub source_uri: Option<String>,
    #[serde(default)]
    pub contribution_path: Option<String>,
    pub trigger_label: String,
    pub enabled: bool,
    pub status_label: String,
    pub trust_posture: String,
    pub governed_profile: String,
    pub authority_tier_label: String,
    pub availability_label: String,
    pub session_scope_label: String,
    pub why_active: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionHookSnapshot {
    pub generated_at_ms: u64,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    pub active_hook_count: usize,
    pub disabled_hook_count: usize,
    pub runtime_receipt_count: usize,
    pub approval_receipt_count: usize,
    pub hooks: Vec<SessionHookRecord>,
    #[serde(default)]
    pub recent_receipts: Vec<SessionHookReceiptSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionBranchRecord {
    pub branch_name: String,
    #[serde(default)]
    pub upstream_branch: Option<String>,
    pub is_current: bool,
    #[serde(default)]
    pub ahead_count: u32,
    #[serde(default)]
    pub behind_count: u32,
    #[serde(default)]
    pub last_commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionWorktreeRecord {
    pub path: String,
    #[serde(default)]
    pub branch_name: Option<String>,
    #[serde(default)]
    pub head: Option<String>,
    #[serde(default)]
    pub last_commit: Option<String>,
    #[serde(default)]
    pub changed_file_count: usize,
    #[serde(default)]
    pub dirty: bool,
    #[serde(default)]
    pub is_current: bool,
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub lock_reason: Option<String>,
    #[serde(default)]
    pub prunable: bool,
    #[serde(default)]
    pub prune_reason: Option<String>,
    pub status_label: String,
    pub status_detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionBranchSnapshot {
    pub generated_at_ms: u64,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    pub is_repo: bool,
    #[serde(default)]
    pub repo_label: Option<String>,
    #[serde(default)]
    pub current_branch: Option<String>,
    #[serde(default)]
    pub upstream_branch: Option<String>,
    #[serde(default)]
    pub last_commit: Option<String>,
    #[serde(default)]
    pub ahead_count: u32,
    #[serde(default)]
    pub behind_count: u32,
    #[serde(default)]
    pub changed_file_count: usize,
    #[serde(default)]
    pub dirty: bool,
    pub worktree_risk_label: String,
    pub worktree_risk_detail: String,
    #[serde(default)]
    pub recent_branches: Vec<SessionBranchRecord>,
    #[serde(default)]
    pub worktrees: Vec<SessionWorktreeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionRemoteEnvBinding {
    pub key: String,
    pub value_preview: String,
    pub source_label: String,
    pub scope_label: String,
    pub provenance_label: String,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionRemoteEnvSnapshot {
    pub generated_at_ms: u64,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    pub focused_scope_label: String,
    pub governing_source_label: String,
    pub posture_label: String,
    pub posture_detail: String,
    #[serde(default)]
    pub binding_count: usize,
    #[serde(default)]
    pub control_plane_binding_count: usize,
    #[serde(default)]
    pub process_binding_count: usize,
    #[serde(default)]
    pub overlapping_binding_count: usize,
    #[serde(default)]
    pub secret_binding_count: usize,
    #[serde(default)]
    pub redacted_binding_count: usize,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub bindings: Vec<SessionRemoteEnvBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionServerSessionRecord {
    pub session_id: String,
    pub title: String,
    pub timestamp: u64,
    pub source_label: String,
    #[serde(default)]
    pub presence_state: String,
    #[serde(default)]
    pub presence_label: String,
    #[serde(default)]
    pub resume_hint: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionServerSnapshot {
    pub generated_at_ms: u64,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    pub rpc_url: String,
    pub rpc_source_label: String,
    pub continuity_mode_label: String,
    pub continuity_status_label: String,
    pub continuity_detail: String,
    pub kernel_connection_label: String,
    pub kernel_connection_detail: String,
    #[serde(default)]
    pub explicit_rpc_target: bool,
    #[serde(default)]
    pub remote_kernel_target: bool,
    #[serde(default)]
    pub kernel_reachable: bool,
    #[serde(default)]
    pub remote_history_available: bool,
    #[serde(default)]
    pub local_session_count: usize,
    #[serde(default)]
    pub remote_session_count: usize,
    #[serde(default)]
    pub merged_session_count: usize,
    #[serde(default)]
    pub remote_only_session_count: usize,
    #[serde(default)]
    pub overlapping_session_count: usize,
    #[serde(default)]
    pub remote_attachable_session_count: usize,
    #[serde(default)]
    pub remote_history_only_session_count: usize,
    #[serde(default)]
    pub current_session_visible_remotely: bool,
    #[serde(default)]
    pub current_session_continuity_state: String,
    #[serde(default)]
    pub current_session_continuity_label: String,
    #[serde(default)]
    pub current_session_continuity_detail: String,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub recent_remote_sessions: Vec<SessionServerSessionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct VoiceInputTranscriptionRequest {
    pub audio_base64: String,
    pub mime_type: String,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct VoiceInputTranscriptionResult {
    pub text: String,
    pub mime_type: String,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub model_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionPluginLifecycleReceipt {
    pub receipt_id: String,
    pub timestamp_ms: u64,
    pub plugin_id: String,
    pub plugin_label: String,
    pub action: String,
    pub status: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionPluginRecord {
    pub plugin_id: String,
    #[serde(default)]
    pub entry_id: Option<String>,
    pub label: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    pub source_enabled: bool,
    pub enabled: bool,
    pub status_label: String,
    pub source_label: String,
    pub source_kind: String,
    #[serde(default)]
    pub source_uri: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub marketplace_display_name: Option<String>,
    #[serde(default)]
    pub marketplace_installation_policy: Option<String>,
    #[serde(default)]
    pub marketplace_authentication_policy: Option<String>,
    #[serde(default)]
    pub marketplace_products: Vec<String>,
    pub authenticity_state: String,
    pub authenticity_label: String,
    pub authenticity_detail: String,
    #[serde(default)]
    pub verification_error: Option<String>,
    #[serde(default)]
    pub verification_algorithm: Option<String>,
    #[serde(default)]
    pub publisher_label: Option<String>,
    #[serde(default)]
    pub publisher_id: Option<String>,
    #[serde(default)]
    pub signer_identity: Option<String>,
    #[serde(default)]
    pub signing_key_id: Option<String>,
    #[serde(default)]
    pub verification_timestamp_ms: Option<u64>,
    #[serde(default)]
    pub verification_source: Option<String>,
    #[serde(default)]
    pub verified_digest_sha256: Option<String>,
    #[serde(default)]
    pub publisher_trust_state: Option<String>,
    #[serde(default)]
    pub publisher_trust_label: Option<String>,
    #[serde(default)]
    pub publisher_trust_detail: Option<String>,
    #[serde(default)]
    pub publisher_trust_source: Option<String>,
    #[serde(default)]
    pub publisher_root_id: Option<String>,
    #[serde(default)]
    pub publisher_root_label: Option<String>,
    #[serde(default)]
    pub authority_bundle_id: Option<String>,
    #[serde(default)]
    pub authority_bundle_label: Option<String>,
    #[serde(default)]
    pub authority_bundle_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub authority_trust_bundle_id: Option<String>,
    #[serde(default)]
    pub authority_trust_bundle_label: Option<String>,
    #[serde(default)]
    pub authority_trust_bundle_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub authority_trust_bundle_expires_at_ms: Option<u64>,
    #[serde(default)]
    pub authority_trust_bundle_status: Option<String>,
    #[serde(default)]
    pub authority_trust_issuer_id: Option<String>,
    #[serde(default)]
    pub authority_trust_issuer_label: Option<String>,
    #[serde(default)]
    pub authority_id: Option<String>,
    #[serde(default)]
    pub authority_label: Option<String>,
    #[serde(default)]
    pub publisher_statement_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub publisher_revoked_at_ms: Option<u64>,
    #[serde(default)]
    pub trust_score_label: Option<String>,
    #[serde(default)]
    pub trust_score_source: Option<String>,
    #[serde(default)]
    pub trust_recommendation: Option<String>,
    pub operator_review_state: String,
    pub operator_review_label: String,
    pub operator_review_reason: String,
    pub catalog_status: String,
    pub catalog_status_label: String,
    pub catalog_status_detail: String,
    #[serde(default)]
    pub catalog_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub catalog_expires_at_ms: Option<u64>,
    #[serde(default)]
    pub catalog_refreshed_at_ms: Option<u64>,
    #[serde(default)]
    pub catalog_refresh_source: Option<String>,
    #[serde(default)]
    pub catalog_channel: Option<String>,
    #[serde(default)]
    pub catalog_source_id: Option<String>,
    #[serde(default)]
    pub catalog_source_label: Option<String>,
    #[serde(default)]
    pub catalog_source_uri: Option<String>,
    #[serde(default)]
    pub marketplace_package_url: Option<String>,
    #[serde(default)]
    pub catalog_refresh_bundle_id: Option<String>,
    #[serde(default)]
    pub catalog_refresh_bundle_label: Option<String>,
    #[serde(default)]
    pub catalog_refresh_bundle_issued_at_ms: Option<u64>,
    #[serde(default)]
    pub catalog_refresh_bundle_expires_at_ms: Option<u64>,
    #[serde(default)]
    pub catalog_refresh_available_version: Option<String>,
    #[serde(default)]
    pub catalog_refresh_error: Option<String>,
    #[serde(default)]
    pub last_catalog_refresh_at_ms: Option<u64>,
    #[serde(default)]
    pub update_severity: Option<String>,
    #[serde(default)]
    pub update_severity_label: Option<String>,
    #[serde(default)]
    pub update_detail: Option<String>,
    #[serde(default)]
    pub requested_capabilities: Vec<String>,
    pub trust_posture: String,
    pub governed_profile: String,
    pub authority_tier_label: String,
    pub availability_label: String,
    pub session_scope_label: String,
    #[serde(default)]
    pub reloadable: bool,
    pub reloadability_label: String,
    #[serde(default)]
    pub contribution_count: usize,
    #[serde(default)]
    pub hook_contribution_count: usize,
    #[serde(default)]
    pub filesystem_skill_count: usize,
    #[serde(default)]
    pub capability_count: usize,
    pub runtime_trust_state: String,
    pub runtime_trust_label: String,
    pub runtime_load_state: String,
    pub runtime_load_label: String,
    pub runtime_status_detail: String,
    #[serde(default)]
    pub load_error: Option<String>,
    #[serde(default)]
    pub last_trusted_at_ms: Option<u64>,
    #[serde(default)]
    pub last_reloaded_at_ms: Option<u64>,
    #[serde(default)]
    pub last_installed_at_ms: Option<u64>,
    #[serde(default)]
    pub last_updated_at_ms: Option<u64>,
    #[serde(default)]
    pub last_removed_at_ms: Option<u64>,
    #[serde(default)]
    pub trust_remembered: bool,
    #[serde(default)]
    pub package_managed: bool,
    pub package_install_state: String,
    pub package_install_label: String,
    pub package_install_detail: String,
    #[serde(default)]
    pub package_install_source: Option<String>,
    #[serde(default)]
    pub package_install_source_label: Option<String>,
    #[serde(default)]
    pub package_root_path: Option<String>,
    #[serde(default)]
    pub package_manifest_path: Option<String>,
    #[serde(default)]
    pub installed_version: Option<String>,
    #[serde(default)]
    pub available_version: Option<String>,
    #[serde(default)]
    pub update_available: bool,
    #[serde(default)]
    pub package_error: Option<String>,
    pub why_available: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionPluginCatalogChannelRecord {
    pub catalog_id: String,
    pub label: String,
    pub source_uri: String,
    #[serde(default)]
    pub refresh_source: Option<String>,
    #[serde(default)]
    pub channel: Option<String>,
    pub status: String,
    pub status_label: String,
    pub status_detail: String,
    #[serde(default)]
    pub issued_at_ms: Option<u64>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub refreshed_at_ms: Option<u64>,
    #[serde(default)]
    pub plugin_count: usize,
    #[serde(default)]
    pub valid_plugin_count: usize,
    #[serde(default)]
    pub invalid_plugin_count: usize,
    #[serde(default)]
    pub refresh_bundle_count: usize,
    #[serde(default)]
    pub refresh_error: Option<String>,
    pub conformance_status: String,
    pub conformance_label: String,
    #[serde(default)]
    pub conformance_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionPluginCatalogSourceRecord {
    pub source_id: String,
    pub label: String,
    pub source_uri: String,
    pub transport_kind: String,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub authority_bundle_id: Option<String>,
    #[serde(default)]
    pub authority_bundle_label: Option<String>,
    pub status: String,
    pub status_label: String,
    pub status_detail: String,
    #[serde(default)]
    pub last_successful_refresh_at_ms: Option<u64>,
    #[serde(default)]
    pub last_failed_refresh_at_ms: Option<u64>,
    #[serde(default)]
    pub refresh_error: Option<String>,
    pub conformance_status: String,
    pub conformance_label: String,
    #[serde(default)]
    pub conformance_error: Option<String>,
    #[serde(default)]
    pub catalog_count: usize,
    #[serde(default)]
    pub valid_catalog_count: usize,
    #[serde(default)]
    pub invalid_catalog_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionPluginSnapshot {
    pub generated_at_ms: u64,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub plugin_count: usize,
    #[serde(default)]
    pub enabled_plugin_count: usize,
    #[serde(default)]
    pub disabled_plugin_count: usize,
    #[serde(default)]
    pub trusted_plugin_count: usize,
    #[serde(default)]
    pub untrusted_plugin_count: usize,
    #[serde(default)]
    pub blocked_plugin_count: usize,
    #[serde(default)]
    pub reloadable_plugin_count: usize,
    #[serde(default)]
    pub managed_package_count: usize,
    #[serde(default)]
    pub update_available_count: usize,
    #[serde(default)]
    pub installable_package_count: usize,
    #[serde(default)]
    pub verified_plugin_count: usize,
    #[serde(default)]
    pub unverified_plugin_count: usize,
    #[serde(default)]
    pub signature_mismatch_plugin_count: usize,
    #[serde(default)]
    pub recommended_plugin_count: usize,
    #[serde(default)]
    pub review_required_plugin_count: usize,
    #[serde(default)]
    pub stale_catalog_count: usize,
    #[serde(default)]
    pub expired_catalog_count: usize,
    #[serde(default)]
    pub critical_update_count: usize,
    #[serde(default)]
    pub refresh_available_count: usize,
    #[serde(default)]
    pub refresh_failed_count: usize,
    #[serde(default)]
    pub catalog_channel_count: usize,
    #[serde(default)]
    pub nonconformant_channel_count: usize,
    #[serde(default)]
    pub catalog_source_count: usize,
    #[serde(default)]
    pub local_catalog_source_count: usize,
    #[serde(default)]
    pub remote_catalog_source_count: usize,
    #[serde(default)]
    pub failed_catalog_source_count: usize,
    #[serde(default)]
    pub nonconformant_source_count: usize,
    #[serde(default)]
    pub hook_contribution_count: usize,
    #[serde(default)]
    pub filesystem_skill_count: usize,
    #[serde(default)]
    pub recent_receipt_count: usize,
    #[serde(default)]
    pub recent_receipts: Vec<SessionPluginLifecycleReceipt>,
    #[serde(default)]
    pub catalog_sources: Vec<SessionPluginCatalogSourceRecord>,
    #[serde(default)]
    pub catalog_channels: Vec<SessionPluginCatalogChannelRecord>,
    #[serde(default)]
    pub plugins: Vec<SessionPluginRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityGovernanceRequestAction {
    Widen,
    Baseline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityGovernanceRequest {
    pub request_id: String,
    pub created_at_ms: u64,
    pub status: String,
    pub action: CapabilityGovernanceRequestAction,
    pub capability_entry_id: String,
    pub capability_label: String,
    pub capability_kind: String,
    #[serde(default)]
    pub governing_entry_id: Option<String>,
    #[serde(default)]
    pub governing_label: Option<String>,
    #[serde(default)]
    pub governing_kind: Option<String>,
    pub connector_id: String,
    pub connector_label: String,
    pub source_label: String,
    pub authority_tier_label: String,
    #[serde(default)]
    pub governed_profile_label: Option<String>,
    #[serde(default)]
    pub lease_mode_label: Option<String>,
    pub why_selectable: String,
    pub headline: String,
    pub detail: String,
    pub requested_state: ShieldPolicyState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityGovernanceTargetOption {
    pub target_entry_id: String,
    pub target_label: String,
    pub target_kind: String,
    pub target_summary: String,
    pub recommendation_reason: String,
    pub delta_summary: String,
    pub request: CapabilityGovernanceRequest,
    #[serde(default)]
    pub delta_magnitude: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityGovernanceProposal {
    pub capability_entry_id: String,
    pub capability_label: String,
    pub action: CapabilityGovernanceRequestAction,
    pub recommended_target_entry_id: String,
    pub targets: Vec<CapabilityGovernanceTargetOption>,
    #[serde(default)]
    pub compared_entry_id: Option<String>,
    #[serde(default)]
    pub compared_entry_label: Option<String>,
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

    // Studio's typed outcome router may use a separate real runtime so
    // lightweight route planning does not stall behind heavier artifact generation.
    pub studio_routing_inference_runtime: Option<Arc<dyn InferenceRuntime>>,

    // Acceptance judge runtime kept distinct from the production artifact runtime
    // so Studio can surface separate provenance truthfully.
    pub acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,

    // Primary local runtime for checkpoints, memory, events, artifacts, and cache state.
    pub memory_runtime: Option<Arc<MemoryRuntime>>,

    // Cross-window Studio launch intent survives a recreated Studio shell.
    pub pending_studio_launch_request: Option<Value>,

    // Recent launch receipts make Studio shell handoff failures inspectable.
    pub studio_launch_receipts: Vec<StudioLaunchReceipt>,

    // Active assistant workbench session is kernel-owned so shell recreation
    // does not drop reply/prep context.
    pub active_assistant_workbench_session: Option<Value>,

    // Cached full session history snapshot lets shell projections stay live
    // without falling back to frontend polling during active runs.
    pub session_history_projection: Vec<SessionSummary>,

    // Active capability governance request keeps lease widening / baseline
    // review durable across shell hops until the operator applies or dismisses it.
    pub capability_governance_request: Option<CapabilityGovernanceRequest>,

    // Coalesce kernel-owned session history refreshes so event-stream and
    // background monitor paths can keep projections fresh without piling up
    // duplicate RPC work.
    pub session_projection_refresh_in_flight: bool,
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
