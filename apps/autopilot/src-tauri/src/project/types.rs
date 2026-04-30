use serde::{Deserialize, Serialize};
use serde_json::Value;

// Define the file format structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectFile {
    pub version: String,
    pub nodes: Vec<crate::orchestrator::GraphNode>,
    pub edges: Vec<crate::orchestrator::GraphEdge>,
    pub global_config: Option<Value>,
    // Metadata for tracking
    pub metadata: Option<ProjectMetadata>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectMetadata {
    pub name: String,
    pub created_at: u64,
    pub last_modified: u64,
    pub author: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowProjectMetadata {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub workflow_kind: String,
    pub execution_mode: String,
    #[serde(default)]
    pub git_location: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub dirty: Option<bool>,
    #[serde(default)]
    pub read_only: Option<bool>,
    #[serde(default)]
    pub created_at_ms: Option<u64>,
    #[serde(default)]
    pub updated_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowProject {
    pub version: String,
    pub metadata: WorkflowProjectMetadata,
    pub nodes: Vec<Value>,
    pub edges: Vec<Value>,
    #[serde(rename = "global_config")]
    pub global_config: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowTestAssertion {
    pub kind: String,
    #[serde(default)]
    pub expected: Option<Value>,
    #[serde(default)]
    pub expression: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowTestCase {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub target_node_ids: Vec<String>,
    #[serde(default)]
    pub target_subgraph_id: Option<String>,
    pub assertion: WorkflowTestAssertion,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub last_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowNodeFixture {
    pub id: String,
    pub node_id: String,
    pub name: String,
    #[serde(default)]
    pub input: Option<Value>,
    #[serde(default)]
    pub output: Option<Value>,
    #[serde(default)]
    pub schema_hash: Option<String>,
    #[serde(default)]
    pub node_config_hash: Option<String>,
    #[serde(default)]
    pub source_run_id: Option<String>,
    #[serde(default)]
    pub pinned: Option<bool>,
    #[serde(default)]
    pub stale: Option<bool>,
    #[serde(default)]
    pub validation_status: Option<String>,
    #[serde(default)]
    pub validation_message: Option<String>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowProposalGraphDiff {
    #[serde(default)]
    pub added_node_ids: Option<Vec<String>>,
    #[serde(default)]
    pub removed_node_ids: Option<Vec<String>>,
    #[serde(default)]
    pub changed_node_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowProposalConfigDiff {
    #[serde(default)]
    pub changed_node_ids: Vec<String>,
    #[serde(default)]
    pub changed_global_keys: Vec<String>,
    #[serde(default)]
    pub changed_metadata_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowProposalSidecarDiff {
    #[serde(default)]
    pub tests_changed: bool,
    #[serde(default)]
    pub fixtures_changed: bool,
    #[serde(default)]
    pub functions_changed: bool,
    #[serde(default)]
    pub bindings_changed: bool,
    #[serde(default)]
    pub proposals_changed: bool,
    #[serde(default)]
    pub changed_roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowProposal {
    pub id: String,
    pub title: String,
    pub summary: String,
    pub status: String,
    pub created_at_ms: u64,
    #[serde(default)]
    pub bounded_targets: Vec<String>,
    #[serde(default)]
    pub graph_diff: Option<WorkflowProposalGraphDiff>,
    #[serde(default)]
    pub config_diff: Option<WorkflowProposalConfigDiff>,
    #[serde(default)]
    pub sidecar_diff: Option<WorkflowProposalSidecarDiff>,
    #[serde(default)]
    pub code_diff: Option<String>,
    #[serde(default)]
    pub workflow_patch: Option<WorkflowProject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowRunSummary {
    pub id: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    pub status: String,
    pub started_at_ms: u64,
    #[serde(default)]
    pub finished_at_ms: Option<u64>,
    pub node_count: usize,
    #[serde(default)]
    pub test_count: Option<usize>,
    #[serde(default)]
    pub checkpoint_count: Option<usize>,
    #[serde(default)]
    pub interrupt_id: Option<String>,
    pub summary: String,
    #[serde(default)]
    pub evidence_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowProjectSummary {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub workflow_kind: String,
    pub execution_mode: String,
    pub workflow_path: String,
    pub tests_path: String,
    pub proposals_dir: String,
    pub node_count: usize,
    #[serde(default)]
    pub updated_at_ms: Option<u64>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub dirty: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowWorkbenchBundle {
    pub workflow_path: String,
    pub tests_path: String,
    pub proposals_dir: String,
    pub workflow: WorkflowProject,
    pub tests: Vec<WorkflowTestCase>,
    pub proposals: Vec<WorkflowProposal>,
    pub runs: Vec<WorkflowRunSummary>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWorkflowProjectRequest {
    pub project_root: String,
    pub name: String,
    pub workflow_kind: String,
    pub execution_mode: String,
    #[serde(default)]
    pub template_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWorkflowFromTemplateRequest {
    pub project_root: String,
    pub template_id: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWorkflowProposalRequest {
    pub title: String,
    pub summary: String,
    #[serde(default)]
    pub bounded_targets: Vec<String>,
    #[serde(default)]
    pub workflow_patch: Option<WorkflowProject>,
    #[serde(default)]
    pub code_diff: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWorkflowNodeFromScaffoldRequest {
    pub scaffold_id: String,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub x: Option<i64>,
    #[serde(default)]
    pub y: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowValidationIssue {
    #[serde(default)]
    pub node_id: Option<String>,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowValidationResult {
    pub status: String,
    pub errors: Vec<WorkflowValidationIssue>,
    pub warnings: Vec<WorkflowValidationIssue>,
    pub blocked_nodes: Vec<String>,
    pub missing_config: Vec<WorkflowValidationIssue>,
    pub unsupported_runtime_nodes: Vec<String>,
    pub policy_required_nodes: Vec<String>,
    pub coverage_by_node_id: std::collections::BTreeMap<String, Vec<String>>,
    pub connector_binding_issues: Vec<WorkflowValidationIssue>,
    #[serde(default)]
    pub execution_readiness_issues: Vec<WorkflowValidationIssue>,
    #[serde(default)]
    pub verification_issues: Vec<WorkflowValidationIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowSandboxPolicy {
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub memory_mb: Option<u64>,
    #[serde(default)]
    pub output_limit_bytes: Option<usize>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowFunctionRef {
    pub runtime: String,
    pub entrypoint: String,
    pub source_path: String,
    #[serde(default)]
    pub code_hash: Option<String>,
    #[serde(default)]
    pub dependency_manifest: Option<Value>,
    #[serde(default)]
    pub input_schema: Option<Value>,
    #[serde(default)]
    pub output_schema: Option<Value>,
    #[serde(default)]
    pub sandbox_policy: Option<WorkflowSandboxPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowFunctionBinding {
    pub language: String,
    pub code: String,
    #[serde(default)]
    pub function_ref: Option<WorkflowFunctionRef>,
    #[serde(default)]
    pub input_schema: Option<Value>,
    #[serde(default)]
    pub output_schema: Option<Value>,
    #[serde(default)]
    pub sandbox_policy: Option<WorkflowSandboxPolicy>,
    #[serde(default)]
    pub test_input: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowParserBinding {
    pub parser_ref: String,
    pub parser_kind: String,
    #[serde(default)]
    pub result_schema: Option<Value>,
    #[serde(default)]
    pub mock_binding: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowModelBinding {
    pub model_ref: String,
    pub mock_binding: bool,
    #[serde(default)]
    pub capability_scope: Vec<String>,
    #[serde(default)]
    pub argument_schema: Option<Value>,
    #[serde(default)]
    pub result_schema: Option<Value>,
    pub side_effect_class: String,
    pub requires_approval: bool,
    #[serde(default)]
    pub credential_ready: Option<bool>,
    #[serde(default)]
    pub tool_use_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowToolSubgraphBinding {
    pub workflow_path: String,
    #[serde(default)]
    pub argument_schema: Option<Value>,
    #[serde(default)]
    pub result_schema: Option<Value>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub max_attempts: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowToolBinding {
    pub tool_ref: String,
    #[serde(default)]
    pub binding_kind: Option<String>,
    pub mock_binding: bool,
    #[serde(default)]
    pub credential_ready: Option<bool>,
    #[serde(default)]
    pub capability_scope: Vec<String>,
    pub side_effect_class: String,
    pub requires_approval: bool,
    #[serde(default)]
    pub arguments: Option<Value>,
    #[serde(default)]
    pub argument_schema: Option<Value>,
    #[serde(default)]
    pub result_schema: Option<Value>,
    #[serde(default)]
    pub workflow_tool: Option<WorkflowToolSubgraphBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowConnectorBinding {
    pub connector_ref: String,
    pub mock_binding: bool,
    #[serde(default)]
    pub credential_ready: Option<bool>,
    #[serde(default)]
    pub capability_scope: Vec<String>,
    pub side_effect_class: String,
    pub requires_approval: bool,
    #[serde(default)]
    pub operation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowVerificationEvidence {
    pub node_id: String,
    pub evidence_type: String,
    pub status: String,
    pub summary: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowCompletionRequirement {
    pub id: String,
    #[serde(default)]
    pub node_id: Option<String>,
    pub requirement_type: String,
    pub status: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowRendererRef {
    pub renderer_id: String,
    pub display_mode: String,
    #[serde(default)]
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowMaterializedAsset {
    pub id: String,
    pub node_id: String,
    pub asset_kind: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub hash: Option<String>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowDeliveryTarget {
    pub target_kind: String,
    #[serde(default)]
    pub target_ref: Option<String>,
    #[serde(default)]
    pub requires_approval: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowOutputVersioning {
    pub enabled: bool,
    #[serde(default)]
    pub version_ref: Option<String>,
    #[serde(default)]
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowOutputBundle {
    pub id: String,
    pub node_id: String,
    pub format: String,
    pub value: Value,
    #[serde(default)]
    pub renderer_ref: Option<WorkflowRendererRef>,
    #[serde(default)]
    pub materialized_assets: Vec<WorkflowMaterializedAsset>,
    #[serde(default)]
    pub delivery_target: Option<WorkflowDeliveryTarget>,
    #[serde(default)]
    pub dependency_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub version: Option<WorkflowOutputVersioning>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowDogfoodRun {
    pub id: String,
    pub suite_id: String,
    pub started_at_ms: u64,
    #[serde(default)]
    pub finished_at_ms: Option<u64>,
    pub status: String,
    pub output_dir: String,
    pub workflow_paths: Vec<String>,
    pub gap_ledger_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowGapLedgerEntry {
    pub id: String,
    pub workflow_id: String,
    pub severity: String,
    pub area: String,
    pub summary: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowPortablePackageFile {
    pub role: String,
    pub relative_path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowPortablePackageManifest {
    pub schema_version: String,
    pub exported_at_ms: u64,
    pub workflow_name: String,
    pub workflow_slug: String,
    pub source_workflow_path: String,
    pub readiness_status: String,
    pub portable: bool,
    #[serde(default)]
    pub blockers: Vec<WorkflowValidationIssue>,
    #[serde(default)]
    pub files: Vec<WorkflowPortablePackageFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowPortablePackage {
    pub package_path: String,
    pub manifest_path: String,
    pub manifest: WorkflowPortablePackageManifest,
    #[serde(default)]
    pub imported_workflow_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportWorkflowPackageRequest {
    pub package_path: String,
    pub project_root: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowEvidenceSummary {
    pub id: String,
    pub kind: String,
    pub created_at_ms: u64,
    pub summary: String,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowBindingCheckResult {
    pub id: String,
    pub row_id: String,
    pub node_id: String,
    pub binding_kind: String,
    pub reference: String,
    pub mode: String,
    pub status: String,
    pub summary: String,
    pub detail: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowBindingManifestEntry {
    pub id: String,
    pub node_id: String,
    pub node_name: String,
    pub node_type: String,
    pub binding_kind: String,
    pub reference: String,
    pub mode: String,
    pub credential_ready: bool,
    pub mock_binding: bool,
    pub side_effect_class: String,
    pub requires_approval: bool,
    pub capability_scope: Vec<String>,
    pub status: String,
    pub status_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowBindingManifestSummary {
    pub total: usize,
    pub live: usize,
    #[serde(rename = "mock")]
    pub mock_bindings: usize,
    pub local: usize,
    pub ready: usize,
    pub blocked: usize,
    pub approval_required: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowBindingManifest {
    pub schema_version: String,
    pub workflow_id: String,
    pub workflow_slug: String,
    pub generated_at_ms: u64,
    pub environment_profile: Value,
    pub bindings: Vec<WorkflowBindingManifestEntry>,
    pub summary: WorkflowBindingManifestSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowTestCaseRun {
    pub test_id: String,
    pub status: String,
    pub message: String,
    pub covered_node_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowTestRunResult {
    pub run_id: String,
    pub status: String,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub passed: usize,
    pub failed: usize,
    pub blocked: usize,
    pub skipped: usize,
    pub results: Vec<WorkflowTestCaseRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowThread {
    pub id: String,
    pub workflow_path: String,
    pub status: String,
    pub created_at_ms: u64,
    #[serde(default)]
    pub latest_checkpoint_id: Option<String>,
    #[serde(default)]
    pub input: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowStateUpdate {
    pub node_id: String,
    pub key: String,
    pub value: Value,
    pub reducer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowStateSnapshot {
    pub thread_id: String,
    pub checkpoint_id: String,
    pub run_id: String,
    pub step_index: usize,
    pub values: std::collections::BTreeMap<String, Value>,
    pub node_outputs: std::collections::BTreeMap<String, Value>,
    pub completed_node_ids: Vec<String>,
    pub blocked_node_ids: Vec<String>,
    pub interrupted_node_ids: Vec<String>,
    pub active_node_ids: Vec<String>,
    pub branch_decisions: std::collections::BTreeMap<String, String>,
    pub pending_writes: Vec<WorkflowStateUpdate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowCheckpoint {
    pub id: String,
    pub thread_id: String,
    pub run_id: String,
    pub created_at_ms: u64,
    pub step_index: usize,
    #[serde(default)]
    pub node_id: Option<String>,
    pub status: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowNodeRun {
    pub node_id: String,
    pub node_type: String,
    pub status: String,
    pub started_at_ms: u64,
    #[serde(default)]
    pub finished_at_ms: Option<u64>,
    pub attempt: usize,
    #[serde(default)]
    pub input: Option<Value>,
    #[serde(default)]
    pub output: Option<Value>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub checkpoint_id: Option<String>,
    #[serde(default)]
    pub lifecycle: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowInterrupt {
    pub id: String,
    pub run_id: String,
    pub thread_id: String,
    pub node_id: String,
    pub status: String,
    pub created_at_ms: u64,
    #[serde(default)]
    pub resolved_at_ms: Option<u64>,
    pub prompt: String,
    pub allowed_outcomes: Vec<String>,
    #[serde(default)]
    pub response: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowStreamEvent {
    pub id: String,
    pub run_id: String,
    pub thread_id: String,
    pub sequence: usize,
    pub kind: String,
    pub created_at_ms: u64,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub state_delta: Option<Vec<WorkflowStateUpdate>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowRunResult {
    pub summary: WorkflowRunSummary,
    pub thread: WorkflowThread,
    pub final_state: WorkflowStateSnapshot,
    pub node_runs: Vec<WorkflowNodeRun>,
    pub checkpoints: Vec<WorkflowCheckpoint>,
    pub events: Vec<WorkflowStreamEvent>,
    #[serde(default)]
    pub verification_evidence: Vec<WorkflowVerificationEvidence>,
    #[serde(default)]
    pub completion_requirements: Vec<WorkflowCompletionRequirement>,
    #[serde(default)]
    pub interrupt: Option<WorkflowInterrupt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowRunNodeComparison {
    pub node_id: String,
    #[serde(default)]
    pub baseline_status: Option<String>,
    #[serde(default)]
    pub target_status: Option<String>,
    pub input_changed: bool,
    pub output_changed: bool,
    pub error_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowRunStateComparison {
    pub key: String,
    pub change: String,
    #[serde(default)]
    pub baseline_value: Option<Value>,
    #[serde(default)]
    pub target_value: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowRunComparison {
    pub baseline_run_id: String,
    pub target_run_id: String,
    pub status_changed: bool,
    pub checkpoint_delta: i64,
    pub node_changes: Vec<WorkflowRunNodeComparison>,
    pub state_changes: Vec<WorkflowRunStateComparison>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowResumeRequest {
    #[serde(default)]
    pub run_id: Option<String>,
    pub thread_id: String,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub interrupt_id: Option<String>,
    #[serde(default)]
    pub checkpoint_id: Option<String>,
    pub outcome: String,
    #[serde(default)]
    pub edited_state: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowCheckpointForkRequest {
    pub checkpoint_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub input: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct ProjectGitStatus {
    pub is_repo: bool,
    pub branch: Option<String>,
    pub dirty: bool,
    pub last_commit: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProjectExplorerNode {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub has_children: bool,
    pub children: Vec<ProjectExplorerNode>,
}

#[derive(Debug, Serialize)]
pub struct ProjectArtifactCandidate {
    pub title: String,
    pub path: String,
    pub artifact_type: String,
}

#[derive(Debug, Serialize)]
pub struct ProjectShellSnapshot {
    pub root_path: String,
    pub git: ProjectGitStatus,
    pub tree: Vec<ProjectExplorerNode>,
    pub artifacts: Vec<ProjectArtifactCandidate>,
}

#[derive(Debug, Serialize)]
pub struct ProjectFileDocument {
    pub name: String,
    pub path: String,
    pub absolute_path: String,
    pub language_hint: Option<String>,
    pub content: String,
    pub size_bytes: usize,
    pub modified_at_ms: Option<u64>,
    pub is_binary: bool,
    pub is_too_large: bool,
    pub read_only: bool,
}
