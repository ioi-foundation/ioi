use ioi_types::app::{
    ChatExecutionBudgetEnvelope, ChatExecutionBudgetExpansionPolicy, ChatExecutionModeDecision,
    ChatExecutionStrategy, ChatOutcomeArtifactRequest, ChatOutcomeKind, ChatRuntimeProvenance,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use ts_rs::TS;

fn default_execution_domain() -> String {
    "execution".to_string()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStage {
    Plan,
    Dispatch,
    Work,
    Mutate,
    Merge,
    Verify,
    Finalize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionDomainKind {
    Artifact,
    Conversation,
    ToolWidget,
    Visualizer,
    Workflow,
    Research,
    Reply,
    Code,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLivePreviewKind {
    TokenStream,
    WorkerOutput,
    ChangePreview,
    CommandStream,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkGraphWorkerRole {
    Planner,
    Coordinator,
    Responder,
    Skeleton,
    SectionContent,
    StyleSystem,
    Interaction,
    Integrator,
    Validation,
    Repair,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkGraphLeaseMode {
    SharedRead,
    ExclusiveWrite,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkGraphLeaseScopeKind {
    File,
    Region,
    Surface,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkGraphLeaseRequirement {
    pub target: String,
    pub scope_kind: WorkGraphLeaseScopeKind,
    pub mode: WorkGraphLeaseMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkGraphVerificationPolicy {
    Normal,
    Elevated,
    Blocking,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkGraphWorkItemStatus {
    Pending,
    Blocked,
    Running,
    Succeeded,
    Failed,
    Skipped,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkGraphWorkerResultKind {
    Completed,
    Noop,
    Blocked,
    Conflict,
    DependencyDiscovered,
    SubtaskRequested,
    ReplanRequested,
    VerificationConcern,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkGraphWorkItem {
    pub id: String,
    pub title: String,
    pub role: WorkGraphWorkerRole,
    pub summary: String,
    #[serde(default)]
    pub spawned_from_id: Option<String>,
    #[serde(default)]
    pub read_paths: Vec<String>,
    #[serde(default)]
    pub write_paths: Vec<String>,
    #[serde(default)]
    pub write_regions: Vec<String>,
    #[serde(default)]
    pub lease_requirements: Vec<WorkGraphLeaseRequirement>,
    #[serde(default)]
    pub acceptance_criteria: Vec<String>,
    #[serde(default)]
    pub dependency_ids: Vec<String>,
    #[serde(default)]
    pub blocked_on_ids: Vec<String>,
    #[serde(default)]
    pub verification_policy: Option<WorkGraphVerificationPolicy>,
    #[serde(default)]
    pub retry_budget: Option<u32>,
    pub status: WorkGraphWorkItemStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkGraphPlan {
    pub version: u32,
    pub strategy: String,
    #[serde(default = "default_execution_domain")]
    pub execution_domain: String,
    pub adapter_label: String,
    pub parallelism_mode: String,
    #[serde(default)]
    pub top_level_objective: Option<String>,
    #[serde(default)]
    pub decomposition_hypothesis: Option<String>,
    #[serde(default)]
    pub decomposition_type: Option<String>,
    #[serde(default)]
    pub first_frontier_ids: Vec<String>,
    #[serde(default)]
    pub spawn_conditions: Vec<String>,
    #[serde(default)]
    pub prune_conditions: Vec<String>,
    #[serde(default)]
    pub merge_strategy: Option<String>,
    #[serde(default)]
    pub verification_strategy: Option<String>,
    #[serde(default)]
    pub fallback_collapse_strategy: Option<String>,
    #[serde(default)]
    pub completion_invariant: Option<ExecutionCompletionInvariant>,
    #[serde(default)]
    pub work_items: Vec<WorkGraphWorkItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkGraphExecutionSummary {
    pub enabled: bool,
    pub current_stage: String,
    #[serde(default)]
    pub execution_stage: Option<ExecutionStage>,
    #[serde(default)]
    pub active_worker_role: Option<WorkGraphWorkerRole>,
    pub total_work_items: usize,
    pub completed_work_items: usize,
    pub failed_work_items: usize,
    pub verification_status: String,
    pub strategy: String,
    #[serde(default = "default_execution_domain")]
    pub execution_domain: String,
    pub adapter_label: String,
    pub parallelism_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkGraphWorkerReceipt {
    pub work_item_id: String,
    pub role: WorkGraphWorkerRole,
    pub status: WorkGraphWorkItemStatus,
    #[serde(default)]
    pub result_kind: Option<WorkGraphWorkerResultKind>,
    pub summary: String,
    pub started_at: String,
    #[serde(default)]
    pub finished_at: Option<String>,
    pub runtime: ChatRuntimeProvenance,
    #[serde(default)]
    pub read_paths: Vec<String>,
    #[serde(default)]
    pub write_paths: Vec<String>,
    #[serde(default)]
    pub write_regions: Vec<String>,
    #[serde(default)]
    pub spawned_work_item_ids: Vec<String>,
    #[serde(default)]
    pub blocked_on_ids: Vec<String>,
    #[serde(default)]
    pub prompt_bytes: Option<usize>,
    #[serde(default)]
    pub output_bytes: Option<usize>,
    #[serde(default)]
    pub output_preview: Option<String>,
    #[serde(default)]
    pub preview_language: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkGraphChangeReceipt {
    pub work_item_id: String,
    pub status: WorkGraphWorkItemStatus,
    pub summary: String,
    pub operation_count: usize,
    #[serde(default)]
    pub touched_paths: Vec<String>,
    #[serde(default)]
    pub touched_regions: Vec<String>,
    #[serde(default)]
    pub operation_kinds: Vec<String>,
    #[serde(default)]
    pub preview: Option<String>,
    #[serde(default)]
    pub preview_language: Option<String>,
    #[serde(default)]
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkGraphMergeReceipt {
    pub work_item_id: String,
    pub status: WorkGraphWorkItemStatus,
    pub summary: String,
    pub applied_operation_count: usize,
    #[serde(default)]
    pub touched_paths: Vec<String>,
    #[serde(default)]
    pub touched_regions: Vec<String>,
    #[serde(default)]
    pub rejected_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkGraphVerificationReceipt {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub summary: String,
    #[serde(default)]
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkGraphWorkItemCommit {
    pub work_item_id: String,
    pub status: WorkGraphWorkItemStatus,
    #[serde(default)]
    pub write_paths: Vec<String>,
    #[serde(default)]
    pub write_regions: Vec<String>,
    pub write_scope_hash: String,
    #[serde(default)]
    pub worker_receipt_hash: Option<String>,
    #[serde(default)]
    pub change_receipt_hash: Option<String>,
    pub commit_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkGraphMergeDecisionArtifact {
    pub work_item_id: String,
    pub status: WorkGraphWorkItemStatus,
    pub scope_conflict_free: bool,
    #[serde(default)]
    pub required_commit_hashes: Vec<String>,
    #[serde(default)]
    pub merge_receipt_hash: Option<String>,
    pub merge_hash: String,
    #[serde(default)]
    pub rejected_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkGraphRetryDecisionArtifact {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub triggered_by_work_item_id: Option<String>,
    #[serde(default)]
    pub spawned_work_item_ids: Vec<String>,
    #[serde(default)]
    pub blocked_work_item_ids: Vec<String>,
    #[serde(default)]
    pub replan_receipt_hash: Option<String>,
    pub retry_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkGraphRepairActionArtifact {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub triggered_by_verification_id: Option<String>,
    #[serde(default)]
    pub work_item_ids: Vec<String>,
    #[serde(default)]
    pub repair_receipt_hash: Option<String>,
    pub repair_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionGraphMutationReceipt {
    pub id: String,
    pub mutation_kind: String,
    pub status: String,
    pub summary: String,
    #[serde(default)]
    pub triggered_by_work_item_id: Option<String>,
    #[serde(default)]
    pub affected_work_item_ids: Vec<String>,
    #[serde(default)]
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionDispatchBatch {
    pub id: String,
    pub sequence: u32,
    pub status: String,
    #[serde(default)]
    pub work_item_ids: Vec<String>,
    #[serde(default)]
    pub deferred_work_item_ids: Vec<String>,
    #[serde(default)]
    pub blocked_work_item_ids: Vec<String>,
    #[serde(default)]
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionRepairReceipt {
    pub id: String,
    pub status: String,
    pub summary: String,
    #[serde(default)]
    pub triggered_by_verification_id: Option<String>,
    #[serde(default)]
    pub work_item_ids: Vec<String>,
    #[serde(default)]
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionReplanReceipt {
    pub id: String,
    pub status: String,
    pub summary: String,
    #[serde(default)]
    pub triggered_by_work_item_id: Option<String>,
    #[serde(default)]
    pub spawned_work_item_ids: Vec<String>,
    #[serde(default)]
    pub blocked_work_item_ids: Vec<String>,
    #[serde(default)]
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionBudgetSummary {
    #[serde(default)]
    pub planned_worker_count: Option<usize>,
    #[serde(default)]
    pub dispatched_worker_count: Option<usize>,
    #[serde(default)]
    pub token_budget: Option<u32>,
    #[serde(default)]
    pub token_usage: Option<u32>,
    #[serde(default)]
    pub wall_clock_ms: Option<u64>,
    #[serde(default)]
    pub coordination_overhead_ms: Option<u64>,
    pub status: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCompletionInvariantStatus {
    Pending,
    Satisfied,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionCompletionInvariant {
    pub summary: String,
    pub status: ExecutionCompletionInvariantStatus,
    #[serde(default)]
    pub required_work_item_ids: Vec<String>,
    #[serde(default)]
    pub satisfied_work_item_ids: Vec<String>,
    #[serde(default)]
    pub speculative_work_item_ids: Vec<String>,
    #[serde(default)]
    pub pruned_work_item_ids: Vec<String>,
    #[serde(default)]
    pub required_verification_ids: Vec<String>,
    #[serde(default)]
    pub satisfied_verification_ids: Vec<String>,
    #[serde(default)]
    pub required_artifact_paths: Vec<String>,
    #[serde(default)]
    pub remaining_obligations: Vec<String>,
    #[serde(default)]
    pub allows_early_exit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionLivePreview {
    pub id: String,
    pub kind: ExecutionLivePreviewKind,
    pub label: String,
    #[serde(default)]
    pub work_item_id: Option<String>,
    #[serde(default)]
    pub role: Option<WorkGraphWorkerRole>,
    pub status: String,
    #[serde(default)]
    pub language: Option<String>,
    pub content: String,
    #[serde(default)]
    pub is_final: bool,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionEnvelope {
    pub version: u32,
    #[serde(default)]
    pub strategy: Option<ChatExecutionStrategy>,
    #[serde(default)]
    pub mode_decision: Option<ChatExecutionModeDecision>,
    #[serde(default)]
    pub budget_envelope: Option<ChatExecutionBudgetEnvelope>,
    pub execution_domain: String,
    #[serde(default)]
    pub domain_kind: Option<ExecutionDomainKind>,
    #[serde(default)]
    pub workflow_artifact_root_hash: Option<String>,
    #[serde(default)]
    pub completion_invariant: Option<ExecutionCompletionInvariant>,
    #[serde(default)]
    pub plan: Option<WorkGraphPlan>,
    #[serde(default)]
    pub execution_summary: Option<WorkGraphExecutionSummary>,
    #[serde(default)]
    pub worker_receipts: Vec<WorkGraphWorkerReceipt>,
    #[serde(default)]
    pub change_receipts: Vec<WorkGraphChangeReceipt>,
    #[serde(default)]
    pub merge_receipts: Vec<WorkGraphMergeReceipt>,
    #[serde(default)]
    pub verification_receipts: Vec<WorkGraphVerificationReceipt>,
    #[serde(default)]
    pub work_item_commits: Vec<WorkGraphWorkItemCommit>,
    #[serde(default)]
    pub merge_decision_artifacts: Vec<WorkGraphMergeDecisionArtifact>,
    #[serde(default)]
    pub graph_mutation_receipts: Vec<ExecutionGraphMutationReceipt>,
    #[serde(default)]
    pub dispatch_batches: Vec<ExecutionDispatchBatch>,
    #[serde(default)]
    pub repair_receipts: Vec<ExecutionRepairReceipt>,
    #[serde(default)]
    pub replan_receipts: Vec<ExecutionReplanReceipt>,
    #[serde(default)]
    pub retry_decision_artifacts: Vec<WorkGraphRetryDecisionArtifact>,
    #[serde(default)]
    pub repair_action_artifacts: Vec<WorkGraphRepairActionArtifact>,
    #[serde(default)]
    pub budget_summary: Option<ExecutionBudgetSummary>,
    #[serde(default)]
    pub live_previews: Vec<ExecutionLivePreview>,
}

fn execution_strategy_id(strategy: ChatExecutionStrategy) -> &'static str {
    match strategy {
        ChatExecutionStrategy::SinglePass => "single_pass",
        ChatExecutionStrategy::DirectAuthor => "direct_author",
        ChatExecutionStrategy::PlanExecute => "plan_execute",
        ChatExecutionStrategy::MicroWorkGraph => "micro_work_graph",
        ChatExecutionStrategy::AdaptiveWorkGraph => "adaptive_work_graph",
    }
}

fn artifact_verification_requirement_count(request: &ChatOutcomeArtifactRequest) -> u32 {
    [
        request.verification.require_render,
        request.verification.require_build,
        request.verification.require_preview,
        request.verification.require_export,
        request.verification.require_diff_review,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count() as u32
}

fn artifact_work_graph_size_estimate(request: &ChatOutcomeArtifactRequest) -> u32 {
    let base = match request.renderer {
        ioi_types::app::ChatRendererKind::WorkspaceSurface => 5,
        ioi_types::app::ChatRendererKind::HtmlIframe
        | ioi_types::app::ChatRendererKind::JsxSandbox => 3,
        ioi_types::app::ChatRendererKind::DownloadCard
        | ioi_types::app::ChatRendererKind::BundleManifest
        | ioi_types::app::ChatRendererKind::PdfEmbed => 2,
        ioi_types::app::ChatRendererKind::Markdown
        | ioi_types::app::ChatRendererKind::Svg
        | ioi_types::app::ChatRendererKind::Mermaid => 1,
    };
    base + u32::from(request.scope.create_new_workspace)
        + u32::from(request.verification.require_build || request.verification.require_preview)
}

fn clamp_score(value: f32) -> f32 {
    value.clamp(0.0, 1.0)
}

fn canonical_execution_hash<T: Serialize>(value: &T) -> String {
    serde_jcs::to_vec(value)
        .ok()
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .unwrap_or_else(|| "unavailable".to_string())
}

fn build_work_graph_work_item_commits(
    worker_receipts: &[WorkGraphWorkerReceipt],
    change_receipts: &[WorkGraphChangeReceipt],
) -> Vec<WorkGraphWorkItemCommit> {
    let worker_by_id = worker_receipts
        .iter()
        .map(|receipt| (receipt.work_item_id.clone(), receipt))
        .collect::<BTreeMap<_, _>>();
    let change_by_id = change_receipts
        .iter()
        .map(|receipt| (receipt.work_item_id.clone(), receipt))
        .collect::<BTreeMap<_, _>>();
    let work_item_ids = worker_by_id
        .keys()
        .chain(change_by_id.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    work_item_ids
        .iter()
        .map(|work_item_id| {
            let worker = worker_by_id.get(work_item_id);
            let change = change_by_id.get(work_item_id);
            let write_paths = worker
                .map(|receipt| receipt.write_paths.clone())
                .or_else(|| change.map(|receipt| receipt.touched_paths.clone()))
                .unwrap_or_default();
            let write_regions = worker
                .map(|receipt| receipt.write_regions.clone())
                .or_else(|| change.map(|receipt| receipt.touched_regions.clone()))
                .unwrap_or_default();
            let status = worker
                .map(|receipt| receipt.status)
                .or_else(|| change.map(|receipt| receipt.status))
                .unwrap_or(WorkGraphWorkItemStatus::Pending);
            let write_scope_hash =
                canonical_execution_hash(&(work_item_id, &write_paths, &write_regions, status));
            let worker_receipt_hash = worker.map(canonical_execution_hash);
            let change_receipt_hash = change.map(canonical_execution_hash);
            let commit_hash = canonical_execution_hash(&(
                work_item_id,
                status,
                &write_paths,
                &write_regions,
                &worker_receipt_hash,
                &change_receipt_hash,
            ));
            WorkGraphWorkItemCommit {
                work_item_id: work_item_id.clone(),
                status,
                write_paths,
                write_regions,
                write_scope_hash,
                worker_receipt_hash,
                change_receipt_hash,
                commit_hash,
            }
        })
        .collect()
}

fn build_work_graph_merge_decision_artifacts(
    merge_receipts: &[WorkGraphMergeReceipt],
    work_item_commits: &[WorkGraphWorkItemCommit],
) -> Vec<WorkGraphMergeDecisionArtifact> {
    let commit_by_id = work_item_commits
        .iter()
        .map(|commit| (commit.work_item_id.clone(), commit))
        .collect::<BTreeMap<_, _>>();
    merge_receipts
        .iter()
        .map(|receipt| {
            let required_commit_hashes = commit_by_id
                .get(&receipt.work_item_id)
                .map(|commit| vec![commit.commit_hash.clone()])
                .unwrap_or_default();
            let merge_receipt_hash = Some(canonical_execution_hash(receipt));
            let scope_conflict_free = receipt.status != WorkGraphWorkItemStatus::Rejected
                && receipt.rejected_reason.is_none();
            let merge_hash = canonical_execution_hash(&(
                &receipt.work_item_id,
                receipt.status,
                scope_conflict_free,
                &required_commit_hashes,
                &merge_receipt_hash,
                &receipt.rejected_reason,
            ));
            WorkGraphMergeDecisionArtifact {
                work_item_id: receipt.work_item_id.clone(),
                status: receipt.status,
                scope_conflict_free,
                required_commit_hashes,
                merge_receipt_hash,
                merge_hash,
                rejected_reason: receipt.rejected_reason.clone(),
            }
        })
        .collect()
}

fn build_work_graph_retry_decision_artifacts(
    replan_receipts: &[ExecutionReplanReceipt],
) -> Vec<WorkGraphRetryDecisionArtifact> {
    replan_receipts
        .iter()
        .map(|receipt| {
            let replan_receipt_hash = Some(canonical_execution_hash(receipt));
            let retry_hash = canonical_execution_hash(&(
                &receipt.id,
                &receipt.status,
                &receipt.triggered_by_work_item_id,
                &receipt.spawned_work_item_ids,
                &receipt.blocked_work_item_ids,
                &replan_receipt_hash,
            ));
            WorkGraphRetryDecisionArtifact {
                id: receipt.id.clone(),
                status: receipt.status.clone(),
                triggered_by_work_item_id: receipt.triggered_by_work_item_id.clone(),
                spawned_work_item_ids: receipt.spawned_work_item_ids.clone(),
                blocked_work_item_ids: receipt.blocked_work_item_ids.clone(),
                replan_receipt_hash,
                retry_hash,
            }
        })
        .collect()
}

fn build_work_graph_repair_action_artifacts(
    repair_receipts: &[ExecutionRepairReceipt],
) -> Vec<WorkGraphRepairActionArtifact> {
    repair_receipts
        .iter()
        .map(|receipt| {
            let repair_receipt_hash = Some(canonical_execution_hash(receipt));
            let repair_hash = canonical_execution_hash(&(
                &receipt.id,
                &receipt.status,
                &receipt.triggered_by_verification_id,
                &receipt.work_item_ids,
                &repair_receipt_hash,
            ));
            WorkGraphRepairActionArtifact {
                id: receipt.id.clone(),
                status: receipt.status.clone(),
                triggered_by_verification_id: receipt.triggered_by_verification_id.clone(),
                work_item_ids: receipt.work_item_ids.clone(),
                repair_receipt_hash,
                repair_hash,
            }
        })
        .collect()
}

fn build_workflow_artifact_root_hash(
    work_item_commits: &[WorkGraphWorkItemCommit],
    merge_decision_artifacts: &[WorkGraphMergeDecisionArtifact],
    retry_decision_artifacts: &[WorkGraphRetryDecisionArtifact],
    repair_action_artifacts: &[WorkGraphRepairActionArtifact],
) -> String {
    canonical_execution_hash(&(
        work_item_commits,
        merge_decision_artifacts,
        retry_decision_artifacts,
        repair_action_artifacts,
    ))
}

pub fn validate_execution_envelope(envelope: &ExecutionEnvelope) -> Result<(), String> {
    let commit_by_id = envelope
        .work_item_commits
        .iter()
        .map(|commit| (commit.work_item_id.clone(), commit))
        .collect::<BTreeMap<_, _>>();

    for commit in &envelope.work_item_commits {
        let expected_scope_hash = canonical_execution_hash(&(
            &commit.work_item_id,
            &commit.write_paths,
            &commit.write_regions,
            commit.status,
        ));
        if commit.write_scope_hash != expected_scope_hash {
            return Err(format!(
                "workflow commit '{}' has non-canonical write_scope_hash",
                commit.work_item_id
            ));
        }
        let expected_commit_hash = canonical_execution_hash(&(
            &commit.work_item_id,
            commit.status,
            &commit.write_paths,
            &commit.write_regions,
            &commit.worker_receipt_hash,
            &commit.change_receipt_hash,
        ));
        if commit.commit_hash != expected_commit_hash {
            return Err(format!(
                "workflow commit '{}' has non-canonical commit_hash",
                commit.work_item_id
            ));
        }
    }

    for receipt in &envelope.change_receipts {
        if !commit_by_id.contains_key(&receipt.work_item_id) {
            return Err(format!(
                "change receipt '{}' missing matching work_item_commit",
                receipt.work_item_id
            ));
        }
    }
    for receipt in &envelope.merge_receipts {
        if !envelope
            .merge_decision_artifacts
            .iter()
            .any(|artifact| artifact.work_item_id == receipt.work_item_id)
        {
            return Err(format!(
                "merge receipt '{}' missing matching merge_decision_artifact",
                receipt.work_item_id
            ));
        }
    }
    for artifact in &envelope.merge_decision_artifacts {
        if !artifact.required_commit_hashes.iter().all(|hash| {
            commit_by_id
                .values()
                .any(|commit| &commit.commit_hash == hash)
        }) {
            return Err(format!(
                "merge decision '{}' references unknown work item commit",
                artifact.work_item_id
            ));
        }
        let expected_merge_hash = canonical_execution_hash(&(
            &artifact.work_item_id,
            artifact.status,
            artifact.scope_conflict_free,
            &artifact.required_commit_hashes,
            &artifact.merge_receipt_hash,
            &artifact.rejected_reason,
        ));
        if artifact.merge_hash != expected_merge_hash {
            return Err(format!(
                "merge decision '{}' has non-canonical merge_hash",
                artifact.work_item_id
            ));
        }
    }
    if envelope.retry_decision_artifacts.len() != envelope.replan_receipts.len() {
        return Err("retry decision artifacts do not match replan receipt count".to_string());
    }
    if envelope.repair_action_artifacts.len() != envelope.repair_receipts.len() {
        return Err("repair action artifacts do not match repair receipt count".to_string());
    }
    for artifact in &envelope.retry_decision_artifacts {
        let expected = canonical_execution_hash(&(
            &artifact.id,
            &artifact.status,
            &artifact.triggered_by_work_item_id,
            &artifact.spawned_work_item_ids,
            &artifact.blocked_work_item_ids,
            &artifact.replan_receipt_hash,
        ));
        if artifact.retry_hash != expected {
            return Err(format!(
                "retry decision '{}' has non-canonical retry_hash",
                artifact.id
            ));
        }
    }
    for artifact in &envelope.repair_action_artifacts {
        let expected = canonical_execution_hash(&(
            &artifact.id,
            &artifact.status,
            &artifact.triggered_by_verification_id,
            &artifact.work_item_ids,
            &artifact.repair_receipt_hash,
        ));
        if artifact.repair_hash != expected {
            return Err(format!(
                "repair action '{}' has non-canonical repair_hash",
                artifact.id
            ));
        }
    }
    let expected_root = build_workflow_artifact_root_hash(
        &envelope.work_item_commits,
        &envelope.merge_decision_artifacts,
        &envelope.retry_decision_artifacts,
        &envelope.repair_action_artifacts,
    );
    if envelope.workflow_artifact_root_hash.as_deref() != Some(expected_root.as_str()) {
        return Err(
            "workflow_artifact_root_hash does not match canonical work_graph settlement artifacts"
                .to_string(),
        );
    }
    Ok(())
}

fn artifact_supports_direct_authoring(
    request: &ChatOutcomeArtifactRequest,
    has_active_artifact: bool,
) -> bool {
    matches!(
        request.renderer,
        ioi_types::app::ChatRendererKind::Markdown
            | ioi_types::app::ChatRendererKind::HtmlIframe
            | ioi_types::app::ChatRendererKind::Svg
            | ioi_types::app::ChatRendererKind::Mermaid
            | ioi_types::app::ChatRendererKind::PdfEmbed
    ) && request.deliverable_shape == ioi_types::app::ChatArtifactDeliverableShape::SingleFile
        && request.execution_substrate != ioi_types::app::ChatExecutionSubstrate::WorkspaceRuntime
        && !request.scope.create_new_workspace
        && !has_active_artifact
        && !request.verification.require_build
        && !request.verification.require_preview
        && !request.verification.require_diff_review
}

pub fn execution_budget_envelope_for_strategy(
    strategy: ChatExecutionStrategy,
) -> ChatExecutionBudgetEnvelope {
    match strategy {
        ChatExecutionStrategy::SinglePass => ChatExecutionBudgetEnvelope {
            max_workers: 1,
            max_parallel_depth: 1,
            max_replans: 0,
            max_wall_clock_ms: 60_000,
            max_tokens: 2_048,
            max_tool_calls: 1,
            max_repairs: 0,
            expansion_policy: ChatExecutionBudgetExpansionPolicy::Fixed,
        },
        ChatExecutionStrategy::DirectAuthor => ChatExecutionBudgetEnvelope {
            max_workers: 1,
            max_parallel_depth: 1,
            max_replans: 0,
            max_wall_clock_ms: 90_000,
            max_tokens: 4_096,
            max_tool_calls: 1,
            max_repairs: 1,
            expansion_policy: ChatExecutionBudgetExpansionPolicy::Fixed,
        },
        ChatExecutionStrategy::PlanExecute => ChatExecutionBudgetEnvelope {
            max_workers: 1,
            max_parallel_depth: 1,
            max_replans: 0,
            max_wall_clock_ms: 180_000,
            max_tokens: 8_192,
            max_tool_calls: 4,
            max_repairs: 1,
            expansion_policy: ChatExecutionBudgetExpansionPolicy::Fixed,
        },
        ChatExecutionStrategy::MicroWorkGraph => ChatExecutionBudgetEnvelope {
            max_workers: 3,
            max_parallel_depth: 2,
            max_replans: 1,
            max_wall_clock_ms: 300_000,
            max_tokens: 12_000,
            max_tool_calls: 6,
            max_repairs: 1,
            expansion_policy: ChatExecutionBudgetExpansionPolicy::ConfidenceGated,
        },
        ChatExecutionStrategy::AdaptiveWorkGraph => ChatExecutionBudgetEnvelope {
            max_workers: 8,
            max_parallel_depth: 4,
            max_replans: 4,
            max_wall_clock_ms: 600_000,
            max_tokens: 24_000,
            max_tool_calls: 12,
            max_repairs: 2,
            expansion_policy: ChatExecutionBudgetExpansionPolicy::FrontierAdaptive,
        },
    }
}

pub fn derive_execution_mode_decision(
    outcome_kind: ChatOutcomeKind,
    artifact: Option<&ChatOutcomeArtifactRequest>,
    requested_strategy: ChatExecutionStrategy,
    confidence: f32,
    needs_clarification: bool,
    has_active_artifact: bool,
) -> ChatExecutionModeDecision {
    let ambiguity = if needs_clarification {
        1.0
    } else {
        clamp_score(1.0 - confidence)
    };

    let (
        work_graph_size_estimate,
        hidden_dependency_likelihood,
        verification_pressure,
        revision_cost,
        evidence_breadth,
        merge_burden,
    ) = match (outcome_kind, artifact) {
        (ChatOutcomeKind::Artifact, Some(request)) => {
            let verification_count = artifact_verification_requirement_count(request) as f32;
            let verification_pressure = clamp_score(verification_count / 5.0);
            let work_graph_size = artifact_work_graph_size_estimate(request);
            let hidden_dependency_likelihood = clamp_score(
                (if request.scope.create_new_workspace {
                    0.35
                } else {
                    0.0
                }) + (if has_active_artifact { 0.2 } else { 0.0 })
                    + (if request.verification.require_build || request.verification.require_preview
                    {
                        0.45
                    } else {
                        0.0
                    })
                    + (if matches!(
                        request.renderer,
                        ioi_types::app::ChatRendererKind::HtmlIframe
                            | ioi_types::app::ChatRendererKind::JsxSandbox
                            | ioi_types::app::ChatRendererKind::WorkspaceSurface
                    ) {
                        0.2
                    } else {
                        0.0
                    }),
            );
            let revision_cost = clamp_score(
                (if request.verification.require_build || request.verification.require_preview {
                    0.45
                } else {
                    0.0
                }) + (if matches!(
                    request.persistence,
                    ioi_types::app::ChatArtifactPersistenceMode::SharedArtifactScoped
                        | ioi_types::app::ChatArtifactPersistenceMode::WorkspaceFilesystem
                ) {
                    0.3
                } else {
                    0.1
                }),
            );
            let evidence_breadth = clamp_score(
                verification_pressure * 0.6
                    + if request.verification.require_export {
                        0.2
                    } else {
                        0.0
                    }
                    + if request.verification.require_diff_review {
                        0.2
                    } else {
                        0.0
                    },
            );
            let merge_burden = clamp_score(match request.renderer {
                ioi_types::app::ChatRendererKind::WorkspaceSurface => 1.0,
                ioi_types::app::ChatRendererKind::HtmlIframe
                | ioi_types::app::ChatRendererKind::JsxSandbox => 0.65,
                ioi_types::app::ChatRendererKind::DownloadCard
                | ioi_types::app::ChatRendererKind::BundleManifest
                | ioi_types::app::ChatRendererKind::PdfEmbed => 0.4,
                ioi_types::app::ChatRendererKind::Markdown
                | ioi_types::app::ChatRendererKind::Svg
                | ioi_types::app::ChatRendererKind::Mermaid => 0.2,
            });
            (
                work_graph_size,
                hidden_dependency_likelihood,
                verification_pressure,
                revision_cost,
                evidence_breadth,
                merge_burden,
            )
        }
        (ChatOutcomeKind::Conversation, _) => (1, 0.1, 0.1, 0.1, 0.1, 0.0),
        (ChatOutcomeKind::ToolWidget, _) => (1, 0.25, 0.2, 0.2, 0.15, 0.15),
        (ChatOutcomeKind::Visualizer, _) => (1, 0.2, 0.15, 0.15, 0.15, 0.1),
        _ => (1, 0.2, 0.15, 0.15, 0.15, 0.1),
    };

    let graph_pressure = clamp_score((work_graph_size_estimate as f32 - 1.0) / 4.0);
    let decomposition_payoff = clamp_score(
        (graph_pressure * 0.35)
            + (hidden_dependency_likelihood * 0.25)
            + (verification_pressure * 0.2)
            + (merge_burden * 0.2),
    );
    let one_shot_sufficiency = clamp_score(
        1.0 - ((graph_pressure * 0.35)
            + (hidden_dependency_likelihood * 0.25)
            + (verification_pressure * 0.2)
            + (revision_cost * 0.1)
            + (merge_burden * 0.1)),
    );

    let resolved_strategy = match outcome_kind {
        ChatOutcomeKind::Conversation | ChatOutcomeKind::Visualizer => {
            if needs_clarification {
                ChatExecutionStrategy::PlanExecute
            } else if matches!(
                requested_strategy,
                ChatExecutionStrategy::AdaptiveWorkGraph | ChatExecutionStrategy::MicroWorkGraph
            ) {
                requested_strategy
            } else {
                ChatExecutionStrategy::SinglePass
            }
        }
        ChatOutcomeKind::ToolWidget => ChatExecutionStrategy::PlanExecute,
        ChatOutcomeKind::Artifact => match artifact {
            Some(request)
                if request.scope.create_new_workspace
                    || request.verification.require_build
                    || request.verification.require_preview
                    || requested_strategy == ChatExecutionStrategy::AdaptiveWorkGraph =>
            {
                ChatExecutionStrategy::AdaptiveWorkGraph
            }
            Some(request)
                if artifact_supports_direct_authoring(request, has_active_artifact)
                    && !needs_clarification
                    && requested_strategy != ChatExecutionStrategy::MicroWorkGraph
                    && requested_strategy != ChatExecutionStrategy::AdaptiveWorkGraph
                    && one_shot_sufficiency >= 0.48
                    && decomposition_payoff < 0.62 =>
            {
                ChatExecutionStrategy::DirectAuthor
            }
            Some(request)
                if requested_strategy == ChatExecutionStrategy::SinglePass
                    && !has_active_artifact
                    && one_shot_sufficiency >= 0.72
                    && artifact_verification_requirement_count(request) <= 1 =>
            {
                ChatExecutionStrategy::SinglePass
            }
            Some(request)
                if requested_strategy == ChatExecutionStrategy::MicroWorkGraph
                    || (matches!(
                        request.renderer,
                        ioi_types::app::ChatRendererKind::HtmlIframe
                            | ioi_types::app::ChatRendererKind::JsxSandbox
                    ) && decomposition_payoff >= 0.45) =>
            {
                if decomposition_payoff >= 0.72 {
                    ChatExecutionStrategy::AdaptiveWorkGraph
                } else {
                    ChatExecutionStrategy::MicroWorkGraph
                }
            }
            Some(_request) if requested_strategy == ChatExecutionStrategy::AdaptiveWorkGraph => {
                ChatExecutionStrategy::AdaptiveWorkGraph
            }
            Some(_) if requested_strategy == ChatExecutionStrategy::MicroWorkGraph => {
                ChatExecutionStrategy::MicroWorkGraph
            }
            Some(_) => ChatExecutionStrategy::PlanExecute,
            None => ChatExecutionStrategy::PlanExecute,
        },
    };

    let decomposition_reason = match resolved_strategy {
        ChatExecutionStrategy::SinglePass => {
            "One bounded execution unit is sufficient; decomposition is not justified.".to_string()
        }
        ChatExecutionStrategy::DirectAuthor => {
            "The request is coherent as one direct document authoring pass, so Chat should preserve the raw ask and author the first artifact before planning."
                .to_string()
        }
        ChatExecutionStrategy::PlanExecute => {
            "The request benefits from planning and verification, but not from a mutable work graph."
                .to_string()
        }
        ChatExecutionStrategy::MicroWorkGraph => {
            "A small known work graph is justified, but full adaptive graph expansion would be coordination overkill."
                .to_string()
        }
        ChatExecutionStrategy::AdaptiveWorkGraph => {
            "The request implies multiple obligations or hidden dependencies, so a mutable work graph is justified."
                .to_string()
        }
    };

    let budget_envelope = execution_budget_envelope_for_strategy(resolved_strategy);
    let work_graph_required = matches!(
        resolved_strategy,
        ChatExecutionStrategy::MicroWorkGraph | ChatExecutionStrategy::AdaptiveWorkGraph
    );
    let mode_confidence = clamp_score(
        confidence * 0.5
            + (if resolved_strategy == requested_strategy {
                0.35
            } else {
                0.15
            })
            + ((1.0 - ambiguity) * 0.15),
    );

    ChatExecutionModeDecision {
        requested_strategy,
        resolved_strategy,
        mode_confidence,
        one_shot_sufficiency,
        ambiguity,
        work_graph_size_estimate,
        hidden_dependency_likelihood,
        verification_pressure,
        revision_cost,
        evidence_breadth,
        merge_burden,
        decomposition_payoff,
        work_graph_required,
        decomposition_reason,
        budget_envelope,
    }
}

pub fn committed_execution_mode_decision(
    outcome_kind: ChatOutcomeKind,
    artifact: Option<&ChatOutcomeArtifactRequest>,
    execution_strategy: ChatExecutionStrategy,
) -> ChatExecutionModeDecision {
    let mut decision = derive_execution_mode_decision(
        outcome_kind,
        artifact,
        execution_strategy,
        1.0,
        false,
        false,
    );
    decision.requested_strategy = execution_strategy;
    decision.resolved_strategy = execution_strategy;
    decision.mode_confidence = 1.0;
    decision.work_graph_required = matches!(
        execution_strategy,
        ChatExecutionStrategy::MicroWorkGraph | ChatExecutionStrategy::AdaptiveWorkGraph
    );
    decision.decomposition_reason = match execution_strategy {
        ChatExecutionStrategy::SinglePass => {
            "Chat committed to a single bounded execution pass for this outcome.".to_string()
        }
        ChatExecutionStrategy::DirectAuthor => {
            "Chat committed to direct authoring for this outcome.".to_string()
        }
        ChatExecutionStrategy::PlanExecute => {
            "Chat committed to a staged plan-and-execute pass for this outcome.".to_string()
        }
        ChatExecutionStrategy::MicroWorkGraph => {
            "Chat committed to a bounded micro-work_graph for this outcome.".to_string()
        }
        ChatExecutionStrategy::AdaptiveWorkGraph => {
            "Chat committed to an adaptive work graph for this outcome.".to_string()
        }
    };
    decision.budget_envelope = execution_budget_envelope_for_strategy(execution_strategy);
    decision
}

pub fn annotate_execution_envelope(
    envelope: &mut Option<ExecutionEnvelope>,
    mode_decision: Option<ChatExecutionModeDecision>,
    completion_invariant: Option<ExecutionCompletionInvariant>,
) {
    let Some(entry) = envelope.as_mut() else {
        return;
    };
    if let Some(decision) = mode_decision {
        entry.strategy = Some(decision.resolved_strategy);
        entry.budget_envelope = Some(decision.budget_envelope.clone());
        entry.mode_decision = Some(decision);
    }
    if completion_invariant.is_some() {
        entry.completion_invariant = completion_invariant;
    }
}

pub fn completion_invariant_for_direct_execution(
    strategy: ChatExecutionStrategy,
    required_artifact_paths: Vec<String>,
    required_verification_ids: Vec<String>,
    status: ExecutionCompletionInvariantStatus,
) -> ExecutionCompletionInvariant {
    let satisfied_verification_ids =
        if matches!(status, ExecutionCompletionInvariantStatus::Satisfied) {
            required_verification_ids.clone()
        } else {
            Vec::new()
        };
    let remaining_obligations = if matches!(status, ExecutionCompletionInvariantStatus::Satisfied) {
        Vec::new()
    } else {
        required_verification_ids
            .iter()
            .map(|id| format!("verification:{id}"))
            .collect()
    };
    ExecutionCompletionInvariant {
        summary: format!(
            "{} completes when the primary artifact exists and verification passes.",
            execution_strategy_id(strategy)
        ),
        status,
        required_work_item_ids: Vec::new(),
        satisfied_work_item_ids: Vec::new(),
        speculative_work_item_ids: Vec::new(),
        pruned_work_item_ids: Vec::new(),
        required_verification_ids,
        satisfied_verification_ids,
        required_artifact_paths,
        remaining_obligations,
        allows_early_exit: matches!(
            strategy,
            ChatExecutionStrategy::SinglePass
                | ChatExecutionStrategy::DirectAuthor
                | ChatExecutionStrategy::PlanExecute
        ),
    }
}

pub fn completion_invariant_for_plan(
    plan: &WorkGraphPlan,
    verification_receipts: &[WorkGraphVerificationReceipt],
    required_artifact_paths: Vec<String>,
) -> ExecutionCompletionInvariant {
    let required_work_item_ids = plan
        .work_items
        .iter()
        .filter(|item| {
            item.role != WorkGraphWorkerRole::Repair && !item.id.starts_with("repair-pass-")
        })
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let satisfied_work_item_ids = plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                WorkGraphWorkItemStatus::Succeeded | WorkGraphWorkItemStatus::Skipped
            )
        })
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let speculative_work_item_ids = plan
        .work_items
        .iter()
        .filter(|item| {
            item.role == WorkGraphWorkerRole::Repair || item.id.starts_with("repair-pass-")
        })
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let pruned_work_item_ids = plan
        .work_items
        .iter()
        .filter(|item| {
            item.status == WorkGraphWorkItemStatus::Skipped
                && (item.role == WorkGraphWorkerRole::Repair
                    || item.role == WorkGraphWorkerRole::Integrator
                    || item.id.starts_with("repair-pass-"))
        })
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let required_verification_ids = verification_receipts
        .iter()
        .map(|receipt| receipt.id.clone())
        .collect::<Vec<_>>();
    let satisfied_verification_ids = verification_receipts
        .iter()
        .filter(|receipt| matches!(receipt.status.as_str(), "success" | "ready" | "pass"))
        .map(|receipt| receipt.id.clone())
        .collect::<Vec<_>>();
    let mut remaining_obligations = required_work_item_ids
        .iter()
        .filter(|id| !satisfied_work_item_ids.iter().any(|done| done == *id))
        .map(|id| format!("work_item:{id}"))
        .collect::<Vec<_>>();
    remaining_obligations.extend(
        required_verification_ids
            .iter()
            .filter(|id| !satisfied_verification_ids.iter().any(|done| done == *id))
            .map(|id| format!("verification:{id}")),
    );
    let status = if remaining_obligations.is_empty() {
        ExecutionCompletionInvariantStatus::Satisfied
    } else if plan.work_items.iter().any(|item| {
        matches!(
            item.status,
            WorkGraphWorkItemStatus::Failed
                | WorkGraphWorkItemStatus::Rejected
                | WorkGraphWorkItemStatus::Blocked
        )
    }) {
        ExecutionCompletionInvariantStatus::Blocked
    } else {
        ExecutionCompletionInvariantStatus::Pending
    };
    ExecutionCompletionInvariant {
        summary: plan
            .completion_invariant
            .as_ref()
            .map(|entry| entry.summary.clone())
            .unwrap_or_else(|| {
                "The run completes when the mandatory work graph and verification obligations are satisfied."
                    .to_string()
            }),
        status,
        required_work_item_ids,
        satisfied_work_item_ids,
        speculative_work_item_ids,
        pruned_work_item_ids,
        required_verification_ids,
        satisfied_verification_ids,
        required_artifact_paths,
        remaining_obligations,
        allows_early_exit: matches!(
            plan.strategy.as_str(),
            "micro_work_graph" | "adaptive_work_graph" | "work_graph"
        ),
    }
}

pub fn shared_read_lease_for_path(path: impl Into<String>) -> WorkGraphLeaseRequirement {
    WorkGraphLeaseRequirement {
        target: path.into(),
        scope_kind: WorkGraphLeaseScopeKind::File,
        mode: WorkGraphLeaseMode::SharedRead,
    }
}

pub fn exclusive_write_lease_for_path(path: impl Into<String>) -> WorkGraphLeaseRequirement {
    WorkGraphLeaseRequirement {
        target: path.into(),
        scope_kind: WorkGraphLeaseScopeKind::File,
        mode: WorkGraphLeaseMode::ExclusiveWrite,
    }
}

pub fn exclusive_write_lease_for_region(region: impl Into<String>) -> WorkGraphLeaseRequirement {
    WorkGraphLeaseRequirement {
        target: region.into(),
        scope_kind: WorkGraphLeaseScopeKind::Region,
        mode: WorkGraphLeaseMode::ExclusiveWrite,
    }
}

pub fn spawn_follow_up_work_graph_work_item(
    work_graph_plan: &mut WorkGraphPlan,
    mut work_item: WorkGraphWorkItem,
) -> Result<(), String> {
    if work_graph_plan
        .work_items
        .iter()
        .any(|item| item.id == work_item.id)
    {
        return Err(format!(
            "WorkGraph work item '{}' already exists in the work graph.",
            work_item.id
        ));
    }

    if let Some(parent_id) = work_item.spawned_from_id.as_ref() {
        if !work_graph_plan
            .work_items
            .iter()
            .any(|item| item.id == *parent_id)
        {
            return Err(format!(
                "WorkGraph work item '{}' cannot spawn from missing parent '{}'.",
                work_item.id, parent_id
            ));
        }
        if !work_item
            .dependency_ids
            .iter()
            .any(|dependency| dependency == parent_id)
        {
            work_item.dependency_ids.push(parent_id.clone());
        }
    }

    work_graph_plan.work_items.push(work_item);
    work_graph_plan.version = work_graph_plan.version.saturating_add(1);
    Ok(())
}

pub fn block_work_graph_work_item_on(
    work_graph_plan: &mut WorkGraphPlan,
    work_item_id: &str,
    blocked_on_ids: &[String],
) -> Result<(), String> {
    for blocked_on_id in blocked_on_ids {
        if !work_graph_plan
            .work_items
            .iter()
            .any(|item| item.id == *blocked_on_id)
        {
            return Err(format!(
                "WorkGraph work item '{}' cannot be blocked on missing work item '{}'.",
                work_item_id, blocked_on_id
            ));
        }
    }

    let Some(work_item) = work_graph_plan
        .work_items
        .iter_mut()
        .find(|item| item.id == work_item_id)
    else {
        return Err(format!(
            "WorkGraph work item '{}' is missing from the work graph.",
            work_item_id
        ));
    };

    for blocked_on_id in blocked_on_ids {
        if !work_item
            .blocked_on_ids
            .iter()
            .any(|entry| entry == blocked_on_id)
        {
            work_item.blocked_on_ids.push(blocked_on_id.clone());
        }
        if !work_item
            .dependency_ids
            .iter()
            .any(|entry| entry == blocked_on_id)
        {
            work_item.dependency_ids.push(blocked_on_id.clone());
        }
    }
    if !blocked_on_ids.is_empty()
        && !matches!(
            work_item.status,
            WorkGraphWorkItemStatus::Succeeded | WorkGraphWorkItemStatus::Skipped
        )
    {
        work_item.status = WorkGraphWorkItemStatus::Blocked;
    }
    work_graph_plan.version = work_graph_plan.version.saturating_add(1);
    Ok(())
}

pub fn work_graph_work_item_lease_conflicts(
    left: &WorkGraphWorkItem,
    right: &WorkGraphWorkItem,
) -> bool {
    left.lease_requirements.iter().any(|left_lease| {
        right.lease_requirements.iter().any(|right_lease| {
            left_lease.target == right_lease.target
                && left_lease.scope_kind == right_lease.scope_kind
                && (left_lease.mode == WorkGraphLeaseMode::ExclusiveWrite
                    || right_lease.mode == WorkGraphLeaseMode::ExclusiveWrite)
        })
    })
}

fn work_graph_dependency_states<'a>(
    work_item: &WorkGraphWorkItem,
    work_item_by_id: &HashMap<String, &'a WorkGraphWorkItem>,
) -> (Vec<String>, Vec<String>) {
    let mut unmet_dependencies = Vec::new();
    let mut failed_dependencies = Vec::new();
    for dependency_id in work_item
        .dependency_ids
        .iter()
        .chain(work_item.blocked_on_ids.iter())
    {
        match work_item_by_id.get(dependency_id) {
            Some(dependency) => match dependency.status {
                WorkGraphWorkItemStatus::Succeeded | WorkGraphWorkItemStatus::Skipped => {}
                WorkGraphWorkItemStatus::Failed | WorkGraphWorkItemStatus::Rejected => {
                    failed_dependencies.push(dependency_id.clone());
                }
                WorkGraphWorkItemStatus::Pending
                | WorkGraphWorkItemStatus::Blocked
                | WorkGraphWorkItemStatus::Running => {
                    unmet_dependencies.push(dependency_id.clone());
                }
            },
            None => failed_dependencies.push(dependency_id.clone()),
        }
    }
    (unmet_dependencies, failed_dependencies)
}

pub fn next_work_graph_dispatch_batch(
    work_graph_plan: &WorkGraphPlan,
    candidate_work_item_ids: &[String],
    sequence: u32,
) -> Option<ExecutionDispatchBatch> {
    let work_item_by_id = work_graph_plan
        .work_items
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<HashMap<_, _>>();
    let pending_ids = candidate_work_item_ids
        .iter()
        .filter_map(|work_item_id| {
            work_item_by_id
                .get(work_item_id)
                .map(|item| (*item).clone())
        })
        .filter(|item| {
            !matches!(
                item.status,
                WorkGraphWorkItemStatus::Succeeded
                    | WorkGraphWorkItemStatus::Skipped
                    | WorkGraphWorkItemStatus::Failed
                    | WorkGraphWorkItemStatus::Rejected
            )
        })
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    if pending_ids.is_empty() {
        return None;
    }

    let mut ready_ids = Vec::new();
    let mut blocked_ids = Vec::new();
    let mut blocked_details = Vec::new();

    for work_item_id in &pending_ids {
        let Some(work_item) = work_item_by_id.get(work_item_id) else {
            continue;
        };
        let (unmet_dependencies, failed_dependencies) =
            work_graph_dependency_states(work_item, &work_item_by_id);
        if !failed_dependencies.is_empty() {
            blocked_ids.push(work_item_id.clone());
            blocked_details.push(format!(
                "{} blocked by failed dependency {}",
                work_item_id,
                failed_dependencies.join(" · ")
            ));
        } else if !unmet_dependencies.is_empty() {
            blocked_ids.push(work_item_id.clone());
            blocked_details.push(format!(
                "{} waits on {}",
                work_item_id,
                unmet_dependencies.join(" · ")
            ));
        } else {
            ready_ids.push(work_item_id.clone());
        }
    }

    if ready_ids.is_empty() {
        return Some(ExecutionDispatchBatch {
            id: format!("dispatch-batch-{sequence}"),
            sequence,
            status: "blocked".to_string(),
            work_item_ids: Vec::new(),
            deferred_work_item_ids: Vec::new(),
            blocked_work_item_ids: pending_ids,
            details: blocked_details,
        });
    }

    let mut dispatchable_ids = Vec::new();
    let mut deferred_ids = Vec::new();
    let mut details = Vec::new();
    for ready_id in ready_ids {
        let Some(candidate) = work_item_by_id.get(&ready_id) else {
            continue;
        };
        if let Some(conflicting_id) = dispatchable_ids.iter().find(|selected_id| {
            work_item_by_id
                .get(*selected_id)
                .map(|selected| work_graph_work_item_lease_conflicts(candidate, selected))
                .unwrap_or(false)
        }) {
            deferred_ids.push(ready_id.clone());
            details.push(format!(
                "{} deferred because it conflicts with {}",
                ready_id, conflicting_id
            ));
        } else {
            dispatchable_ids.push(ready_id);
        }
    }

    if dispatchable_ids.is_empty() {
        if let Some(first_deferred) = deferred_ids.first().cloned() {
            dispatchable_ids.push(first_deferred.clone());
            deferred_ids.retain(|entry| entry != &first_deferred);
            details.push(format!(
                "{} forced into its own dispatch wave to break a pure lease conflict set",
                first_deferred
            ));
        }
    }

    Some(ExecutionDispatchBatch {
        id: format!("dispatch-batch-{sequence}"),
        sequence,
        status: if deferred_ids.is_empty() && blocked_ids.is_empty() {
            "ready".to_string()
        } else {
            "constrained".to_string()
        },
        work_item_ids: dispatchable_ids,
        deferred_work_item_ids: deferred_ids,
        blocked_work_item_ids: blocked_ids,
        details: {
            details.extend(blocked_details);
            details
        },
    })
}

pub fn constrain_dispatch_batch_by_parallelism(
    batch: &mut ExecutionDispatchBatch,
    max_parallelism: usize,
) {
    let capped_parallelism = max_parallelism.max(1);
    if batch.work_item_ids.len() <= capped_parallelism {
        return;
    }

    let overflow = batch.work_item_ids.split_off(capped_parallelism);
    for work_item_id in &overflow {
        if !batch
            .deferred_work_item_ids
            .iter()
            .any(|existing| existing == work_item_id)
        {
            batch.deferred_work_item_ids.push(work_item_id.clone());
        }
    }
    batch.details.push(format!(
        "Budget capped this dispatch wave at {} parallel worker(s); deferred {}.",
        capped_parallelism,
        overflow.join(" · ")
    ));
    if batch.status == "ready" {
        batch.status = "budget_limited".to_string();
    }
}

pub fn plan_work_graph_dispatch_batches(
    work_graph_plan: &WorkGraphPlan,
) -> Vec<ExecutionDispatchBatch> {
    let work_item_by_id = work_graph_plan
        .work_items
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<HashMap<_, _>>();
    let mut remaining = work_graph_plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                WorkGraphWorkItemStatus::Pending
                    | WorkGraphWorkItemStatus::Blocked
                    | WorkGraphWorkItemStatus::Running
            )
        })
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let mut completed = work_graph_plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                WorkGraphWorkItemStatus::Succeeded | WorkGraphWorkItemStatus::Skipped
            )
        })
        .map(|item| item.id.clone())
        .collect::<BTreeSet<_>>();
    let mut batches = Vec::new();
    let mut sequence = 1u32;

    while !remaining.is_empty() {
        let mut ready_ids = Vec::new();
        let mut blocked_ids = Vec::new();
        let mut blocked_details = Vec::new();

        for work_item_id in &remaining {
            let Some(work_item) = work_item_by_id.get(work_item_id) else {
                continue;
            };
            let (mut unmet_dependencies, failed_dependencies) =
                work_graph_dependency_states(work_item, &work_item_by_id);
            unmet_dependencies.retain(|dependency_id| !completed.contains(dependency_id));
            if !failed_dependencies.is_empty() {
                blocked_ids.push(work_item_id.clone());
                blocked_details.push(format!(
                    "{} blocked by failed dependency {}",
                    work_item_id,
                    failed_dependencies.join(" · ")
                ));
            } else if unmet_dependencies.is_empty() {
                ready_ids.push(work_item_id.clone());
            } else {
                blocked_ids.push(work_item_id.clone());
                blocked_details.push(format!(
                    "{} waits on {}",
                    work_item_id,
                    unmet_dependencies.join(" · ")
                ));
            }
        }

        if ready_ids.is_empty() {
            batches.push(ExecutionDispatchBatch {
                id: format!("dispatch-batch-{sequence}"),
                sequence,
                status: "blocked".to_string(),
                work_item_ids: Vec::new(),
                deferred_work_item_ids: Vec::new(),
                blocked_work_item_ids: remaining.clone(),
                details: blocked_details,
            });
            break;
        }

        let mut dispatchable_ids = Vec::new();
        let mut deferred_ids = Vec::new();
        let mut details = Vec::new();
        for ready_id in ready_ids {
            let Some(candidate) = work_item_by_id.get(&ready_id) else {
                continue;
            };
            if let Some(conflicting_id) = dispatchable_ids.iter().find(|selected_id| {
                work_item_by_id
                    .get(*selected_id)
                    .map(|selected| work_graph_work_item_lease_conflicts(candidate, selected))
                    .unwrap_or(false)
            }) {
                deferred_ids.push(ready_id.clone());
                details.push(format!(
                    "{} deferred because it conflicts with {}",
                    ready_id, conflicting_id
                ));
            } else {
                dispatchable_ids.push(ready_id);
            }
        }

        if dispatchable_ids.is_empty() {
            if let Some(first_deferred) = deferred_ids.first().cloned() {
                dispatchable_ids.push(first_deferred.clone());
                deferred_ids.retain(|entry| entry != &first_deferred);
                details.push(format!(
                    "{} forced into its own dispatch wave to break a pure lease conflict set",
                    first_deferred
                ));
            }
        }

        completed.extend(dispatchable_ids.iter().cloned());
        remaining
            .retain(|work_item_id| !dispatchable_ids.iter().any(|entry| entry == work_item_id));

        batches.push(ExecutionDispatchBatch {
            id: format!("dispatch-batch-{sequence}"),
            sequence,
            status: if deferred_ids.is_empty() && blocked_ids.is_empty() {
                "planned".to_string()
            } else {
                "constrained".to_string()
            },
            work_item_ids: dispatchable_ids,
            deferred_work_item_ids: deferred_ids,
            blocked_work_item_ids: blocked_ids,
            details: {
                details.extend(blocked_details);
                details
            },
        });
        sequence = sequence.saturating_add(1);
    }

    batches
}

pub fn execution_strategy_for_outcome(
    outcome_kind: ChatOutcomeKind,
    artifact: Option<&ChatOutcomeArtifactRequest>,
) -> ChatExecutionStrategy {
    match outcome_kind {
        ChatOutcomeKind::Conversation | ChatOutcomeKind::Visualizer => {
            ChatExecutionStrategy::SinglePass
        }
        ChatOutcomeKind::ToolWidget => ChatExecutionStrategy::PlanExecute,
        ChatOutcomeKind::Artifact => artifact
            .filter(|request| artifact_supports_direct_authoring(request, false))
            .map(|_| ChatExecutionStrategy::DirectAuthor)
            .unwrap_or(ChatExecutionStrategy::PlanExecute),
    }
}

pub fn execution_domain_kind_for_outcome(outcome_kind: ChatOutcomeKind) -> ExecutionDomainKind {
    match outcome_kind {
        ChatOutcomeKind::Artifact => ExecutionDomainKind::Artifact,
        ChatOutcomeKind::Conversation => ExecutionDomainKind::Conversation,
        ChatOutcomeKind::ToolWidget => ExecutionDomainKind::ToolWidget,
        ChatOutcomeKind::Visualizer => ExecutionDomainKind::Visualizer,
    }
}

pub fn infer_execution_domain_kind(execution_domain: &str) -> Option<ExecutionDomainKind> {
    let normalized = execution_domain.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "artifact" | "chat_artifact" => Some(ExecutionDomainKind::Artifact),
        "conversation" | "chat_conversation" => Some(ExecutionDomainKind::Conversation),
        "tool_widget" | "chat_tool_widget" => Some(ExecutionDomainKind::ToolWidget),
        "visualizer" | "chat_visualizer" => Some(ExecutionDomainKind::Visualizer),
        "workflow" => Some(ExecutionDomainKind::Workflow),
        "research" => Some(ExecutionDomainKind::Research),
        "reply" => Some(ExecutionDomainKind::Reply),
        "code" => Some(ExecutionDomainKind::Code),
        "" => None,
        _ => Some(ExecutionDomainKind::Unknown),
    }
}

pub fn parse_execution_strategy_id(raw: &str) -> Option<ChatExecutionStrategy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "single_pass" => Some(ChatExecutionStrategy::SinglePass),
        "direct_author" => Some(ChatExecutionStrategy::DirectAuthor),
        "plan_execute" => Some(ChatExecutionStrategy::PlanExecute),
        "micro_work_graph" => Some(ChatExecutionStrategy::MicroWorkGraph),
        "adaptive_work_graph" | "work_graph" => Some(ChatExecutionStrategy::AdaptiveWorkGraph),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_execution_envelope_from_work_graph(
    strategy: Option<ChatExecutionStrategy>,
    execution_domain: Option<String>,
    domain_kind: Option<ExecutionDomainKind>,
    plan: Option<&WorkGraphPlan>,
    execution_summary: Option<&WorkGraphExecutionSummary>,
    worker_receipts: &[WorkGraphWorkerReceipt],
    change_receipts: &[WorkGraphChangeReceipt],
    merge_receipts: &[WorkGraphMergeReceipt],
    verification_receipts: &[WorkGraphVerificationReceipt],
) -> Option<ExecutionEnvelope> {
    build_execution_envelope_from_work_graph_with_receipts(
        strategy,
        execution_domain,
        domain_kind,
        plan,
        execution_summary,
        worker_receipts,
        change_receipts,
        merge_receipts,
        verification_receipts,
        &[],
        &[],
        &[],
        &[],
        None,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_execution_envelope_from_work_graph_with_receipts(
    strategy: Option<ChatExecutionStrategy>,
    execution_domain: Option<String>,
    domain_kind: Option<ExecutionDomainKind>,
    plan: Option<&WorkGraphPlan>,
    execution_summary: Option<&WorkGraphExecutionSummary>,
    worker_receipts: &[WorkGraphWorkerReceipt],
    change_receipts: &[WorkGraphChangeReceipt],
    merge_receipts: &[WorkGraphMergeReceipt],
    verification_receipts: &[WorkGraphVerificationReceipt],
    graph_mutation_receipts: &[ExecutionGraphMutationReceipt],
    dispatch_batches: &[ExecutionDispatchBatch],
    repair_receipts: &[ExecutionRepairReceipt],
    replan_receipts: &[ExecutionReplanReceipt],
    budget_summary: Option<ExecutionBudgetSummary>,
    live_previews: &[ExecutionLivePreview],
) -> Option<ExecutionEnvelope> {
    let has_any_data = strategy.is_some()
        || execution_domain.is_some()
        || domain_kind.is_some()
        || plan.is_some()
        || execution_summary.is_some()
        || !worker_receipts.is_empty()
        || !change_receipts.is_empty()
        || !merge_receipts.is_empty()
        || !verification_receipts.is_empty()
        || !graph_mutation_receipts.is_empty()
        || !dispatch_batches.is_empty()
        || !repair_receipts.is_empty()
        || !replan_receipts.is_empty()
        || budget_summary.is_some()
        || !live_previews.is_empty();
    if !has_any_data {
        return None;
    }

    let resolved_strategy = strategy
        .or_else(|| plan.and_then(|entry| parse_execution_strategy_id(&entry.strategy)))
        .or_else(|| {
            execution_summary.and_then(|entry| parse_execution_strategy_id(&entry.strategy))
        });
    let resolved_domain = execution_domain
        .or_else(|| execution_summary.map(|entry| entry.execution_domain.clone()))
        .or_else(|| plan.map(|entry| entry.execution_domain.clone()))
        .unwrap_or_else(default_execution_domain);
    let resolved_domain_kind =
        domain_kind.or_else(|| infer_execution_domain_kind(&resolved_domain));
    let resolved_dispatch_batches = if dispatch_batches.is_empty() {
        plan.map(plan_work_graph_dispatch_batches)
            .unwrap_or_default()
    } else {
        dispatch_batches.to_vec()
    };
    let work_item_commits = build_work_graph_work_item_commits(worker_receipts, change_receipts);
    let merge_decision_artifacts =
        build_work_graph_merge_decision_artifacts(merge_receipts, &work_item_commits);
    let retry_decision_artifacts = build_work_graph_retry_decision_artifacts(replan_receipts);
    let repair_action_artifacts = build_work_graph_repair_action_artifacts(repair_receipts);
    let workflow_artifact_root_hash = build_workflow_artifact_root_hash(
        &work_item_commits,
        &merge_decision_artifacts,
        &retry_decision_artifacts,
        &repair_action_artifacts,
    );

    let envelope = ExecutionEnvelope {
        version: 1,
        strategy: resolved_strategy,
        mode_decision: None,
        budget_envelope: None,
        execution_domain: resolved_domain,
        domain_kind: resolved_domain_kind,
        workflow_artifact_root_hash: Some(workflow_artifact_root_hash),
        completion_invariant: plan.and_then(|entry| entry.completion_invariant.clone()),
        plan: plan.cloned(),
        execution_summary: execution_summary.cloned(),
        worker_receipts: worker_receipts.to_vec(),
        change_receipts: change_receipts.to_vec(),
        merge_receipts: merge_receipts.to_vec(),
        verification_receipts: verification_receipts.to_vec(),
        work_item_commits,
        merge_decision_artifacts,
        graph_mutation_receipts: graph_mutation_receipts.to_vec(),
        dispatch_batches: resolved_dispatch_batches,
        repair_receipts: repair_receipts.to_vec(),
        replan_receipts: replan_receipts.to_vec(),
        retry_decision_artifacts,
        repair_action_artifacts,
        budget_summary,
        live_previews: live_previews.to_vec(),
    };
    debug_assert!(validate_execution_envelope(&envelope).is_ok());
    Some(envelope)
}

#[cfg(test)]
#[path = "execution/tests.rs"]
mod tests;
