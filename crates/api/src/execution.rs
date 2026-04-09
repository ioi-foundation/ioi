use ioi_types::app::{
    StudioExecutionBudgetEnvelope, StudioExecutionBudgetExpansionPolicy,
    StudioExecutionModeDecision, StudioExecutionStrategy, StudioOutcomeArtifactRequest,
    StudioOutcomeKind, StudioRuntimeProvenance,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
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
pub enum SwarmWorkerRole {
    Planner,
    Coordinator,
    Responder,
    Skeleton,
    SectionContent,
    StyleSystem,
    Interaction,
    Integrator,
    Judge,
    Repair,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SwarmLeaseMode {
    SharedRead,
    ExclusiveWrite,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SwarmLeaseScopeKind {
    File,
    Region,
    Surface,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmLeaseRequirement {
    pub target: String,
    pub scope_kind: SwarmLeaseScopeKind,
    pub mode: SwarmLeaseMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SwarmVerificationPolicy {
    Normal,
    Elevated,
    Blocking,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SwarmWorkItemStatus {
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
pub enum SwarmWorkerResultKind {
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
pub struct SwarmWorkItem {
    pub id: String,
    pub title: String,
    pub role: SwarmWorkerRole,
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
    pub lease_requirements: Vec<SwarmLeaseRequirement>,
    #[serde(default)]
    pub acceptance_criteria: Vec<String>,
    #[serde(default)]
    pub dependency_ids: Vec<String>,
    #[serde(default)]
    pub blocked_on_ids: Vec<String>,
    #[serde(default)]
    pub verification_policy: Option<SwarmVerificationPolicy>,
    #[serde(default)]
    pub retry_budget: Option<u32>,
    pub status: SwarmWorkItemStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmPlan {
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
    pub work_items: Vec<SwarmWorkItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwarmExecutionSummary {
    pub enabled: bool,
    pub current_stage: String,
    #[serde(default)]
    pub execution_stage: Option<ExecutionStage>,
    #[serde(default)]
    pub active_worker_role: Option<SwarmWorkerRole>,
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
pub struct SwarmWorkerReceipt {
    pub work_item_id: String,
    pub role: SwarmWorkerRole,
    pub status: SwarmWorkItemStatus,
    #[serde(default)]
    pub result_kind: Option<SwarmWorkerResultKind>,
    pub summary: String,
    pub started_at: String,
    #[serde(default)]
    pub finished_at: Option<String>,
    pub runtime: StudioRuntimeProvenance,
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
pub struct SwarmChangeReceipt {
    pub work_item_id: String,
    pub status: SwarmWorkItemStatus,
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
pub struct SwarmMergeReceipt {
    pub work_item_id: String,
    pub status: SwarmWorkItemStatus,
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
pub struct SwarmVerificationReceipt {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub summary: String,
    #[serde(default)]
    pub details: Vec<String>,
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
    pub role: Option<SwarmWorkerRole>,
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
    pub strategy: Option<StudioExecutionStrategy>,
    #[serde(default)]
    pub mode_decision: Option<StudioExecutionModeDecision>,
    #[serde(default)]
    pub budget_envelope: Option<StudioExecutionBudgetEnvelope>,
    pub execution_domain: String,
    #[serde(default)]
    pub domain_kind: Option<ExecutionDomainKind>,
    #[serde(default)]
    pub completion_invariant: Option<ExecutionCompletionInvariant>,
    #[serde(default)]
    pub plan: Option<SwarmPlan>,
    #[serde(default)]
    pub execution_summary: Option<SwarmExecutionSummary>,
    #[serde(default)]
    pub worker_receipts: Vec<SwarmWorkerReceipt>,
    #[serde(default)]
    pub change_receipts: Vec<SwarmChangeReceipt>,
    #[serde(default)]
    pub merge_receipts: Vec<SwarmMergeReceipt>,
    #[serde(default)]
    pub verification_receipts: Vec<SwarmVerificationReceipt>,
    #[serde(default)]
    pub graph_mutation_receipts: Vec<ExecutionGraphMutationReceipt>,
    #[serde(default)]
    pub dispatch_batches: Vec<ExecutionDispatchBatch>,
    #[serde(default)]
    pub repair_receipts: Vec<ExecutionRepairReceipt>,
    #[serde(default)]
    pub replan_receipts: Vec<ExecutionReplanReceipt>,
    #[serde(default)]
    pub budget_summary: Option<ExecutionBudgetSummary>,
    #[serde(default)]
    pub live_previews: Vec<ExecutionLivePreview>,
}

fn execution_strategy_id(strategy: StudioExecutionStrategy) -> &'static str {
    match strategy {
        StudioExecutionStrategy::SinglePass => "single_pass",
        StudioExecutionStrategy::DirectAuthor => "direct_author",
        StudioExecutionStrategy::PlanExecute => "plan_execute",
        StudioExecutionStrategy::MicroSwarm => "micro_swarm",
        StudioExecutionStrategy::AdaptiveWorkGraph => "adaptive_work_graph",
    }
}

fn artifact_verification_requirement_count(request: &StudioOutcomeArtifactRequest) -> u32 {
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

fn artifact_work_graph_size_estimate(request: &StudioOutcomeArtifactRequest) -> u32 {
    let base = match request.renderer {
        ioi_types::app::StudioRendererKind::WorkspaceSurface => 5,
        ioi_types::app::StudioRendererKind::HtmlIframe
        | ioi_types::app::StudioRendererKind::JsxSandbox => 3,
        ioi_types::app::StudioRendererKind::DownloadCard
        | ioi_types::app::StudioRendererKind::BundleManifest
        | ioi_types::app::StudioRendererKind::PdfEmbed => 2,
        ioi_types::app::StudioRendererKind::Markdown
        | ioi_types::app::StudioRendererKind::Svg
        | ioi_types::app::StudioRendererKind::Mermaid => 1,
    };
    base + u32::from(request.scope.create_new_workspace)
        + u32::from(request.verification.require_build || request.verification.require_preview)
}

fn clamp_score(value: f32) -> f32 {
    value.clamp(0.0, 1.0)
}

fn artifact_supports_direct_authoring(
    request: &StudioOutcomeArtifactRequest,
    has_active_artifact: bool,
) -> bool {
    matches!(
        request.renderer,
        ioi_types::app::StudioRendererKind::Markdown
            | ioi_types::app::StudioRendererKind::HtmlIframe
            | ioi_types::app::StudioRendererKind::Svg
            | ioi_types::app::StudioRendererKind::Mermaid
            | ioi_types::app::StudioRendererKind::PdfEmbed
    )
        && request.deliverable_shape == ioi_types::app::StudioArtifactDeliverableShape::SingleFile
        && request.execution_substrate != ioi_types::app::StudioExecutionSubstrate::WorkspaceRuntime
        && !request.scope.create_new_workspace
        && !has_active_artifact
        && !request.verification.require_build
        && !request.verification.require_preview
        && !request.verification.require_diff_review
}

pub fn execution_budget_envelope_for_strategy(
    strategy: StudioExecutionStrategy,
) -> StudioExecutionBudgetEnvelope {
    match strategy {
        StudioExecutionStrategy::SinglePass => StudioExecutionBudgetEnvelope {
            max_workers: 1,
            max_parallel_depth: 1,
            max_replans: 0,
            max_wall_clock_ms: 60_000,
            max_tokens: 2_048,
            max_tool_calls: 1,
            max_repairs: 0,
            expansion_policy: StudioExecutionBudgetExpansionPolicy::Fixed,
        },
        StudioExecutionStrategy::DirectAuthor => StudioExecutionBudgetEnvelope {
            max_workers: 1,
            max_parallel_depth: 1,
            max_replans: 0,
            max_wall_clock_ms: 90_000,
            max_tokens: 4_096,
            max_tool_calls: 1,
            max_repairs: 1,
            expansion_policy: StudioExecutionBudgetExpansionPolicy::Fixed,
        },
        StudioExecutionStrategy::PlanExecute => StudioExecutionBudgetEnvelope {
            max_workers: 1,
            max_parallel_depth: 1,
            max_replans: 0,
            max_wall_clock_ms: 180_000,
            max_tokens: 8_192,
            max_tool_calls: 4,
            max_repairs: 1,
            expansion_policy: StudioExecutionBudgetExpansionPolicy::Fixed,
        },
        StudioExecutionStrategy::MicroSwarm => StudioExecutionBudgetEnvelope {
            max_workers: 3,
            max_parallel_depth: 2,
            max_replans: 1,
            max_wall_clock_ms: 300_000,
            max_tokens: 12_000,
            max_tool_calls: 6,
            max_repairs: 1,
            expansion_policy: StudioExecutionBudgetExpansionPolicy::ConfidenceGated,
        },
        StudioExecutionStrategy::AdaptiveWorkGraph => StudioExecutionBudgetEnvelope {
            max_workers: 8,
            max_parallel_depth: 4,
            max_replans: 4,
            max_wall_clock_ms: 600_000,
            max_tokens: 24_000,
            max_tool_calls: 12,
            max_repairs: 2,
            expansion_policy: StudioExecutionBudgetExpansionPolicy::FrontierAdaptive,
        },
    }
}

pub fn derive_execution_mode_decision(
    outcome_kind: StudioOutcomeKind,
    artifact: Option<&StudioOutcomeArtifactRequest>,
    requested_strategy: StudioExecutionStrategy,
    confidence: f32,
    needs_clarification: bool,
    has_active_artifact: bool,
) -> StudioExecutionModeDecision {
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
        (StudioOutcomeKind::Artifact, Some(request)) => {
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
                        ioi_types::app::StudioRendererKind::HtmlIframe
                            | ioi_types::app::StudioRendererKind::JsxSandbox
                            | ioi_types::app::StudioRendererKind::WorkspaceSurface
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
                    ioi_types::app::StudioArtifactPersistenceMode::SharedArtifactScoped
                        | ioi_types::app::StudioArtifactPersistenceMode::WorkspaceFilesystem
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
                ioi_types::app::StudioRendererKind::WorkspaceSurface => 1.0,
                ioi_types::app::StudioRendererKind::HtmlIframe
                | ioi_types::app::StudioRendererKind::JsxSandbox => 0.65,
                ioi_types::app::StudioRendererKind::DownloadCard
                | ioi_types::app::StudioRendererKind::BundleManifest
                | ioi_types::app::StudioRendererKind::PdfEmbed => 0.4,
                ioi_types::app::StudioRendererKind::Markdown
                | ioi_types::app::StudioRendererKind::Svg
                | ioi_types::app::StudioRendererKind::Mermaid => 0.2,
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
        (StudioOutcomeKind::Conversation, _) => (1, 0.1, 0.1, 0.1, 0.1, 0.0),
        (StudioOutcomeKind::ToolWidget, _) => (1, 0.25, 0.2, 0.2, 0.15, 0.15),
        (StudioOutcomeKind::Visualizer, _) => (1, 0.2, 0.15, 0.15, 0.15, 0.1),
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
        StudioOutcomeKind::Conversation | StudioOutcomeKind::Visualizer => {
            if needs_clarification {
                StudioExecutionStrategy::PlanExecute
            } else {
                StudioExecutionStrategy::SinglePass
            }
        }
        StudioOutcomeKind::ToolWidget => StudioExecutionStrategy::PlanExecute,
        StudioOutcomeKind::Artifact => match artifact {
            Some(request)
                if request.scope.create_new_workspace
                    || request.verification.require_build
                    || request.verification.require_preview
                    || requested_strategy == StudioExecutionStrategy::AdaptiveWorkGraph =>
            {
                StudioExecutionStrategy::AdaptiveWorkGraph
            }
            Some(request)
                if artifact_supports_direct_authoring(request, has_active_artifact)
                    && !needs_clarification
                    && requested_strategy != StudioExecutionStrategy::MicroSwarm
                    && requested_strategy != StudioExecutionStrategy::AdaptiveWorkGraph
                    && one_shot_sufficiency >= 0.48
                    && decomposition_payoff < 0.62 =>
            {
                StudioExecutionStrategy::DirectAuthor
            }
            Some(request)
                if requested_strategy == StudioExecutionStrategy::SinglePass
                    && !has_active_artifact
                    && one_shot_sufficiency >= 0.72
                    && artifact_verification_requirement_count(request) <= 1 =>
            {
                StudioExecutionStrategy::SinglePass
            }
            Some(request)
                if requested_strategy == StudioExecutionStrategy::MicroSwarm
                    || (matches!(
                        request.renderer,
                        ioi_types::app::StudioRendererKind::HtmlIframe
                            | ioi_types::app::StudioRendererKind::JsxSandbox
                    ) && decomposition_payoff >= 0.45) =>
            {
                if decomposition_payoff >= 0.72 {
                    StudioExecutionStrategy::AdaptiveWorkGraph
                } else {
                    StudioExecutionStrategy::MicroSwarm
                }
            }
            Some(_request) if requested_strategy == StudioExecutionStrategy::AdaptiveWorkGraph => {
                StudioExecutionStrategy::AdaptiveWorkGraph
            }
            Some(_) if requested_strategy == StudioExecutionStrategy::MicroSwarm => {
                StudioExecutionStrategy::MicroSwarm
            }
            Some(_) => StudioExecutionStrategy::PlanExecute,
            None => StudioExecutionStrategy::PlanExecute,
        },
    };

    let decomposition_reason = match resolved_strategy {
        StudioExecutionStrategy::SinglePass => {
            "One bounded execution unit is sufficient; decomposition is not justified.".to_string()
        }
        StudioExecutionStrategy::DirectAuthor => {
            "The request is coherent as one direct document authoring pass, so Studio should preserve the raw ask and author the first artifact before planning."
                .to_string()
        }
        StudioExecutionStrategy::PlanExecute => {
            "The request benefits from planning and verification, but not from a mutable work graph."
                .to_string()
        }
        StudioExecutionStrategy::MicroSwarm => {
            "A small known work graph is justified, but full adaptive graph expansion would be coordination overkill."
                .to_string()
        }
        StudioExecutionStrategy::AdaptiveWorkGraph => {
            "The request implies multiple obligations or hidden dependencies, so a mutable work graph is justified."
                .to_string()
        }
    };

    let budget_envelope = execution_budget_envelope_for_strategy(resolved_strategy);
    let work_graph_required = matches!(
        resolved_strategy,
        StudioExecutionStrategy::MicroSwarm | StudioExecutionStrategy::AdaptiveWorkGraph
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

    StudioExecutionModeDecision {
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

pub fn annotate_execution_envelope(
    envelope: &mut Option<ExecutionEnvelope>,
    mode_decision: Option<StudioExecutionModeDecision>,
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
    strategy: StudioExecutionStrategy,
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
            StudioExecutionStrategy::SinglePass
                | StudioExecutionStrategy::DirectAuthor
                | StudioExecutionStrategy::PlanExecute
        ),
    }
}

pub fn completion_invariant_for_plan(
    plan: &SwarmPlan,
    verification_receipts: &[SwarmVerificationReceipt],
    required_artifact_paths: Vec<String>,
) -> ExecutionCompletionInvariant {
    let required_work_item_ids = plan
        .work_items
        .iter()
        .filter(|item| item.role != SwarmWorkerRole::Repair && !item.id.starts_with("repair-pass-"))
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let satisfied_work_item_ids = plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                SwarmWorkItemStatus::Succeeded | SwarmWorkItemStatus::Skipped
            )
        })
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let speculative_work_item_ids = plan
        .work_items
        .iter()
        .filter(|item| item.role == SwarmWorkerRole::Repair || item.id.starts_with("repair-pass-"))
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let pruned_work_item_ids = plan
        .work_items
        .iter()
        .filter(|item| {
            item.status == SwarmWorkItemStatus::Skipped
                && (item.role == SwarmWorkerRole::Repair
                    || item.role == SwarmWorkerRole::Integrator
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
            SwarmWorkItemStatus::Failed
                | SwarmWorkItemStatus::Rejected
                | SwarmWorkItemStatus::Blocked
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
            "micro_swarm" | "adaptive_work_graph" | "swarm"
        ),
    }
}

pub fn shared_read_lease_for_path(path: impl Into<String>) -> SwarmLeaseRequirement {
    SwarmLeaseRequirement {
        target: path.into(),
        scope_kind: SwarmLeaseScopeKind::File,
        mode: SwarmLeaseMode::SharedRead,
    }
}

pub fn exclusive_write_lease_for_path(path: impl Into<String>) -> SwarmLeaseRequirement {
    SwarmLeaseRequirement {
        target: path.into(),
        scope_kind: SwarmLeaseScopeKind::File,
        mode: SwarmLeaseMode::ExclusiveWrite,
    }
}

pub fn exclusive_write_lease_for_region(region: impl Into<String>) -> SwarmLeaseRequirement {
    SwarmLeaseRequirement {
        target: region.into(),
        scope_kind: SwarmLeaseScopeKind::Region,
        mode: SwarmLeaseMode::ExclusiveWrite,
    }
}

pub fn spawn_follow_up_swarm_work_item(
    swarm_plan: &mut SwarmPlan,
    mut work_item: SwarmWorkItem,
) -> Result<(), String> {
    if swarm_plan
        .work_items
        .iter()
        .any(|item| item.id == work_item.id)
    {
        return Err(format!(
            "Swarm work item '{}' already exists in the work graph.",
            work_item.id
        ));
    }

    if let Some(parent_id) = work_item.spawned_from_id.as_ref() {
        if !swarm_plan
            .work_items
            .iter()
            .any(|item| item.id == *parent_id)
        {
            return Err(format!(
                "Swarm work item '{}' cannot spawn from missing parent '{}'.",
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

    swarm_plan.work_items.push(work_item);
    swarm_plan.version = swarm_plan.version.saturating_add(1);
    Ok(())
}

pub fn block_swarm_work_item_on(
    swarm_plan: &mut SwarmPlan,
    work_item_id: &str,
    blocked_on_ids: &[String],
) -> Result<(), String> {
    for blocked_on_id in blocked_on_ids {
        if !swarm_plan
            .work_items
            .iter()
            .any(|item| item.id == *blocked_on_id)
        {
            return Err(format!(
                "Swarm work item '{}' cannot be blocked on missing work item '{}'.",
                work_item_id, blocked_on_id
            ));
        }
    }

    let Some(work_item) = swarm_plan
        .work_items
        .iter_mut()
        .find(|item| item.id == work_item_id)
    else {
        return Err(format!(
            "Swarm work item '{}' is missing from the work graph.",
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
            SwarmWorkItemStatus::Succeeded | SwarmWorkItemStatus::Skipped
        )
    {
        work_item.status = SwarmWorkItemStatus::Blocked;
    }
    swarm_plan.version = swarm_plan.version.saturating_add(1);
    Ok(())
}

pub fn swarm_work_item_lease_conflicts(left: &SwarmWorkItem, right: &SwarmWorkItem) -> bool {
    left.lease_requirements.iter().any(|left_lease| {
        right.lease_requirements.iter().any(|right_lease| {
            left_lease.target == right_lease.target
                && left_lease.scope_kind == right_lease.scope_kind
                && (left_lease.mode == SwarmLeaseMode::ExclusiveWrite
                    || right_lease.mode == SwarmLeaseMode::ExclusiveWrite)
        })
    })
}

fn swarm_dependency_states<'a>(
    work_item: &SwarmWorkItem,
    work_item_by_id: &HashMap<String, &'a SwarmWorkItem>,
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
                SwarmWorkItemStatus::Succeeded | SwarmWorkItemStatus::Skipped => {}
                SwarmWorkItemStatus::Failed | SwarmWorkItemStatus::Rejected => {
                    failed_dependencies.push(dependency_id.clone());
                }
                SwarmWorkItemStatus::Pending
                | SwarmWorkItemStatus::Blocked
                | SwarmWorkItemStatus::Running => {
                    unmet_dependencies.push(dependency_id.clone());
                }
            },
            None => failed_dependencies.push(dependency_id.clone()),
        }
    }
    (unmet_dependencies, failed_dependencies)
}

pub fn next_swarm_dispatch_batch(
    swarm_plan: &SwarmPlan,
    candidate_work_item_ids: &[String],
    sequence: u32,
) -> Option<ExecutionDispatchBatch> {
    let work_item_by_id = swarm_plan
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
                SwarmWorkItemStatus::Succeeded
                    | SwarmWorkItemStatus::Skipped
                    | SwarmWorkItemStatus::Failed
                    | SwarmWorkItemStatus::Rejected
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
            swarm_dependency_states(work_item, &work_item_by_id);
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
                .map(|selected| swarm_work_item_lease_conflicts(candidate, selected))
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

pub fn plan_swarm_dispatch_batches(swarm_plan: &SwarmPlan) -> Vec<ExecutionDispatchBatch> {
    let work_item_by_id = swarm_plan
        .work_items
        .iter()
        .map(|item| (item.id.clone(), item))
        .collect::<HashMap<_, _>>();
    let mut remaining = swarm_plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                SwarmWorkItemStatus::Pending
                    | SwarmWorkItemStatus::Blocked
                    | SwarmWorkItemStatus::Running
            )
        })
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let mut completed = swarm_plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                SwarmWorkItemStatus::Succeeded | SwarmWorkItemStatus::Skipped
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
                swarm_dependency_states(work_item, &work_item_by_id);
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
                    .map(|selected| swarm_work_item_lease_conflicts(candidate, selected))
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
    outcome_kind: StudioOutcomeKind,
    artifact: Option<&StudioOutcomeArtifactRequest>,
) -> StudioExecutionStrategy {
    match outcome_kind {
        StudioOutcomeKind::Conversation | StudioOutcomeKind::Visualizer => {
            StudioExecutionStrategy::SinglePass
        }
        StudioOutcomeKind::ToolWidget => StudioExecutionStrategy::PlanExecute,
        StudioOutcomeKind::Artifact => artifact
            .filter(|request| artifact_supports_direct_authoring(request, false))
            .map(|_| StudioExecutionStrategy::DirectAuthor)
            .unwrap_or(StudioExecutionStrategy::PlanExecute),
    }
}

pub fn execution_domain_kind_for_outcome(outcome_kind: StudioOutcomeKind) -> ExecutionDomainKind {
    match outcome_kind {
        StudioOutcomeKind::Artifact => ExecutionDomainKind::Artifact,
        StudioOutcomeKind::Conversation => ExecutionDomainKind::Conversation,
        StudioOutcomeKind::ToolWidget => ExecutionDomainKind::ToolWidget,
        StudioOutcomeKind::Visualizer => ExecutionDomainKind::Visualizer,
    }
}

pub fn infer_execution_domain_kind(execution_domain: &str) -> Option<ExecutionDomainKind> {
    let normalized = execution_domain.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "artifact" | "studio_artifact" => Some(ExecutionDomainKind::Artifact),
        "conversation" | "studio_conversation" => Some(ExecutionDomainKind::Conversation),
        "tool_widget" | "studio_tool_widget" => Some(ExecutionDomainKind::ToolWidget),
        "visualizer" | "studio_visualizer" => Some(ExecutionDomainKind::Visualizer),
        "workflow" => Some(ExecutionDomainKind::Workflow),
        "research" => Some(ExecutionDomainKind::Research),
        "reply" => Some(ExecutionDomainKind::Reply),
        "code" => Some(ExecutionDomainKind::Code),
        "" => None,
        _ => Some(ExecutionDomainKind::Unknown),
    }
}

pub fn parse_execution_strategy_id(raw: &str) -> Option<StudioExecutionStrategy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "single_pass" => Some(StudioExecutionStrategy::SinglePass),
        "direct_author" => Some(StudioExecutionStrategy::DirectAuthor),
        "plan_execute" => Some(StudioExecutionStrategy::PlanExecute),
        "micro_swarm" => Some(StudioExecutionStrategy::MicroSwarm),
        "adaptive_work_graph" | "swarm" => Some(StudioExecutionStrategy::AdaptiveWorkGraph),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_execution_envelope_from_swarm(
    strategy: Option<StudioExecutionStrategy>,
    execution_domain: Option<String>,
    domain_kind: Option<ExecutionDomainKind>,
    plan: Option<&SwarmPlan>,
    execution_summary: Option<&SwarmExecutionSummary>,
    worker_receipts: &[SwarmWorkerReceipt],
    change_receipts: &[SwarmChangeReceipt],
    merge_receipts: &[SwarmMergeReceipt],
    verification_receipts: &[SwarmVerificationReceipt],
) -> Option<ExecutionEnvelope> {
    build_execution_envelope_from_swarm_with_receipts(
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
pub fn build_execution_envelope_from_swarm_with_receipts(
    strategy: Option<StudioExecutionStrategy>,
    execution_domain: Option<String>,
    domain_kind: Option<ExecutionDomainKind>,
    plan: Option<&SwarmPlan>,
    execution_summary: Option<&SwarmExecutionSummary>,
    worker_receipts: &[SwarmWorkerReceipt],
    change_receipts: &[SwarmChangeReceipt],
    merge_receipts: &[SwarmMergeReceipt],
    verification_receipts: &[SwarmVerificationReceipt],
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
        plan.map(plan_swarm_dispatch_batches).unwrap_or_default()
    } else {
        dispatch_batches.to_vec()
    };

    Some(ExecutionEnvelope {
        version: 1,
        strategy: resolved_strategy,
        mode_decision: None,
        budget_envelope: None,
        execution_domain: resolved_domain,
        domain_kind: resolved_domain_kind,
        completion_invariant: plan.and_then(|entry| entry.completion_invariant.clone()),
        plan: plan.cloned(),
        execution_summary: execution_summary.cloned(),
        worker_receipts: worker_receipts.to_vec(),
        change_receipts: change_receipts.to_vec(),
        merge_receipts: merge_receipts.to_vec(),
        verification_receipts: verification_receipts.to_vec(),
        graph_mutation_receipts: graph_mutation_receipts.to_vec(),
        dispatch_batches: resolved_dispatch_batches,
        repair_receipts: repair_receipts.to_vec(),
        replan_receipts: replan_receipts.to_vec(),
        budget_summary,
        live_previews: live_previews.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{
        StudioArtifactClass, StudioArtifactDeliverableShape, StudioArtifactPersistenceMode,
        StudioExecutionSubstrate, StudioOutcomeArtifactScope,
        StudioOutcomeArtifactVerificationRequest, StudioPresentationSurface, StudioRendererKind,
    };

    fn test_swarm_plan(strategy: &str, work_items: Vec<SwarmWorkItem>) -> SwarmPlan {
        SwarmPlan {
            version: 1,
            strategy: strategy.to_string(),
            execution_domain: "studio_artifact".to_string(),
            adapter_label: "artifact_graph_v1".to_string(),
            parallelism_mode: "sequential_by_default".to_string(),
            top_level_objective: Some("Test objective".to_string()),
            decomposition_hypothesis: Some("Test decomposition hypothesis".to_string()),
            decomposition_type: Some("test_decomposition".to_string()),
            first_frontier_ids: vec!["planner".to_string()],
            spawn_conditions: vec!["verification failure".to_string()],
            prune_conditions: vec!["completion invariant satisfied".to_string()],
            merge_strategy: Some("bounded_merge".to_string()),
            verification_strategy: Some("judge_then_verify".to_string()),
            fallback_collapse_strategy: Some("collapse_to_remaining_frontier".to_string()),
            completion_invariant: Some(ExecutionCompletionInvariant {
                summary: "Complete when mandatory work and verification pass.".to_string(),
                status: ExecutionCompletionInvariantStatus::Pending,
                required_work_item_ids: work_items
                    .iter()
                    .filter(|item| {
                        item.role != SwarmWorkerRole::Repair && !item.id.starts_with("repair-pass-")
                    })
                    .map(|item| item.id.clone())
                    .collect(),
                satisfied_work_item_ids: Vec::new(),
                speculative_work_item_ids: work_items
                    .iter()
                    .filter(|item| {
                        item.role == SwarmWorkerRole::Repair || item.id.starts_with("repair-pass-")
                    })
                    .map(|item| item.id.clone())
                    .collect(),
                pruned_work_item_ids: Vec::new(),
                required_verification_ids: vec!["acceptance-judge".to_string()],
                satisfied_verification_ids: Vec::new(),
                required_artifact_paths: vec!["index.html".to_string()],
                remaining_obligations: vec!["verification:acceptance-judge".to_string()],
                allows_early_exit: true,
            }),
            work_items,
        }
    }

    #[test]
    fn build_execution_envelope_derives_strategy_and_domain_kind_from_swarm() {
        let plan = test_swarm_plan("swarm", Vec::new());
        let summary = SwarmExecutionSummary {
            enabled: true,
            current_stage: "merge".to_string(),
            execution_stage: Some(ExecutionStage::Merge),
            active_worker_role: None,
            total_work_items: 3,
            completed_work_items: 2,
            failed_work_items: 0,
            verification_status: "pending".to_string(),
            strategy: "swarm".to_string(),
            execution_domain: "studio_artifact".to_string(),
            adapter_label: "artifact_swarm_v1".to_string(),
            parallelism_mode: "serial".to_string(),
        };

        let envelope = build_execution_envelope_from_swarm(
            None,
            None,
            None,
            Some(&plan),
            Some(&summary),
            &[],
            &[],
            &[],
            &[],
        )
        .expect("expected execution envelope");

        assert_eq!(
            envelope.strategy,
            Some(StudioExecutionStrategy::AdaptiveWorkGraph)
        );
        assert_eq!(envelope.execution_domain, "studio_artifact");
        assert_eq!(envelope.domain_kind, Some(ExecutionDomainKind::Artifact));
        assert_eq!(
            envelope
                .execution_summary
                .as_ref()
                .map(|entry| entry.current_stage.as_str()),
            Some("merge")
        );
    }

    #[test]
    fn artifact_outcomes_default_single_document_renderers_to_direct_author() {
        let html_request = StudioOutcomeArtifactRequest {
            artifact_class: StudioArtifactClass::InteractiveSingleFile,
            deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
            renderer: StudioRendererKind::HtmlIframe,
            presentation_surface: StudioPresentationSurface::SidePanel,
            persistence: StudioArtifactPersistenceMode::SharedArtifactScoped,
            execution_substrate: StudioExecutionSubstrate::ClientSandbox,
            workspace_recipe_id: None,
            presentation_variant_id: None,
            scope: StudioOutcomeArtifactScope {
                target_project: None,
                create_new_workspace: false,
                mutation_boundary: vec!["artifact".to_string()],
            },
            verification: StudioOutcomeArtifactVerificationRequest {
                require_render: true,
                require_build: false,
                require_preview: false,
                require_export: false,
                require_diff_review: false,
            },
        };
        let markdown_request = StudioOutcomeArtifactRequest {
            renderer: StudioRendererKind::Markdown,
            execution_substrate: StudioExecutionSubstrate::None,
            ..html_request.clone()
        };
        let svg_request = StudioOutcomeArtifactRequest {
            artifact_class: StudioArtifactClass::Visual,
            renderer: StudioRendererKind::Svg,
            execution_substrate: StudioExecutionSubstrate::None,
            ..html_request.clone()
        };
        let pdf_request = StudioOutcomeArtifactRequest {
            artifact_class: StudioArtifactClass::Document,
            renderer: StudioRendererKind::PdfEmbed,
            execution_substrate: StudioExecutionSubstrate::BinaryGenerator,
            ..html_request.clone()
        };

        assert_eq!(
            execution_strategy_for_outcome(StudioOutcomeKind::Artifact, None),
            StudioExecutionStrategy::PlanExecute
        );
        assert_eq!(
            execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(&html_request)),
            StudioExecutionStrategy::DirectAuthor
        );
        assert_eq!(
            execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(&markdown_request)),
            StudioExecutionStrategy::DirectAuthor
        );
        assert_eq!(
            execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(&svg_request)),
            StudioExecutionStrategy::DirectAuthor
        );
        assert_eq!(
            execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(&pdf_request)),
            StudioExecutionStrategy::DirectAuthor
        );
    }

    #[test]
    fn derive_execution_mode_decision_routes_simple_conversation_to_single_pass() {
        let decision = derive_execution_mode_decision(
            StudioOutcomeKind::Conversation,
            None,
            StudioExecutionStrategy::PlanExecute,
            0.94,
            false,
            false,
        );

        assert_eq!(
            decision.requested_strategy,
            StudioExecutionStrategy::PlanExecute
        );
        assert_eq!(
            decision.resolved_strategy,
            StudioExecutionStrategy::SinglePass
        );
        assert!(!decision.work_graph_required);
        assert!(decision.one_shot_sufficiency >= 0.7);
        assert_eq!(decision.budget_envelope.max_workers, 1);
    }

    #[test]
    fn derive_execution_mode_decision_routes_fresh_bounded_document_to_direct_author() {
        let request = StudioOutcomeArtifactRequest {
            artifact_class: StudioArtifactClass::Document,
            deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
            renderer: StudioRendererKind::Markdown,
            presentation_surface: StudioPresentationSurface::SidePanel,
            persistence: StudioArtifactPersistenceMode::ArtifactScoped,
            execution_substrate: StudioExecutionSubstrate::None,
            workspace_recipe_id: None,
            presentation_variant_id: None,
            scope: StudioOutcomeArtifactScope {
                target_project: None,
                create_new_workspace: false,
                mutation_boundary: vec!["artifact".to_string()],
            },
            verification: StudioOutcomeArtifactVerificationRequest {
                require_render: true,
                require_build: false,
                require_preview: false,
                require_export: true,
                require_diff_review: false,
            },
        };

        let decision = derive_execution_mode_decision(
            StudioOutcomeKind::Artifact,
            Some(&request),
            StudioExecutionStrategy::PlanExecute,
            0.92,
            false,
            false,
        );

        assert_eq!(
            decision.resolved_strategy,
            StudioExecutionStrategy::DirectAuthor
        );
        assert!(!decision.work_graph_required);
        assert_eq!(decision.work_graph_size_estimate, 1);
        assert_eq!(decision.budget_envelope.max_workers, 1);
        assert_eq!(decision.budget_envelope.max_replans, 0);
        assert_eq!(
            decision.budget_envelope.expansion_policy,
            StudioExecutionBudgetExpansionPolicy::Fixed
        );
    }

    #[test]
    fn derive_execution_mode_decision_routes_workspace_artifacts_to_adaptive_work_graph() {
        let request = StudioOutcomeArtifactRequest {
            artifact_class: StudioArtifactClass::WorkspaceProject,
            deliverable_shape: StudioArtifactDeliverableShape::WorkspaceProject,
            renderer: StudioRendererKind::WorkspaceSurface,
            presentation_surface: StudioPresentationSurface::TabbedPanel,
            persistence: StudioArtifactPersistenceMode::WorkspaceFilesystem,
            execution_substrate: StudioExecutionSubstrate::WorkspaceRuntime,
            workspace_recipe_id: Some("react".to_string()),
            presentation_variant_id: None,
            scope: StudioOutcomeArtifactScope {
                target_project: Some("workspace".to_string()),
                create_new_workspace: true,
                mutation_boundary: vec!["workspace".to_string()],
            },
            verification: StudioOutcomeArtifactVerificationRequest {
                require_render: true,
                require_build: true,
                require_preview: true,
                require_export: false,
                require_diff_review: true,
            },
        };

        let decision = derive_execution_mode_decision(
            StudioOutcomeKind::Artifact,
            Some(&request),
            StudioExecutionStrategy::PlanExecute,
            0.86,
            false,
            false,
        );

        assert_eq!(
            decision.resolved_strategy,
            StudioExecutionStrategy::AdaptiveWorkGraph
        );
        assert!(decision.work_graph_required);
        assert_eq!(decision.budget_envelope.max_workers, 8);
        assert_eq!(
            decision.budget_envelope.expansion_policy,
            StudioExecutionBudgetExpansionPolicy::FrontierAdaptive
        );
        assert!(decision.hidden_dependency_likelihood >= 0.7);
    }

    #[test]
    fn annotate_execution_envelope_carries_mode_decision_budget_and_invariant() {
        let mut envelope = build_execution_envelope_from_swarm(
            Some(StudioExecutionStrategy::PlanExecute),
            Some("studio_artifact".to_string()),
            Some(ExecutionDomainKind::Artifact),
            None,
            None,
            &[],
            &[],
            &[],
            &[],
        );
        let decision = StudioExecutionModeDecision {
            requested_strategy: StudioExecutionStrategy::PlanExecute,
            resolved_strategy: StudioExecutionStrategy::MicroSwarm,
            mode_confidence: 0.81,
            one_shot_sufficiency: 0.44,
            ambiguity: 0.12,
            work_graph_size_estimate: 3,
            hidden_dependency_likelihood: 0.35,
            verification_pressure: 0.4,
            revision_cost: 0.25,
            evidence_breadth: 0.35,
            merge_burden: 0.55,
            decomposition_payoff: 0.58,
            work_graph_required: true,
            decomposition_reason: "A bounded work graph is justified.".to_string(),
            budget_envelope: execution_budget_envelope_for_strategy(
                StudioExecutionStrategy::MicroSwarm,
            ),
        };
        let invariant = completion_invariant_for_direct_execution(
            StudioExecutionStrategy::MicroSwarm,
            vec!["index.html".to_string()],
            vec!["verify".to_string()],
            ExecutionCompletionInvariantStatus::Pending,
        );

        annotate_execution_envelope(
            &mut envelope,
            Some(decision.clone()),
            Some(invariant.clone()),
        );

        let envelope = envelope.expect("execution envelope");
        assert_eq!(envelope.strategy, Some(StudioExecutionStrategy::MicroSwarm));
        assert_eq!(envelope.mode_decision, Some(decision));
        assert_eq!(
            envelope.budget_envelope,
            Some(invariant_allows_micro_budget())
        );
        assert_eq!(envelope.completion_invariant, Some(invariant));
    }

    fn invariant_allows_micro_budget() -> StudioExecutionBudgetEnvelope {
        execution_budget_envelope_for_strategy(StudioExecutionStrategy::MicroSwarm)
    }

    #[test]
    fn parse_execution_strategy_id_accepts_legacy_swarm_alias() {
        assert_eq!(
            parse_execution_strategy_id("direct_author"),
            Some(StudioExecutionStrategy::DirectAuthor)
        );
        assert_eq!(
            parse_execution_strategy_id("swarm"),
            Some(StudioExecutionStrategy::AdaptiveWorkGraph)
        );
        assert_eq!(
            parse_execution_strategy_id("adaptive_work_graph"),
            Some(StudioExecutionStrategy::AdaptiveWorkGraph)
        );
        assert_eq!(
            parse_execution_strategy_id("micro_swarm"),
            Some(StudioExecutionStrategy::MicroSwarm)
        );
    }

    #[test]
    fn spawn_follow_up_work_item_preserves_parent_lineage_and_increments_version() {
        let mut plan = test_swarm_plan(
            "adaptive_work_graph",
            vec![SwarmWorkItem {
                id: "repair".to_string(),
                title: "Repair".to_string(),
                role: SwarmWorkerRole::Repair,
                summary: "Repair cited failures.".to_string(),
                spawned_from_id: None,
                read_paths: vec!["index.html".to_string()],
                write_paths: vec!["index.html".to_string()],
                write_regions: vec!["section:hero".to_string()],
                lease_requirements: vec![exclusive_write_lease_for_region("section:hero")],
                acceptance_criteria: vec!["Stay scoped.".to_string()],
                dependency_ids: vec!["judge".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: Some(SwarmVerificationPolicy::Blocking),
                retry_budget: Some(2),
                status: SwarmWorkItemStatus::Pending,
            }],
        );

        spawn_follow_up_swarm_work_item(
            &mut plan,
            SwarmWorkItem {
                id: "repair-pass-1".to_string(),
                title: "Repair pass 1".to_string(),
                role: SwarmWorkerRole::Repair,
                summary: "Resolve the first blocked verification issue.".to_string(),
                spawned_from_id: Some("repair".to_string()),
                read_paths: vec!["index.html".to_string()],
                write_paths: vec!["index.html".to_string()],
                write_regions: vec!["section:hero".to_string()],
                lease_requirements: vec![exclusive_write_lease_for_region("section:hero")],
                acceptance_criteria: vec!["Patch only cited issues.".to_string()],
                dependency_ids: vec!["judge".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: Some(SwarmVerificationPolicy::Blocking),
                retry_budget: Some(0),
                status: SwarmWorkItemStatus::Pending,
            },
        )
        .expect("follow-up work item should append");

        let follow_up = plan
            .work_items
            .iter()
            .find(|item| item.id == "repair-pass-1")
            .expect("follow-up repair item");
        assert_eq!(plan.version, 2);
        assert_eq!(follow_up.spawned_from_id.as_deref(), Some("repair"));
        assert!(follow_up
            .dependency_ids
            .iter()
            .any(|dependency| dependency == "repair"));
    }

    #[test]
    fn exclusive_write_leases_conflict_on_the_same_target() {
        let left = SwarmWorkItem {
            id: "section-1".to_string(),
            title: "Section 1".to_string(),
            role: SwarmWorkerRole::SectionContent,
            summary: "Own hero copy.".to_string(),
            spawned_from_id: None,
            read_paths: vec!["index.html".to_string()],
            write_paths: vec!["index.html".to_string()],
            write_regions: vec!["section:hero".to_string()],
            lease_requirements: vec![exclusive_write_lease_for_region("section:hero")],
            acceptance_criteria: vec!["Keep hero visible.".to_string()],
            dependency_ids: vec!["skeleton".to_string()],
            blocked_on_ids: Vec::new(),
            verification_policy: Some(SwarmVerificationPolicy::Normal),
            retry_budget: Some(0),
            status: SwarmWorkItemStatus::Pending,
        };
        let right = SwarmWorkItem {
            id: "repair-pass-1".to_string(),
            title: "Repair pass 1".to_string(),
            role: SwarmWorkerRole::Repair,
            summary: "Patch hero issues.".to_string(),
            spawned_from_id: Some("repair".to_string()),
            read_paths: vec!["index.html".to_string()],
            write_paths: vec!["index.html".to_string()],
            write_regions: vec!["section:hero".to_string()],
            lease_requirements: vec![exclusive_write_lease_for_region("section:hero")],
            acceptance_criteria: vec!["Stay bounded.".to_string()],
            dependency_ids: vec!["judge".to_string()],
            blocked_on_ids: Vec::new(),
            verification_policy: Some(SwarmVerificationPolicy::Blocking),
            retry_budget: Some(0),
            status: SwarmWorkItemStatus::Pending,
        };

        assert!(swarm_work_item_lease_conflicts(&left, &right));
    }

    #[test]
    fn block_swarm_work_item_on_adds_runtime_blockers() {
        let mut plan = test_swarm_plan(
            "plan_execute",
            vec![
                SwarmWorkItem {
                    id: "planner".to_string(),
                    title: "Planner".to_string(),
                    role: SwarmWorkerRole::Planner,
                    summary: "Plan".to_string(),
                    spawned_from_id: None,
                    read_paths: Vec::new(),
                    write_paths: Vec::new(),
                    write_regions: Vec::new(),
                    lease_requirements: Vec::new(),
                    acceptance_criteria: Vec::new(),
                    dependency_ids: Vec::new(),
                    blocked_on_ids: Vec::new(),
                    verification_policy: None,
                    retry_budget: None,
                    status: SwarmWorkItemStatus::Succeeded,
                },
                SwarmWorkItem {
                    id: "handoff".to_string(),
                    title: "Handoff".to_string(),
                    role: SwarmWorkerRole::Responder,
                    summary: "Reply".to_string(),
                    spawned_from_id: None,
                    read_paths: Vec::new(),
                    write_paths: Vec::new(),
                    write_regions: Vec::new(),
                    lease_requirements: Vec::new(),
                    acceptance_criteria: Vec::new(),
                    dependency_ids: vec!["planner".to_string()],
                    blocked_on_ids: Vec::new(),
                    verification_policy: None,
                    retry_budget: None,
                    status: SwarmWorkItemStatus::Pending,
                },
            ],
        );
        plan.execution_domain = "studio_conversation".to_string();
        plan.adapter_label = "conversation_route_v1".to_string();

        spawn_follow_up_swarm_work_item(
            &mut plan,
            SwarmWorkItem {
                id: "clarification_gate".to_string(),
                title: "Clarification gate".to_string(),
                role: SwarmWorkerRole::Coordinator,
                summary: "Wait for the user.".to_string(),
                spawned_from_id: Some("planner".to_string()),
                read_paths: Vec::new(),
                write_paths: Vec::new(),
                write_regions: Vec::new(),
                lease_requirements: Vec::new(),
                acceptance_criteria: Vec::new(),
                dependency_ids: vec!["planner".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: Some(SwarmVerificationPolicy::Blocking),
                retry_budget: Some(0),
                status: SwarmWorkItemStatus::Pending,
            },
        )
        .expect("clarification gate should spawn");
        block_swarm_work_item_on(&mut plan, "handoff", &[String::from("clarification_gate")])
            .expect("handoff should become blocked");

        let handoff = plan
            .work_items
            .iter()
            .find(|item| item.id == "handoff")
            .expect("handoff item");
        assert_eq!(handoff.status, SwarmWorkItemStatus::Blocked);
        assert!(handoff
            .blocked_on_ids
            .iter()
            .any(|entry| entry == "clarification_gate"));
    }

    #[test]
    fn dispatch_batches_respect_dependencies_and_lease_conflicts() {
        let plan = test_swarm_plan(
            "adaptive_work_graph",
            vec![
                SwarmWorkItem {
                    id: "planner".to_string(),
                    title: "Planner".to_string(),
                    role: SwarmWorkerRole::Planner,
                    summary: "Plan".to_string(),
                    spawned_from_id: None,
                    read_paths: Vec::new(),
                    write_paths: Vec::new(),
                    write_regions: Vec::new(),
                    lease_requirements: Vec::new(),
                    acceptance_criteria: Vec::new(),
                    dependency_ids: Vec::new(),
                    blocked_on_ids: Vec::new(),
                    verification_policy: None,
                    retry_budget: None,
                    status: SwarmWorkItemStatus::Succeeded,
                },
                SwarmWorkItem {
                    id: "skeleton".to_string(),
                    title: "Skeleton".to_string(),
                    role: SwarmWorkerRole::Skeleton,
                    summary: "Create scaffold".to_string(),
                    spawned_from_id: None,
                    read_paths: vec!["index.html".to_string()],
                    write_paths: vec!["index.html".to_string()],
                    write_regions: vec!["section:hero".to_string()],
                    lease_requirements: vec![exclusive_write_lease_for_path("index.html")],
                    acceptance_criteria: Vec::new(),
                    dependency_ids: vec!["planner".to_string()],
                    blocked_on_ids: Vec::new(),
                    verification_policy: None,
                    retry_budget: None,
                    status: SwarmWorkItemStatus::Pending,
                },
                SwarmWorkItem {
                    id: "hero".to_string(),
                    title: "Hero".to_string(),
                    role: SwarmWorkerRole::SectionContent,
                    summary: "Patch hero".to_string(),
                    spawned_from_id: None,
                    read_paths: vec!["index.html".to_string()],
                    write_paths: vec!["index.html".to_string()],
                    write_regions: vec!["section:hero".to_string()],
                    lease_requirements: vec![exclusive_write_lease_for_region("section:hero")],
                    acceptance_criteria: Vec::new(),
                    dependency_ids: vec!["skeleton".to_string()],
                    blocked_on_ids: Vec::new(),
                    verification_policy: None,
                    retry_budget: None,
                    status: SwarmWorkItemStatus::Pending,
                },
                SwarmWorkItem {
                    id: "style".to_string(),
                    title: "Style".to_string(),
                    role: SwarmWorkerRole::StyleSystem,
                    summary: "Patch style".to_string(),
                    spawned_from_id: None,
                    read_paths: vec!["index.html".to_string()],
                    write_paths: vec!["index.html".to_string()],
                    write_regions: vec!["section:hero".to_string()],
                    lease_requirements: vec![exclusive_write_lease_for_region("section:hero")],
                    acceptance_criteria: Vec::new(),
                    dependency_ids: vec!["skeleton".to_string()],
                    blocked_on_ids: Vec::new(),
                    verification_policy: None,
                    retry_budget: None,
                    status: SwarmWorkItemStatus::Pending,
                },
            ],
        );

        let batches = plan_swarm_dispatch_batches(&plan);

        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].work_item_ids, vec!["skeleton".to_string()]);
        assert_eq!(batches[1].work_item_ids, vec!["hero".to_string()]);
        assert_eq!(batches[1].deferred_work_item_ids, vec!["style".to_string()]);
        assert_eq!(batches[2].work_item_ids, vec!["style".to_string()]);
    }

    #[test]
    fn dispatch_batch_parallelism_cap_defers_overflow() {
        let mut batch = ExecutionDispatchBatch {
            id: "dispatch-batch-1".to_string(),
            sequence: 1,
            status: "ready".to_string(),
            work_item_ids: vec![
                "section-1".to_string(),
                "section-2".to_string(),
                "section-3".to_string(),
            ],
            deferred_work_item_ids: Vec::new(),
            blocked_work_item_ids: Vec::new(),
            details: Vec::new(),
        };

        constrain_dispatch_batch_by_parallelism(&mut batch, 2);

        assert_eq!(
            batch.work_item_ids,
            vec!["section-1".to_string(), "section-2".to_string()]
        );
        assert_eq!(batch.deferred_work_item_ids, vec!["section-3".to_string()]);
        assert_eq!(batch.status, "budget_limited");
        assert!(batch
            .details
            .iter()
            .any(|detail| detail.contains("Budget capped this dispatch wave")));
    }

    #[test]
    fn build_execution_envelope_preserves_graph_and_repair_receipts() {
        let dispatch_batches = vec![ExecutionDispatchBatch {
            id: "dispatch-batch-1".to_string(),
            sequence: 1,
            status: "planned".to_string(),
            work_item_ids: vec!["planner".to_string()],
            deferred_work_item_ids: Vec::new(),
            blocked_work_item_ids: Vec::new(),
            details: vec!["planner is ready".to_string()],
        }];
        let graph_receipts = vec![ExecutionGraphMutationReceipt {
            id: "repair-requested".to_string(),
            mutation_kind: "repair_requested".to_string(),
            status: "applied".to_string(),
            summary: "Judge requested a repair.".to_string(),
            triggered_by_work_item_id: Some("judge".to_string()),
            affected_work_item_ids: vec!["repair".to_string()],
            details: vec!["Tighten layout".to_string()],
        }];
        let repair_receipts = vec![ExecutionRepairReceipt {
            id: "repair-pass-1".to_string(),
            status: "repairable".to_string(),
            summary: "Applied a scoped repair.".to_string(),
            triggered_by_verification_id: Some("acceptance-judge".to_string()),
            work_item_ids: vec!["repair".to_string()],
            details: vec!["Fix hierarchy".to_string()],
        }];
        let replan_receipts = vec![ExecutionReplanReceipt {
            id: "repair-replan".to_string(),
            status: "blocked".to_string(),
            summary: "Repair requested a broader replan.".to_string(),
            triggered_by_work_item_id: Some("repair".to_string()),
            spawned_work_item_ids: vec!["repair-pass-1".to_string()],
            blocked_work_item_ids: vec!["integrator".to_string()],
            details: vec!["Widen section ownership".to_string()],
        }];

        let envelope = build_execution_envelope_from_swarm_with_receipts(
            Some(StudioExecutionStrategy::AdaptiveWorkGraph),
            Some("studio_artifact".to_string()),
            Some(ExecutionDomainKind::Artifact),
            None,
            None,
            &[],
            &[],
            &[],
            &[],
            &graph_receipts,
            &dispatch_batches,
            &repair_receipts,
            &replan_receipts,
            Some(ExecutionBudgetSummary {
                planned_worker_count: Some(4),
                dispatched_worker_count: Some(4),
                token_budget: Some(4096),
                token_usage: Some(3072),
                wall_clock_ms: Some(1500),
                coordination_overhead_ms: Some(210),
                status: "within_budget".to_string(),
            }),
            &[],
        )
        .expect("expected execution envelope");

        assert_eq!(envelope.graph_mutation_receipts, graph_receipts);
        assert_eq!(envelope.dispatch_batches, dispatch_batches);
        assert_eq!(envelope.repair_receipts, repair_receipts);
        assert_eq!(envelope.replan_receipts, replan_receipts);
        assert_eq!(
            envelope
                .budget_summary
                .as_ref()
                .and_then(|entry| entry.token_budget),
            Some(4096)
        );
    }
}
