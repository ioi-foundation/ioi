#![allow(missing_docs)]
//! Shared Studio outcome and artifact contracts.
//!
//! These types define the schema for outcome routing, artifact manifests, and
//! verification-backed replies so that Studio surfaces and CLI tooling can
//! operate on the same typed work product language.

use serde::{Deserialize, Serialize};

/// The top-level outcome class selected by Studio's router.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioOutcomeKind {
    Conversation,
    ToolWidget,
    Visualizer,
    Artifact,
}

/// The orchestration strategy chosen for this Studio outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioExecutionStrategy {
    SinglePass,
    DirectAuthor,
    PlanExecute,
    MicroSwarm,
    #[serde(rename = "adaptive_work_graph", alias = "swarm")]
    AdaptiveWorkGraph,
}

fn default_studio_execution_strategy() -> StudioExecutionStrategy {
    StudioExecutionStrategy::PlanExecute
}

/// Shared lane families used to describe Studio routing and retained lane
/// state without binding directly to a specific tool name.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioLaneFamily {
    General,
    Research,
    Coding,
    Integrations,
    Conversation,
    ToolWidget,
    Visualizer,
    Artifact,
    Communication,
    UserInput,
}

/// Source families considered when selecting how Studio should answer a
/// request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioSourceFamily {
    UserDirected,
    ConversationContext,
    Memory,
    ConversationRetrieval,
    Connector,
    SpecializedTool,
    WebSearch,
    DirectAnswer,
    Workspace,
    ArtifactContext,
}

/// Transition kind describing whether a lane change was planned or reactive.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioLaneTransitionKind {
    Planned,
    Reactive,
}

/// Shared status labels for objective/task/checkpoint state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioWorkStatus {
    Pending,
    InProgress,
    Complete,
    Blocked,
}

/// Typed lane frame derived from Studio routing signals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioDomainLaneFrame {
    pub primary_lane: StudioLaneFamily,
    #[serde(default)]
    pub secondary_lanes: Vec<StudioLaneFamily>,
    pub primary_goal: String,
    #[serde(default)]
    pub tool_widget_family: Option<String>,
    pub currentness_pressure: bool,
    pub workspace_grounding_required: bool,
    pub persistent_deliverable_requested: bool,
    pub active_artifact_follow_up: bool,
    pub lane_confidence: f32,
}

/// Structured source-selection summary retained alongside Studio route truth.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioSourceSelection {
    #[serde(default)]
    pub candidate_sources: Vec<StudioSourceFamily>,
    pub selected_source: StudioSourceFamily,
    pub explicit_user_source: bool,
    #[serde(default)]
    pub fallback_reason: Option<String>,
}

/// Clarification posture used by a specialized lane.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioClarificationMode {
    AssumeFromRetainedState,
    ClarifyOnMissingSlots,
    BlockUntilClarified,
}

/// Explicit clarification policy retained for a lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioClarificationPolicy {
    pub mode: StudioClarificationMode,
    #[serde(default)]
    pub assumed_bindings: Vec<String>,
    #[serde(default)]
    pub blocking_slots: Vec<String>,
    pub rationale: String,
}

/// Fallback posture used by a specialized lane.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioFallbackMode {
    StayInSpecializedLane,
    AllowRankedFallbacks,
    BlockUntilClarified,
}

/// Explicit fallback policy retained for a lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioFallbackPolicy {
    pub mode: StudioFallbackMode,
    pub primary_lane: StudioLaneFamily,
    #[serde(default)]
    pub fallback_lanes: Vec<StudioLaneFamily>,
    #[serde(default)]
    pub trigger_signals: Vec<String>,
    pub rationale: String,
}

/// Presentation policy for a routed Studio lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioPresentationPolicy {
    pub primary_surface: String,
    #[serde(default)]
    pub widget_family: Option<String>,
    #[serde(default)]
    pub renderer: Option<StudioRendererKind>,
    #[serde(default)]
    pub tab_priority: Vec<String>,
    pub rationale: String,
}

/// Transformation policy explaining how raw structured data becomes the final
/// user-facing output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioTransformationPolicy {
    pub output_shape: String,
    #[serde(default)]
    pub ordered_steps: Vec<String>,
    pub rationale: String,
}

/// Sensitivity tier assigned to a routed Studio lane.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioRiskSensitivity {
    Low,
    Medium,
    High,
}

/// Risk profile retained for a routed Studio lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioRiskProfile {
    pub sensitivity: StudioRiskSensitivity,
    #[serde(default)]
    pub reasons: Vec<String>,
    pub approval_required: bool,
    #[serde(default)]
    pub user_visible_guardrails: Vec<String>,
}

/// Verification contract for a specialized lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioVerificationContract {
    pub strategy: String,
    #[serde(default)]
    pub required_checks: Vec<String>,
    pub completion_gate: String,
}

/// Ordered source-ranking entry retained for audit and replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioSourceRankingEntry {
    pub source: StudioSourceFamily,
    pub rank: u32,
    pub rationale: String,
}

/// Retained widget-state binding used to preserve user-visible lane context
/// across follow-up turns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioWidgetStateBinding {
    pub key: String,
    pub value: String,
    pub source: String,
}

/// Retained widget/runtime state for a specialized surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioRetainedWidgetState {
    #[serde(default)]
    pub widget_family: Option<String>,
    #[serde(default)]
    pub bindings: Vec<StudioWidgetStateBinding>,
    #[serde(default)]
    pub last_updated_at: Option<String>,
}

/// Explicit contract showing which behaviors are represented in schema rather
/// than hidden in prompts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioPolicyContractSummary {
    #[serde(default)]
    pub bindings: Vec<String>,
    pub hidden_instruction_dependency: bool,
    pub rationale: String,
}

/// Domain-policy bundle retained for parity inspection and operator truth.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct StudioDomainPolicyBundle {
    pub clarification_policy: Option<StudioClarificationPolicy>,
    pub fallback_policy: Option<StudioFallbackPolicy>,
    pub presentation_policy: Option<StudioPresentationPolicy>,
    pub transformation_policy: Option<StudioTransformationPolicy>,
    pub risk_profile: Option<StudioRiskProfile>,
    pub verification_contract: Option<StudioVerificationContract>,
    pub policy_contract: Option<StudioPolicyContractSummary>,
    #[serde(default)]
    pub source_ranking: Vec<StudioSourceRankingEntry>,
    pub retained_widget_state: Option<StudioRetainedWidgetState>,
}

/// Weather-specific request frame retained by Studio.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioWeatherRequestFrame {
    #[serde(default)]
    pub inferred_locations: Vec<String>,
    #[serde(default)]
    pub assumed_location: Option<String>,
    #[serde(default)]
    pub temporal_scope: Option<String>,
    #[serde(default)]
    pub missing_slots: Vec<String>,
    #[serde(default)]
    pub clarification_required_slots: Vec<String>,
}

/// Sports-specific request frame retained by Studio.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioSportsRequestFrame {
    #[serde(default)]
    pub league: Option<String>,
    #[serde(default)]
    pub team_or_target: Option<String>,
    #[serde(default)]
    pub data_scope: Option<String>,
    #[serde(default)]
    pub missing_slots: Vec<String>,
    #[serde(default)]
    pub clarification_required_slots: Vec<String>,
}

/// Places-specific request frame retained by Studio.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioPlacesRequestFrame {
    #[serde(default)]
    pub search_anchor: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub location_scope: Option<String>,
    #[serde(default)]
    pub missing_slots: Vec<String>,
    #[serde(default)]
    pub clarification_required_slots: Vec<String>,
}

/// Recipe-specific request frame retained by Studio.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioRecipeRequestFrame {
    #[serde(default)]
    pub dish: Option<String>,
    #[serde(default)]
    pub servings: Option<String>,
    #[serde(default)]
    pub missing_slots: Vec<String>,
    #[serde(default)]
    pub clarification_required_slots: Vec<String>,
}

/// Messaging-specific request frame retained by Studio.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioMessageComposeRequestFrame {
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub recipient_context: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub missing_slots: Vec<String>,
    #[serde(default)]
    pub clarification_required_slots: Vec<String>,
}

/// User-input request frame retained by Studio.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioUserInputRequestFrame {
    #[serde(default)]
    pub interaction_kind: Option<String>,
    pub explicit_options_present: bool,
    #[serde(default)]
    pub missing_slots: Vec<String>,
    #[serde(default)]
    pub clarification_required_slots: Vec<String>,
}

/// Tagged normalized request frame for high-value first-party lanes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StudioNormalizedRequestFrame {
    Weather(StudioWeatherRequestFrame),
    Sports(StudioSportsRequestFrame),
    Places(StudioPlacesRequestFrame),
    Recipe(StudioRecipeRequestFrame),
    MessageCompose(StudioMessageComposeRequestFrame),
    UserInput(StudioUserInputRequestFrame),
}

/// Retained lane state used to carry route-relevant context across follow-up
/// turns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioRetainedLaneState {
    pub active_lane: StudioLaneFamily,
    #[serde(default)]
    pub active_tool_widget_family: Option<String>,
    #[serde(default)]
    pub active_artifact_id: Option<String>,
    #[serde(default)]
    pub unresolved_clarification_question: Option<String>,
    #[serde(default)]
    pub selected_provider_family: Option<String>,
    #[serde(default)]
    pub selected_provider_route_label: Option<String>,
    #[serde(default)]
    pub selected_source_family: Option<StudioSourceFamily>,
}

/// Recorded lane transition used by Studio route receipts and retained state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioLaneTransition {
    pub transition_kind: StudioLaneTransitionKind,
    #[serde(default)]
    pub from_lane: Option<StudioLaneFamily>,
    pub to_lane: StudioLaneFamily,
    pub reason: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

/// Objective-level state for long-form orchestration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioObjectiveState {
    pub objective_id: String,
    pub title: String,
    pub status: StudioWorkStatus,
    #[serde(default)]
    pub success_criteria: Vec<String>,
}

/// Task-unit state for long-form orchestration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioTaskUnitState {
    pub task_id: String,
    pub label: String,
    pub status: StudioWorkStatus,
    pub lane_family: StudioLaneFamily,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
}

/// Checkpoint state for long-form orchestration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioCheckpointState {
    pub checkpoint_id: String,
    pub label: String,
    pub status: StudioWorkStatus,
    pub summary: String,
}

/// Run-level completion invariant retained with Studio orchestration state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioCompletionInvariant {
    pub summary: String,
    pub satisfied: bool,
    #[serde(default)]
    pub outstanding_requirements: Vec<String>,
}

/// Methodology-agnostic orchestration state retained for long-form Studio
/// work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioOrchestrationState {
    #[serde(default)]
    pub objective: Option<StudioObjectiveState>,
    #[serde(default)]
    pub tasks: Vec<StudioTaskUnitState>,
    #[serde(default)]
    pub checkpoints: Vec<StudioCheckpointState>,
    #[serde(default)]
    pub completion_invariant: Option<StudioCompletionInvariant>,
}

/// How the execution controller may expand work once a mode is chosen.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioExecutionBudgetExpansionPolicy {
    Fixed,
    ConfidenceGated,
    FrontierAdaptive,
}

/// Execution-time budget envelope assigned by the escalation gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioExecutionBudgetEnvelope {
    pub max_workers: u32,
    pub max_parallel_depth: u32,
    pub max_replans: u32,
    pub max_wall_clock_ms: u64,
    pub max_tokens: u32,
    pub max_tool_calls: u32,
    pub max_repairs: u32,
    pub expansion_policy: StudioExecutionBudgetExpansionPolicy,
}

/// Typed execution-mode decision recorded after routing and before
/// decomposition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioExecutionModeDecision {
    pub requested_strategy: StudioExecutionStrategy,
    pub resolved_strategy: StudioExecutionStrategy,
    pub mode_confidence: f32,
    pub one_shot_sufficiency: f32,
    pub ambiguity: f32,
    pub work_graph_size_estimate: u32,
    pub hidden_dependency_likelihood: f32,
    pub verification_pressure: f32,
    pub revision_cost: f32,
    pub evidence_breadth: f32,
    pub merge_burden: f32,
    pub decomposition_payoff: f32,
    pub work_graph_required: bool,
    pub decomposition_reason: String,
    pub budget_envelope: StudioExecutionBudgetEnvelope,
}

/// The broad class of artifact being produced.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactClass {
    Document,
    Visual,
    InteractiveSingleFile,
    DownloadableFile,
    WorkspaceProject,
    CompoundBundle,
    CodePatch,
    ReportBundle,
}

/// The deliverable shape for a Studio artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactDeliverableShape {
    SingleFile,
    FileSet,
    WorkspaceProject,
}

/// The renderer backend used to present the artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioRendererKind {
    Markdown,
    HtmlIframe,
    JsxSandbox,
    Svg,
    Mermaid,
    PdfEmbed,
    DownloadCard,
    WorkspaceSurface,
    BundleManifest,
}

/// The presentation surface used in the product shell.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioPresentationSurface {
    Inline,
    SidePanel,
    Overlay,
    TabbedPanel,
}

/// The persistence mode available to the artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactPersistenceMode {
    Ephemeral,
    ArtifactScoped,
    SharedArtifactScoped,
    WorkspaceFilesystem,
}

/// The execution substrate required to materialize the artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioExecutionSubstrate {
    None,
    ClientSandbox,
    BinaryGenerator,
    WorkspaceRuntime,
}

/// The tab kinds supported by the artifact host.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactTabKind {
    Render,
    Source,
    Download,
    Evidence,
    Workspace,
}

/// The role a file plays inside an artifact package.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactFileRole {
    Primary,
    Source,
    Export,
    Supporting,
}

/// Verification state for the manifest as currently known by Studio.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactVerificationStatus {
    Pending,
    Ready,
    Blocked,
    Failed,
    Partial,
}

/// Truthful runtime provenance for Studio generation and validation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioRuntimeProvenanceKind {
    RealRemoteModelRuntime,
    RealLocalRuntime,
    FixtureRuntime,
    MockRuntime,
    DeterministicContinuityFallback,
    InferenceUnavailable,
    OpaqueRuntime,
}

/// Shared Studio runtime provenance surfaced in manifests, evidence, and UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioRuntimeProvenance {
    pub kind: StudioRuntimeProvenanceKind,
    pub label: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// Explicit typed artifact failure surfaced when Studio cannot truthfully
/// produce or validate an artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactFailureKind {
    InferenceUnavailable,
    RoutingFailure,
    GenerationFailure,
    VerificationFailure,
}

/// Failure payload persisted across Studio surfaces instead of being hidden
/// behind substitute artifacts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactFailure {
    pub kind: StudioArtifactFailureKind,
    pub code: String,
    pub message: String,
}

/// Explicit lifecycle state for a Studio artifact session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StudioArtifactLifecycleState {
    Draft,
    Planned,
    Materializing,
    Rendering,
    Implementing,
    Verifying,
    Ready,
    Partial,
    Blocked,
    Failed,
}

/// Scope and mutation boundaries for artifact work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioOutcomeArtifactScope {
    pub target_project: Option<String>,
    pub create_new_workspace: bool,
    pub mutation_boundary: Vec<String>,
}

/// Verification requests attached to an artifact plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioOutcomeArtifactVerificationRequest {
    pub require_render: bool,
    pub require_build: bool,
    pub require_preview: bool,
    pub require_export: bool,
    pub require_diff_review: bool,
}

/// Typed artifact request emitted by the router.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioOutcomeArtifactRequest {
    pub artifact_class: StudioArtifactClass,
    pub deliverable_shape: StudioArtifactDeliverableShape,
    pub renderer: StudioRendererKind,
    pub presentation_surface: StudioPresentationSurface,
    pub persistence: StudioArtifactPersistenceMode,
    pub execution_substrate: StudioExecutionSubstrate,
    pub workspace_recipe_id: Option<String>,
    pub presentation_variant_id: Option<String>,
    pub scope: StudioOutcomeArtifactScope,
    pub verification: StudioOutcomeArtifactVerificationRequest,
}

/// The top-level typed outcome router result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioOutcomeRequest {
    pub request_id: String,
    pub raw_prompt: String,
    pub active_artifact_id: Option<String>,
    pub outcome_kind: StudioOutcomeKind,
    #[serde(default = "default_studio_execution_strategy")]
    pub execution_strategy: StudioExecutionStrategy,
    #[serde(default)]
    pub execution_mode_decision: Option<StudioExecutionModeDecision>,
    pub confidence: f32,
    pub needs_clarification: bool,
    pub clarification_questions: Vec<String>,
    #[serde(default)]
    pub routing_hints: Vec<String>,
    #[serde(default)]
    pub lane_frame: Option<StudioDomainLaneFrame>,
    #[serde(default)]
    pub request_frame: Option<StudioNormalizedRequestFrame>,
    #[serde(default)]
    pub source_selection: Option<StudioSourceSelection>,
    #[serde(default)]
    pub retained_lane_state: Option<StudioRetainedLaneState>,
    #[serde(default)]
    pub lane_transitions: Vec<StudioLaneTransition>,
    #[serde(default)]
    pub orchestration_state: Option<StudioOrchestrationState>,
    pub artifact: Option<StudioOutcomeArtifactRequest>,
}

/// Raw planner payload emitted by inference before request IDs are assigned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StudioOutcomePlanningPayload {
    pub outcome_kind: StudioOutcomeKind,
    #[serde(default = "default_studio_execution_strategy")]
    pub execution_strategy: StudioExecutionStrategy,
    #[serde(default)]
    pub execution_mode_decision: Option<StudioExecutionModeDecision>,
    #[serde(default)]
    pub confidence: f32,
    #[serde(default)]
    pub needs_clarification: bool,
    #[serde(default)]
    pub clarification_questions: Vec<String>,
    #[serde(default)]
    pub routing_hints: Vec<String>,
    #[serde(default)]
    pub lane_frame: Option<StudioDomainLaneFrame>,
    #[serde(default)]
    pub request_frame: Option<StudioNormalizedRequestFrame>,
    #[serde(default)]
    pub source_selection: Option<StudioSourceSelection>,
    #[serde(default)]
    pub retained_lane_state: Option<StudioRetainedLaneState>,
    #[serde(default)]
    pub lane_transitions: Vec<StudioLaneTransition>,
    #[serde(default)]
    pub orchestration_state: Option<StudioOrchestrationState>,
    #[serde(default)]
    pub artifact: Option<StudioOutcomeArtifactRequest>,
}

/// A tab entry inside the artifact manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactManifestTab {
    pub id: String,
    pub label: String,
    pub kind: StudioArtifactTabKind,
    pub renderer: Option<StudioRendererKind>,
    pub file_path: Option<String>,
    pub lens: Option<String>,
}

/// A file entry inside the artifact manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactManifestFile {
    pub path: String,
    pub mime: String,
    pub role: StudioArtifactFileRole,
    pub renderable: bool,
    pub downloadable: bool,
    pub artifact_id: Option<String>,
    pub external_url: Option<String>,
}

/// Verification summary embedded in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactManifestVerification {
    pub status: StudioArtifactVerificationStatus,
    pub lifecycle_state: StudioArtifactLifecycleState,
    pub summary: String,
    #[serde(default)]
    pub production_provenance: Option<StudioRuntimeProvenance>,
    #[serde(default)]
    pub acceptance_provenance: Option<StudioRuntimeProvenance>,
    #[serde(default)]
    pub failure: Option<StudioArtifactFailure>,
}

/// Storage capabilities exposed by the artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactManifestStorage {
    pub mode: StudioArtifactPersistenceMode,
    pub api_label: Option<String>,
}

/// Canonical manifest for a Studio artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioArtifactManifest {
    pub artifact_id: String,
    pub title: String,
    pub artifact_class: StudioArtifactClass,
    pub renderer: StudioRendererKind,
    pub primary_tab: String,
    pub tabs: Vec<StudioArtifactManifestTab>,
    pub files: Vec<StudioArtifactManifestFile>,
    pub verification: StudioArtifactManifestVerification,
    pub storage: Option<StudioArtifactManifestStorage>,
}

/// Verification-backed reply composed from the artifact state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StudioVerifiedReply {
    pub status: StudioArtifactVerificationStatus,
    pub lifecycle_state: StudioArtifactLifecycleState,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub production_provenance: Option<StudioRuntimeProvenance>,
    #[serde(default)]
    pub acceptance_provenance: Option<StudioRuntimeProvenance>,
    #[serde(default)]
    pub failure: Option<StudioArtifactFailure>,
    pub updated_at: String,
}
