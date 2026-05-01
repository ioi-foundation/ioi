#![allow(missing_docs)]
//! Shared Chat outcome and artifact contracts.
//!
//! These types define the schema for outcome routing, artifact manifests, and
//! verification-backed replies so that Chat surfaces and CLI tooling can
//! operate on the same typed work product language.

use serde::{Deserialize, Serialize};

/// The top-level outcome class selected by Chat's router.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatOutcomeKind {
    Conversation,
    ToolWidget,
    Visualizer,
    Artifact,
}

/// The orchestration strategy chosen for this Chat outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatExecutionStrategy {
    SinglePass,
    DirectAuthor,
    PlanExecute,
    #[serde(alias = "micro_swarm")]
    MicroWorkGraph,
    #[serde(rename = "adaptive_work_graph")]
    AdaptiveWorkGraph,
}

fn default_chat_execution_strategy() -> ChatExecutionStrategy {
    ChatExecutionStrategy::PlanExecute
}

/// Shared lane families used to describe Chat routing and retained lane
/// state without binding directly to a specific tool name.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatLaneFamily {
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

/// Source families considered when selecting how Chat should answer a
/// request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatSourceFamily {
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
pub enum ChatLaneTransitionKind {
    Planned,
    Reactive,
}

/// Shared status labels for objective/task/checkpoint state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatWorkStatus {
    Pending,
    InProgress,
    Complete,
    Blocked,
}

/// Typed lane frame derived from Chat routing signals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChatLaneRequest {
    pub primary_lane: ChatLaneFamily,
    #[serde(default)]
    pub secondary_lanes: Vec<ChatLaneFamily>,
    pub primary_goal: String,
    #[serde(default)]
    pub tool_widget_family: Option<String>,
    pub currentness_pressure: bool,
    pub workspace_grounding_required: bool,
    pub persistent_deliverable_requested: bool,
    pub active_artifact_follow_up: bool,
    pub lane_confidence: f32,
}

/// Structured source-selection summary retained alongside Chat route truth.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatSourceDecision {
    #[serde(default)]
    pub candidate_sources: Vec<ChatSourceFamily>,
    pub selected_source: ChatSourceFamily,
    pub explicit_user_source: bool,
    #[serde(default)]
    pub degradation_reason: Option<String>,
}

/// Clarification posture used by a specialized lane.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatClarificationMode {
    AssumeFromRetainedState,
    ClarifyOnMissingSlots,
    BlockUntilClarified,
}

/// Explicit clarification policy retained for a lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatClarificationPolicy {
    pub mode: ChatClarificationMode,
    #[serde(default)]
    pub assumed_bindings: Vec<String>,
    #[serde(default)]
    pub blocking_slots: Vec<String>,
    pub rationale: String,
}

/// Fallback posture used by a specialized lane.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatFallbackMode {
    StayInSpecializedLane,
    AllowRankedFallbacks,
    BlockUntilClarified,
}

/// Explicit fallback policy retained for a lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatFallbackPolicy {
    pub mode: ChatFallbackMode,
    pub primary_lane: ChatLaneFamily,
    #[serde(default)]
    pub fallback_lanes: Vec<ChatLaneFamily>,
    #[serde(default)]
    pub trigger_signals: Vec<String>,
    pub rationale: String,
}

/// Presentation policy for a routed Chat lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatPresentationPolicy {
    pub primary_surface: String,
    #[serde(default)]
    pub widget_family: Option<String>,
    #[serde(default)]
    pub renderer: Option<ChatRendererKind>,
    #[serde(default)]
    pub tab_priority: Vec<String>,
    pub rationale: String,
}

/// Transformation policy explaining how raw structured data becomes the final
/// user-facing output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatTransformationPolicy {
    pub output_shape: String,
    #[serde(default)]
    pub ordered_steps: Vec<String>,
    pub rationale: String,
}

/// Sensitivity tier assigned to a routed Chat lane.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatRiskSensitivity {
    Low,
    Medium,
    High,
}

/// Risk profile retained for a routed Chat lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatRiskProfile {
    pub sensitivity: ChatRiskSensitivity,
    #[serde(default)]
    pub reasons: Vec<String>,
    pub approval_required: bool,
    #[serde(default)]
    pub user_visible_guardrails: Vec<String>,
}

/// Verification contract for a specialized lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatVerificationContract {
    pub strategy: String,
    #[serde(default)]
    pub required_checks: Vec<String>,
    pub completion_gate: String,
}

/// Ordered source-ranking entry retained for audit and replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatSourceRankingEntry {
    pub source: ChatSourceFamily,
    pub rank: u32,
    pub rationale: String,
}

/// Retained widget-state binding used to preserve user-visible lane context
/// across follow-up turns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatWidgetStateBinding {
    pub key: String,
    pub value: String,
    pub source: String,
}

/// Retained widget/runtime state for a specialized surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatRetainedWidgetState {
    #[serde(default)]
    pub widget_family: Option<String>,
    #[serde(default)]
    pub bindings: Vec<ChatWidgetStateBinding>,
    #[serde(default)]
    pub last_updated_at: Option<String>,
}

/// Explicit contract showing which behaviors are represented in schema rather
/// than hidden in prompts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatPolicyContractSummary {
    #[serde(default)]
    pub bindings: Vec<String>,
    pub hidden_instruction_dependency: bool,
    pub rationale: String,
}

/// Domain-policy bundle retained for parity inspection and operator truth.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ChatDomainPolicyBundle {
    pub clarification_policy: Option<ChatClarificationPolicy>,
    pub fallback_policy: Option<ChatFallbackPolicy>,
    pub presentation_policy: Option<ChatPresentationPolicy>,
    pub transformation_policy: Option<ChatTransformationPolicy>,
    pub risk_profile: Option<ChatRiskProfile>,
    pub verification_contract: Option<ChatVerificationContract>,
    pub policy_contract: Option<ChatPolicyContractSummary>,
    #[serde(default)]
    pub source_ranking: Vec<ChatSourceRankingEntry>,
    pub retained_widget_state: Option<ChatRetainedWidgetState>,
}

/// Weather-specific request frame retained by Chat.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatWeatherRequestFrame {
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

/// Sports-specific request frame retained by Chat.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatSportsRequestFrame {
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

/// Places-specific request frame retained by Chat.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatPlacesRequestFrame {
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

/// Recipe-specific request frame retained by Chat.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatRecipeRequestFrame {
    #[serde(default)]
    pub dish: Option<String>,
    #[serde(default)]
    pub servings: Option<String>,
    #[serde(default)]
    pub missing_slots: Vec<String>,
    #[serde(default)]
    pub clarification_required_slots: Vec<String>,
}

/// Messaging-specific request frame retained by Chat.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatMessageComposeRequestFrame {
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

/// User-input request frame retained by Chat.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatUserInputRequestFrame {
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
pub enum ChatNormalizedRequest {
    Weather(ChatWeatherRequestFrame),
    Sports(ChatSportsRequestFrame),
    Places(ChatPlacesRequestFrame),
    Recipe(ChatRecipeRequestFrame),
    MessageCompose(ChatMessageComposeRequestFrame),
    UserInput(ChatUserInputRequestFrame),
}

/// Retained lane state used to carry route-relevant context across follow-up
/// turns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatRetainedLaneState {
    pub active_lane: ChatLaneFamily,
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
    pub selected_source_family: Option<ChatSourceFamily>,
}

/// Recorded lane transition used by Chat route receipts and retained state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatLaneTransition {
    pub transition_kind: ChatLaneTransitionKind,
    #[serde(default)]
    pub from_lane: Option<ChatLaneFamily>,
    pub to_lane: ChatLaneFamily,
    pub reason: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

/// Objective-level state for long-form orchestration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatObjectiveState {
    pub objective_id: String,
    pub title: String,
    pub status: ChatWorkStatus,
    #[serde(default)]
    pub success_criteria: Vec<String>,
}

/// Task-unit state for long-form orchestration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatTaskUnitState {
    pub task_id: String,
    pub label: String,
    pub status: ChatWorkStatus,
    pub lane_family: ChatLaneFamily,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
}

/// Checkpoint state for long-form orchestration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatCheckpointState {
    pub checkpoint_id: String,
    pub label: String,
    pub status: ChatWorkStatus,
    pub summary: String,
}

/// Run-level completion invariant retained with Chat orchestration state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatCompletionInvariant {
    pub summary: String,
    pub satisfied: bool,
    #[serde(default)]
    pub outstanding_requirements: Vec<String>,
}

/// Methodology-agnostic orchestration state retained for long-form Chat
/// work.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatOrchestrationState {
    #[serde(default)]
    pub objective: Option<ChatObjectiveState>,
    #[serde(default)]
    pub tasks: Vec<ChatTaskUnitState>,
    #[serde(default)]
    pub checkpoints: Vec<ChatCheckpointState>,
    #[serde(default)]
    pub completion_invariant: Option<ChatCompletionInvariant>,
}

/// How the execution controller may expand work once a mode is chosen.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatExecutionBudgetExpansionPolicy {
    Fixed,
    ConfidenceGated,
    FrontierAdaptive,
}

/// Execution-time budget envelope assigned by the escalation gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatExecutionBudgetEnvelope {
    pub max_workers: u32,
    pub max_parallel_depth: u32,
    pub max_replans: u32,
    pub max_wall_clock_ms: u64,
    pub max_tokens: u32,
    pub max_tool_calls: u32,
    pub max_repairs: u32,
    pub expansion_policy: ChatExecutionBudgetExpansionPolicy,
}

/// Typed execution-mode decision recorded after routing and before
/// decomposition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChatExecutionModeDecision {
    pub requested_strategy: ChatExecutionStrategy,
    pub resolved_strategy: ChatExecutionStrategy,
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
    pub budget_envelope: ChatExecutionBudgetEnvelope,
}

/// The broad class of artifact being produced.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactClass {
    Document,
    Visual,
    InteractiveSingleFile,
    DownloadableFile,
    WorkspaceProject,
    CompoundBundle,
    CodePatch,
    ReportBundle,
}

/// The deliverable shape for a Chat artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactDeliverableShape {
    SingleFile,
    FileSet,
    WorkspaceProject,
}

/// The renderer backend used to present the artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatRendererKind {
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
pub enum ChatPresentationSurface {
    Inline,
    SidePanel,
    Overlay,
    TabbedPanel,
}

/// The persistence mode available to the artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactPersistenceMode {
    Ephemeral,
    ArtifactScoped,
    SharedArtifactScoped,
    WorkspaceFilesystem,
}

/// The execution substrate required to materialize the artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatExecutionSubstrate {
    None,
    ClientSandbox,
    BinaryGenerator,
    WorkspaceRuntime,
}

/// The tab kinds supported by the artifact host.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactTabKind {
    Render,
    Source,
    Download,
    Evidence,
    Workspace,
}

/// The role a file plays inside an artifact package.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactFileRole {
    Primary,
    Source,
    Export,
    Supporting,
}

/// Verification state for the manifest as currently known by Chat.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactVerificationStatus {
    Pending,
    Ready,
    Blocked,
    Failed,
    Partial,
}

/// Truthful runtime provenance for Chat generation and validation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatRuntimeProvenanceKind {
    RealRemoteModelRuntime,
    RealLocalRuntime,
    FixtureRuntime,
    MockRuntime,
    DeterministicContinuityFallback,
    InferenceUnavailable,
    OpaqueRuntime,
}

/// Shared Chat runtime provenance surfaced in manifests, evidence, and UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatRuntimeProvenance {
    pub kind: ChatRuntimeProvenanceKind,
    pub label: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// Explicit typed artifact failure surfaced when Chat cannot truthfully
/// produce or validate an artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactFailureKind {
    InferenceUnavailable,
    RoutingFailure,
    GenerationFailure,
    VerificationFailure,
}

/// Failure payload persisted across Chat surfaces instead of being hidden
/// behind substitute artifacts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactFailure {
    pub kind: ChatArtifactFailureKind,
    pub code: String,
    pub message: String,
}

/// Explicit lifecycle state for a Chat artifact session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChatArtifactLifecycleState {
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
pub struct ChatOutcomeArtifactScope {
    pub target_project: Option<String>,
    pub create_new_workspace: bool,
    pub mutation_boundary: Vec<String>,
}

/// Verification requests attached to an artifact plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatOutcomeArtifactVerificationRequest {
    pub require_render: bool,
    pub require_build: bool,
    pub require_preview: bool,
    pub require_export: bool,
    pub require_diff_review: bool,
}

/// Typed artifact request emitted by the router.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatOutcomeArtifactRequest {
    pub artifact_class: ChatArtifactClass,
    pub deliverable_shape: ChatArtifactDeliverableShape,
    pub renderer: ChatRendererKind,
    pub presentation_surface: ChatPresentationSurface,
    pub persistence: ChatArtifactPersistenceMode,
    pub execution_substrate: ChatExecutionSubstrate,
    pub workspace_recipe_id: Option<String>,
    pub presentation_variant_id: Option<String>,
    pub scope: ChatOutcomeArtifactScope,
    pub verification: ChatOutcomeArtifactVerificationRequest,
}

/// The top-level typed outcome router result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChatOutcomeRequest {
    pub request_id: String,
    pub raw_prompt: String,
    pub active_artifact_id: Option<String>,
    pub outcome_kind: ChatOutcomeKind,
    #[serde(default = "default_chat_execution_strategy")]
    pub execution_strategy: ChatExecutionStrategy,
    #[serde(default)]
    pub execution_mode_decision: Option<ChatExecutionModeDecision>,
    pub confidence: f32,
    pub needs_clarification: bool,
    pub clarification_questions: Vec<String>,
    #[serde(default)]
    pub decision_evidence: Vec<String>,
    #[serde(default)]
    pub lane_request: Option<ChatLaneRequest>,
    #[serde(default)]
    pub normalized_request: Option<ChatNormalizedRequest>,
    #[serde(default)]
    pub source_decision: Option<ChatSourceDecision>,
    #[serde(default)]
    pub retained_lane_state: Option<ChatRetainedLaneState>,
    #[serde(default)]
    pub lane_transitions: Vec<ChatLaneTransition>,
    #[serde(default)]
    pub orchestration_state: Option<ChatOrchestrationState>,
    pub artifact: Option<ChatOutcomeArtifactRequest>,
}

/// Raw planner payload emitted by inference before request IDs are assigned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChatOutcomePlanningPayload {
    pub outcome_kind: ChatOutcomeKind,
    #[serde(default = "default_chat_execution_strategy")]
    pub execution_strategy: ChatExecutionStrategy,
    #[serde(default)]
    pub execution_mode_decision: Option<ChatExecutionModeDecision>,
    #[serde(default)]
    pub confidence: f32,
    #[serde(default)]
    pub needs_clarification: bool,
    #[serde(default)]
    pub clarification_questions: Vec<String>,
    #[serde(default)]
    pub decision_evidence: Vec<String>,
    #[serde(default)]
    pub lane_request: Option<ChatLaneRequest>,
    #[serde(default)]
    pub normalized_request: Option<ChatNormalizedRequest>,
    #[serde(default)]
    pub source_decision: Option<ChatSourceDecision>,
    #[serde(default)]
    pub retained_lane_state: Option<ChatRetainedLaneState>,
    #[serde(default)]
    pub lane_transitions: Vec<ChatLaneTransition>,
    #[serde(default)]
    pub orchestration_state: Option<ChatOrchestrationState>,
    #[serde(default)]
    pub artifact: Option<ChatOutcomeArtifactRequest>,
}

/// A tab entry inside the artifact manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactManifestTab {
    pub id: String,
    pub label: String,
    pub kind: ChatArtifactTabKind,
    pub renderer: Option<ChatRendererKind>,
    pub file_path: Option<String>,
    pub lens: Option<String>,
}

/// A file entry inside the artifact manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactManifestFile {
    pub path: String,
    pub mime: String,
    pub role: ChatArtifactFileRole,
    pub renderable: bool,
    pub downloadable: bool,
    pub artifact_id: Option<String>,
    pub external_url: Option<String>,
}

/// Verification summary embedded in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactManifestVerification {
    pub status: ChatArtifactVerificationStatus,
    pub lifecycle_state: ChatArtifactLifecycleState,
    pub summary: String,
    #[serde(default)]
    pub production_provenance: Option<ChatRuntimeProvenance>,
    #[serde(default)]
    pub acceptance_provenance: Option<ChatRuntimeProvenance>,
    #[serde(default)]
    pub failure: Option<ChatArtifactFailure>,
}

/// Storage capabilities exposed by the artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactManifestStorage {
    pub mode: ChatArtifactPersistenceMode,
    pub api_label: Option<String>,
}

/// Canonical manifest for a Chat artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatArtifactManifest {
    pub artifact_id: String,
    pub title: String,
    pub artifact_class: ChatArtifactClass,
    pub renderer: ChatRendererKind,
    pub primary_tab: String,
    pub tabs: Vec<ChatArtifactManifestTab>,
    pub files: Vec<ChatArtifactManifestFile>,
    pub verification: ChatArtifactManifestVerification,
    pub storage: Option<ChatArtifactManifestStorage>,
}

/// Verification-backed reply composed from the artifact state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChatVerifiedReply {
    pub status: ChatArtifactVerificationStatus,
    pub lifecycle_state: ChatArtifactLifecycleState,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub production_provenance: Option<ChatRuntimeProvenance>,
    #[serde(default)]
    pub acceptance_provenance: Option<ChatRuntimeProvenance>,
    #[serde(default)]
    pub failure: Option<ChatArtifactFailure>,
    pub updated_at: String,
}
