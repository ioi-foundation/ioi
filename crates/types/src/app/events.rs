// Path: crates/types/src/app/events.rs

use crate::app::agentic::{
    FirewallDecision, IntentCandidateScore, IntentConfidenceBand, IntentScopeProfile,
    PiiDecisionMaterial, PiiReviewSummary, PiiTarget, StepTrace,
};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Classifies a failed action attempt for anti-loop routing.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum RoutingFailureClass {
    /// Active foreground window/app did not match the expected target.
    FocusMismatch,
    /// Expected clickable/typed target could not be resolved.
    TargetNotFound,
    /// Visual grounding target could not be resolved with sufficient confidence.
    VisionTargetNotFound,
    /// Action executed but produced no meaningful observable UI effect.
    NoEffectAfterAction,
    /// Action violated tier policy constraints.
    TierViolation,
    /// Required dependency for the requested action was unavailable.
    MissingDependency,
    /// Visual or interaction context drifted before/after execution.
    ContextDrift,
    /// Policy denied action or explicit approval is still required.
    PermissionOrApprovalRequired,
    /// Required tool/capability was missing in the current tier.
    ToolUnavailable,
    /// UI behavior/state changed nondeterministically between attempts.
    NonDeterministicUI,
    /// Failure reason did not match a more specific class.
    UnexpectedState,
    /// Action timed out or appeared to hang.
    TimeoutOrHang,
    /// Human input is required before proceeding.
    UserInterventionNeeded,
}

/// Pre-action snapshot used in routing receipts.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct RoutingStateSummary {
    /// Lifecycle status before action execution (e.g. Running/Paused).
    pub agent_status: String,
    /// Router modality label used for this step.
    pub tier: String,
    /// Step index before execution.
    pub step_index: u32,
    /// Consecutive failure counter before execution.
    pub consecutive_failures: u8,
    /// Optional app/window hint bound to this session.
    pub target_hint: Option<String>,
}

/// Post-action snapshot used in routing receipts.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct RoutingPostStateSummary {
    /// Lifecycle status after action execution.
    pub agent_status: String,
    /// Router modality label after execution.
    pub tier: String,
    /// Step index after execution logic.
    pub step_index: u32,
    /// Consecutive failure counter after execution.
    pub consecutive_failures: u8,
    /// Whether the action execution succeeded.
    pub success: bool,
    /// Verification checkpoints emitted by the router.
    pub verification_checks: Vec<String>,
}

/// Auditable per-turn tool surface projection used by routing receipts.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(default)]
pub struct RoutingEffectiveToolSurface {
    /// Ordered union of the projected tools surfaced to the model/runtime for this turn.
    pub projected_tools: Vec<String>,
    /// Route-shaped tools preferred for the current turn.
    pub primary_tools: Vec<String>,
    /// Broad fallback tools that remained available after projection.
    pub broad_fallback_tools: Vec<String>,
    /// Additional discovered tools retained for audit/diagnostic truth.
    pub diagnostic_tools: Vec<String>,
}

/// Typed route-decision contract emitted alongside routing receipts.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(default)]
pub struct RoutingRouteDecision {
    /// High-level runtime family selected for this step.
    pub route_family: String,
    /// Whether a direct inline answer remained viable for this turn.
    pub direct_answer_allowed: bool,
    /// Named blockers explaining why direct inline answering was not selected.
    pub direct_answer_blockers: Vec<String>,
    /// Whether fresh/current data requirements overrode direct answering.
    pub currentness_override: bool,
    /// Number of provider candidates synthesized for this turn.
    pub connector_candidate_count: u32,
    /// Provider family selected by provider selection, when any.
    pub selected_provider_family: Option<String>,
    /// Provider route label selected by provider selection, when any.
    pub selected_provider_route_label: Option<String>,
    /// Whether connector/provider-aligned tools were preferred over built-in fallbacks.
    pub connector_first_preference: bool,
    /// Whether narrow route-shaped tools outranked broad fallback tools.
    pub narrow_tool_preference: bool,
    /// Whether the route points toward filesystem/file-backed output.
    pub file_output_intent: bool,
    /// Whether the route points toward generated artifact output.
    pub artifact_output_intent: bool,
    /// Whether the route points toward inline visual/browser/UI output.
    pub inline_visual_intent: bool,
    /// Whether conditional skill/guidance preparation was required.
    pub skill_prep_required: bool,
    /// High-level output intent for the selected route.
    pub output_intent: String,
    /// Auditable projected tool surface for the turn.
    pub effective_tool_surface: RoutingEffectiveToolSurface,
}

/// Receipted parity router decision emitted for each impactful action.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct RoutingReceiptEvent {
    /// Session this receipt belongs to.
    pub session_id: [u8; 32],
    /// Step index this receipt was generated for.
    pub step_index: u32,
    /// Hex-encoded canonical intent hash for this action.
    pub intent_hash: String,
    /// Policy decision rendered for this action path.
    pub policy_decision: String,
    /// Tool/capability invoked.
    pub tool_name: String,
    /// Tool/driver version used for execution.
    pub tool_version: String,
    /// Pre-execution state summary.
    pub pre_state: RoutingStateSummary,
    /// Canonical action JSON payload.
    pub action_json: String,
    /// Post-execution state summary.
    pub post_state: RoutingPostStateSummary,
    /// Artifact pointers relevant to this action.
    pub artifacts: Vec<String>,
    /// Optional classified failure reason.
    pub failure_class: Option<RoutingFailureClass>,
    /// Canonical failure class name used by clients without enum mapping tables.
    pub failure_class_name: String,
    /// Ontology intent class for this routed action.
    pub intent_class: String,
    /// Active ontology incident identifier.
    pub incident_id: String,
    /// Incident stage at receipt emission time.
    pub incident_stage: String,
    /// Ontology strategy name used by resolver.
    pub strategy_name: String,
    /// Ontology strategy node/cursor.
    pub strategy_node: String,
    /// Approval gate state (None/Pending/Approved/Denied/Cleared).
    pub gate_state: String,
    /// Resolver action decided for this step (wait_for_user/execute_remedy/retry_root/etc).
    pub resolution_action: String,
    /// Whether retry guard stop condition was triggered.
    pub stop_condition_hit: bool,
    /// Optional escalation path selected by the router.
    pub escalation_path: Option<String>,
    /// Optional legacy lineage pointer for skill/trace provenance.
    pub lineage_ptr: Option<String>,
    /// Optional memory mutation receipt pointer for RSI lineage.
    pub mutation_receipt_ptr: Option<String>,
    /// Canonical hash binding `intent_hash` and `policy_decision`.
    pub policy_binding_hash: String,
    /// Optional signature over `policy_binding_hash` for non-repudiation.
    pub policy_binding_sig: Option<String>,
    /// Optional signer public key (hex-encoded protobuf bytes).
    pub policy_binding_signer: Option<String>,
    /// Typed route-decision contract derived from the runtime's effective surface.
    #[serde(default)]
    pub route_decision: RoutingRouteDecision,
}

/// PII decision receipt emitted by the local-only PII firewall pipeline.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct PiiDecisionReceiptEvent {
    /// Session this decision belongs to (if available).
    pub session_id: Option<[u8; 32]>,
    /// Action target being evaluated.
    pub target: String,
    /// Optional typed action target for deterministic tooling/debug.
    #[serde(default)]
    pub target_id: Option<PiiTarget>,
    /// Risk surface ("local_processing" or "egress").
    pub risk_surface: String,
    /// Deterministic decision hash.
    pub decision_hash: [u8; 32],
    /// Final decision selected by the router.
    #[serde(default)]
    pub decision: FirewallDecision,
    /// Optional chosen transform plan identifier.
    #[serde(default)]
    pub transform_plan_id: Option<String>,
    /// Number of evidence spans considered during routing.
    #[serde(default)]
    pub span_count: u32,
    /// Whether ambiguity remained after deterministic refinement.
    #[serde(default)]
    pub ambiguous: bool,
    /// Optional stage2 decision kind.
    #[serde(default)]
    pub stage2_kind: Option<String>,
    /// Whether an assist provider was invoked.
    #[serde(default)]
    pub assist_invoked: bool,
    /// Whether the assist output graph differs from the input graph.
    #[serde(default)]
    pub assist_applied: bool,
    /// Deterministic assist provider kind.
    #[serde(default)]
    pub assist_kind: String,
    /// Deterministic assist provider version.
    #[serde(default)]
    pub assist_version: String,
    /// Hash commitment to assist identity/config.
    #[serde(default)]
    pub assist_identity_hash: [u8; 32],
    /// Hash of assist input EvidenceGraph SCALE bytes.
    #[serde(default)]
    pub assist_input_graph_hash: [u8; 32],
    /// Hash of assist output EvidenceGraph SCALE bytes.
    #[serde(default)]
    pub assist_output_graph_hash: [u8; 32],
}

/// Intent resolution receipt emitted by the global step/action intent router.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq)]
pub struct IntentResolutionReceiptEvent {
    /// Resolver contract version.
    #[serde(default)]
    pub contract_version: String,
    /// Session this resolution belongs to.
    pub session_id: Option<[u8; 32]>,
    /// Canonical winning intent id.
    pub intent_id: String,
    /// Canonical selected intent id (duplicated for strict receipt schema parity).
    #[serde(default)]
    pub selected_intent_id: String,
    /// Ontological scope selected for this step.
    pub scope: IntentScopeProfile,
    /// Confidence band used for downstream policy.
    pub band: IntentConfidenceBand,
    /// Winning confidence score in [0.0, 1.0].
    pub score: f32,
    /// Policy-quantized selected score in [0.0, 1.0].
    #[serde(default)]
    pub selected_score_quantized: f32,
    /// Ranked top-k candidates for diagnostics.
    #[serde(default)]
    pub top_k: Vec<IntentCandidateScore>,
    /// Preferred tier selected from the matrix profile.
    pub preferred_tier: String,
    /// Matrix version used for this decision.
    pub matrix_version: String,
    /// Embedding model identifier used for ranking.
    #[serde(default)]
    pub embedding_model_id: String,
    /// Embedding model version used for ranking.
    #[serde(default)]
    pub embedding_model_version: String,
    /// Similarity function identifier used during ranking.
    #[serde(default)]
    pub similarity_function_id: String,
    /// Hash commitment over the active intent set.
    #[serde(default)]
    pub intent_set_hash: [u8; 32],
    /// Hash commitment over the active tool capability registry.
    #[serde(default)]
    pub tool_registry_hash: [u8; 32],
    /// Hash commitment over the capability ontology.
    #[serde(default)]
    pub capability_ontology_hash: [u8; 32],
    /// Query normalization version used before embedding.
    #[serde(default)]
    pub query_normalization_version: String,
    /// Hash commitment to the active matrix source.
    pub matrix_source_hash: [u8; 32],
    /// Deterministic receipt hash over resolution material.
    pub receipt_hash: [u8; 32],
    /// Optional provider-selection material synthesized for this intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_selection: Option<crate::app::agentic::ProviderSelectionState>,
    /// Optional resolver failure class when classification is unclassified/blocked/infeasible.
    #[serde(default)]
    pub error_class: Option<String>,
    /// Deprecated/compat: always false (constrained mode removed).
    #[serde(default)]
    pub constrained: bool,
}

/// CEC execution-contract receipt emitted for each required stage key.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct ExecutionContractReceiptEvent {
    /// CEC contract version.
    pub contract_version: String,
    /// Session this receipt belongs to.
    pub session_id: [u8; 32],
    /// Step index this receipt belongs to.
    pub step_index: u32,
    /// Resolved intent id for this execution flow.
    pub intent_id: String,
    /// Execution stage (`discovery`, `provider_selection`, `execution`, `verification`, `completion_gate`).
    pub stage: String,
    /// Receipt/postcondition key under this stage.
    pub key: String,
    /// Whether the key is satisfied.
    pub satisfied: bool,
    /// Milliseconds since UNIX epoch when this receipt was emitted.
    pub timestamp_ms: u64,
    /// Cryptographic commit hash over receipt evidence.
    pub evidence_commit_hash: String,
    /// Optional verification-command commit hash.
    #[serde(default)]
    pub verifier_command_commit_hash: Option<String>,
    /// Optional probe source used to derive the observed value.
    #[serde(default)]
    pub probe_source: Option<String>,
    /// Optional observed value backing the receipt.
    #[serde(default)]
    pub observed_value: Option<String>,
    /// Optional evidence type label for `observed_value` (for example `scalar`, `json`, `url`).
    #[serde(default)]
    pub evidence_type: Option<String>,
    /// Optional provider identifier.
    #[serde(default)]
    pub provider_id: Option<String>,
    /// Optional synthesized-payload hash.
    #[serde(default)]
    pub synthesized_payload_hash: Option<String>,
}

/// Worker vertex captured in a planner receipt.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct PlanWorkerNode {
    /// Worker session id in hex format.
    pub worker_session_id_hex: String,
    /// Stable step key inside the execution plan.
    pub step_key: String,
    /// Goal/assignment dispatched to the worker.
    pub goal: String,
    /// Terminal worker status string.
    pub status: String,
}

/// Receipt emitted when a synthesized execution plan is persisted.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct PlanReceiptEvent {
    /// Session this plan belongs to.
    pub session_id: Option<[u8; 32]>,
    /// Deterministic plan hash commitment.
    pub plan_hash: [u8; 32],
    /// Selected route identifier chosen by planner.
    pub selected_route: String,
    /// Worker graph emitted for this plan execution.
    #[serde(default)]
    pub worker_graph: Vec<PlanWorkerNode>,
    /// Effective policy bindings considered by planner execution.
    #[serde(default)]
    pub policy_bindings: Vec<String>,
}

/// Structured workload activity event for glass-box orchestration.
///
/// This is a higher-level, typed stream intended to back Autopilot rendering and replayable
/// receipts.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct WorkloadActivityEvent {
    /// Session this activity belongs to.
    pub session_id: [u8; 32],
    /// Step index this activity belongs to.
    pub step_index: u32,
    /// Stable identifier for the running workload within a step.
    pub workload_id: String,
    /// Milliseconds since UNIX epoch when emitted.
    pub timestamp_ms: u64,
    /// Typed activity kind.
    pub kind: WorkloadActivityKind,
}

/// Typed activity kinds for workloads.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum WorkloadActivityKind {
    /// Lifecycle signal for the workload (start/detach/exit).
    Lifecycle {
        /// Phase label (e.g., "started", "detached", "completed", "failed").
        phase: String,
        /// Optional exit code.
        #[serde(default)]
        exit_code: Option<i32>,
    },
    /// Bounded stdio chunk stream.
    Stdio {
        /// Stream label ("stdout", "stderr", "status").
        stream: String,
        /// Chunk payload.
        chunk: String,
        /// Monotonic sequence number within the stream.
        seq: u64,
        /// Marks terminal chunk for this stream.
        is_final: bool,
        /// Optional exit code when available.
        #[serde(default)]
        exit_code: Option<i32>,
    },
}

/// Observed receipt for a completed workload action (telemetry; not consensus-deterministic).
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct WorkloadReceiptEvent {
    /// Session this receipt belongs to.
    pub session_id: [u8; 32],
    /// Step index this receipt belongs to.
    pub step_index: u32,
    /// Stable identifier for the workload within a step.
    pub workload_id: String,
    /// Milliseconds since UNIX epoch when emitted.
    pub timestamp_ms: u64,
    /// Typed receipt payload.
    pub receipt: WorkloadReceipt,
}

/// Typed workload receipt payloads.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum WorkloadReceipt {
    /// A command execution receipt.
    Exec(WorkloadExecReceipt),
    /// A filesystem mutation/write receipt.
    FsWrite(WorkloadFsWriteReceipt),
    /// A network fetch receipt ("http__fetch").
    NetFetch(WorkloadNetFetchReceipt),
    /// A governed web retrieval receipt ("web__search" / "web__read").
    WebRetrieve(WorkloadWebRetrieveReceipt),
    /// A legacy-named governed memory retrieval receipt ("memory__search" / retrieval pipelines).
    MemoryRetrieve(WorkloadMemoryRetrieveReceipt),
    /// A first-party inference receipt for text generation, embeddings, rerank, or classification.
    Inference(crate::app::WorkloadInferenceReceipt),
    /// A first-party media receipt for transcription, TTS, vision, image, or video workloads.
    Media(crate::app::WorkloadMediaReceipt),
    /// A first-party model and backend lifecycle receipt.
    ModelLifecycle(crate::app::WorkloadModelLifecycleReceipt),
    /// A first-party child-worker completion and merge receipt.
    Worker(crate::app::WorkloadWorkerReceipt),
    /// A first-party parent-playbook lifecycle receipt.
    ParentPlaybook(crate::app::WorkloadParentPlaybookReceipt),
    /// A generic external adapter receipt.
    Adapter(crate::app::AdapterReceipt),
}

/// Audit receipt for an `Exec` workload.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct WorkloadExecReceipt {
    /// Tool that initiated the workload (e.g. "shell__run").
    pub tool_name: String,
    /// Executed command.
    pub command: String,
    /// Executed argv args.
    pub args: Vec<String>,
    /// Working directory used for execution (resolved/canonical where possible).
    pub cwd: String,
    /// Whether the process was detached.
    pub detach: bool,
    /// Timeout applied (milliseconds).
    pub timeout_ms: u64,
    /// Success flag as surfaced by the executor.
    pub success: bool,
    /// Optional exit code when available.
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// Optional error class when failure output includes an `ERROR_CLASS=...` prefix.
    #[serde(default)]
    pub error_class: Option<String>,
    /// Human-friendly preview string (for UI correlation).
    pub command_preview: String,
}

/// Audit receipt for filesystem mutation/write workloads.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct WorkloadFsWriteReceipt {
    /// Tool that initiated the filesystem mutation.
    pub tool_name: String,
    /// Operation label (e.g. "write_file", "patch", "create_directory", "move", "copy", "delete", "create_zip").
    pub operation: String,
    /// Primary target path for the operation (scrubbed when policy requires).
    pub target_path: String,
    /// Optional secondary/destination path.
    #[serde(default)]
    pub destination_path: Option<String>,
    /// Optional bytes written/produced when known.
    #[serde(default)]
    pub bytes_written: Option<u64>,
    /// Success flag as surfaced by the executor.
    pub success: bool,
    /// Optional error class when failure output includes an `ERROR_CLASS=...` prefix.
    #[serde(default)]
    pub error_class: Option<String>,
}

/// Audit receipt for a `http__fetch` workload.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct WorkloadNetFetchReceipt {
    /// Tool that initiated the workload (always "http__fetch" for this receipt).
    pub tool_name: String,
    /// HTTP method (currently "GET").
    pub method: String,
    /// Redacted request URL for receipts (query/fragment/userinfo removed; scrubbed if configured).
    pub requested_url: String,
    /// Redacted final URL after redirects (query/fragment/userinfo removed; scrubbed if configured).
    #[serde(default)]
    pub final_url: Option<String>,
    /// HTTP status code when a response was received.
    #[serde(default)]
    pub status_code: Option<u32>,
    /// Response content-type when available.
    #[serde(default)]
    pub content_type: Option<String>,
    /// Max character budget requested.
    pub max_chars: u32,
    /// Max byte budget enforced while reading the body.
    pub max_bytes: u64,
    /// Bytes actually read into the buffer (post truncation-by-bytes).
    pub bytes_read: u64,
    /// True if output was truncated by bytes or chars.
    pub truncated: bool,
    /// Timeout applied (milliseconds).
    pub timeout_ms: u64,
    /// Success flag (request+read+serialization succeeded; independent of HTTP status).
    pub success: bool,
    /// Optional error class when failure output includes an `ERROR_CLASS=...` prefix.
    #[serde(default)]
    pub error_class: Option<String>,
}

/// Audit receipt for `web__search` / `web__read` workloads.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct WorkloadWebRetrieveReceipt {
    /// Tool that initiated the workload ("web__search" or "web__read").
    pub tool_name: String,
    /// Retrieval backend identifier (e.g. "edge:ddg", "edge:read").
    pub backend: String,
    /// Optional scrubbed search query (for `web__search`).
    #[serde(default)]
    pub query: Option<String>,
    /// Optional redacted/scrubbed URL (for `web__read`).
    #[serde(default)]
    pub url: Option<String>,
    /// Optional search limit applied (for `web__search`).
    #[serde(default)]
    pub limit: Option<u32>,
    /// Optional max character budget applied (for `web__read`).
    #[serde(default)]
    pub max_chars: Option<u32>,
    /// Number of sources returned on success.
    pub sources_count: u32,
    /// Number of documents returned on success.
    pub documents_count: u32,
    /// Success flag (retrieve + serialization succeeded).
    pub success: bool,
    /// Optional error class when failure output includes an `ERROR_CLASS=...` prefix.
    #[serde(default)]
    pub error_class: Option<String>,
}

/// Audit receipt for `memory__search` retrieval workloads.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct WorkloadMemoryRetrieveReceipt {
    /// Tool that initiated the retrieval workload.
    pub tool_name: String,
    /// Retrieval backend identifier (e.g. "memory:sqlite+semantic").
    pub backend: String,
    /// Hash of query bytes used for retrieval.
    pub query_hash: String,
    /// Hex root commitment of the index used for retrieval.
    pub index_root: String,
    /// Requested top-k.
    pub k: u32,
    /// ANN exploration budget.
    pub ef_search: u32,
    /// Candidate rerank hard cap.
    pub candidate_limit: u32,
    /// Number of ANN candidates prior to truncation.
    pub candidate_count_total: u32,
    /// Number of candidates reranked.
    pub candidate_count_reranked: u32,
    /// Whether candidate set was truncated deterministically.
    pub candidate_truncated: bool,
    /// Rerank metric label.
    pub distance_metric: String,
    /// Embedding normalization policy.
    pub embedding_normalized: bool,
    /// Optional content-addressed pointer to proof blob.
    #[serde(default)]
    pub proof_ref: Option<String>,
    /// Optional proof hash commitment.
    #[serde(default)]
    pub proof_hash: Option<String>,
    /// Retrieval certificate mode (single-level contract: "single_level_lb").
    #[serde(default)]
    pub certificate_mode: Option<String>,
    /// Success flag as surfaced by the retriever.
    pub success: bool,
    /// Optional error class when retrieval fails.
    #[serde(default)]
    pub error_class: Option<String>,
}

/// Audit receipt for child-worker completion and deterministic parent merge.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct WorkloadWorkerReceipt {
    /// Tool that initiated the worker flow ("agent__delegate" or "agent__await").
    pub tool_name: String,
    /// Phase label ("completed" or "merged").
    pub phase: String,
    /// Child session id in hex format.
    pub child_session_id: String,
    /// Parent session id in hex format.
    pub parent_session_id: String,
    /// Human-readable worker role.
    pub role: String,
    /// Optional higher-order parent playbook id coordinating this delegation sequence.
    #[serde(default)]
    pub playbook_id: Option<String>,
    /// Optional template id when the worker was spawned from a named archetype.
    #[serde(default)]
    pub template_id: Option<String>,
    /// Optional playbook id when the worker was spawned from a template workflow.
    #[serde(default)]
    pub workflow_id: Option<String>,
    /// Deterministic merge mode label.
    pub merge_mode: String,
    /// Terminal worker status string.
    pub status: String,
    /// Success flag for the child worker lifecycle.
    pub success: bool,
    /// Human-readable summary or merged handoff preview.
    pub summary: String,
    /// Optional verification hint carried from the worker contract.
    #[serde(default)]
    pub verification_hint: Option<String>,
    /// Optional error class when worker completion failed.
    #[serde(default)]
    pub error_class: Option<String>,
}

/// Research-specific verifier scorecard surfaced through parent-playbook receipts.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
pub struct ResearchVerificationScorecard {
    /// Overall verifier verdict for the research brief.
    pub verdict: String,
    /// Distinct cited source count observed in the research brief.
    pub source_count: u32,
    /// Distinct cited domain count observed in the research brief.
    pub distinct_domain_count: u32,
    /// Whether the route met the minimum cited-source floor.
    pub source_count_floor_met: bool,
    /// Whether the route met the minimum independent-domain floor.
    pub source_independence_floor_met: bool,
    /// Freshness verifier status ("passed", "needs_attention", "blocked", "unknown").
    pub freshness_status: String,
    /// Quote-grounding verifier status ("passed", "needs_attention", "blocked", "unknown").
    pub quote_grounding_status: String,
    /// Optional compact verifier note.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Computer-use perception summary surfaced through parent-playbook receipts.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
pub struct ComputerUsePerceptionSummary {
    /// Whether the current UI state was clearly observed.
    pub surface_status: String,
    /// Compact statement of what the system thinks the UI currently is.
    pub ui_state: String,
    /// Optional likely target or missing prerequisite surfaced by perception.
    #[serde(default)]
    pub target: Option<String>,
    /// Approval risk assessment before execution begins.
    pub approval_risk: String,
    /// Optional next safe action suggested by the perception pass.
    #[serde(default)]
    pub next_action: Option<String>,
    /// Optional compact note about ambiguities or blockers.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Coding-specific verifier scorecard surfaced through parent-playbook receipts.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
pub struct CodingVerificationScorecard {
    /// Overall verifier verdict for the targeted coding verification pass.
    pub verdict: String,
    /// Number of targeted verification commands the route expected to check.
    pub targeted_command_count: u32,
    /// Number of targeted verification commands reported as passing.
    pub targeted_pass_count: u32,
    /// Whether the verifier had to widen beyond targeted checks.
    pub widening_status: String,
    /// Whether the verifier found regression risk in the widened or targeted pass.
    pub regression_status: String,
    /// Optional compact verifier note.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Artifact-generation summary surfaced through parent-playbook receipts.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
pub struct ArtifactGenerationSummary {
    /// Overall handoff status for the generation pass.
    pub status: String,
    /// Number of produced files named in the generation handoff.
    pub produced_file_count: u32,
    /// Whether the generator retained verification signals for the artifact.
    pub verification_signal_status: String,
    /// Whether the generator believes the artifact is presentation-ready or still open.
    pub presentation_status: String,
    /// Optional compact generation note.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Computer-use verification scorecard surfaced through parent-playbook receipts.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
pub struct ComputerUseVerificationScorecard {
    /// Overall verifier verdict for the computer-use postcondition audit.
    pub verdict: String,
    /// Whether the claimed browser postcondition currently holds.
    pub postcondition_status: String,
    /// Approval state observed during execution or verification.
    pub approval_state: String,
    /// Whether the route needs no recovery, a recommended retry, or is blocked.
    pub recovery_status: String,
    /// Optional observed postcondition carried forward from the executor handoff.
    #[serde(default)]
    pub observed_postcondition: Option<String>,
    /// Optional compact verifier note.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Artifact-quality scorecard surfaced through parent-playbook receipts.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
pub struct ArtifactQualityScorecard {
    /// Overall verdict for the artifact quality audit.
    pub verdict: String,
    /// Whether the artifact stayed faithful to the requested brief.
    pub fidelity_status: String,
    /// Whether the artifact is ready for presentation or still needs repair.
    pub presentation_status: String,
    /// Whether repair is unnecessary, recommended, required, or blocked.
    pub repair_status: String,
    /// Optional compact validation note.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Patch-synthesis summary surfaced through parent-playbook receipts.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
pub struct PatchSynthesisSummary {
    /// Overall synthesis state for the final patch handoff.
    pub status: String,
    /// Distinct touched file count carried into the synthesized handoff.
    pub touched_file_count: u32,
    /// Whether the synthesis pass accepted the verifier result as ready.
    pub verification_ready: bool,
    /// Optional compact synthesis note.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Artifact-repair summary surfaced through parent-playbook receipts.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
pub struct ArtifactRepairSummary {
    /// Repair state derived from generator and validation evidence.
    pub status: String,
    /// Optional reason for the chosen repair path.
    #[serde(default)]
    pub reason: Option<String>,
    /// Optional next safe step for the operator or planner.
    #[serde(default)]
    pub next_step: Option<String>,
}

/// Computer-use recovery summary surfaced through parent-playbook receipts.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
pub struct ComputerUseRecoverySummary {
    /// Recovery state derived from executor and verifier evidence.
    pub status: String,
    /// Optional reason for the chosen recovery path.
    #[serde(default)]
    pub reason: Option<String>,
    /// Optional next safe step for the operator or planner.
    #[serde(default)]
    pub next_step: Option<String>,
}

/// Audit receipt for parent-playbook lifecycle, step advancement, and terminal outcome.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct WorkloadParentPlaybookReceipt {
    /// Tool that initiated the playbook lifecycle edge ("agent__delegate" or "agent__await").
    pub tool_name: String,
    /// Phase label ("started", "step_spawned", "step_completed", "blocked", "completed").
    pub phase: String,
    /// Parent session id in hex format.
    pub parent_session_id: String,
    /// Stable parent playbook id.
    pub playbook_id: String,
    /// Human-readable playbook label.
    pub playbook_label: String,
    /// Terminal or current playbook status label.
    pub status: String,
    /// Whether the parent playbook lifecycle edge succeeded.
    pub success: bool,
    /// Optional step id associated with this lifecycle edge.
    #[serde(default)]
    pub step_id: Option<String>,
    /// Optional step label associated with this lifecycle edge.
    #[serde(default)]
    pub step_label: Option<String>,
    /// Optional child session id in hex format for step-bound phases.
    #[serde(default)]
    pub child_session_id: Option<String>,
    /// Optional worker template id for the active step.
    #[serde(default)]
    pub template_id: Option<String>,
    /// Optional worker workflow id for the active step.
    #[serde(default)]
    pub workflow_id: Option<String>,
    /// Explicit workload family for the selected higher-order route.
    pub route_family: String,
    /// Explicit topology label for the selected higher-order route.
    pub topology: String,
    /// Explicit planner-of-record authority for the higher-order route.
    #[serde(default)]
    pub planner_authority: String,
    /// Explicit verifier lifecycle state for the higher-order route.
    pub verifier_state: String,
    /// Explicit verifier role for the higher-order route when verification is part of the contract.
    #[serde(default)]
    pub verifier_role: String,
    /// Explicit bounded verifier outcome when a verifier produced a terminal result.
    #[serde(default)]
    pub verifier_outcome: String,
    /// Selected skill names surfaced during route preparation.
    #[serde(default)]
    pub selected_skills: Vec<String>,
    /// Human-readable summary of recalled context prepared before the step spawn.
    #[serde(default)]
    pub prep_summary: Option<String>,
    /// Optional artifact-generation summary emitted by artifact-builder routes.
    #[serde(default)]
    pub artifact_generation: Option<ArtifactGenerationSummary>,
    /// Optional computer-use perception summary emitted by UI-state observation routes.
    #[serde(default)]
    pub computer_use_perception: Option<ComputerUsePerceptionSummary>,
    /// Optional research-specific scorecard emitted by citation-verifier routes.
    #[serde(default)]
    pub research_scorecard: Option<ResearchVerificationScorecard>,
    /// Optional artifact-quality scorecard emitted by artifact validation routes.
    #[serde(default)]
    pub artifact_quality: Option<ArtifactQualityScorecard>,
    /// Optional computer-use verification scorecard emitted by browser verifier routes.
    #[serde(default)]
    pub computer_use_verification: Option<ComputerUseVerificationScorecard>,
    /// Optional coding-specific scorecard emitted by targeted-test verifier routes.
    #[serde(default)]
    pub coding_scorecard: Option<CodingVerificationScorecard>,
    /// Optional coding patch-synthesis summary emitted by synthesis routes.
    #[serde(default)]
    pub patch_synthesis: Option<PatchSynthesisSummary>,
    /// Optional artifact-repair summary emitted by artifact generation or validation routes.
    #[serde(default)]
    pub artifact_repair: Option<ArtifactRepairSummary>,
    /// Optional computer-use recovery summary emitted by browser execution or verification routes.
    #[serde(default)]
    pub computer_use_recovery: Option<ComputerUseRecoverySummary>,
    /// Human-readable summary or block reason.
    pub summary: String,
    /// Optional error class when the parent playbook blocks or fails.
    #[serde(default)]
    pub error_class: Option<String>,
}

/// A unified event type representing observable state changes within the Kernel.
/// These events are streamed to the UI (Autopilot) to provide visual feedback
/// and "Visual Sovereignty".
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode)]
pub enum KernelEvent {
    /// The agent "thought" or took a step (Thought -> Action -> Output).
    AgentStep(StepTrace),

    /// Streaming thought token from the inference engine.
    /// This allows the UI to render the agent's internal monologue character-by-character.
    AgentThought {
        /// The unique session ID this thought belongs to.
        session_id: [u8; 32],
        /// The partial text content (token) generated by the LLM.
        token: String,
    },

    /// The Agency Firewall intercepted an action.
    FirewallInterception {
        /// The decision made ("BLOCK", "REQUIRE_APPROVAL", "ALLOW").
        verdict: String,
        /// The target capability (e.g., "net::fetch").
        target: String,
        /// The hash of the ActionRequest, used for signing ApprovalTokens.
        request_hash: [u8; 32],
        /// The session ID associated with this interception (if available).
        session_id: Option<[u8; 32]>,
    },

    /// The user performed a physical input while in Ghost Mode (Recording).
    GhostInput {
        /// The input device ("mouse", "keyboard").
        device: String,
        /// Human-readable description of the input (e.g., "Click(100, 200)").
        description: String,
    },

    /// A new block was committed to the local chain state.
    BlockCommitted {
        /// The height of the committed block.
        height: u64,
        /// The number of transactions included in the block.
        tx_count: u64,
    },

    /// The result of an agent action execution.
    AgentActionResult {
        /// The session ID the action belongs to.
        session_id: [u8; 32],
        /// The sequence number of the step.
        step_index: u32,
        /// The name of the tool executed (e.g. "shell__run").
        tool_name: String,
        /// The output/result of the execution (e.g. stdout).
        output: String,
        /// Typed execution classification for failures when available.
        #[serde(default)]
        error_class: Option<String>,
        /// [NEW] The authoritative lifecycle state after this action.
        /// e.g. "Running", "Paused", "Completed", "Failed".
        agent_status: String,
    },

    /// Structured workload activity stream for orchestration and replay.
    WorkloadActivity(WorkloadActivityEvent),

    /// Deterministic workload receipt stream (exec/fs/net).
    WorkloadReceipt(WorkloadReceiptEvent),

    /// A fully typed per-action routing receipt from the Parity Router.
    RoutingReceipt(RoutingReceiptEvent),

    /// [NEW] A new sub-agent was spawned (delegation).
    AgentSpawn {
        /// The session ID of the parent agent initiating the delegation.
        parent_session_id: [u8; 32],
        /// The unique session ID for the new child agent.
        new_session_id: [u8; 32],
        /// The human-readable name of the agent (e.g., "Researcher-1").
        name: String,
        /// The specialized role of the agent (e.g., "Browser", "Coder").
        role: String,
        /// The initial budget allocated to this agent (Labor Gas).
        budget: u64,
        /// The specific goal assigned to this agent.
        goal: String,
    },

    /// [NEW] A system-level component status update (e.g. Optimizer, P2P).
    SystemUpdate {
        /// The component identifier (e.g., "Optimizer", "P2P").
        component: String,
        /// The status message or value.
        status: String,
    },

    /// Receipt emitted when the PII firewall pipeline reaches a deterministic decision.
    PiiDecisionReceipt(PiiDecisionReceiptEvent),

    /// Canonical review request emitted when PII flow requires approval.
    PiiReviewRequested {
        /// Deterministic decision hash key.
        decision_hash: [u8; 32],
        /// Canonical deterministic decision material.
        material: PiiDecisionMaterial,
        /// Human-readable summary for review UI.
        summary: PiiReviewSummary,
        /// Governance deadline in milliseconds since UNIX epoch.
        deadline_ms: u64,
        /// Session this request belongs to when available.
        session_id: Option<[u8; 32]>,
    },

    /// Receipt emitted when the global intent resolver classifies a step/action.
    IntentResolutionReceipt(IntentResolutionReceiptEvent),
    /// CEC execution-contract receipt for lifecycle evidence and completion gating.
    ExecutionContractReceipt(ExecutionContractReceiptEvent),
    /// Receipt emitted when planner synthesis commits to an execution plan.
    PlanReceipt(PlanReceiptEvent),
}

#[cfg(test)]
mod tests {
    use super::PiiDecisionReceiptEvent;

    #[test]
    fn pii_decision_receipt_event_back_compat_defaults() {
        let legacy_json = r#"{
            "session_id": null,
            "target": "clipboard::write",
            "target_id": null,
            "risk_surface": "egress",
            "decision_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "decision": "allow",
            "transform_plan_id": null,
            "span_count": 0,
            "ambiguous": false,
            "stage2_kind": null
        }"#;

        let parsed: PiiDecisionReceiptEvent =
            serde_json::from_str(legacy_json).expect("legacy pii receipt event");
        assert!(!parsed.assist_invoked);
        assert!(!parsed.assist_applied);
        assert_eq!(parsed.assist_kind, "");
        assert_eq!(parsed.assist_version, "");
        assert_eq!(parsed.assist_identity_hash, [0u8; 32]);
        assert_eq!(parsed.assist_input_graph_hash, [0u8; 32]);
        assert_eq!(parsed.assist_output_graph_hash, [0u8; 32]);
        assert!(parsed.target_id.is_none());
    }
}
