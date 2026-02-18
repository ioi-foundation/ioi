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
    /// Optional SCS lineage pointer for skill/trace provenance.
    pub scs_lineage_ptr: Option<String>,
    /// Optional SCS mutation receipt pointer for RSI lineage.
    pub mutation_receipt_ptr: Option<String>,
    /// Canonical hash binding `intent_hash` and `policy_decision`.
    pub policy_binding_hash: String,
    /// Optional signature over `policy_binding_hash` for non-repudiation.
    pub policy_binding_sig: Option<String>,
    /// Optional signer public key (hex-encoded protobuf bytes).
    pub policy_binding_signer: Option<String>,
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
    /// Session this resolution belongs to.
    pub session_id: Option<[u8; 32]>,
    /// Canonical winning intent id.
    pub intent_id: String,
    /// Ontological scope selected for this step.
    pub scope: IntentScopeProfile,
    /// Confidence band used for downstream policy.
    pub band: IntentConfidenceBand,
    /// Winning confidence score in [0.0, 1.0].
    pub score: f32,
    /// Ranked top-k candidates for diagnostics.
    #[serde(default)]
    pub top_k: Vec<IntentCandidateScore>,
    /// Preferred tier selected from the matrix profile.
    pub preferred_tier: String,
    /// Matrix version used for this decision.
    pub matrix_version: String,
    /// Hash commitment to the active matrix source.
    pub matrix_source_hash: [u8; 32],
    /// Deterministic receipt hash over resolution material.
    pub receipt_hash: [u8; 32],
    /// Deprecated/compat: always false (constrained mode removed).
    #[serde(default)]
    pub constrained: bool,
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
    /// A network fetch receipt ("net__fetch").
    NetFetch(WorkloadNetFetchReceipt),
    /// A governed web retrieval receipt ("web__search" / "web__read").
    WebRetrieve(WorkloadWebRetrieveReceipt),
}

/// Audit receipt for an `Exec` workload.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct WorkloadExecReceipt {
    /// Tool that initiated the workload (e.g. "sys__exec").
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

/// Audit receipt for a `net__fetch` workload.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct WorkloadNetFetchReceipt {
    /// Tool that initiated the workload (always "net__fetch" for this receipt).
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
        /// The name of the tool executed (e.g. "sys__exec").
        tool_name: String,
        /// The output/result of the execution (e.g. stdout).
        output: String,
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
