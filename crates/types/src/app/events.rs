// Path: crates/types/src/app/events.rs

use crate::app::agentic::StepTrace;
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

    /// Live stdout/stderr/status activity for a running process tool.
    ProcessActivity {
        /// The session ID the process belongs to.
        session_id: [u8; 32],
        /// The sequence number of the step.
        step_index: u32,
        /// The tool currently running (for example "sys__install_package").
        tool_name: String,
        /// Stable ID for stream correlation within a step.
        stream_id: String,
        /// Stream channel ("stdout", "stderr", "status").
        channel: String,
        /// Stream chunk payload.
        chunk: String,
        /// Monotonic sequence number for chunk ordering.
        seq: u64,
        /// Marks terminal chunk for this stream.
        is_final: bool,
        /// Exit code when available.
        exit_code: Option<i32>,
        /// User-friendly command preview.
        command_preview: String,
    },

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
}
