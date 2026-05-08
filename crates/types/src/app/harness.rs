#![allow(missing_docs)]

use crate::app::action::ActionTarget;
use crate::app::adapter::AdapterKind;
use crate::app::events::{
    ExecutionContractReceiptEvent, PlanReceiptEvent, RoutingReceiptEvent, WorkloadReceipt,
    WorkloadReceiptEvent,
};
use parity_scale_codec::{Decode, Encode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

pub const DEFAULT_AGENT_HARNESS_WORKFLOW_ID: &str = "default-agent-harness";
pub const DEFAULT_AGENT_HARNESS_VERSION: &str = "2026.04.default-harness.v1";
pub const DEFAULT_AGENT_HARNESS_HASH: &str = "sha256:default-agent-harness-component-projection-v1";
pub const DEFAULT_AGENT_HARNESS_ACTIVATION_ID: &str =
    "activation:default-agent-harness:blessed-readonly";
pub const DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS: u64 = 5 * 60 * 1000;

pub const HARNESS_COMPONENT_VERSION_V1: &str = "1.0.0";
pub const HARNESS_INPUT_SCHEMA_ID: &str = "ioi.agent-harness.input.v1";
pub const HARNESS_OUTPUT_SCHEMA_ID: &str = "ioi.agent-harness.output.v1";
pub const HARNESS_ERROR_SCHEMA_ID: &str = "ioi.agent-harness.error.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessExecutionMode {
    Projection,
    Shadow,
    Gated,
    Live,
}

impl HarnessExecutionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Projection => "projection",
            Self::Shadow => "shadow",
            Self::Gated => "gated",
            Self::Live => "live",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessComponentReadiness {
    ProjectionOnly,
    Simulated,
    ShadowReady,
    LiveReady,
}

impl HarnessComponentReadiness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProjectionOnly => "projection_only",
            Self::Simulated => "simulated",
            Self::ShadowReady => "shadow_ready",
            Self::LiveReady => "live_ready",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessReplayDeterminism {
    Deterministic,
    Nondeterministic,
    Redacted,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessReplayEnvelope {
    pub deterministic_envelope: bool,
    pub captures_input: bool,
    pub captures_output: bool,
    pub captures_policy_decision: bool,
    pub fixture_ref: Option<String>,
    pub determinism: HarnessReplayDeterminism,
    pub nondeterminism_reason: Option<String>,
    pub redaction_policy: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessNodeAttemptStatus {
    Projection,
    Shadow,
    Gated,
    Live,
    Succeeded,
    Failed,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessNodeAttemptRecord {
    pub attempt_id: String,
    pub harness_workflow_id: String,
    pub harness_activation_id: String,
    pub harness_hash: String,
    pub workflow_node_id: String,
    pub component_id: String,
    pub component_kind: HarnessComponentKind,
    pub execution_mode: HarnessExecutionMode,
    pub readiness: HarnessComponentReadiness,
    pub attempt_index: u32,
    pub status: HarnessNodeAttemptStatus,
    pub input_hash: Option<String>,
    pub output_hash: Option<String>,
    pub error_class: Option<String>,
    pub policy_decision: Option<String>,
    pub started_at_ms: Option<u64>,
    pub duration_ms: Option<u64>,
    pub receipt_ids: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub replay: HarnessReplayEnvelope,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessDivergenceClass {
    None,
    HarmlessMetadata,
    MissingReceipt,
    PolicyDivergence,
    RoutingDivergence,
    OutputDivergence,
    BehavioralRegression,
    Unclassified,
}

impl HarnessDivergenceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HarmlessMetadata => "harmless_metadata",
            Self::MissingReceipt => "missing_receipt",
            Self::PolicyDivergence => "policy_divergence",
            Self::RoutingDivergence => "routing_divergence",
            Self::OutputDivergence => "output_divergence",
            Self::BehavioralRegression => "behavioral_regression",
            Self::Unclassified => "unclassified",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessShadowComparison {
    pub workflow_node_id: String,
    pub component_kind: HarnessComponentKind,
    pub live_attempt_id: String,
    pub shadow_attempt_id: String,
    pub divergence: HarnessDivergenceClass,
    pub blocking: bool,
    pub summary: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessShadowRun {
    pub schema_version: String,
    pub run_id: String,
    pub harness_workflow_id: String,
    pub harness_activation_id: String,
    pub harness_hash: String,
    pub source_session_id: Option<String>,
    pub live_turn_id: Option<String>,
    pub execution_mode: HarnessExecutionMode,
    pub node_attempts: Vec<HarnessNodeAttemptRecord>,
    pub comparisons: Vec<HarnessShadowComparison>,
    pub blocking_divergence_count: u32,
    pub unclassified_divergence_count: u32,
    pub promotion_blocked: bool,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessPromotionClusterId {
    Cognition,
    RoutingModel,
    VerificationOutput,
    AuthorityTooling,
}

impl HarnessPromotionClusterId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cognition => "cognition",
            Self::RoutingModel => "routing_model",
            Self::VerificationOutput => "verification_output",
            Self::AuthorityTooling => "authority_tooling",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Cognition => "Cognition",
            Self::RoutingModel => "Routing and model",
            Self::VerificationOutput => "Verification and output",
            Self::AuthorityTooling => "Authority and tooling",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessClusterPromotionStatus {
    ShadowReady,
    Gated,
    Blocked,
    Live,
}

impl HarnessClusterPromotionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShadowReady => "shadow_ready",
            Self::Gated => "gated",
            Self::Blocked => "blocked",
            Self::Live => "live",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessPromotionCluster {
    pub cluster_id: HarnessPromotionClusterId,
    pub label: String,
    pub activation_order: u32,
    pub component_kinds: Vec<HarnessComponentKind>,
    pub required_execution_mode: HarnessExecutionMode,
    pub minimum_readiness: HarnessComponentReadiness,
    pub promotion_rule: String,
    pub rollback_target: String,
    pub blocks_live_activation: bool,
    pub promotion_status: HarnessClusterPromotionStatus,
    pub replay_gate_proof: Option<HarnessPromotionClusterReplayGateProof>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessPromotionClusterReplayGateStatus {
    NotRun,
    Passed,
    Blocked,
    Failed,
}

impl HarnessPromotionClusterReplayGateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotRun => "not_run",
            Self::Passed => "passed",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessActivationGateImpact {
    Pending,
    Passed,
    Blocked,
}

impl HarnessActivationGateImpact {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Passed => "passed",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessPromotionClusterReplayGateProof {
    pub schema_version: String,
    pub cluster_id: HarnessPromotionClusterId,
    pub gate_id: Option<String>,
    pub gate_status: HarnessPromotionClusterReplayGateStatus,
    pub activation_gate_impact: HarnessActivationGateImpact,
    pub total_fixtures: u32,
    pub passed_count: u32,
    pub blocked_count: u32,
    pub failed_count: u32,
    pub blocking_divergence_count: u32,
    pub replay_fixture_refs: Vec<String>,
    pub blocking_replay_fixture_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub blockers: Vec<String>,
    pub verified_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessGatedClusterRun {
    pub schema_version: String,
    pub run_id: String,
    pub cluster_id: HarnessPromotionClusterId,
    pub cluster_label: String,
    pub harness_workflow_id: String,
    pub harness_activation_id: String,
    pub harness_hash: String,
    pub execution_mode: HarnessExecutionMode,
    pub status: HarnessClusterPromotionStatus,
    pub component_kinds: Vec<HarnessComponentKind>,
    pub shadow_run_id: String,
    pub node_attempt_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub activation_blockers: Vec<String>,
    pub gate_decision: String,
    pub rollback_target: String,
    pub canary_status: String,
    pub promotion_blocked: bool,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessPromotionTransitionTarget {
    Gated,
    Live,
}

impl HarnessPromotionTransitionTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gated => "gated",
            Self::Live => "live",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessPromotionTransitionEligibility {
    pub schema_version: String,
    pub cluster_id: HarnessPromotionClusterId,
    pub target_execution_mode: HarnessPromotionTransitionTarget,
    pub current_status: HarnessClusterPromotionStatus,
    pub eligible: bool,
    pub readiness_ready: bool,
    pub receipt_ready: bool,
    pub replay_gate_ready: bool,
    pub canary_ready: bool,
    pub rollback_ready: bool,
    pub component_ids: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub canary_boundary_id: Option<String>,
    pub rollback_target: Option<String>,
    pub blockers: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessPromotionTransitionAttempt {
    pub schema_version: String,
    pub transition_id: String,
    pub workflow_id: String,
    pub activation_id: Option<String>,
    pub cluster_id: HarnessPromotionClusterId,
    pub cluster_label: String,
    pub target_execution_mode: HarnessPromotionTransitionTarget,
    pub previous_status: HarnessClusterPromotionStatus,
    pub next_status: HarnessClusterPromotionStatus,
    pub attempt_status: String,
    pub gate_decision: String,
    pub eligibility: HarnessPromotionTransitionEligibility,
    pub blockers: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub created_at_ms: u64,
}

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum HarnessComponentKind {
    Planner,
    PromptAssembler,
    TaskState,
    UncertaintyGate,
    ProbeRunner,
    BudgetGate,
    CapabilitySequencer,
    ModelRouter,
    ModelCall,
    ToolRouter,
    ToolCall,
    DryRunSimulator,
    McpProvider,
    McpToolCall,
    ConnectorCall,
    PolicyGate,
    ApprovalGate,
    WalletCapability,
    MemoryRead,
    MemoryWrite,
    SemanticImpactAnalyzer,
    PostconditionSynthesizer,
    Verifier,
    DriftDetector,
    OutputWriter,
    ReceiptWriter,
    QualityLedger,
    RetryPolicy,
    RepairLoop,
    MergeJudge,
    HandoffBridge,
    CompletionGate,
    GuiHarnessValidator,
}

impl HarnessComponentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planner => "planner",
            Self::PromptAssembler => "prompt_assembler",
            Self::TaskState => "task_state",
            Self::UncertaintyGate => "uncertainty_gate",
            Self::ProbeRunner => "probe_runner",
            Self::BudgetGate => "budget_gate",
            Self::CapabilitySequencer => "capability_sequencer",
            Self::ModelRouter => "model_router",
            Self::ModelCall => "model_call",
            Self::ToolRouter => "tool_router",
            Self::ToolCall => "tool_call",
            Self::DryRunSimulator => "dry_run_simulator",
            Self::McpProvider => "mcp_provider",
            Self::McpToolCall => "mcp_tool_call",
            Self::ConnectorCall => "connector_call",
            Self::PolicyGate => "policy_gate",
            Self::ApprovalGate => "approval_gate",
            Self::WalletCapability => "wallet_capability",
            Self::MemoryRead => "memory_read",
            Self::MemoryWrite => "memory_write",
            Self::SemanticImpactAnalyzer => "semantic_impact_analyzer",
            Self::PostconditionSynthesizer => "postcondition_synthesizer",
            Self::Verifier => "verifier",
            Self::DriftDetector => "drift_detector",
            Self::OutputWriter => "output_writer",
            Self::ReceiptWriter => "receipt_writer",
            Self::QualityLedger => "quality_ledger",
            Self::RetryPolicy => "retry_policy",
            Self::RepairLoop => "repair_loop",
            Self::MergeJudge => "merge_judge",
            Self::HandoffBridge => "handoff_bridge",
            Self::CompletionGate => "completion_gate",
            Self::GuiHarnessValidator => "gui_harness_validator",
        }
    }

    pub fn component_id(self) -> String {
        format!("ioi.agent-harness.{}.v1", self.as_str())
    }

    pub fn workflow_node_id(self) -> String {
        format!("harness.{}", self.as_str())
    }

    pub fn kernel_ref(self) -> &'static str {
        match self {
            Self::Planner => "crates/services/src/agentic/runtime/service/planning/planner",
            Self::PromptAssembler => {
                "crates/types/src/app/runtime_contracts.rs::PromptAssemblyContract"
            }
            Self::TaskState => "crates/types/src/app/runtime_contracts.rs::TaskStateModel",
            Self::UncertaintyGate => {
                "crates/types/src/app/runtime_contracts.rs::UncertaintyAssessment"
            }
            Self::ProbeRunner => "crates/types/src/app/runtime_contracts.rs::Probe",
            Self::BudgetGate => "crates/types/src/app/runtime_contracts.rs::CognitiveBudget",
            Self::CapabilitySequencer => {
                "crates/types/src/app/runtime_contracts.rs::CapabilitySequence"
            }
            Self::ModelRouter => "crates/services/src/agentic/runtime/service/decision_loop/cognition/router.rs",
            Self::ModelCall => "crates/services/src/agentic/runtime/service/handler/execution/handlers/model.rs",
            Self::ToolRouter => "crates/services/src/agentic/runtime/service/handler/execution/execution/action_execution.rs",
            Self::ToolCall => "crates/services/src/agentic/runtime/service/handler/execution",
            Self::DryRunSimulator => {
                "crates/types/src/app/runtime_contracts.rs::DryRunCapability"
            }
            Self::McpProvider => "crates/services/src/agentic/runtime/tools/mcp.rs",
            Self::McpToolCall => "crates/services/src/agentic/runtime/tools/mcp.rs",
            Self::ConnectorCall => "crates/services/src/agentic/runtime/connectors",
            Self::PolicyGate => "crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs",
            Self::ApprovalGate => "crates/services/src/agentic/runtime/service/handler/approvals.rs",
            Self::WalletCapability => "crates/services/src/agentic/runtime/kernel/capability.rs",
            Self::MemoryRead | Self::MemoryWrite => "crates/services/src/agentic/runtime/service/memory",
            Self::SemanticImpactAnalyzer => {
                "crates/types/src/app/runtime_contracts.rs::SemanticImpactAnalysis"
            }
            Self::PostconditionSynthesizer => {
                "crates/types/src/app/runtime_contracts.rs::PostconditionSynthesis"
            }
            Self::Verifier => "crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs",
            Self::DriftDetector => "crates/types/src/app/runtime_contracts.rs::DriftSignal",
            Self::OutputWriter => "crates/services/src/agentic/runtime/service/queue/processing/completion_receipts.rs",
            Self::ReceiptWriter => "crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs",
            Self::QualityLedger => "crates/types/src/app/runtime_contracts.rs::AgentQualityLedger",
            Self::RetryPolicy => "crates/services/src/agentic/runtime/service/recovery/anti_loop",
            Self::RepairLoop => "crates/services/src/agentic/runtime/service/tool_execution/processing/repair",
            Self::MergeJudge => "crates/services/src/agentic/runtime/service/lifecycle/worker_results/merge.rs",
            Self::HandoffBridge => "crates/types/src/app/runtime_contracts.rs::HandoffQuality",
            Self::CompletionGate => "crates/services/src/agentic/runtime/service/visual_loop/browser_completion.rs",
            Self::GuiHarnessValidator => {
                "crates/types/src/app/runtime_contracts.rs::AutopilotGuiHarnessValidationContract"
            }
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Planner => "Planner",
            Self::PromptAssembler => "Prompt assembler",
            Self::TaskState => "Task state model",
            Self::UncertaintyGate => "Uncertainty gate",
            Self::ProbeRunner => "Probe runner",
            Self::BudgetGate => "Cognitive budget gate",
            Self::CapabilitySequencer => "Capability sequencer",
            Self::ModelRouter => "Model router",
            Self::ModelCall => "Model call",
            Self::ToolRouter => "Tool router",
            Self::ToolCall => "Tool call",
            Self::DryRunSimulator => "Dry-run simulator",
            Self::McpProvider => "MCP provider",
            Self::McpToolCall => "MCP tool invocation",
            Self::ConnectorCall => "Connector call",
            Self::PolicyGate => "Policy and firewall gate",
            Self::ApprovalGate => "Approval gate",
            Self::WalletCapability => "Wallet capability request",
            Self::MemoryRead => "Memory read",
            Self::MemoryWrite => "Memory write",
            Self::SemanticImpactAnalyzer => "Semantic impact analyzer",
            Self::PostconditionSynthesizer => "Postcondition synthesizer",
            Self::Verifier => "Verifier",
            Self::DriftDetector => "Drift detector",
            Self::OutputWriter => "Output writer",
            Self::ReceiptWriter => "Receipt writer",
            Self::QualityLedger => "Quality ledger",
            Self::RetryPolicy => "Retry policy",
            Self::RepairLoop => "Repair loop",
            Self::MergeJudge => "Merge and judge",
            Self::HandoffBridge => "Handoff bridge",
            Self::CompletionGate => "Completion gate",
            Self::GuiHarnessValidator => "Autopilot GUI harness validator",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessSlotKind {
    StatePolicy,
    ModelPolicy,
    ToolGrantPolicy,
    BudgetPolicy,
    DryRunPolicy,
    VerifierPolicy,
    ApprovalPolicy,
    OutputPolicy,
    MemoryPolicy,
    QualityLedgerPolicy,
    RetryRepairPolicy,
    HandoffPolicy,
}

impl HarnessSlotKind {
    pub fn slot_id(self) -> &'static str {
        match self {
            Self::StatePolicy => "slot.state-policy",
            Self::ModelPolicy => "slot.model-policy",
            Self::ToolGrantPolicy => "slot.tool-grants",
            Self::BudgetPolicy => "slot.budget",
            Self::DryRunPolicy => "slot.dry-run",
            Self::VerifierPolicy => "slot.verifier",
            Self::ApprovalPolicy => "slot.approval",
            Self::OutputPolicy => "slot.output-policy",
            Self::MemoryPolicy => "slot.memory-policy",
            Self::QualityLedgerPolicy => "slot.quality-ledger",
            Self::RetryRepairPolicy => "slot.retry-repair",
            Self::HandoffPolicy => "slot.handoff",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessTimeoutBehavior {
    pub timeout_ms: u64,
    pub cancellation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessRetryBehavior {
    pub max_attempts: u32,
    pub backoff_ms: u64,
    pub retryable_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessApprovalSemantics {
    pub required: bool,
    pub mode: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessComponentSpec {
    pub component_id: String,
    pub version: String,
    pub kind: HarnessComponentKind,
    pub readiness: HarnessComponentReadiness,
    pub label: String,
    pub kernel_ref: String,
    pub input_schema: String,
    pub output_schema: String,
    pub error_schema: String,
    pub timeout: HarnessTimeoutBehavior,
    pub retry: HarnessRetryBehavior,
    pub required_capability_scope: Vec<String>,
    pub approval: HarnessApprovalSemantics,
    pub emitted_events: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessSlotSpec {
    pub slot_id: String,
    pub kind: HarnessSlotKind,
    pub label: String,
    pub required: bool,
    pub allowed_component_kinds: Vec<HarnessComponentKind>,
    pub default_component_id: String,
    pub blocks_activation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessActionFrame {
    pub workflow_id: String,
    pub workflow_version: String,
    pub workflow_hash: String,
    pub execution_mode: HarnessExecutionMode,
    pub node_id: String,
    pub component_id: String,
    pub component_version: String,
    pub component_kind: HarnessComponentKind,
    pub readiness: HarnessComponentReadiness,
    pub kernel_ref: String,
    pub slot_ids: Vec<String>,
    pub deterministic_envelope: bool,
    pub replay: HarnessReplayEnvelope,
    pub event_kinds: Vec<String>,
    pub evidence_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessComponentInvocation {
    pub invocation_id: String,
    pub component_kind: HarnessComponentKind,
    pub execution_mode: HarnessExecutionMode,
    pub attempt_index: u32,
    pub input_hash: Option<String>,
    pub output_hash: Option<String>,
    pub policy_decision: Option<String>,
    pub receipt_ids: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub replay_fixture_ref: Option<String>,
    pub started_at_ms: Option<u64>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessComponentAdapterResult {
    pub schema_version: String,
    pub invocation_id: String,
    pub action_frame: HarnessActionFrame,
    pub node_attempt: HarnessNodeAttemptRecord,
    pub slot_ids: Vec<String>,
    pub result_hash: Option<String>,
    pub error_class: Option<String>,
    pub readiness: HarnessComponentReadiness,
    pub receipt_ids: Vec<String>,
    pub replay: HarnessReplayEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessWorkerBinding {
    pub harness_workflow_id: String,
    pub harness_activation_id: Option<String>,
    pub harness_hash: String,
    pub execution_mode: HarnessExecutionMode,
    pub source: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessLiveHandoffSelector {
    LegacyRuntime,
    BlessedWorkflowGated,
    BlessedWorkflowLiveCanary,
    BlessedWorkflowLiveDefault,
}

impl HarnessLiveHandoffSelector {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegacyRuntime => "legacy_runtime",
            Self::BlessedWorkflowGated => "blessed_workflow_gated",
            Self::BlessedWorkflowLiveCanary => "blessed_workflow_live_canary",
            Self::BlessedWorkflowLiveDefault => "blessed_workflow_live_default",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessComponentVersionBinding {
    pub component_id: String,
    pub component_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessDefaultPromotionGate {
    pub config_key: String,
    pub enabled: bool,
    pub eligible: bool,
    pub non_mutating_only: bool,
    pub selector: HarnessLiveHandoffSelector,
    pub production_default_selector: HarnessLiveHandoffSelector,
    pub default_authority_transferred: bool,
    pub rollback_target: String,
    pub activation_blockers: Vec<String>,
    pub policy_decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessLiveHandoffProof {
    pub schema_version: String,
    pub selector: HarnessLiveHandoffSelector,
    pub available_selectors: Vec<HarnessLiveHandoffSelector>,
    pub production_default_selector: HarnessLiveHandoffSelector,
    pub workflow_id: String,
    pub activation_id: String,
    pub harness_hash: String,
    pub component_version_set: Vec<HarnessComponentVersionBinding>,
    pub canary_status: String,
    pub canary_turn_routed_through_workflow: bool,
    pub execution_boundary_id: String,
    pub execution_boundary_ids: Vec<String>,
    pub execution_boundary_cluster_ids: Vec<HarnessPromotionClusterId>,
    pub execution_boundary_status: String,
    pub execution_boundary_executor: String,
    pub default_authority_transferred: bool,
    pub runtime_authority: String,
    pub fallback_selector: HarnessLiveHandoffSelector,
    pub rollback_target: String,
    pub rollback_available: bool,
    pub policy_decision: String,
    pub gated_cluster_ids: Vec<HarnessPromotionClusterId>,
    pub node_timeline_attempt_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub activation_blockers: Vec<String>,
    pub default_promotion_gate: HarnessDefaultPromotionGate,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessRuntimeSelectorDecision {
    pub schema_version: String,
    pub decision_id: String,
    pub requested_selector: String,
    pub selected_selector: HarnessLiveHandoffSelector,
    pub production_default_selector: HarnessLiveHandoffSelector,
    pub canary_eligible: bool,
    pub canary_blockers: Vec<String>,
    pub workflow_id: String,
    pub activation_id: String,
    pub harness_hash: String,
    pub execution_mode: HarnessExecutionMode,
    pub actual_runtime_authority: String,
    pub fallback_selector: HarnessLiveHandoffSelector,
    pub rollback_target: String,
    pub rollback_available: bool,
    pub policy_decision: String,
    pub route_reason: String,
    pub default_promotion_gate: HarnessDefaultPromotionGate,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessDefaultRuntimeDispatchProof {
    pub schema_version: String,
    pub dispatch_id: String,
    pub selector_decision_id: String,
    pub selected_selector: HarnessLiveHandoffSelector,
    pub production_default_selector: HarnessLiveHandoffSelector,
    pub workflow_id: String,
    pub activation_id: String,
    pub harness_hash: String,
    pub execution_mode: HarnessExecutionMode,
    pub runtime_authority: String,
    pub dispatch_scope: String,
    pub accepted_cluster_ids: Vec<HarnessPromotionClusterId>,
    pub component_kinds: Vec<HarnessComponentKind>,
    pub deferred_component_kinds: Vec<HarnessComponentKind>,
    pub handoff_validated_component_kinds: Vec<HarnessComponentKind>,
    pub materialization_canary_component_kinds: Vec<HarnessComponentKind>,
    pub source_boundary_ids: Vec<String>,
    pub dispatch_node_attempt_ids: Vec<String>,
    pub cognition_execution_attempt_ids: Vec<String>,
    pub cognition_execution_receipt_ids: Vec<String>,
    pub cognition_execution_replay_fixture_refs: Vec<String>,
    pub model_execution_attempt_ids: Vec<String>,
    pub model_execution_receipt_ids: Vec<String>,
    pub model_execution_replay_fixture_refs: Vec<String>,
    pub model_provider_canary_attempt_ids: Vec<String>,
    pub model_provider_canary_receipt_ids: Vec<String>,
    pub model_provider_canary_replay_fixture_refs: Vec<String>,
    pub model_provider_gated_visible_output_attempt_ids: Vec<String>,
    pub model_provider_gated_visible_output_receipt_ids: Vec<String>,
    pub model_provider_gated_visible_output_replay_fixture_refs: Vec<String>,
    pub model_provider_gated_visible_output_rollback_drill_attempt_ids: Vec<String>,
    pub model_provider_gated_visible_output_rollback_drill_receipt_ids: Vec<String>,
    pub model_provider_gated_visible_output_rollback_drill_replay_fixture_refs: Vec<String>,
    pub read_only_capability_routing_attempt_ids: Vec<String>,
    pub read_only_capability_routing_receipt_ids: Vec<String>,
    pub read_only_capability_routing_replay_fixture_refs: Vec<String>,
    pub output_writer_handoff_attempt_ids: Vec<String>,
    pub output_writer_materialization_canary_attempt_ids: Vec<String>,
    pub output_writer_staged_write_canary_attempt_ids: Vec<String>,
    pub output_writer_visible_write_attempt_ids: Vec<String>,
    pub authority_tooling_live_dry_run_attempt_ids: Vec<String>,
    pub authority_tooling_gate_live_attempt_ids: Vec<String>,
    pub authority_tooling_gate_live_receipt_ids: Vec<String>,
    pub authority_tooling_gate_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_policy_gate_live_attempt_ids: Vec<String>,
    pub authority_tooling_policy_gate_live_receipt_ids: Vec<String>,
    pub authority_tooling_policy_gate_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_destructive_denial_live_attempt_ids: Vec<String>,
    pub authority_tooling_destructive_denial_live_receipt_ids: Vec<String>,
    pub authority_tooling_destructive_denial_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_approval_gate_live_attempt_ids: Vec<String>,
    pub authority_tooling_approval_gate_live_receipt_ids: Vec<String>,
    pub authority_tooling_approval_gate_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_read_only_live_attempt_ids: Vec<String>,
    pub authority_tooling_read_only_receipt_ids: Vec<String>,
    pub authority_tooling_read_only_replay_fixture_refs: Vec<String>,
    pub authority_tooling_provider_catalog_live_attempt_ids: Vec<String>,
    pub authority_tooling_provider_catalog_live_receipt_ids: Vec<String>,
    pub authority_tooling_provider_catalog_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_mcp_tool_catalog_live_attempt_ids: Vec<String>,
    pub authority_tooling_mcp_tool_catalog_live_receipt_ids: Vec<String>,
    pub authority_tooling_mcp_tool_catalog_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_native_tool_catalog_live_attempt_ids: Vec<String>,
    pub authority_tooling_native_tool_catalog_live_receipt_ids: Vec<String>,
    pub authority_tooling_native_tool_catalog_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_connector_catalog_live_attempt_ids: Vec<String>,
    pub authority_tooling_connector_catalog_live_receipt_ids: Vec<String>,
    pub authority_tooling_connector_catalog_live_replay_fixture_refs: Vec<String>,
    pub authority_tooling_wallet_capability_live_dry_run_attempt_ids: Vec<String>,
    pub authority_tooling_wallet_capability_live_dry_run_receipt_ids: Vec<String>,
    pub authority_tooling_wallet_capability_live_dry_run_replay_fixture_refs: Vec<String>,
    pub authority_tooling_read_only_component_kinds: Vec<HarnessComponentKind>,
    pub authority_tooling_mutation_deferred_component_kinds: Vec<HarnessComponentKind>,
    pub authority_tooling_denial_receipt_ids: Vec<String>,
    pub accepted_node_attempt_ids: Vec<String>,
    pub node_attempt_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub executor_kind: String,
    pub executor_ref: String,
    pub synchronous: bool,
    pub drives_runtime_decision: bool,
    pub activation_id_gate_click_proof_present: bool,
    pub activation_id_gate_click_proof_passed: bool,
    pub activation_id_gate_click_proof_blockers: Vec<String>,
    pub default_dispatch_activation_blockers: Vec<String>,
    pub cognition_execution_mode: String,
    pub cognition_execution_ready: bool,
    pub prompt_assembly_mode: String,
    pub prompt_assembly_prompt_hash: String,
    pub prompt_assembly_prompt_hash_matches: bool,
    pub model_execution_mode: String,
    pub model_execution_envelope_ready: bool,
    pub model_execution_binding_id: String,
    pub model_execution_binding_ready: bool,
    pub model_execution_prompt_hash: String,
    pub model_execution_prompt_hash_matches: bool,
    pub model_execution_output_hash: String,
    pub model_execution_output_hash_matches: bool,
    pub model_execution_provider_invocation_mode: String,
    pub model_execution_low_level_invocation_deferred: bool,
    pub model_execution_fallback_selector: String,
    pub model_execution_latency_ms: u64,
    pub model_provider_canary_mode: String,
    pub model_provider_canary_ready: bool,
    pub model_provider_canary_candidate_output_hash: String,
    pub model_provider_canary_legacy_output_hash: String,
    pub model_provider_canary_output_hash_matches: bool,
    pub model_provider_canary_transcript_matches: bool,
    pub model_provider_canary_fallback_retained: bool,
    pub model_provider_canary_rollback_available: bool,
    pub model_provider_gated_visible_output_mode: String,
    pub model_provider_gated_visible_output_enabled: bool,
    pub model_provider_gated_visible_output_ready: bool,
    pub model_provider_gated_visible_output_selected: bool,
    pub model_provider_gated_visible_output_eligible: bool,
    pub model_provider_gated_visible_output_scenario: String,
    pub model_provider_gated_visible_output_cohort: String,
    pub model_provider_gated_visible_output_retained_read_only_no_tool: bool,
    pub model_provider_gated_visible_output_required_scenario_set: Vec<String>,
    pub model_provider_gated_visible_output_scenario_coverage_key: Option<String>,
    pub model_provider_gated_visible_output_activation_flag: String,
    pub model_provider_gated_visible_output_activation_id: String,
    pub model_provider_gated_visible_output_authority: String,
    pub model_provider_gated_visible_output_rollback_target: String,
    pub model_provider_gated_visible_output_rollback_available: bool,
    pub selected_visible_output_authority: String,
    pub selected_visible_output_hash: String,
    pub workflow_provider_visible_output_hash: String,
    pub legacy_visible_output_hash: String,
    pub legacy_visible_output_computed: bool,
    pub legacy_visible_output_hash_matches_selected: bool,
    pub selected_visible_output_authority_matches_transcript: bool,
    pub visible_output_divergence_class: Option<String>,
    pub model_provider_gated_visible_output_rollback_drill_enabled: bool,
    pub model_provider_gated_visible_output_rollback_drill_ready: bool,
    pub model_provider_gated_visible_output_rollback_drill_failure_injected: bool,
    pub model_provider_gated_visible_output_rollback_drill_injected_output_hash: String,
    pub model_provider_gated_visible_output_rollback_drill_output_hash_diverges: bool,
    pub model_provider_gated_visible_output_rollback_drill_divergence_class: String,
    pub model_provider_gated_visible_output_rollback_drill_fallback_authority: String,
    pub model_provider_gated_visible_output_rollback_drill_selected_authority: String,
    pub model_provider_gated_visible_output_rollback_drill_transcript_unchanged: bool,
    pub model_provider_gated_visible_output_rollback_drill_rollback_executed: bool,
    pub model_provider_gated_visible_output_rollback_drill_activation_blockers: Vec<String>,
    pub read_only_capability_routing_mode: String,
    pub read_only_capability_routing_ready: bool,
    pub read_only_capability_routing_selected: bool,
    pub read_only_capability_routing_eligible: bool,
    pub read_only_capability_routing_scenario: String,
    pub read_only_capability_routing_required_scenario_set: Vec<String>,
    pub read_only_capability_routing_scenario_coverage_key: Option<String>,
    pub read_only_capability_routing_source_material_ready: bool,
    pub read_only_capability_routing_no_mutation_ready: bool,
    pub read_only_capability_routing_workflow_owned_node_kinds: Vec<HarnessComponentKind>,
    pub output_authority: String,
    pub output_writer_deferred: bool,
    pub output_writer_status: String,
    pub output_writer_handoff_ready: bool,
    pub output_writer_authority_transferred: bool,
    pub output_writer_materialization_mode: String,
    pub output_writer_materialization_canary_ready: bool,
    pub output_writer_materialization_committed: bool,
    pub output_writer_staged_write_mode: String,
    pub output_writer_staged_write_canary_ready: bool,
    pub output_writer_staged_write_persisted: bool,
    pub output_writer_staged_write_committed: bool,
    pub output_writer_staged_write_visible: bool,
    pub output_writer_staged_write_excluded_from_visible_transcript: bool,
    pub output_writer_staged_write_rollback_status: String,
    pub output_writer_staged_write_rollback_verified: bool,
    pub output_writer_visible_write_mode: String,
    pub output_writer_visible_write_ready: bool,
    pub output_writer_visible_write_persisted: bool,
    pub output_writer_visible_write_committed: bool,
    pub output_writer_visible_write_visible: bool,
    pub output_writer_visible_write_identity_checkpoint_persisted: bool,
    pub output_writer_visible_write_legacy_duplicate_suppressed: bool,
    pub authority_tooling_mode: String,
    pub authority_tooling_ready: bool,
    pub authority_tooling_policy_gate_ready: bool,
    pub authority_tooling_tool_router_ready: bool,
    pub authority_tooling_dry_run_simulator_ready: bool,
    pub authority_tooling_approval_gate_ready: bool,
    pub authority_tooling_gate_live_ready: bool,
    pub authority_tooling_policy_gate_live_ready: bool,
    pub authority_tooling_destructive_denial_live_ready: bool,
    pub authority_tooling_approval_gate_live_ready: bool,
    pub authority_tooling_read_only_route_accepted: bool,
    pub authority_tooling_destructive_route_denied: bool,
    pub authority_tooling_mutating_tool_calls_blocked: bool,
    pub authority_tooling_side_effects_executed: bool,
    pub authority_tooling_rollback_available: bool,
    pub legacy_transcript_authority_retained: bool,
    pub legacy_transcript_fallback_available: bool,
    pub proposed_visible_output_hash: String,
    pub actual_visible_output_hash: String,
    pub output_hash_algorithm: String,
    pub output_hash_matches: bool,
    pub output_hash_divergence: bool,
    pub output_hash_divergence_count: u32,
    pub transcript_materialization_content_hash_matches: bool,
    pub transcript_materialization_order_matches: bool,
    pub transcript_materialization_receipt_binding_matches: bool,
    pub transcript_materialization_target_matches: bool,
    pub transcript_materialization_matches: bool,
    pub transcript_materialization_divergence_count: u32,
    pub staged_transcript_write_content_hash_matches: bool,
    pub staged_transcript_write_order_matches: bool,
    pub staged_transcript_write_receipt_binding_matches: bool,
    pub staged_transcript_write_target_matches: bool,
    pub staged_transcript_write_matches: bool,
    pub staged_transcript_write_divergence_count: u32,
    pub visible_transcript_write_content_hash_matches: bool,
    pub visible_transcript_write_order_matches: bool,
    pub visible_transcript_write_receipt_binding_matches: bool,
    pub visible_transcript_write_target_matches: bool,
    pub visible_transcript_write_matches: bool,
    pub visible_transcript_write_divergence_count: u32,
    pub legacy_output_authority_retained: bool,
    pub legacy_output_fallback_available: bool,
    pub mutating_turns_blocked: bool,
    pub rollback_target: String,
    pub rollback_available: bool,
    pub activation_blockers: Vec<String>,
    pub policy_decision: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessCanaryRollbackDrill {
    pub schema_version: String,
    pub drill_id: String,
    pub selector_decision_id: String,
    pub failure_injected: bool,
    pub failed_node_id: String,
    pub cluster_id: HarnessPromotionClusterId,
    pub failure_class: String,
    pub observed_failure: bool,
    pub rollback_executed: bool,
    pub rollback_selector: HarnessLiveHandoffSelector,
    pub fallback_authority: String,
    pub rollback_target: String,
    pub rollback_available: bool,
    pub drill_status: String,
    pub policy_decision: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessCanaryExecutionBoundary {
    pub schema_version: String,
    pub boundary_id: String,
    pub cluster_id: HarnessPromotionClusterId,
    pub cluster_label: String,
    pub selector_decision_id: String,
    pub selected_selector: HarnessLiveHandoffSelector,
    pub production_default_selector: HarnessLiveHandoffSelector,
    pub workflow_id: String,
    pub activation_id: String,
    pub harness_hash: String,
    pub execution_mode: HarnessExecutionMode,
    pub runtime_authority: String,
    pub executor_kind: String,
    pub executor_ref: String,
    pub synchronous: bool,
    pub enforced_before_visible_output: bool,
    pub canary_eligible: bool,
    pub status: String,
    pub component_kinds: Vec<HarnessComponentKind>,
    pub executed_component_kinds: Vec<HarnessComponentKind>,
    pub workflow_node_ids: Vec<String>,
    pub node_attempt_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub replay_fixture_refs: Vec<String>,
    pub activation_blockers: Vec<String>,
    pub rollback_target: String,
    pub rollback_available: bool,
    pub rollback_drill: HarnessCanaryRollbackDrill,
    pub policy_decision: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessReceiptBinding {
    pub harness_workflow_id: String,
    pub harness_activation_id: String,
    pub harness_hash: String,
    pub workflow_node_id: String,
    pub component_id: String,
    pub component_kind: HarnessComponentKind,
    pub event_kind: String,
    pub receipt_id: String,
    pub step_index: Option<u32>,
    pub evidence_refs: Vec<String>,
    pub decision_reason: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HarnessBindingError {
    #[error("harness workflow id is missing")]
    MissingWorkflowId,
    #[error("harness activation id is missing")]
    MissingActivationId,
    #[error("harness hash is missing")]
    MissingHash,
}

const DEFAULT_HARNESS_FLOW: &[HarnessComponentKind] = &[
    HarnessComponentKind::Planner,
    HarnessComponentKind::PromptAssembler,
    HarnessComponentKind::TaskState,
    HarnessComponentKind::UncertaintyGate,
    HarnessComponentKind::ProbeRunner,
    HarnessComponentKind::BudgetGate,
    HarnessComponentKind::CapabilitySequencer,
    HarnessComponentKind::ModelRouter,
    HarnessComponentKind::ModelCall,
    HarnessComponentKind::ToolRouter,
    HarnessComponentKind::DryRunSimulator,
    HarnessComponentKind::PolicyGate,
    HarnessComponentKind::ApprovalGate,
    HarnessComponentKind::WalletCapability,
    HarnessComponentKind::McpProvider,
    HarnessComponentKind::McpToolCall,
    HarnessComponentKind::ToolCall,
    HarnessComponentKind::ConnectorCall,
    HarnessComponentKind::MemoryRead,
    HarnessComponentKind::MemoryWrite,
    HarnessComponentKind::SemanticImpactAnalyzer,
    HarnessComponentKind::PostconditionSynthesizer,
    HarnessComponentKind::Verifier,
    HarnessComponentKind::DriftDetector,
    HarnessComponentKind::RetryPolicy,
    HarnessComponentKind::RepairLoop,
    HarnessComponentKind::MergeJudge,
    HarnessComponentKind::HandoffBridge,
    HarnessComponentKind::CompletionGate,
    HarnessComponentKind::ReceiptWriter,
    HarnessComponentKind::QualityLedger,
    HarnessComponentKind::OutputWriter,
    HarnessComponentKind::GuiHarnessValidator,
];

const COGNITION_CLUSTER_COMPONENTS: &[HarnessComponentKind] = &[
    HarnessComponentKind::Planner,
    HarnessComponentKind::PromptAssembler,
    HarnessComponentKind::TaskState,
    HarnessComponentKind::UncertaintyGate,
    HarnessComponentKind::BudgetGate,
    HarnessComponentKind::CapabilitySequencer,
];

const ROUTING_MODEL_CLUSTER_COMPONENTS: &[HarnessComponentKind] = &[
    HarnessComponentKind::ModelRouter,
    HarnessComponentKind::ModelCall,
    HarnessComponentKind::ToolRouter,
];

const VERIFICATION_OUTPUT_CLUSTER_COMPONENTS: &[HarnessComponentKind] = &[
    HarnessComponentKind::PostconditionSynthesizer,
    HarnessComponentKind::Verifier,
    HarnessComponentKind::CompletionGate,
    HarnessComponentKind::ReceiptWriter,
    HarnessComponentKind::QualityLedger,
    HarnessComponentKind::OutputWriter,
];

const AUTHORITY_TOOLING_CLUSTER_COMPONENTS: &[HarnessComponentKind] = &[
    HarnessComponentKind::PolicyGate,
    HarnessComponentKind::ApprovalGate,
    HarnessComponentKind::DryRunSimulator,
    HarnessComponentKind::McpProvider,
    HarnessComponentKind::McpToolCall,
    HarnessComponentKind::ToolCall,
    HarnessComponentKind::ConnectorCall,
    HarnessComponentKind::WalletCapability,
];

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn promotion_cluster_components(
    cluster_id: HarnessPromotionClusterId,
) -> Vec<HarnessComponentKind> {
    match cluster_id {
        HarnessPromotionClusterId::Cognition => COGNITION_CLUSTER_COMPONENTS.to_vec(),
        HarnessPromotionClusterId::RoutingModel => ROUTING_MODEL_CLUSTER_COMPONENTS.to_vec(),
        HarnessPromotionClusterId::VerificationOutput => {
            VERIFICATION_OUTPUT_CLUSTER_COMPONENTS.to_vec()
        }
        HarnessPromotionClusterId::AuthorityTooling => {
            AUTHORITY_TOOLING_CLUSTER_COMPONENTS.to_vec()
        }
    }
}

pub fn harness_promotion_cluster_components(
    cluster_id: HarnessPromotionClusterId,
) -> Vec<HarnessComponentKind> {
    promotion_cluster_components(cluster_id)
}

fn component_scope(kind: HarnessComponentKind) -> Vec<String> {
    match kind {
        HarnessComponentKind::Planner => strings(&["reasoning.read", "session.state.read"]),
        HarnessComponentKind::PromptAssembler => {
            strings(&["prompt.assemble", "session.state.read", "evidence.read"])
        }
        HarnessComponentKind::TaskState => {
            strings(&["session.state.read", "session.state.write", "evidence.read"])
        }
        HarnessComponentKind::UncertaintyGate => {
            strings(&["uncertainty.assess", "session.state.read"])
        }
        HarnessComponentKind::ProbeRunner => strings(&["probe.plan", "probe.run"]),
        HarnessComponentKind::BudgetGate => strings(&["budget.evaluate"]),
        HarnessComponentKind::CapabilitySequencer => {
            strings(&["capability.read", "tool.route", "quality.read"])
        }
        HarnessComponentKind::ModelRouter => strings(&["model.route"]),
        HarnessComponentKind::ModelCall => strings(&["model.invoke"]),
        HarnessComponentKind::ToolRouter => strings(&["tool.route", "capability.read"]),
        HarnessComponentKind::ToolCall => strings(&["tool.invoke"]),
        HarnessComponentKind::DryRunSimulator => strings(&["dry_run.preview"]),
        HarnessComponentKind::McpProvider => strings(&["mcp.provider.read", "mcp.catalog.read"]),
        HarnessComponentKind::McpToolCall => strings(&["mcp.tool.invoke"]),
        HarnessComponentKind::ConnectorCall => strings(&["connector.invoke"]),
        HarnessComponentKind::PolicyGate => strings(&["policy.evaluate", "capability.lease"]),
        HarnessComponentKind::ApprovalGate => strings(&["approval.request"]),
        HarnessComponentKind::WalletCapability => strings(&["wallet.request", "capability.grant"]),
        HarnessComponentKind::MemoryRead => strings(&["memory.read"]),
        HarnessComponentKind::MemoryWrite => strings(&["memory.write"]),
        HarnessComponentKind::SemanticImpactAnalyzer => {
            strings(&["impact.analyze", "workspace.read"])
        }
        HarnessComponentKind::PostconditionSynthesizer => {
            strings(&["postcondition.synthesize", "evidence.read"])
        }
        HarnessComponentKind::Verifier => strings(&["verification.run"]),
        HarnessComponentKind::DriftDetector => strings(&["drift.detect", "session.state.read"]),
        HarnessComponentKind::OutputWriter => strings(&["output.write"]),
        HarnessComponentKind::ReceiptWriter => strings(&["receipt.write"]),
        HarnessComponentKind::QualityLedger => strings(&["quality.write", "scorecard.read"]),
        HarnessComponentKind::RetryPolicy => strings(&["retry.evaluate"]),
        HarnessComponentKind::RepairLoop => strings(&["repair.propose"]),
        HarnessComponentKind::MergeJudge => strings(&["judgement.run"]),
        HarnessComponentKind::HandoffBridge => strings(&["handoff.write", "session.state.read"]),
        HarnessComponentKind::CompletionGate => strings(&["completion.evaluate"]),
        HarnessComponentKind::GuiHarnessValidator => strings(&["gui.validate", "trace.read"]),
    }
}

fn component_events(kind: HarnessComponentKind) -> Vec<String> {
    match kind {
        HarnessComponentKind::Planner => strings(&["PlanReceipt", "KernelEvent::PlanReceipt"]),
        HarnessComponentKind::PromptAssembler => {
            strings(&["PromptAssemblyContract", "AgentRuntimeEvent"])
        }
        HarnessComponentKind::TaskState => strings(&["TaskStateModel", "AgentRuntimeEvent"]),
        HarnessComponentKind::UncertaintyGate => {
            strings(&["UncertaintyAssessment", "AgentRuntimeEvent"])
        }
        HarnessComponentKind::ProbeRunner => strings(&["Probe", "AgentRuntimeEvent"]),
        HarnessComponentKind::BudgetGate => strings(&["CognitiveBudget", "AgentRuntimeEvent"]),
        HarnessComponentKind::CapabilitySequencer => {
            strings(&["CapabilitySequence", "AgentRuntimeEvent"])
        }
        HarnessComponentKind::ModelRouter => {
            strings(&["RoutingReceipt", "KernelEvent::RoutingReceipt"])
        }
        HarnessComponentKind::ModelCall => {
            strings(&["WorkloadReceipt", "WorkloadReceipt::Inference"])
        }
        HarnessComponentKind::ToolRouter => strings(&["RoutingReceipt", "ActionDispatchPrepared"]),
        HarnessComponentKind::ToolCall => strings(&["AgentActionResult", "WorkloadReceipt"]),
        HarnessComponentKind::DryRunSimulator => {
            strings(&["DryRunCapability", "AgentRuntimeEvent"])
        }
        HarnessComponentKind::McpProvider => strings(&["McpServerCatalogued", "CapabilityLease"]),
        HarnessComponentKind::McpToolCall => {
            strings(&["AgentActionResult", "ExecutionContractReceipt"])
        }
        HarnessComponentKind::ConnectorCall => strings(&["ConnectorInvocation", "WorkloadReceipt"]),
        HarnessComponentKind::PolicyGate => strings(&["FirewallInterception", "RoutingReceipt"]),
        HarnessComponentKind::ApprovalGate => strings(&["ApprovalRequested", "ApprovalSatisfied"]),
        HarnessComponentKind::WalletCapability => {
            strings(&["CapabilityLease", "WalletRequestReceipt"])
        }
        HarnessComponentKind::MemoryRead => strings(&["WorkloadReceipt::MemoryRetrieve"]),
        HarnessComponentKind::MemoryWrite => strings(&["StateUpdate", "WorkloadReceipt"]),
        HarnessComponentKind::SemanticImpactAnalyzer => {
            strings(&["SemanticImpactAnalysis", "AgentRuntimeEvent"])
        }
        HarnessComponentKind::PostconditionSynthesizer => {
            strings(&["PostconditionSynthesis", "ExecutionContractReceipt"])
        }
        HarnessComponentKind::Verifier => {
            strings(&["ExecutionContractReceipt", "VerificationReceipt"])
        }
        HarnessComponentKind::DriftDetector => strings(&["DriftSignal", "AgentRuntimeEvent"]),
        HarnessComponentKind::OutputWriter => strings(&["OutputWritten", "AgentActionResult"]),
        HarnessComponentKind::ReceiptWriter => {
            strings(&["ExecutionContractReceipt", "PlanReceipt", "WorkloadReceipt"])
        }
        HarnessComponentKind::QualityLedger => strings(&["AgentQualityLedger", "Scorecard"]),
        HarnessComponentKind::RetryPolicy => strings(&["RetryScheduled", "RetryExhausted"]),
        HarnessComponentKind::RepairLoop => {
            strings(&["RepairAttemptStarted", "RepairAttemptCompleted"])
        }
        HarnessComponentKind::MergeJudge => strings(&["MergeReceipt", "JudgementReceipt"]),
        HarnessComponentKind::HandoffBridge => strings(&["HandoffQuality", "AgentRuntimeEvent"]),
        HarnessComponentKind::CompletionGate => strings(&["CompletionGateReceipt", "PlanReceipt"]),
        HarnessComponentKind::GuiHarnessValidator => {
            strings(&["AutopilotGuiHarnessValidationContract", "Scorecard"])
        }
    }
}

fn component_evidence(kind: HarnessComponentKind) -> Vec<String> {
    match kind {
        HarnessComponentKind::Planner => {
            strings(&["plan_id", "planner_policy_hash", "chosen_step_reason"])
        }
        HarnessComponentKind::PromptAssembler => strings(&[
            "sections",
            "final_prompt_hash",
            "conflict_resolutions",
            "truncation_diagnostics",
        ]),
        HarnessComponentKind::TaskState => strings(&[
            "objective",
            "known_facts",
            "uncertain_facts",
            "evidence_refs",
        ]),
        HarnessComponentKind::UncertaintyGate => strings(&[
            "ambiguity_level",
            "value_of_information",
            "selected_action",
            "rationale",
        ]),
        HarnessComponentKind::ProbeRunner => strings(&[
            "hypothesis",
            "expected_observation",
            "result",
            "confidence_update",
        ]),
        HarnessComponentKind::BudgetGate => strings(&[
            "max_tool_calls",
            "max_retries",
            "max_wall_time_ms",
            "stop_threshold",
        ]),
        HarnessComponentKind::CapabilitySequencer => strings(&[
            "discovered",
            "selected",
            "ordered_steps",
            "retired_or_deprioritized",
        ]),
        HarnessComponentKind::ModelRouter => {
            strings(&["model_policy_slot", "candidate_models", "routing_reason"])
        }
        HarnessComponentKind::ModelCall => {
            strings(&["request_hash", "response_hash", "model_binding"])
        }
        HarnessComponentKind::ToolRouter => {
            strings(&["tool_grant_slot", "candidate_tools", "routing_reason"])
        }
        HarnessComponentKind::ToolCall => {
            strings(&["action_request_id", "tool_ref", "result_hash"])
        }
        HarnessComponentKind::DryRunSimulator => strings(&[
            "capability_id",
            "supported_tool_classes",
            "side_effect_preview",
        ]),
        HarnessComponentKind::McpProvider => strings(&["server_id", "catalog_hash", "grant_scope"]),
        HarnessComponentKind::McpToolCall => {
            strings(&["server_id", "tool_name", "argument_hash", "result_hash"])
        }
        HarnessComponentKind::ConnectorCall => {
            strings(&["connector_id", "operation", "request_hash", "result_hash"])
        }
        HarnessComponentKind::PolicyGate => {
            strings(&["policy_hash", "decision", "lease_id", "determinism_commit"])
        }
        HarnessComponentKind::ApprovalGate => {
            strings(&["approval_id", "approval_scope", "approver"])
        }
        HarnessComponentKind::WalletCapability => {
            strings(&["capability_scope", "lease_id", "budget"])
        }
        HarnessComponentKind::MemoryRead => strings(&["memory_key", "state_hash"]),
        HarnessComponentKind::MemoryWrite => strings(&["memory_key", "previous_hash", "next_hash"]),
        HarnessComponentKind::SemanticImpactAnalyzer => strings(&[
            "changed_symbols",
            "affected_tests",
            "risk_class",
            "unknowns",
        ]),
        HarnessComponentKind::PostconditionSynthesizer => {
            strings(&["objective", "checks", "minimum_evidence", "unknowns"])
        }
        HarnessComponentKind::Verifier => {
            strings(&["schema_hash", "contract_key", "verification_result"])
        }
        HarnessComponentKind::DriftDetector => strings(&[
            "plan_drift",
            "file_drift",
            "policy_drift",
            "projection_state_drift",
        ]),
        HarnessComponentKind::OutputWriter => {
            strings(&["output_hash", "delivery_target", "output_policy_slot"])
        }
        HarnessComponentKind::ReceiptWriter => {
            strings(&["receipt_id", "node_id", "evidence_commit_hash"])
        }
        HarnessComponentKind::QualityLedger => strings(&[
            "ledger_id",
            "task_family",
            "scorecard_metrics",
            "stop_condition",
        ]),
        HarnessComponentKind::RetryPolicy => strings(&["attempt", "max_attempts", "retry_reason"]),
        HarnessComponentKind::RepairLoop => {
            strings(&["failure_ref", "repair_strategy", "bounded_targets"])
        }
        HarnessComponentKind::MergeJudge => {
            strings(&["candidate_hashes", "winner_reason", "judge_policy_hash"])
        }
        HarnessComponentKind::HandoffBridge => strings(&[
            "objective_preserved",
            "blockers_included",
            "evidence_refs_included",
        ]),
        HarnessComponentKind::CompletionGate => {
            strings(&["completion_contract", "pending_actions", "final_decision"])
        }
        HarnessComponentKind::GuiHarnessValidator => strings(&[
            "launch_command",
            "retained_queries",
            "screenshots",
            "scorecard",
        ]),
    }
}

fn component_readiness(kind: HarnessComponentKind) -> HarnessComponentReadiness {
    match kind {
        HarnessComponentKind::Planner
        | HarnessComponentKind::PromptAssembler
        | HarnessComponentKind::TaskState
        | HarnessComponentKind::UncertaintyGate
        | HarnessComponentKind::BudgetGate
        | HarnessComponentKind::CapabilitySequencer
        | HarnessComponentKind::ModelRouter
        | HarnessComponentKind::ModelCall
        | HarnessComponentKind::ToolRouter
        | HarnessComponentKind::ToolCall
        | HarnessComponentKind::DryRunSimulator
        | HarnessComponentKind::McpProvider
        | HarnessComponentKind::McpToolCall
        | HarnessComponentKind::ConnectorCall
        | HarnessComponentKind::PolicyGate
        | HarnessComponentKind::ApprovalGate
        | HarnessComponentKind::WalletCapability
        | HarnessComponentKind::PostconditionSynthesizer
        | HarnessComponentKind::Verifier
        | HarnessComponentKind::CompletionGate
        | HarnessComponentKind::ReceiptWriter
        | HarnessComponentKind::QualityLedger
        | HarnessComponentKind::OutputWriter => HarnessComponentReadiness::ShadowReady,
        _ => HarnessComponentReadiness::ProjectionOnly,
    }
}

fn replay_captures_policy_decision(kind: HarnessComponentKind) -> bool {
    matches!(
        kind,
        HarnessComponentKind::UncertaintyGate
            | HarnessComponentKind::BudgetGate
            | HarnessComponentKind::DryRunSimulator
            | HarnessComponentKind::PolicyGate
            | HarnessComponentKind::ApprovalGate
            | HarnessComponentKind::WalletCapability
            | HarnessComponentKind::RetryPolicy
            | HarnessComponentKind::CompletionGate
    )
}

fn replay_is_intrinsically_nondeterministic(kind: HarnessComponentKind) -> bool {
    matches!(
        kind,
        HarnessComponentKind::ModelCall
            | HarnessComponentKind::ToolCall
            | HarnessComponentKind::McpToolCall
            | HarnessComponentKind::ConnectorCall
            | HarnessComponentKind::WalletCapability
    )
}

fn default_harness_replay_envelope(kind: HarnessComponentKind) -> HarnessReplayEnvelope {
    let nondeterministic = replay_is_intrinsically_nondeterministic(kind);
    HarnessReplayEnvelope {
        deterministic_envelope: !nondeterministic,
        captures_input: true,
        captures_output: true,
        captures_policy_decision: replay_captures_policy_decision(kind),
        fixture_ref: None,
        determinism: if nondeterministic {
            HarnessReplayDeterminism::Nondeterministic
        } else {
            HarnessReplayDeterminism::Deterministic
        },
        nondeterminism_reason: nondeterministic.then(|| {
            "External model, tool, connector, or wallet boundary requires retained fixture evidence"
                .to_string()
        }),
        redaction_policy: "runtime_redacted".to_string(),
    }
}

fn approval_for(kind: HarnessComponentKind) -> HarnessApprovalSemantics {
    let required = matches!(
        kind,
        HarnessComponentKind::ToolCall
            | HarnessComponentKind::DryRunSimulator
            | HarnessComponentKind::McpToolCall
            | HarnessComponentKind::ConnectorCall
            | HarnessComponentKind::ApprovalGate
            | HarnessComponentKind::WalletCapability
            | HarnessComponentKind::MemoryWrite
            | HarnessComponentKind::OutputWriter
    );
    let mode = match kind {
        HarnessComponentKind::ApprovalGate => "human_gate",
        HarnessComponentKind::WalletCapability => "wallet_capability",
        _ if required => "policy_gate",
        _ => "none",
    };
    HarnessApprovalSemantics {
        required,
        mode: mode.to_string(),
        reason: if required {
            "Component may cross a privileged runtime boundary.".to_string()
        } else {
            "Component is governed by workflow and node policy.".to_string()
        },
    }
}

pub fn default_harness_component_spec(kind: HarnessComponentKind) -> HarnessComponentSpec {
    let max_attempts = match kind {
        HarnessComponentKind::RetryPolicy => 3,
        HarnessComponentKind::RepairLoop
        | HarnessComponentKind::ProbeRunner
        | HarnessComponentKind::ModelCall
        | HarnessComponentKind::ToolCall
        | HarnessComponentKind::DryRunSimulator
        | HarnessComponentKind::McpToolCall
        | HarnessComponentKind::ConnectorCall => 2,
        _ => 1,
    };
    let timeout_ms = match kind {
        HarnessComponentKind::ModelCall => 120_000,
        HarnessComponentKind::GuiHarnessValidator => 600_000,
        HarnessComponentKind::ToolCall
        | HarnessComponentKind::DryRunSimulator
        | HarnessComponentKind::McpToolCall
        | HarnessComponentKind::ConnectorCall => 60_000,
        _ => 30_000,
    };
    HarnessComponentSpec {
        component_id: kind.component_id(),
        version: HARNESS_COMPONENT_VERSION_V1.to_string(),
        kind,
        readiness: component_readiness(kind),
        label: kind.label().to_string(),
        kernel_ref: kind.kernel_ref().to_string(),
        input_schema: HARNESS_INPUT_SCHEMA_ID.to_string(),
        output_schema: HARNESS_OUTPUT_SCHEMA_ID.to_string(),
        error_schema: HARNESS_ERROR_SCHEMA_ID.to_string(),
        timeout: HarnessTimeoutBehavior {
            timeout_ms,
            cancellation: "cooperative".to_string(),
        },
        retry: HarnessRetryBehavior {
            max_attempts,
            backoff_ms: if max_attempts > 1 { 250 } else { 0 },
            retryable_errors: strings(&["timeout", "rate_limit", "transient_provider_error"]),
        },
        required_capability_scope: component_scope(kind),
        approval: approval_for(kind),
        emitted_events: component_events(kind),
        evidence: component_evidence(kind),
    }
}

pub fn default_agent_harness_components() -> Vec<HarnessComponentSpec> {
    DEFAULT_HARNESS_FLOW
        .iter()
        .copied()
        .map(default_harness_component_spec)
        .collect()
}

pub fn default_harness_promotion_clusters() -> Vec<HarnessPromotionCluster> {
    [
        HarnessPromotionClusterId::Cognition,
        HarnessPromotionClusterId::RoutingModel,
        HarnessPromotionClusterId::VerificationOutput,
        HarnessPromotionClusterId::AuthorityTooling,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, cluster_id)| HarnessPromotionCluster {
        cluster_id,
        label: cluster_id.label().to_string(),
        activation_order: (index + 1) as u32,
        component_kinds: promotion_cluster_components(cluster_id),
        required_execution_mode: HarnessExecutionMode::Gated,
        minimum_readiness: HarnessComponentReadiness::ShadowReady,
        promotion_rule: "zero blocking or unclassified divergence, receipt coverage, replay fixture coverage, and rollback target required".to_string(),
        rollback_target: "shadow".to_string(),
        blocks_live_activation: true,
        promotion_status: HarnessClusterPromotionStatus::ShadowReady,
        replay_gate_proof: None,
    })
    .collect()
}

fn slot_kinds_for_component(kind: HarnessComponentKind) -> Vec<HarnessSlotKind> {
    match kind {
        HarnessComponentKind::Planner
        | HarnessComponentKind::PromptAssembler
        | HarnessComponentKind::TaskState
        | HarnessComponentKind::UncertaintyGate
        | HarnessComponentKind::CapabilitySequencer
        | HarnessComponentKind::DriftDetector => vec![HarnessSlotKind::StatePolicy],
        HarnessComponentKind::ModelRouter | HarnessComponentKind::ModelCall => {
            vec![HarnessSlotKind::ModelPolicy]
        }
        HarnessComponentKind::ToolRouter
        | HarnessComponentKind::ToolCall
        | HarnessComponentKind::McpProvider
        | HarnessComponentKind::McpToolCall
        | HarnessComponentKind::ConnectorCall => vec![HarnessSlotKind::ToolGrantPolicy],
        HarnessComponentKind::BudgetGate => vec![HarnessSlotKind::BudgetPolicy],
        HarnessComponentKind::DryRunSimulator => vec![HarnessSlotKind::DryRunPolicy],
        HarnessComponentKind::PolicyGate
        | HarnessComponentKind::ApprovalGate
        | HarnessComponentKind::WalletCapability => vec![HarnessSlotKind::ApprovalPolicy],
        HarnessComponentKind::MemoryRead | HarnessComponentKind::MemoryWrite => {
            vec![HarnessSlotKind::MemoryPolicy]
        }
        HarnessComponentKind::SemanticImpactAnalyzer
        | HarnessComponentKind::PostconditionSynthesizer
        | HarnessComponentKind::Verifier
        | HarnessComponentKind::CompletionGate => {
            vec![HarnessSlotKind::VerifierPolicy]
        }
        HarnessComponentKind::OutputWriter
        | HarnessComponentKind::ReceiptWriter
        | HarnessComponentKind::GuiHarnessValidator => {
            vec![HarnessSlotKind::OutputPolicy]
        }
        HarnessComponentKind::QualityLedger => vec![HarnessSlotKind::QualityLedgerPolicy],
        HarnessComponentKind::RetryPolicy | HarnessComponentKind::RepairLoop => {
            vec![HarnessSlotKind::RetryRepairPolicy]
        }
        HarnessComponentKind::MergeJudge => {
            vec![
                HarnessSlotKind::RetryRepairPolicy,
                HarnessSlotKind::VerifierPolicy,
            ]
        }
        HarnessComponentKind::ProbeRunner => vec![
            HarnessSlotKind::StatePolicy,
            HarnessSlotKind::ToolGrantPolicy,
            HarnessSlotKind::BudgetPolicy,
        ],
        HarnessComponentKind::HandoffBridge => vec![HarnessSlotKind::HandoffPolicy],
    }
}

pub fn default_agent_harness_slots() -> Vec<HarnessSlotSpec> {
    vec![
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::StatePolicy.slot_id().to_string(),
            kind: HarnessSlotKind::StatePolicy,
            label: "Task state and strategy policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::Planner,
                HarnessComponentKind::PromptAssembler,
                HarnessComponentKind::TaskState,
                HarnessComponentKind::UncertaintyGate,
                HarnessComponentKind::ProbeRunner,
                HarnessComponentKind::CapabilitySequencer,
                HarnessComponentKind::DriftDetector,
            ],
            default_component_id: HarnessComponentKind::TaskState.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::ModelPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::ModelPolicy,
            label: "Model policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::ModelRouter,
                HarnessComponentKind::ModelCall,
            ],
            default_component_id: HarnessComponentKind::ModelRouter.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::ToolGrantPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::ToolGrantPolicy,
            label: "Tool grant policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::ToolRouter,
                HarnessComponentKind::ToolCall,
                HarnessComponentKind::McpProvider,
                HarnessComponentKind::McpToolCall,
                HarnessComponentKind::ConnectorCall,
            ],
            default_component_id: HarnessComponentKind::ToolRouter.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::BudgetPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::BudgetPolicy,
            label: "Cognitive budget policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::BudgetGate,
                HarnessComponentKind::ProbeRunner,
            ],
            default_component_id: HarnessComponentKind::BudgetGate.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::DryRunPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::DryRunPolicy,
            label: "Dry-run policy".to_string(),
            required: true,
            allowed_component_kinds: vec![HarnessComponentKind::DryRunSimulator],
            default_component_id: HarnessComponentKind::DryRunSimulator.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::VerifierPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::VerifierPolicy,
            label: "Verifier policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::SemanticImpactAnalyzer,
                HarnessComponentKind::PostconditionSynthesizer,
                HarnessComponentKind::Verifier,
                HarnessComponentKind::MergeJudge,
                HarnessComponentKind::CompletionGate,
            ],
            default_component_id: HarnessComponentKind::Verifier.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::ApprovalPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::ApprovalPolicy,
            label: "Approval policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::ApprovalGate,
                HarnessComponentKind::PolicyGate,
                HarnessComponentKind::WalletCapability,
            ],
            default_component_id: HarnessComponentKind::ApprovalGate.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::OutputPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::OutputPolicy,
            label: "Output policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::OutputWriter,
                HarnessComponentKind::ReceiptWriter,
                HarnessComponentKind::GuiHarnessValidator,
            ],
            default_component_id: HarnessComponentKind::OutputWriter.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::MemoryPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::MemoryPolicy,
            label: "Memory policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::MemoryRead,
                HarnessComponentKind::MemoryWrite,
            ],
            default_component_id: HarnessComponentKind::MemoryRead.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::QualityLedgerPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::QualityLedgerPolicy,
            label: "Quality ledger policy".to_string(),
            required: true,
            allowed_component_kinds: vec![HarnessComponentKind::QualityLedger],
            default_component_id: HarnessComponentKind::QualityLedger.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::RetryRepairPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::RetryRepairPolicy,
            label: "Retry and repair policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::RetryPolicy,
                HarnessComponentKind::RepairLoop,
                HarnessComponentKind::MergeJudge,
            ],
            default_component_id: HarnessComponentKind::RetryPolicy.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::HandoffPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::HandoffPolicy,
            label: "Handoff policy".to_string(),
            required: true,
            allowed_component_kinds: vec![HarnessComponentKind::HandoffBridge],
            default_component_id: HarnessComponentKind::HandoffBridge.component_id(),
            blocks_activation: true,
        },
    ]
}

pub fn default_agent_harness_action_frames() -> Vec<HarnessActionFrame> {
    default_agent_harness_components()
        .into_iter()
        .map(|component| {
            default_harness_action_frame_for_component(
                component.kind,
                HarnessExecutionMode::Projection,
            )
        })
        .collect()
}

pub fn default_harness_action_frame_for_component(
    component_kind: HarnessComponentKind,
    execution_mode: HarnessExecutionMode,
) -> HarnessActionFrame {
    let component = default_harness_component_spec(component_kind);
    HarnessActionFrame {
        workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        workflow_version: DEFAULT_AGENT_HARNESS_VERSION.to_string(),
        workflow_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        execution_mode,
        node_id: component.kind.workflow_node_id(),
        component_id: component.component_id,
        component_version: component.version,
        component_kind: component.kind,
        readiness: component.readiness,
        kernel_ref: component.kernel_ref,
        slot_ids: slot_kinds_for_component(component.kind)
            .into_iter()
            .map(HarnessSlotKind::slot_id)
            .map(str::to_string)
            .collect(),
        deterministic_envelope: default_harness_replay_envelope(component.kind)
            .deterministic_envelope,
        replay: default_harness_replay_envelope(component.kind),
        event_kinds: component.emitted_events,
        evidence_keys: component.evidence,
    }
}

pub fn default_harness_worker_binding() -> HarnessWorkerBinding {
    HarnessWorkerBinding {
        harness_workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        harness_activation_id: Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string()),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        execution_mode: HarnessExecutionMode::Projection,
        source: "default".to_string(),
    }
}

pub fn default_blessed_live_handoff_proof(
    node_timeline_attempt_ids: Vec<String>,
    receipt_ids: Vec<String>,
    replay_fixture_refs: Vec<String>,
) -> HarnessLiveHandoffProof {
    HarnessLiveHandoffProof {
        schema_version: "workflow.harness.live-handoff.v1".to_string(),
        selector: HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary,
        available_selectors: vec![
            HarnessLiveHandoffSelector::LegacyRuntime,
            HarnessLiveHandoffSelector::BlessedWorkflowGated,
            HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary,
            HarnessLiveHandoffSelector::BlessedWorkflowLiveDefault,
        ],
        production_default_selector: HarnessLiveHandoffSelector::LegacyRuntime,
        workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        component_version_set: DEFAULT_HARNESS_FLOW
            .iter()
            .copied()
            .map(default_harness_component_spec)
            .map(|component| HarnessComponentVersionBinding {
                component_id: component.component_id,
                component_version: component.version,
            })
            .collect(),
        canary_status: "passed".to_string(),
        canary_turn_routed_through_workflow: true,
        execution_boundary_id: "harness-canary-boundary:default-agent-harness:verification_output"
            .to_string(),
        execution_boundary_ids: vec![
            "harness-canary-boundary:default-agent-harness:cognition".to_string(),
            "harness-canary-boundary:default-agent-harness:routing_model".to_string(),
            "harness-canary-boundary:default-agent-harness:verification_output".to_string(),
            "harness-canary-boundary:default-agent-harness:authority_tooling".to_string(),
        ],
        execution_boundary_cluster_ids: vec![
            HarnessPromotionClusterId::Cognition,
            HarnessPromotionClusterId::RoutingModel,
            HarnessPromotionClusterId::VerificationOutput,
            HarnessPromotionClusterId::AuthorityTooling,
        ],
        execution_boundary_status: "passed".to_string(),
        execution_boundary_executor: "crate::project::execute_workflow_harness_canary_node"
            .to_string(),
        default_authority_transferred: false,
        runtime_authority: "blessed_workflow_activation_canary".to_string(),
        fallback_selector: HarnessLiveHandoffSelector::LegacyRuntime,
        rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        rollback_available: true,
        policy_decision: "allow_blessed_workflow_live_canary".to_string(),
        gated_cluster_ids: vec![
            HarnessPromotionClusterId::Cognition,
            HarnessPromotionClusterId::RoutingModel,
            HarnessPromotionClusterId::VerificationOutput,
            HarnessPromotionClusterId::AuthorityTooling,
        ],
        node_timeline_attempt_ids,
        receipt_ids,
        replay_fixture_refs,
        activation_blockers: Vec::new(),
        default_promotion_gate: HarnessDefaultPromotionGate {
            config_key: "AUTOPILOT_HARNESS_DEFAULT_PROMOTION".to_string(),
            enabled: false,
            eligible: false,
            non_mutating_only: true,
            selector: HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary,
            production_default_selector: HarnessLiveHandoffSelector::LegacyRuntime,
            default_authority_transferred: false,
            rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            activation_blockers: vec!["promotion_gate_disabled".to_string()],
            policy_decision: "retain_legacy_runtime_default".to_string(),
        },
        evidence_refs: vec!["runtime-evidence:blessed-live-handoff-canary".to_string()],
    }
}

pub fn default_harness_runtime_selector_decision() -> HarnessRuntimeSelectorDecision {
    HarnessRuntimeSelectorDecision {
        schema_version: "workflow.harness.runtime-selector.v1".to_string(),
        decision_id: "harness-selector:default-agent-harness:canary".to_string(),
        requested_selector: "auto_canary".to_string(),
        selected_selector: HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary,
        production_default_selector: HarnessLiveHandoffSelector::LegacyRuntime,
        canary_eligible: true,
        canary_blockers: Vec::new(),
        workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        execution_mode: HarnessExecutionMode::Live,
        actual_runtime_authority: "blessed_workflow_activation_canary".to_string(),
        fallback_selector: HarnessLiveHandoffSelector::LegacyRuntime,
        rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        rollback_available: true,
        policy_decision: "allow_blessed_workflow_live_canary".to_string(),
        route_reason: "Turn is non-mutating and eligible for blessed workflow canary routing."
            .to_string(),
        default_promotion_gate: HarnessDefaultPromotionGate {
            config_key: "AUTOPILOT_HARNESS_DEFAULT_PROMOTION".to_string(),
            enabled: false,
            eligible: false,
            non_mutating_only: true,
            selector: HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary,
            production_default_selector: HarnessLiveHandoffSelector::LegacyRuntime,
            default_authority_transferred: false,
            rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            activation_blockers: vec!["promotion_gate_disabled".to_string()],
            policy_decision: "retain_legacy_runtime_default".to_string(),
        },
        evidence_refs: vec!["runtime-evidence:selector-canary".to_string()],
    }
}

pub fn default_harness_default_runtime_dispatch_proof() -> HarnessDefaultRuntimeDispatchProof {
    HarnessDefaultRuntimeDispatchProof {
        schema_version: "workflow.harness.default-runtime-dispatch.v1".to_string(),
        dispatch_id: "harness-default-dispatch:default-agent-harness:readonly".to_string(),
        selector_decision_id: "harness-selector:default-agent-harness:default".to_string(),
        selected_selector: HarnessLiveHandoffSelector::BlessedWorkflowLiveDefault,
        production_default_selector: HarnessLiveHandoffSelector::BlessedWorkflowLiveDefault,
        workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        execution_mode: HarnessExecutionMode::Live,
        runtime_authority: "blessed_workflow_activation_default".to_string(),
        dispatch_scope: "read_only_cognition_routing_verification_completion_authority_tooling"
            .to_string(),
        accepted_cluster_ids: vec![
            HarnessPromotionClusterId::Cognition,
            HarnessPromotionClusterId::RoutingModel,
            HarnessPromotionClusterId::VerificationOutput,
            HarnessPromotionClusterId::AuthorityTooling,
        ],
        component_kinds: vec![
            HarnessComponentKind::Planner,
            HarnessComponentKind::PromptAssembler,
            HarnessComponentKind::TaskState,
            HarnessComponentKind::UncertaintyGate,
            HarnessComponentKind::BudgetGate,
            HarnessComponentKind::CapabilitySequencer,
            HarnessComponentKind::ModelRouter,
            HarnessComponentKind::ModelCall,
            HarnessComponentKind::ToolRouter,
            HarnessComponentKind::PostconditionSynthesizer,
            HarnessComponentKind::Verifier,
            HarnessComponentKind::CompletionGate,
            HarnessComponentKind::ReceiptWriter,
            HarnessComponentKind::QualityLedger,
            HarnessComponentKind::OutputWriter,
            HarnessComponentKind::PolicyGate,
            HarnessComponentKind::DryRunSimulator,
            HarnessComponentKind::ApprovalGate,
        ],
        deferred_component_kinds: vec![
            HarnessComponentKind::McpProvider,
            HarnessComponentKind::McpToolCall,
            HarnessComponentKind::ToolCall,
            HarnessComponentKind::ConnectorCall,
            HarnessComponentKind::WalletCapability,
        ],
        handoff_validated_component_kinds: vec![HarnessComponentKind::OutputWriter],
        materialization_canary_component_kinds: vec![HarnessComponentKind::OutputWriter],
        source_boundary_ids: vec![
            "harness-canary-boundary:default-agent-harness:cognition".to_string(),
            "harness-canary-boundary:default-agent-harness:routing_model".to_string(),
            "harness-canary-boundary:default-agent-harness:verification_output".to_string(),
            "harness-canary-boundary:default-agent-harness:authority_tooling".to_string(),
        ],
        dispatch_node_attempt_ids: vec![
            "harness-default-dispatch:attempt-cognition".to_string(),
            "harness-default-dispatch:attempt-routing_model".to_string(),
            "harness-default-dispatch:attempt-verification_output".to_string(),
            "harness-default-dispatch:attempt-authority_tooling".to_string(),
            "harness-default-dispatch:attempt-planner_envelope".to_string(),
            "harness-default-dispatch:attempt-prompt_assembler_envelope".to_string(),
            "harness-default-dispatch:attempt-task_state_envelope".to_string(),
            "harness-default-dispatch:attempt-model_router_envelope".to_string(),
            "harness-default-dispatch:attempt-model_call_envelope".to_string(),
            "harness-default-dispatch:attempt-model_provider_call_canary".to_string(),
            "harness-default-dispatch:attempt-model_provider_gated_visible_output".to_string(),
            "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill"
                .to_string(),
            "harness-default-dispatch:attempt-read_only_source_router".to_string(),
            "harness-default-dispatch:attempt-read_only_capability_sequencer".to_string(),
            "harness-default-dispatch:attempt-read_only_tool_router".to_string(),
            "harness-default-dispatch:attempt-read_only_no_mutation_drill".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_policy_gate".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_tool_router".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_dry_run_simulator".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_destructive_denial".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_approval_gate".to_string(),
            "harness-default-dispatch:attempt-output_writer_handoff".to_string(),
            "harness-default-dispatch:attempt-output_writer_materialization_canary".to_string(),
            "harness-default-dispatch:attempt-output_writer_staged_write_canary".to_string(),
            "harness-default-dispatch:attempt-output_writer_visible_write_commit".to_string(),
        ],
        cognition_execution_attempt_ids: vec![
            "harness-default-dispatch:attempt-planner_envelope".to_string(),
            "harness-default-dispatch:attempt-prompt_assembler_envelope".to_string(),
            "harness-default-dispatch:attempt-task_state_envelope".to_string(),
        ],
        cognition_execution_receipt_ids: vec![
            "harness-default-dispatch:receipt-planner_envelope".to_string(),
            "harness-default-dispatch:receipt-prompt_assembler_envelope".to_string(),
            "harness-default-dispatch:receipt-task_state_envelope".to_string(),
        ],
        cognition_execution_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-planner_envelope".to_string(),
            "harness-default-dispatch:fixture-prompt_assembler_envelope".to_string(),
            "harness-default-dispatch:fixture-task_state_envelope".to_string(),
        ],
        model_execution_attempt_ids: vec![
            "harness-default-dispatch:attempt-model_router_envelope".to_string(),
            "harness-default-dispatch:attempt-model_call_envelope".to_string(),
            "harness-default-dispatch:attempt-model_provider_call_canary".to_string(),
            "harness-default-dispatch:attempt-model_provider_gated_visible_output".to_string(),
            "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill"
                .to_string(),
        ],
        model_execution_receipt_ids: vec![
            "harness-default-dispatch:receipt-model_router_envelope".to_string(),
            "harness-default-dispatch:receipt-model_call_envelope".to_string(),
            "harness-default-dispatch:receipt-model_provider_call_canary".to_string(),
            "harness-default-dispatch:receipt-model_provider_gated_visible_output".to_string(),
            "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill"
                .to_string(),
        ],
        model_execution_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-model_router_envelope".to_string(),
            "harness-default-dispatch:fixture-model_call_envelope".to_string(),
            "harness-default-dispatch:fixture-model_provider_call_canary".to_string(),
            "harness-default-dispatch:fixture-model_provider_gated_visible_output".to_string(),
            "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill"
                .to_string(),
        ],
        model_provider_canary_attempt_ids: vec![
            "harness-default-dispatch:attempt-model_provider_call_canary".to_string(),
        ],
        model_provider_canary_receipt_ids: vec![
            "harness-default-dispatch:receipt-model_provider_call_canary".to_string(),
        ],
        model_provider_canary_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-model_provider_call_canary".to_string(),
        ],
        model_provider_gated_visible_output_attempt_ids: vec![
            "harness-default-dispatch:attempt-model_provider_gated_visible_output".to_string(),
        ],
        model_provider_gated_visible_output_receipt_ids: vec![
            "harness-default-dispatch:receipt-model_provider_gated_visible_output".to_string(),
        ],
        model_provider_gated_visible_output_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-model_provider_gated_visible_output".to_string(),
        ],
        model_provider_gated_visible_output_rollback_drill_attempt_ids: vec![
            "harness-default-dispatch:attempt-model_provider_gated_visible_output_rollback_drill"
                .to_string(),
        ],
        model_provider_gated_visible_output_rollback_drill_receipt_ids: vec![
            "harness-default-dispatch:receipt-model_provider_gated_visible_output_rollback_drill"
                .to_string(),
        ],
        model_provider_gated_visible_output_rollback_drill_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-model_provider_gated_visible_output_rollback_drill"
                .to_string(),
        ],
        read_only_capability_routing_attempt_ids: vec![
            "harness-default-dispatch:attempt-read_only_source_router".to_string(),
            "harness-default-dispatch:attempt-read_only_capability_sequencer".to_string(),
            "harness-default-dispatch:attempt-read_only_tool_router".to_string(),
            "harness-default-dispatch:attempt-read_only_no_mutation_drill".to_string(),
        ],
        read_only_capability_routing_receipt_ids: vec![
            "harness-default-dispatch:receipt-read_only_source_router".to_string(),
            "harness-default-dispatch:receipt-read_only_capability_sequencer".to_string(),
            "harness-default-dispatch:receipt-read_only_tool_router".to_string(),
            "harness-default-dispatch:receipt-read_only_no_mutation_drill".to_string(),
        ],
        read_only_capability_routing_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-read_only_source_router".to_string(),
            "harness-default-dispatch:fixture-read_only_capability_sequencer".to_string(),
            "harness-default-dispatch:fixture-read_only_tool_router".to_string(),
            "harness-default-dispatch:fixture-read_only_no_mutation_drill".to_string(),
        ],
        output_writer_handoff_attempt_ids: vec![
            "harness-default-dispatch:attempt-output_writer_handoff".to_string(),
        ],
        output_writer_materialization_canary_attempt_ids: vec![
            "harness-default-dispatch:attempt-output_writer_materialization_canary".to_string(),
        ],
        output_writer_staged_write_canary_attempt_ids: vec![
            "harness-default-dispatch:attempt-output_writer_staged_write_canary".to_string(),
        ],
        output_writer_visible_write_attempt_ids: vec![
            "harness-default-dispatch:attempt-output_writer_visible_write_commit".to_string(),
        ],
        authority_tooling_live_dry_run_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_policy_gate".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_tool_router".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_dry_run_simulator".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_destructive_denial".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_approval_gate".to_string(),
        ],
        authority_tooling_gate_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_policy_gate".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_destructive_denial".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_approval_gate".to_string(),
        ],
        authority_tooling_gate_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_policy_gate".to_string(),
            "harness-default-dispatch:receipt-authority_tooling_destructive_denial".to_string(),
            "harness-default-dispatch:receipt-authority_tooling_approval_gate".to_string(),
        ],
        authority_tooling_gate_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_policy_gate".to_string(),
            "harness-default-dispatch:fixture-authority_tooling_destructive_denial".to_string(),
            "harness-default-dispatch:fixture-authority_tooling_approval_gate".to_string(),
        ],
        authority_tooling_policy_gate_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_policy_gate".to_string(),
        ],
        authority_tooling_policy_gate_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_policy_gate".to_string(),
        ],
        authority_tooling_policy_gate_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_policy_gate".to_string(),
        ],
        authority_tooling_destructive_denial_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_destructive_denial".to_string(),
        ],
        authority_tooling_destructive_denial_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_destructive_denial".to_string(),
        ],
        authority_tooling_destructive_denial_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_destructive_denial".to_string(),
        ],
        authority_tooling_approval_gate_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_approval_gate".to_string(),
        ],
        authority_tooling_approval_gate_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_approval_gate".to_string(),
        ],
        authority_tooling_approval_gate_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_approval_gate".to_string(),
        ],
        authority_tooling_read_only_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only"
                .to_string(),
            "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only".to_string(),
            "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only"
                .to_string(),
            "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only"
                .to_string(),
        ],
        authority_tooling_read_only_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_mcp_provider_read_only".to_string(),
            "harness-default-dispatch:receipt-authority_tooling_mcp_tool_call_read_only"
                .to_string(),
            "harness-default-dispatch:receipt-authority_tooling_tool_call_read_only".to_string(),
            "harness-default-dispatch:receipt-authority_tooling_connector_call_read_only"
                .to_string(),
            "harness-default-dispatch:receipt-authority_tooling_wallet_capability_read_only"
                .to_string(),
        ],
        authority_tooling_read_only_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_mcp_provider_read_only".to_string(),
            "harness-default-dispatch:fixture-authority_tooling_mcp_tool_call_read_only"
                .to_string(),
            "harness-default-dispatch:fixture-authority_tooling_tool_call_read_only".to_string(),
            "harness-default-dispatch:fixture-authority_tooling_connector_call_read_only"
                .to_string(),
            "harness-default-dispatch:fixture-authority_tooling_wallet_capability_read_only"
                .to_string(),
        ],
        authority_tooling_provider_catalog_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_mcp_provider_read_only".to_string(),
        ],
        authority_tooling_provider_catalog_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_mcp_provider_read_only".to_string(),
        ],
        authority_tooling_provider_catalog_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_mcp_provider_read_only".to_string(),
        ],
        authority_tooling_mcp_tool_catalog_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_mcp_tool_call_read_only"
                .to_string(),
        ],
        authority_tooling_mcp_tool_catalog_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_mcp_tool_call_read_only"
                .to_string(),
        ],
        authority_tooling_mcp_tool_catalog_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_mcp_tool_call_read_only"
                .to_string(),
        ],
        authority_tooling_native_tool_catalog_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_tool_call_read_only".to_string(),
        ],
        authority_tooling_native_tool_catalog_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_tool_call_read_only".to_string(),
        ],
        authority_tooling_native_tool_catalog_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_tool_call_read_only".to_string(),
        ],
        authority_tooling_connector_catalog_live_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_connector_call_read_only"
                .to_string(),
        ],
        authority_tooling_connector_catalog_live_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_connector_call_read_only"
                .to_string(),
        ],
        authority_tooling_connector_catalog_live_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_connector_call_read_only"
                .to_string(),
        ],
        authority_tooling_wallet_capability_live_dry_run_attempt_ids: vec![
            "harness-default-dispatch:attempt-authority_tooling_wallet_capability_read_only"
                .to_string(),
        ],
        authority_tooling_wallet_capability_live_dry_run_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_wallet_capability_read_only"
                .to_string(),
        ],
        authority_tooling_wallet_capability_live_dry_run_replay_fixture_refs: vec![
            "harness-default-dispatch:fixture-authority_tooling_wallet_capability_read_only"
                .to_string(),
        ],
        authority_tooling_read_only_component_kinds: vec![
            HarnessComponentKind::McpProvider,
            HarnessComponentKind::McpToolCall,
            HarnessComponentKind::ToolCall,
            HarnessComponentKind::ConnectorCall,
            HarnessComponentKind::WalletCapability,
        ],
        authority_tooling_mutation_deferred_component_kinds: vec![
            HarnessComponentKind::McpProvider,
            HarnessComponentKind::McpToolCall,
            HarnessComponentKind::ToolCall,
            HarnessComponentKind::ConnectorCall,
            HarnessComponentKind::WalletCapability,
        ],
        authority_tooling_denial_receipt_ids: vec![
            "harness-default-dispatch:receipt-authority_tooling_destructive_denial".to_string(),
        ],
        accepted_node_attempt_ids: vec!["harness-canary:attempt-planner".to_string()],
        node_attempt_ids: vec!["harness-default-dispatch:attempt-planner".to_string()],
        receipt_ids: vec!["harness-default-dispatch:receipt-planner".to_string()],
        replay_fixture_refs: vec!["harness-default-dispatch:fixture-planner".to_string()],
        executor_kind: "workflow_node_executor".to_string(),
        executor_ref: "crate::project::execute_workflow_harness_live_default_node".to_string(),
        synchronous: true,
        drives_runtime_decision: true,
        activation_id_gate_click_proof_present: true,
        activation_id_gate_click_proof_passed: true,
        activation_id_gate_click_proof_blockers: Vec::new(),
        default_dispatch_activation_blockers: Vec::new(),
        cognition_execution_mode: "workflow_synchronous_envelope".to_string(),
        cognition_execution_ready: true,
        prompt_assembly_mode: "workflow_synchronous_envelope".to_string(),
        prompt_assembly_prompt_hash: "sha256:prompt-final".to_string(),
        prompt_assembly_prompt_hash_matches: true,
        model_execution_mode: "workflow_synchronous_envelope".to_string(),
        model_execution_envelope_ready: true,
        model_execution_binding_id:
            "model-binding:default-agent-harness:workflow-default-model-route".to_string(),
        model_execution_binding_ready: true,
        model_execution_prompt_hash: "sha256:prompt-final".to_string(),
        model_execution_prompt_hash_matches: true,
        model_execution_output_hash: "sha256:visible-output".to_string(),
        model_execution_output_hash_matches: true,
        model_execution_provider_invocation_mode: "workflow_provider_canary".to_string(),
        model_execution_low_level_invocation_deferred: false,
        model_execution_fallback_selector: "legacy_runtime_model_invocation".to_string(),
        model_execution_latency_ms: 0,
        model_provider_canary_mode: "workflow_provider_canary".to_string(),
        model_provider_canary_ready: true,
        model_provider_canary_candidate_output_hash: "sha256:visible-output".to_string(),
        model_provider_canary_legacy_output_hash: "sha256:visible-output".to_string(),
        model_provider_canary_output_hash_matches: true,
        model_provider_canary_transcript_matches: true,
        model_provider_canary_fallback_retained: true,
        model_provider_canary_rollback_available: true,
        model_provider_gated_visible_output_mode: "workflow_provider_gated_visible_output"
            .to_string(),
        model_provider_gated_visible_output_enabled: true,
        model_provider_gated_visible_output_ready: true,
        model_provider_gated_visible_output_selected: true,
        model_provider_gated_visible_output_eligible: true,
        model_provider_gated_visible_output_scenario: "retained_no_tool_answer".to_string(),
        model_provider_gated_visible_output_cohort: "retained_read_only_no_tool".to_string(),
        model_provider_gated_visible_output_retained_read_only_no_tool: true,
        model_provider_gated_visible_output_required_scenario_set: vec![
            "retained_no_tool_answer".to_string(),
            "retained_repo_grounded_answer".to_string(),
            "retained_planning_without_mutation".to_string(),
            "retained_mermaid_rendering".to_string(),
            "retained_source_heavy_synthesis".to_string(),
            "retained_probe_behavior".to_string(),
            "retained_harness_dogfooding".to_string(),
        ],
        model_provider_gated_visible_output_scenario_coverage_key: Some(
            "retained_no_tool_answer".to_string(),
        ),
        model_provider_gated_visible_output_activation_flag:
            "AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT".to_string(),
        model_provider_gated_visible_output_activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID
            .to_string(),
        model_provider_gated_visible_output_authority: "workflow_model_provider_call".to_string(),
        model_provider_gated_visible_output_rollback_target: "legacy_runtime_model_invocation"
            .to_string(),
        model_provider_gated_visible_output_rollback_available: true,
        selected_visible_output_authority: "workflow_model_provider_call".to_string(),
        selected_visible_output_hash: "sha256:visible-output".to_string(),
        workflow_provider_visible_output_hash: "sha256:visible-output".to_string(),
        legacy_visible_output_hash: "sha256:visible-output".to_string(),
        legacy_visible_output_computed: true,
        legacy_visible_output_hash_matches_selected: true,
        selected_visible_output_authority_matches_transcript: true,
        visible_output_divergence_class: None,
        model_provider_gated_visible_output_rollback_drill_enabled: true,
        model_provider_gated_visible_output_rollback_drill_ready: true,
        model_provider_gated_visible_output_rollback_drill_failure_injected: true,
        model_provider_gated_visible_output_rollback_drill_injected_output_hash:
            "sha256:provider-output-divergence".to_string(),
        model_provider_gated_visible_output_rollback_drill_output_hash_diverges: true,
        model_provider_gated_visible_output_rollback_drill_divergence_class:
            "provider_output_hash_divergence".to_string(),
        model_provider_gated_visible_output_rollback_drill_fallback_authority:
            "legacy_runtime_model_invocation".to_string(),
        model_provider_gated_visible_output_rollback_drill_selected_authority:
            "legacy_runtime_model_invocation".to_string(),
        model_provider_gated_visible_output_rollback_drill_transcript_unchanged: true,
        model_provider_gated_visible_output_rollback_drill_rollback_executed: true,
        model_provider_gated_visible_output_rollback_drill_activation_blockers: vec![
            "model_provider_output_hash_divergence".to_string(),
        ],
        read_only_capability_routing_mode: "workflow_read_only_capability_routing".to_string(),
        read_only_capability_routing_ready: true,
        read_only_capability_routing_selected: true,
        read_only_capability_routing_eligible: true,
        read_only_capability_routing_scenario: "retained_repo_grounded_answer".to_string(),
        read_only_capability_routing_required_scenario_set: vec![
            "retained_repo_grounded_answer".to_string(),
            "retained_source_heavy_synthesis".to_string(),
            "retained_probe_behavior".to_string(),
        ],
        read_only_capability_routing_scenario_coverage_key: Some(
            "retained_repo_grounded_answer".to_string(),
        ),
        read_only_capability_routing_source_material_ready: true,
        read_only_capability_routing_no_mutation_ready: true,
        read_only_capability_routing_workflow_owned_node_kinds: vec![
            HarnessComponentKind::MemoryRead,
            HarnessComponentKind::CapabilitySequencer,
            HarnessComponentKind::ToolRouter,
            HarnessComponentKind::DryRunSimulator,
        ],
        output_authority: "blessed_workflow_activation_default".to_string(),
        output_writer_deferred: false,
        output_writer_status: "visible_write_committed".to_string(),
        output_writer_handoff_ready: true,
        output_writer_authority_transferred: true,
        output_writer_materialization_mode: "workflow_visible_transcript_write".to_string(),
        output_writer_materialization_canary_ready: true,
        output_writer_materialization_committed: true,
        output_writer_staged_write_mode: "isolated_checkpoint_blob".to_string(),
        output_writer_staged_write_canary_ready: true,
        output_writer_staged_write_persisted: true,
        output_writer_staged_write_committed: true,
        output_writer_staged_write_visible: false,
        output_writer_staged_write_excluded_from_visible_transcript: true,
        output_writer_staged_write_rollback_status: "deleted".to_string(),
        output_writer_staged_write_rollback_verified: true,
        output_writer_visible_write_mode: "workflow_visible_transcript_write".to_string(),
        output_writer_visible_write_ready: true,
        output_writer_visible_write_persisted: true,
        output_writer_visible_write_committed: true,
        output_writer_visible_write_visible: true,
        output_writer_visible_write_identity_checkpoint_persisted: true,
        output_writer_visible_write_legacy_duplicate_suppressed: true,
        authority_tooling_mode: "workflow_live_dry_run".to_string(),
        authority_tooling_ready: true,
        authority_tooling_policy_gate_ready: true,
        authority_tooling_tool_router_ready: true,
        authority_tooling_dry_run_simulator_ready: true,
        authority_tooling_approval_gate_ready: true,
        authority_tooling_gate_live_ready: true,
        authority_tooling_policy_gate_live_ready: true,
        authority_tooling_destructive_denial_live_ready: true,
        authority_tooling_approval_gate_live_ready: true,
        authority_tooling_read_only_route_accepted: true,
        authority_tooling_destructive_route_denied: true,
        authority_tooling_mutating_tool_calls_blocked: true,
        authority_tooling_side_effects_executed: false,
        authority_tooling_rollback_available: true,
        legacy_transcript_authority_retained: false,
        legacy_transcript_fallback_available: true,
        proposed_visible_output_hash: "sha256:visible-output".to_string(),
        actual_visible_output_hash: "sha256:visible-output".to_string(),
        output_hash_algorithm: "runtime_prompt_hash:v1".to_string(),
        output_hash_matches: true,
        output_hash_divergence: false,
        output_hash_divergence_count: 0,
        transcript_materialization_content_hash_matches: true,
        transcript_materialization_order_matches: true,
        transcript_materialization_receipt_binding_matches: true,
        transcript_materialization_target_matches: true,
        transcript_materialization_matches: true,
        transcript_materialization_divergence_count: 0,
        staged_transcript_write_content_hash_matches: true,
        staged_transcript_write_order_matches: true,
        staged_transcript_write_receipt_binding_matches: true,
        staged_transcript_write_target_matches: true,
        staged_transcript_write_matches: true,
        staged_transcript_write_divergence_count: 0,
        visible_transcript_write_content_hash_matches: true,
        visible_transcript_write_order_matches: true,
        visible_transcript_write_receipt_binding_matches: true,
        visible_transcript_write_target_matches: true,
        visible_transcript_write_matches: true,
        visible_transcript_write_divergence_count: 0,
        legacy_output_authority_retained: false,
        legacy_output_fallback_available: true,
        mutating_turns_blocked: true,
        rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        rollback_available: true,
        activation_blockers: Vec::new(),
        policy_decision:
            "accept_read_only_workflow_default_dispatch_with_authority_dry_run_and_visible_write"
                .to_string(),
        evidence_refs: vec!["runtime-evidence:default-runtime-dispatch".to_string()],
    }
}

fn default_harness_canary_execution_boundary_for_cluster(
    cluster_id: HarnessPromotionClusterId,
) -> HarnessCanaryExecutionBoundary {
    let component_kinds = match cluster_id {
        HarnessPromotionClusterId::Cognition => vec![
            HarnessComponentKind::Planner,
            HarnessComponentKind::PromptAssembler,
            HarnessComponentKind::TaskState,
            HarnessComponentKind::UncertaintyGate,
            HarnessComponentKind::BudgetGate,
            HarnessComponentKind::CapabilitySequencer,
        ],
        HarnessPromotionClusterId::VerificationOutput => vec![
            HarnessComponentKind::PostconditionSynthesizer,
            HarnessComponentKind::Verifier,
            HarnessComponentKind::CompletionGate,
            HarnessComponentKind::ReceiptWriter,
            HarnessComponentKind::QualityLedger,
            HarnessComponentKind::OutputWriter,
        ],
        HarnessPromotionClusterId::RoutingModel => vec![
            HarnessComponentKind::ModelRouter,
            HarnessComponentKind::ModelCall,
            HarnessComponentKind::ToolRouter,
        ],
        HarnessPromotionClusterId::AuthorityTooling => vec![
            HarnessComponentKind::PolicyGate,
            HarnessComponentKind::ApprovalGate,
            HarnessComponentKind::DryRunSimulator,
            HarnessComponentKind::McpProvider,
            HarnessComponentKind::McpToolCall,
            HarnessComponentKind::ToolCall,
            HarnessComponentKind::ConnectorCall,
            HarnessComponentKind::WalletCapability,
        ],
    };
    let cluster_slug = cluster_id.as_str();
    let failed_component = match cluster_id {
        HarnessPromotionClusterId::Cognition => HarnessComponentKind::TaskState,
        HarnessPromotionClusterId::VerificationOutput => HarnessComponentKind::Verifier,
        HarnessPromotionClusterId::RoutingModel => HarnessComponentKind::ModelRouter,
        HarnessPromotionClusterId::AuthorityTooling => HarnessComponentKind::PolicyGate,
    };
    HarnessCanaryExecutionBoundary {
        schema_version: "workflow.harness.canary-execution-boundary.v1".to_string(),
        boundary_id: format!("harness-canary-boundary:default-agent-harness:{cluster_slug}"),
        cluster_id,
        cluster_label: cluster_id.label().to_string(),
        selector_decision_id: "harness-selector:default-agent-harness:canary".to_string(),
        selected_selector: HarnessLiveHandoffSelector::BlessedWorkflowLiveCanary,
        production_default_selector: HarnessLiveHandoffSelector::LegacyRuntime,
        workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        execution_mode: HarnessExecutionMode::Live,
        runtime_authority: "blessed_workflow_activation_canary".to_string(),
        executor_kind: "workflow_node_executor".to_string(),
        executor_ref: "crate::project::execute_workflow_harness_canary_node".to_string(),
        synchronous: true,
        enforced_before_visible_output: true,
        canary_eligible: true,
        status: "passed".to_string(),
        component_kinds: component_kinds.clone(),
        executed_component_kinds: component_kinds.clone(),
        workflow_node_ids: component_kinds
            .iter()
            .map(|kind| format!("harness.{}", kind.as_str()))
            .collect(),
        node_attempt_ids: component_kinds
            .iter()
            .enumerate()
            .map(|(index, kind)| {
                format!(
                    "harness-canary:default:turn-1:{}:attempt-{}",
                    kind.as_str(),
                    index + 1
                )
            })
            .collect(),
        receipt_ids: component_kinds
            .iter()
            .map(|kind| format!("default:harness.{}:workflow-node-execution", kind.as_str()))
            .collect(),
        replay_fixture_refs: component_kinds
            .iter()
            .map(|kind| format!("runtime-evidence:default:canary-fixture:{}", kind.as_str()))
            .collect(),
        activation_blockers: Vec::new(),
        rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        rollback_available: true,
        rollback_drill: HarnessCanaryRollbackDrill {
            schema_version: "workflow.harness.canary-rollback-drill.v1".to_string(),
            drill_id: "harness-canary-rollback-drill:default".to_string(),
            selector_decision_id: "harness-selector:default-agent-harness:canary".to_string(),
            failure_injected: true,
            failed_node_id: format!("harness.{}.rollback_drill", failed_component.as_str()),
            cluster_id,
            failure_class: "deterministic_executor_failure".to_string(),
            observed_failure: true,
            rollback_executed: true,
            rollback_selector: HarnessLiveHandoffSelector::LegacyRuntime,
            fallback_authority: "existing_runtime_service".to_string(),
            rollback_target: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
            rollback_available: true,
            drill_status: "passed".to_string(),
            policy_decision: "rollback_to_legacy_runtime_on_workflow_executor_failure".to_string(),
            evidence_refs: vec![
                "runtime-evidence:default".to_string(),
                format!("rollback-target:{DEFAULT_AGENT_HARNESS_ACTIVATION_ID}"),
            ],
        },
        policy_decision: "allow_synchronous_workflow_node_canary_boundary".to_string(),
        evidence_refs: vec![format!("runtime-evidence:canary-boundary:{cluster_slug}")],
    }
}

pub fn default_harness_canary_execution_boundary() -> HarnessCanaryExecutionBoundary {
    default_harness_canary_execution_boundary_for_cluster(
        HarnessPromotionClusterId::VerificationOutput,
    )
}

pub fn default_harness_canary_execution_boundaries() -> Vec<HarnessCanaryExecutionBoundary> {
    vec![
        default_harness_canary_execution_boundary_for_cluster(HarnessPromotionClusterId::Cognition),
        default_harness_canary_execution_boundary_for_cluster(
            HarnessPromotionClusterId::RoutingModel,
        ),
        default_harness_canary_execution_boundary_for_cluster(
            HarnessPromotionClusterId::VerificationOutput,
        ),
        default_harness_canary_execution_boundary_for_cluster(
            HarnessPromotionClusterId::AuthorityTooling,
        ),
    ]
}

pub fn validate_harness_worker_binding(
    binding: &HarnessWorkerBinding,
) -> Result<(), HarnessBindingError> {
    if binding.harness_workflow_id.trim().is_empty() {
        return Err(HarnessBindingError::MissingWorkflowId);
    }
    if binding
        .harness_activation_id
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        return Err(HarnessBindingError::MissingActivationId);
    }
    if binding.harness_hash.trim().is_empty() {
        return Err(HarnessBindingError::MissingHash);
    }
    Ok(())
}

pub fn harness_component_kind_for_action_target(target: &ActionTarget) -> HarnessComponentKind {
    match target {
        ActionTarget::ModelRespond | ActionTarget::ModelEmbed | ActionTarget::ModelRerank => {
            HarnessComponentKind::ModelCall
        }
        ActionTarget::WalletSign | ActionTarget::WalletSend => {
            HarnessComponentKind::WalletCapability
        }
        ActionTarget::FsRead | ActionTarget::WebRetrieve | ActionTarget::BrowserInspect => {
            HarnessComponentKind::ToolCall
        }
        ActionTarget::FsWrite | ActionTarget::ClipboardWrite => HarnessComponentKind::ToolCall,
        ActionTarget::Custom(name) => harness_component_kind_for_tool_name(name),
        _ => HarnessComponentKind::ToolCall,
    }
}

pub fn harness_component_kind_for_tool_name(tool_name: &str) -> HarnessComponentKind {
    let normalized = tool_name.trim().to_ascii_lowercase();
    if normalized.starts_with("mcp__") || normalized.contains("__mcp_") {
        return HarnessComponentKind::McpToolCall;
    }
    if normalized.starts_with("memory__") {
        return if normalized.contains("write") || normalized.contains("save") {
            HarnessComponentKind::MemoryWrite
        } else {
            HarnessComponentKind::MemoryRead
        };
    }
    if normalized.starts_with("model__")
        || normalized.starts_with("llm__")
        || normalized.starts_with("inference__")
    {
        return HarnessComponentKind::ModelCall;
    }
    if normalized.starts_with("wallet__") {
        return HarnessComponentKind::WalletCapability;
    }
    if normalized.starts_with("connector__")
        || normalized.starts_with("gmail__")
        || normalized.starts_with("calendar__")
        || normalized.starts_with("mail__")
        || normalized.starts_with("google_workspace__")
    {
        return HarnessComponentKind::ConnectorCall;
    }
    HarnessComponentKind::ToolCall
}

pub fn harness_component_kind_for_policy_decision(
    policy_decision: &str,
    gate_state: &str,
) -> HarnessComponentKind {
    let decision = policy_decision.to_ascii_lowercase();
    let gate = gate_state.to_ascii_lowercase();
    if decision.contains("approval")
        || gate.contains("pending")
        || gate.contains("approved")
        || gate.contains("denied")
        || gate.contains("required")
    {
        HarnessComponentKind::ApprovalGate
    } else {
        HarnessComponentKind::PolicyGate
    }
}

fn workload_tool_name(receipt: &WorkloadReceipt) -> &str {
    match receipt {
        WorkloadReceipt::Exec(receipt) => &receipt.tool_name,
        WorkloadReceipt::FsWrite(receipt) => &receipt.tool_name,
        WorkloadReceipt::NetFetch(receipt) => &receipt.tool_name,
        WorkloadReceipt::WebRetrieve(receipt) => &receipt.tool_name,
        WorkloadReceipt::MemoryRetrieve(receipt) => &receipt.tool_name,
        WorkloadReceipt::Inference(receipt) => &receipt.tool_name,
        WorkloadReceipt::Media(receipt) => &receipt.tool_name,
        WorkloadReceipt::ModelLifecycle(receipt) => &receipt.tool_name,
        WorkloadReceipt::Worker(receipt) => &receipt.tool_name,
        WorkloadReceipt::ParentPlaybook(receipt) => &receipt.tool_name,
        WorkloadReceipt::Adapter(receipt) => &receipt.tool_name,
    }
}

fn workload_component_kind(receipt: &WorkloadReceipt) -> HarnessComponentKind {
    match receipt {
        WorkloadReceipt::Inference(_) => HarnessComponentKind::ModelCall,
        WorkloadReceipt::ModelLifecycle(_) => HarnessComponentKind::ModelRouter,
        WorkloadReceipt::MemoryRetrieve(_) => HarnessComponentKind::MemoryRead,
        WorkloadReceipt::Worker(_) => HarnessComponentKind::MergeJudge,
        WorkloadReceipt::ParentPlaybook(_) => HarnessComponentKind::Planner,
        WorkloadReceipt::Adapter(receipt) => match &receipt.kind {
            AdapterKind::Mcp => HarnessComponentKind::McpToolCall,
            AdapterKind::Connector => HarnessComponentKind::ConnectorCall,
            _ => harness_component_kind_for_tool_name(&receipt.tool_name),
        },
        other => harness_component_kind_for_tool_name(workload_tool_name(other)),
    }
}

fn receipt_binding(
    component_kind: HarnessComponentKind,
    event_kind: impl Into<String>,
    receipt_id: impl Into<String>,
    step_index: Option<u32>,
    evidence_refs: Vec<String>,
    decision_reason: impl Into<String>,
) -> HarnessReceiptBinding {
    HarnessReceiptBinding {
        harness_workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        harness_activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        workflow_node_id: component_kind.workflow_node_id(),
        component_id: component_kind.component_id(),
        component_kind,
        event_kind: event_kind.into(),
        receipt_id: receipt_id.into(),
        step_index,
        evidence_refs,
        decision_reason: decision_reason.into(),
    }
}

pub fn default_harness_receipt_binding_for_workload(
    event: &WorkloadReceiptEvent,
) -> HarnessReceiptBinding {
    let component_kind = workload_component_kind(&event.receipt);
    receipt_binding(
        component_kind,
        "KernelEvent::WorkloadReceipt",
        format!("workload:{}:{}", event.step_index, event.workload_id),
        Some(event.step_index),
        vec![
            format!("workload_id:{}", event.workload_id),
            format!("tool:{}", workload_tool_name(&event.receipt)),
        ],
        "typed workload receipt mapped to default harness component",
    )
}

pub fn default_harness_receipt_binding_for_routing(
    receipt: &RoutingReceiptEvent,
) -> HarnessReceiptBinding {
    let component_kind =
        harness_component_kind_for_policy_decision(&receipt.policy_decision, &receipt.gate_state);
    receipt_binding(
        component_kind,
        "KernelEvent::RoutingReceipt",
        format!("routing:{}:{}", receipt.step_index, receipt.intent_hash),
        Some(receipt.step_index),
        vec![
            format!("intent_hash:{}", receipt.intent_hash),
            format!("policy_decision:{}", receipt.policy_decision),
            format!("tool:{}", receipt.tool_name),
        ],
        "routing decision mapped to policy or approval gate",
    )
}

pub fn default_harness_receipt_binding_for_execution_contract(
    receipt: &ExecutionContractReceiptEvent,
) -> HarnessReceiptBinding {
    let stage = receipt.stage.to_ascii_lowercase();
    let component_kind = match stage.as_str() {
        "provider_selection" => HarnessComponentKind::ToolRouter,
        "verification" => HarnessComponentKind::Verifier,
        "completion_gate" => HarnessComponentKind::CompletionGate,
        "execution" => HarnessComponentKind::ToolCall,
        _ => HarnessComponentKind::ReceiptWriter,
    };
    receipt_binding(
        component_kind,
        "KernelEvent::ExecutionContractReceipt",
        format!(
            "cec:{}:{}:{}",
            receipt.step_index, receipt.stage, receipt.key
        ),
        Some(receipt.step_index),
        vec![
            format!("intent_id:{}", receipt.intent_id),
            format!("evidence_commit_hash:{}", receipt.evidence_commit_hash),
        ],
        "execution contract receipt mapped by lifecycle stage",
    )
}

pub fn default_harness_receipt_binding_for_plan(
    receipt: &PlanReceiptEvent,
) -> HarnessReceiptBinding {
    let plan_hash = receipt
        .plan_hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    receipt_binding(
        HarnessComponentKind::Planner,
        "KernelEvent::PlanReceipt",
        format!("plan:{plan_hash}"),
        None,
        vec![
            format!("selected_route:{}", receipt.selected_route),
            format!("workers:{}", receipt.worker_graph.len()),
        ],
        "planner receipt mapped to planner component",
    )
}

pub fn default_harness_node_attempt_for_receipt(
    binding: &HarnessReceiptBinding,
    execution_mode: HarnessExecutionMode,
    attempt_index: u32,
    status: HarnessNodeAttemptStatus,
) -> HarnessNodeAttemptRecord {
    let component = default_harness_component_spec(binding.component_kind);
    HarnessNodeAttemptRecord {
        attempt_id: format!(
            "{}:{}:{}",
            binding.workflow_node_id, attempt_index, binding.receipt_id
        ),
        harness_workflow_id: binding.harness_workflow_id.clone(),
        harness_activation_id: binding.harness_activation_id.clone(),
        harness_hash: binding.harness_hash.clone(),
        workflow_node_id: binding.workflow_node_id.clone(),
        component_id: binding.component_id.clone(),
        component_kind: binding.component_kind,
        execution_mode,
        readiness: component.readiness,
        attempt_index,
        status,
        input_hash: None,
        output_hash: None,
        error_class: None,
        policy_decision: binding
            .evidence_refs
            .iter()
            .find_map(|entry| entry.strip_prefix("policy_decision:").map(str::to_string)),
        started_at_ms: None,
        duration_ms: None,
        receipt_ids: vec![binding.receipt_id.clone()],
        evidence_refs: binding.evidence_refs.clone(),
        replay: default_harness_replay_envelope(binding.component_kind),
    }
}

pub fn default_harness_shadow_run_for_attempts(
    run_id: impl Into<String>,
    source_session_id: Option<String>,
    live_turn_id: Option<String>,
    node_attempts: Vec<HarnessNodeAttemptRecord>,
    comparisons: Vec<HarnessShadowComparison>,
    evidence_refs: Vec<String>,
) -> HarnessShadowRun {
    let blocking_divergence_count = comparisons
        .iter()
        .filter(|comparison| comparison.blocking)
        .count() as u32;
    let unclassified_divergence_count = comparisons
        .iter()
        .filter(|comparison| comparison.divergence == HarnessDivergenceClass::Unclassified)
        .count() as u32;
    HarnessShadowRun {
        schema_version: "ioi.agent-harness.shadow-run.v1".to_string(),
        run_id: run_id.into(),
        harness_workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        harness_activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        source_session_id,
        live_turn_id,
        execution_mode: HarnessExecutionMode::Shadow,
        node_attempts,
        comparisons,
        blocking_divergence_count,
        unclassified_divergence_count,
        promotion_blocked: blocking_divergence_count > 0 || unclassified_divergence_count > 0,
        evidence_refs,
    }
}

pub fn default_harness_gated_cluster_run_for_shadow_run(
    cluster_id: HarnessPromotionClusterId,
    shadow_run: &HarnessShadowRun,
) -> HarnessGatedClusterRun {
    let component_kinds = promotion_cluster_components(cluster_id);
    let mut node_attempt_ids = Vec::new();
    let mut receipt_ids = Vec::new();
    let mut replay_fixture_refs = Vec::new();
    let mut activation_blockers = Vec::new();

    for component_kind in &component_kinds {
        let attempts = shadow_run
            .node_attempts
            .iter()
            .filter(|attempt| attempt.component_kind == *component_kind)
            .collect::<Vec<_>>();
        if attempts.is_empty() {
            activation_blockers.push(format!("missing_attempt:{}", component_kind.as_str()));
            continue;
        }
        for attempt in attempts {
            node_attempt_ids.push(attempt.attempt_id.clone());
            receipt_ids.extend(attempt.receipt_ids.clone());
            if let Some(fixture_ref) = attempt.replay.fixture_ref.clone() {
                replay_fixture_refs.push(fixture_ref);
            } else {
                activation_blockers.push(format!(
                    "missing_replay_fixture:{}",
                    component_kind.as_str()
                ));
            }
            if !matches!(
                attempt.readiness,
                HarnessComponentReadiness::ShadowReady | HarnessComponentReadiness::LiveReady
            ) {
                activation_blockers.push(format!(
                    "readiness_below_shadow:{}",
                    component_kind.as_str()
                ));
            }
            if attempt.receipt_ids.is_empty() {
                activation_blockers.push(format!("missing_receipt:{}", component_kind.as_str()));
            }
        }
    }

    if shadow_run.blocking_divergence_count > 0 {
        activation_blockers.push("blocking_shadow_divergence".to_string());
    }
    if shadow_run.unclassified_divergence_count > 0 {
        activation_blockers.push("unclassified_shadow_divergence".to_string());
    }

    node_attempt_ids.sort();
    node_attempt_ids.dedup();
    receipt_ids.sort();
    receipt_ids.dedup();
    replay_fixture_refs.sort();
    replay_fixture_refs.dedup();
    activation_blockers.sort();
    activation_blockers.dedup();

    let promotion_blocked = !activation_blockers.is_empty();
    HarnessGatedClusterRun {
        schema_version: "ioi.agent-harness.gated-cluster-run.v1".to_string(),
        run_id: format!("{}:{}:gated", shadow_run.run_id, cluster_id.as_str()),
        cluster_id,
        cluster_label: cluster_id.label().to_string(),
        harness_workflow_id: shadow_run.harness_workflow_id.clone(),
        harness_activation_id: shadow_run.harness_activation_id.clone(),
        harness_hash: shadow_run.harness_hash.clone(),
        execution_mode: HarnessExecutionMode::Gated,
        status: if promotion_blocked {
            HarnessClusterPromotionStatus::Blocked
        } else {
            HarnessClusterPromotionStatus::Gated
        },
        component_kinds,
        shadow_run_id: shadow_run.run_id.clone(),
        node_attempt_ids,
        receipt_ids,
        replay_fixture_refs,
        activation_blockers,
        gate_decision: if promotion_blocked {
            "block_promotion".to_string()
        } else {
            "allow_live_runtime_passthrough".to_string()
        },
        rollback_target: "shadow".to_string(),
        canary_status: if promotion_blocked {
            "not_started".to_string()
        } else {
            "passed".to_string()
        },
        promotion_blocked,
        evidence_refs: shadow_run.evidence_refs.clone(),
    }
}

pub fn compare_harness_live_shadow_attempts(
    live: &HarnessNodeAttemptRecord,
    shadow: &HarnessNodeAttemptRecord,
) -> HarnessShadowComparison {
    let mut evidence_refs = live.evidence_refs.clone();
    evidence_refs.extend(shadow.evidence_refs.clone());
    evidence_refs.sort();
    evidence_refs.dedup();

    let (divergence, blocking, summary) = if live.workflow_node_id != shadow.workflow_node_id
        || live.component_kind != shadow.component_kind
    {
        (
            HarnessDivergenceClass::BehavioralRegression,
            true,
            "live and shadow attempts resolved to different harness components".to_string(),
        )
    } else if live.receipt_ids.is_empty() || shadow.receipt_ids.is_empty() {
        (
            HarnessDivergenceClass::MissingReceipt,
            true,
            "live or shadow attempt is missing receipt binding".to_string(),
        )
    } else if live.policy_decision != shadow.policy_decision {
        (
            HarnessDivergenceClass::PolicyDivergence,
            true,
            "live and shadow attempts disagreed on policy decision".to_string(),
        )
    } else if live.output_hash != shadow.output_hash {
        (
            HarnessDivergenceClass::OutputDivergence,
            true,
            "live and shadow attempts disagreed on output hash".to_string(),
        )
    } else {
        (
            HarnessDivergenceClass::None,
            false,
            "live and shadow attempts match for harness promotion purposes".to_string(),
        )
    };

    HarnessShadowComparison {
        workflow_node_id: live.workflow_node_id.clone(),
        component_kind: live.component_kind,
        live_attempt_id: live.attempt_id.clone(),
        shadow_attempt_id: shadow.attempt_id.clone(),
        divergence,
        blocking,
        summary,
        evidence_refs,
    }
}

fn harness_enum_from_str<T>(value: &str) -> Option<T>
where
    T: DeserializeOwned,
{
    serde_json::from_value(Value::String(value.to_string())).ok()
}

fn harness_optional_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn harness_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn harness_replay_envelope_from_camel_value(value: Option<&Value>) -> HarnessReplayEnvelope {
    let replay = value.unwrap_or(&Value::Null);
    let deterministic = replay
        .get("deterministicEnvelope")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let determinism = replay
        .get("determinism")
        .and_then(Value::as_str)
        .and_then(harness_enum_from_str)
        .unwrap_or(if deterministic {
            HarnessReplayDeterminism::Deterministic
        } else {
            HarnessReplayDeterminism::Nondeterministic
        });
    HarnessReplayEnvelope {
        deterministic_envelope: deterministic,
        captures_input: replay
            .get("capturesInput")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        captures_output: replay
            .get("capturesOutput")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        captures_policy_decision: replay
            .get("capturesPolicyDecision")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        fixture_ref: harness_optional_string(replay, "fixtureRef"),
        determinism,
        nondeterminism_reason: harness_optional_string(replay, "nondeterminismReason"),
        redaction_policy: harness_optional_string(replay, "redactionPolicy")
            .unwrap_or_else(|| "runtime_redacted".to_string()),
    }
}

pub fn harness_node_attempt_record_from_camel_value(
    attempt: &Value,
) -> Option<HarnessNodeAttemptRecord> {
    let component_kind: HarnessComponentKind = attempt
        .get("componentKind")
        .and_then(Value::as_str)
        .and_then(harness_enum_from_str)?;
    let execution_mode: HarnessExecutionMode = attempt
        .get("executionMode")
        .and_then(Value::as_str)
        .and_then(harness_enum_from_str)?;
    let readiness: HarnessComponentReadiness = attempt
        .get("readiness")
        .and_then(Value::as_str)
        .and_then(harness_enum_from_str)?;
    let status: HarnessNodeAttemptStatus = attempt
        .get("status")
        .and_then(Value::as_str)
        .and_then(harness_enum_from_str)?;
    let attempt_index = attempt
        .get("attemptIndex")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(u32::MAX as u64) as u32;
    Some(HarnessNodeAttemptRecord {
        attempt_id: harness_optional_string(attempt, "attemptId")?,
        harness_workflow_id: harness_optional_string(attempt, "harnessWorkflowId")
            .unwrap_or_else(|| DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string()),
        harness_activation_id: harness_optional_string(attempt, "harnessActivationId")
            .unwrap_or_else(|| DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string()),
        harness_hash: harness_optional_string(attempt, "harnessHash")
            .unwrap_or_else(|| DEFAULT_AGENT_HARNESS_HASH.to_string()),
        workflow_node_id: harness_optional_string(attempt, "workflowNodeId")?,
        component_id: harness_optional_string(attempt, "componentId")
            .unwrap_or_else(|| component_kind.component_id()),
        component_kind,
        execution_mode,
        readiness,
        attempt_index,
        status,
        input_hash: harness_optional_string(attempt, "inputHash"),
        output_hash: harness_optional_string(attempt, "outputHash"),
        error_class: harness_optional_string(attempt, "errorClass"),
        policy_decision: harness_optional_string(attempt, "policyDecision"),
        started_at_ms: attempt.get("startedAtMs").and_then(Value::as_u64),
        duration_ms: attempt.get("durationMs").and_then(Value::as_u64),
        receipt_ids: harness_string_array(attempt.get("receiptIds")),
        evidence_refs: harness_string_array(attempt.get("evidenceRefs")),
        replay: harness_replay_envelope_from_camel_value(attempt.get("replay")),
    })
}

pub fn harness_shadow_comparison_camel_value(comparison: &HarnessShadowComparison) -> Value {
    json!({
        "workflowNodeId": &comparison.workflow_node_id,
        "componentKind": comparison.component_kind.as_str(),
        "liveAttemptId": &comparison.live_attempt_id,
        "shadowAttemptId": &comparison.shadow_attempt_id,
        "divergence": comparison.divergence.as_str(),
        "blocking": comparison.blocking,
        "summary": &comparison.summary,
        "evidenceRefs": &comparison.evidence_refs,
    })
}

pub fn harness_gated_cluster_status_as_str(status: HarnessClusterPromotionStatus) -> &'static str {
    match status {
        HarnessClusterPromotionStatus::ShadowReady => "shadow_ready",
        HarnessClusterPromotionStatus::Gated => "gated",
        HarnessClusterPromotionStatus::Blocked => "blocked",
        HarnessClusterPromotionStatus::Live => "live",
    }
}

pub fn harness_gated_cluster_run_camel_value(run: &HarnessGatedClusterRun) -> Value {
    let component_kinds = run
        .component_kinds
        .iter()
        .map(|component_kind| component_kind.as_str())
        .collect::<Vec<_>>();
    json!({
        "schemaVersion": &run.schema_version,
        "runId": &run.run_id,
        "clusterId": run.cluster_id.as_str(),
        "clusterLabel": &run.cluster_label,
        "harnessWorkflowId": &run.harness_workflow_id,
        "harnessActivationId": &run.harness_activation_id,
        "harnessHash": &run.harness_hash,
        "executionMode": run.execution_mode.as_str(),
        "status": harness_gated_cluster_status_as_str(run.status),
        "componentKinds": component_kinds,
        "shadowRunId": &run.shadow_run_id,
        "nodeAttemptIds": &run.node_attempt_ids,
        "receiptIds": &run.receipt_ids,
        "replayFixtureRefs": &run.replay_fixture_refs,
        "activationBlockers": &run.activation_blockers,
        "gateDecision": &run.gate_decision,
        "rollbackTarget": &run.rollback_target,
        "rollbackAvailable": true,
        "canaryStatus": &run.canary_status,
        "promotionBlocked": run.promotion_blocked,
        "evidenceRefs": &run.evidence_refs,
    })
}

#[cfg(test)]
#[path = "harness/tests.rs"]
mod tests;
