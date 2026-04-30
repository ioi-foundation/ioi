#![allow(missing_docs)]

use crate::app::action::ActionTarget;
use crate::app::adapter::AdapterKind;
use crate::app::events::{
    ExecutionContractReceiptEvent, PlanReceiptEvent, RoutingReceiptEvent, WorkloadReceipt,
    WorkloadReceiptEvent,
};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_AGENT_HARNESS_WORKFLOW_ID: &str = "default-agent-harness";
pub const DEFAULT_AGENT_HARNESS_VERSION: &str = "2026.04.default-harness.v1";
pub const DEFAULT_AGENT_HARNESS_HASH: &str = "sha256:default-agent-harness-component-projection-v1";
pub const DEFAULT_AGENT_HARNESS_ACTIVATION_ID: &str =
    "activation:default-agent-harness:blessed-readonly";

pub const HARNESS_COMPONENT_VERSION_V1: &str = "1.0.0";
pub const HARNESS_INPUT_SCHEMA_ID: &str = "ioi.agent-harness.input.v1";
pub const HARNESS_OUTPUT_SCHEMA_ID: &str = "ioi.agent-harness.output.v1";
pub const HARNESS_ERROR_SCHEMA_ID: &str = "ioi.agent-harness.error.v1";

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum HarnessComponentKind {
    Planner,
    ModelRouter,
    ModelCall,
    ToolRouter,
    ToolCall,
    McpProvider,
    McpToolCall,
    ConnectorCall,
    PolicyGate,
    ApprovalGate,
    WalletCapability,
    MemoryRead,
    MemoryWrite,
    Verifier,
    OutputWriter,
    ReceiptWriter,
    RetryPolicy,
    RepairLoop,
    MergeJudge,
    CompletionGate,
}

impl HarnessComponentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planner => "planner",
            Self::ModelRouter => "model_router",
            Self::ModelCall => "model_call",
            Self::ToolRouter => "tool_router",
            Self::ToolCall => "tool_call",
            Self::McpProvider => "mcp_provider",
            Self::McpToolCall => "mcp_tool_call",
            Self::ConnectorCall => "connector_call",
            Self::PolicyGate => "policy_gate",
            Self::ApprovalGate => "approval_gate",
            Self::WalletCapability => "wallet_capability",
            Self::MemoryRead => "memory_read",
            Self::MemoryWrite => "memory_write",
            Self::Verifier => "verifier",
            Self::OutputWriter => "output_writer",
            Self::ReceiptWriter => "receipt_writer",
            Self::RetryPolicy => "retry_policy",
            Self::RepairLoop => "repair_loop",
            Self::MergeJudge => "merge_judge",
            Self::CompletionGate => "completion_gate",
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
            Self::Planner => "crates/services/src/agentic/runtime/service/step/planner",
            Self::ModelRouter => "crates/services/src/agentic/runtime/service/step/cognition/router.rs",
            Self::ModelCall => "crates/services/src/agentic/runtime/service/handler/execution/handlers/model.rs",
            Self::ToolRouter => "crates/services/src/agentic/runtime/service/handler/execution/execution/action_execution.rs",
            Self::ToolCall => "crates/services/src/agentic/runtime/service/handler/execution",
            Self::McpProvider => "crates/services/src/agentic/runtime/tools/mcp.rs",
            Self::McpToolCall => "crates/services/src/agentic/runtime/tools/mcp.rs",
            Self::ConnectorCall => "crates/services/src/agentic/runtime/connectors",
            Self::PolicyGate => "crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs",
            Self::ApprovalGate => "crates/services/src/agentic/runtime/service/handler/approvals.rs",
            Self::WalletCapability => "crates/services/src/agentic/runtime/kernel/capability.rs",
            Self::MemoryRead | Self::MemoryWrite => "crates/services/src/agentic/runtime/service/memory",
            Self::Verifier => "crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs",
            Self::OutputWriter => "crates/services/src/agentic/runtime/service/step/queue/processing/completion_receipts.rs",
            Self::ReceiptWriter => "crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs",
            Self::RetryPolicy => "crates/services/src/agentic/runtime/service/step/anti_loop",
            Self::RepairLoop => "crates/services/src/agentic/runtime/service/step/action/processing/repair",
            Self::MergeJudge => "crates/services/src/agentic/runtime/service/lifecycle/worker_results/merge.rs",
            Self::CompletionGate => "crates/services/src/agentic/runtime/service/step/browser_completion.rs",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Planner => "Planner",
            Self::ModelRouter => "Model router",
            Self::ModelCall => "Model call",
            Self::ToolRouter => "Tool router",
            Self::ToolCall => "Tool call",
            Self::McpProvider => "MCP provider",
            Self::McpToolCall => "MCP tool invocation",
            Self::ConnectorCall => "Connector call",
            Self::PolicyGate => "Policy and firewall gate",
            Self::ApprovalGate => "Approval gate",
            Self::WalletCapability => "Wallet capability request",
            Self::MemoryRead => "Memory read",
            Self::MemoryWrite => "Memory write",
            Self::Verifier => "Verifier",
            Self::OutputWriter => "Output writer",
            Self::ReceiptWriter => "Receipt writer",
            Self::RetryPolicy => "Retry policy",
            Self::RepairLoop => "Repair loop",
            Self::MergeJudge => "Merge and judge",
            Self::CompletionGate => "Completion gate",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessSlotKind {
    ModelPolicy,
    ToolGrantPolicy,
    VerifierPolicy,
    ApprovalPolicy,
    OutputPolicy,
    MemoryPolicy,
    RetryRepairPolicy,
}

impl HarnessSlotKind {
    pub fn slot_id(self) -> &'static str {
        match self {
            Self::ModelPolicy => "slot.model-policy",
            Self::ToolGrantPolicy => "slot.tool-grants",
            Self::VerifierPolicy => "slot.verifier",
            Self::ApprovalPolicy => "slot.approval",
            Self::OutputPolicy => "slot.output-policy",
            Self::MemoryPolicy => "slot.memory-policy",
            Self::RetryRepairPolicy => "slot.retry-repair",
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
    pub node_id: String,
    pub component_id: String,
    pub component_version: String,
    pub component_kind: HarnessComponentKind,
    pub kernel_ref: String,
    pub slot_ids: Vec<String>,
    pub deterministic_envelope: bool,
    pub event_kinds: Vec<String>,
    pub evidence_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessWorkerBinding {
    pub harness_workflow_id: String,
    pub harness_activation_id: Option<String>,
    pub harness_hash: String,
    pub source: String,
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

const DEFAULT_HARNESS_FLOW: [HarnessComponentKind; 20] = [
    HarnessComponentKind::Planner,
    HarnessComponentKind::ModelRouter,
    HarnessComponentKind::ModelCall,
    HarnessComponentKind::ToolRouter,
    HarnessComponentKind::PolicyGate,
    HarnessComponentKind::ApprovalGate,
    HarnessComponentKind::WalletCapability,
    HarnessComponentKind::McpProvider,
    HarnessComponentKind::McpToolCall,
    HarnessComponentKind::ToolCall,
    HarnessComponentKind::ConnectorCall,
    HarnessComponentKind::MemoryRead,
    HarnessComponentKind::MemoryWrite,
    HarnessComponentKind::Verifier,
    HarnessComponentKind::RetryPolicy,
    HarnessComponentKind::RepairLoop,
    HarnessComponentKind::MergeJudge,
    HarnessComponentKind::CompletionGate,
    HarnessComponentKind::ReceiptWriter,
    HarnessComponentKind::OutputWriter,
];

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn component_scope(kind: HarnessComponentKind) -> Vec<String> {
    match kind {
        HarnessComponentKind::Planner => strings(&["reasoning.read", "session.state.read"]),
        HarnessComponentKind::ModelRouter => strings(&["model.route"]),
        HarnessComponentKind::ModelCall => strings(&["model.invoke"]),
        HarnessComponentKind::ToolRouter => strings(&["tool.route", "capability.read"]),
        HarnessComponentKind::ToolCall => strings(&["tool.invoke"]),
        HarnessComponentKind::McpProvider => strings(&["mcp.provider.read", "mcp.catalog.read"]),
        HarnessComponentKind::McpToolCall => strings(&["mcp.tool.invoke"]),
        HarnessComponentKind::ConnectorCall => strings(&["connector.invoke"]),
        HarnessComponentKind::PolicyGate => strings(&["policy.evaluate", "capability.lease"]),
        HarnessComponentKind::ApprovalGate => strings(&["approval.request"]),
        HarnessComponentKind::WalletCapability => strings(&["wallet.request", "capability.grant"]),
        HarnessComponentKind::MemoryRead => strings(&["memory.read"]),
        HarnessComponentKind::MemoryWrite => strings(&["memory.write"]),
        HarnessComponentKind::Verifier => strings(&["verification.run"]),
        HarnessComponentKind::OutputWriter => strings(&["output.write"]),
        HarnessComponentKind::ReceiptWriter => strings(&["receipt.write"]),
        HarnessComponentKind::RetryPolicy => strings(&["retry.evaluate"]),
        HarnessComponentKind::RepairLoop => strings(&["repair.propose"]),
        HarnessComponentKind::MergeJudge => strings(&["judgement.run"]),
        HarnessComponentKind::CompletionGate => strings(&["completion.evaluate"]),
    }
}

fn component_events(kind: HarnessComponentKind) -> Vec<String> {
    match kind {
        HarnessComponentKind::Planner => strings(&["PlanReceipt", "KernelEvent::PlanReceipt"]),
        HarnessComponentKind::ModelRouter => {
            strings(&["RoutingReceipt", "KernelEvent::RoutingReceipt"])
        }
        HarnessComponentKind::ModelCall => {
            strings(&["WorkloadReceipt", "WorkloadReceipt::Inference"])
        }
        HarnessComponentKind::ToolRouter => strings(&["RoutingReceipt", "ActionDispatchPrepared"]),
        HarnessComponentKind::ToolCall => strings(&["AgentActionResult", "WorkloadReceipt"]),
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
        HarnessComponentKind::Verifier => {
            strings(&["ExecutionContractReceipt", "VerificationReceipt"])
        }
        HarnessComponentKind::OutputWriter => strings(&["OutputWritten", "AgentActionResult"]),
        HarnessComponentKind::ReceiptWriter => {
            strings(&["ExecutionContractReceipt", "PlanReceipt", "WorkloadReceipt"])
        }
        HarnessComponentKind::RetryPolicy => strings(&["RetryScheduled", "RetryExhausted"]),
        HarnessComponentKind::RepairLoop => {
            strings(&["RepairAttemptStarted", "RepairAttemptCompleted"])
        }
        HarnessComponentKind::MergeJudge => strings(&["MergeReceipt", "JudgementReceipt"]),
        HarnessComponentKind::CompletionGate => strings(&["CompletionGateReceipt", "PlanReceipt"]),
    }
}

fn component_evidence(kind: HarnessComponentKind) -> Vec<String> {
    match kind {
        HarnessComponentKind::Planner => {
            strings(&["plan_id", "planner_policy_hash", "chosen_step_reason"])
        }
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
        HarnessComponentKind::Verifier => {
            strings(&["schema_hash", "contract_key", "verification_result"])
        }
        HarnessComponentKind::OutputWriter => {
            strings(&["output_hash", "delivery_target", "output_policy_slot"])
        }
        HarnessComponentKind::ReceiptWriter => {
            strings(&["receipt_id", "node_id", "evidence_commit_hash"])
        }
        HarnessComponentKind::RetryPolicy => strings(&["attempt", "max_attempts", "retry_reason"]),
        HarnessComponentKind::RepairLoop => {
            strings(&["failure_ref", "repair_strategy", "bounded_targets"])
        }
        HarnessComponentKind::MergeJudge => {
            strings(&["candidate_hashes", "winner_reason", "judge_policy_hash"])
        }
        HarnessComponentKind::CompletionGate => {
            strings(&["completion_contract", "pending_actions", "final_decision"])
        }
    }
}

fn approval_for(kind: HarnessComponentKind) -> HarnessApprovalSemantics {
    let required = matches!(
        kind,
        HarnessComponentKind::ToolCall
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
        | HarnessComponentKind::ModelCall
        | HarnessComponentKind::ToolCall
        | HarnessComponentKind::McpToolCall
        | HarnessComponentKind::ConnectorCall => 2,
        _ => 1,
    };
    let timeout_ms = match kind {
        HarnessComponentKind::ModelCall => 120_000,
        HarnessComponentKind::ToolCall
        | HarnessComponentKind::McpToolCall
        | HarnessComponentKind::ConnectorCall => 60_000,
        _ => 30_000,
    };
    HarnessComponentSpec {
        component_id: kind.component_id(),
        version: HARNESS_COMPONENT_VERSION_V1.to_string(),
        kind,
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

fn slot_kinds_for_component(kind: HarnessComponentKind) -> Vec<HarnessSlotKind> {
    match kind {
        HarnessComponentKind::ModelRouter | HarnessComponentKind::ModelCall => {
            vec![HarnessSlotKind::ModelPolicy]
        }
        HarnessComponentKind::ToolRouter
        | HarnessComponentKind::ToolCall
        | HarnessComponentKind::McpProvider
        | HarnessComponentKind::McpToolCall
        | HarnessComponentKind::ConnectorCall => vec![HarnessSlotKind::ToolGrantPolicy],
        HarnessComponentKind::PolicyGate
        | HarnessComponentKind::ApprovalGate
        | HarnessComponentKind::WalletCapability => vec![HarnessSlotKind::ApprovalPolicy],
        HarnessComponentKind::MemoryRead | HarnessComponentKind::MemoryWrite => {
            vec![HarnessSlotKind::MemoryPolicy]
        }
        HarnessComponentKind::Verifier | HarnessComponentKind::CompletionGate => {
            vec![HarnessSlotKind::VerifierPolicy]
        }
        HarnessComponentKind::OutputWriter | HarnessComponentKind::ReceiptWriter => {
            vec![HarnessSlotKind::OutputPolicy]
        }
        HarnessComponentKind::RetryPolicy | HarnessComponentKind::RepairLoop => {
            vec![HarnessSlotKind::RetryRepairPolicy]
        }
        HarnessComponentKind::MergeJudge => {
            vec![
                HarnessSlotKind::RetryRepairPolicy,
                HarnessSlotKind::VerifierPolicy,
            ]
        }
        HarnessComponentKind::Planner => vec![],
    }
}

pub fn default_agent_harness_slots() -> Vec<HarnessSlotSpec> {
    vec![
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
            slot_id: HarnessSlotKind::VerifierPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::VerifierPolicy,
            label: "Verifier policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
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
    ]
}

pub fn default_agent_harness_action_frames() -> Vec<HarnessActionFrame> {
    default_agent_harness_components()
        .into_iter()
        .map(|component| HarnessActionFrame {
            workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
            workflow_version: DEFAULT_AGENT_HARNESS_VERSION.to_string(),
            workflow_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
            node_id: component.kind.workflow_node_id(),
            component_id: component.component_id,
            component_version: component.version,
            component_kind: component.kind,
            kernel_ref: component.kernel_ref,
            slot_ids: slot_kinds_for_component(component.kind)
                .into_iter()
                .map(HarnessSlotKind::slot_id)
                .map(str::to_string)
                .collect(),
            deterministic_envelope: true,
            event_kinds: component.emitted_events,
            evidence_keys: component.evidence,
        })
        .collect()
}

pub fn default_harness_worker_binding() -> HarnessWorkerBinding {
    HarnessWorkerBinding {
        harness_workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        harness_activation_id: Some(DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string()),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        source: "default".to_string(),
    }
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

#[cfg(test)]
#[path = "harness/tests.rs"]
mod tests;
