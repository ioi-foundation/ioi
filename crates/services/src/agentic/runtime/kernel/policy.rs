use crate::agentic::rules::Verdict;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.context-budget-policy-request.v1";
pub const CONTEXT_BUDGET_POLICY_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.context-budget-policy.v1";
pub const CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-budget-policy-request.v1";
pub const CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-budget-recovery-state-update-request.v1";
pub const CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-budget-recovery-state-update.v1";
pub const DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-operator-override-state-update-request.v1";
pub const DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-operator-override-state-update.v1";
pub const OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.operator-interrupt-state-update-request.v1";
pub const OPERATOR_INTERRUPT_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.operator-interrupt-state-update.v1";
pub const OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.operator-steer-state-update-request.v1";
pub const OPERATOR_STEER_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.operator-steer-state-update.v1";
pub const RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.run-cancel-state-update-request.v1";
pub const RUN_CANCEL_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.run-cancel-state-update.v1";
pub const THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-control-agent-state-update-request.v1";
pub const THREAD_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-control-agent-state-update.v1";
pub const AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.agent-create-state-update-request.v1";
pub const AGENT_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.agent-create-state-update.v1";
pub const RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.run-create-state-update-request.v1";
pub const RUN_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.run-create-state-update.v1";
pub const AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.agent-status-state-update-request.v1";
pub const AGENT_STATUS_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.agent-status-state-update.v1";
pub const MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-control-agent-state-update-request.v1";
pub const MCP_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-control-agent-state-update.v1";
pub const MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-server-validation-request.v1";
pub const MCP_SERVER_VALIDATION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-server-validation.v1";
pub const MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-server-validation-input-request.v1";
pub const MCP_SERVER_VALIDATION_INPUT_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-server-validation-input.v1";
pub const MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-validation-projection-request.v1";
pub const MCP_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-validation.v1";
pub const MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-status-projection-request.v1";
pub const MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-status.v1";
pub const MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-catalog-projection-request.v1";
pub const MCP_MANAGER_CATALOG_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-catalog-projection.v1";
pub const MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-catalog-summary-projection-request.v1";
pub const MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.mcp-manager-catalog-summary.v1";
pub const MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-manager-validation-projection-request.v1";
pub const MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-manager-validation.v1";
pub const MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-manager-status-projection-request.v1";
pub const MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-manager-status.v1";
pub const THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-memory-agent-state-update-request.v1";
pub const THREAD_MEMORY_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-memory-agent-state-update.v1";
pub const RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.runtime-bridge-thread-start-agent-state-update-request.v1";
pub const RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.runtime-bridge-thread-start-agent-state-update.v1";
pub const RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.runtime-bridge-turn-run-state-update-request.v1";
pub const RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.runtime-bridge-turn-run-state-update.v1";
pub const SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.subagent-record-state-update-request.v1";
pub const SUBAGENT_RECORD_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.subagent-record-state-update.v1";
pub const COMPACTION_POLICY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.compaction-policy-request.v1";
pub const COMPACTION_POLICY_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.compaction-policy.v1";
pub const CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.context-compaction-plan-request.v1";
pub const CONTEXT_COMPACTION_PLAN_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.context-compaction-plan.v1";
pub const CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.context-compaction-state-update-request.v1";
pub const CONTEXT_COMPACTION_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.context-compaction-state-update.v1";
pub const CONTEXT_COMPACTION_PAYLOAD_SCHEMA_VERSION: &str = "ioi.runtime.context-compaction.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluationRecord {
    pub verdict: Verdict,
    #[serde(default)]
    pub matched_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_policy_used: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pii_decision_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_eval_trace_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_eval_hash: Option<[u8; 32]>,
}

impl PolicyEvaluationRecord {
    pub fn matched_rules_for_decision(&self) -> Vec<String> {
        let mut rules = self.matched_rule_ids.clone();
        if rules.is_empty() {
            if let Some(default_policy) = &self.default_policy_used {
                rules.push(format!("default:{}", default_policy));
            }
        }
        if let Some(hash) = self.pii_decision_hash {
            rules.push(format!("pii:{}", hex::encode(hash)));
        }
        rules
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContextBudgetPolicyError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CompactionPolicyError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContextCompactionPlanError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContextCompactionStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CodingToolBudgetRecoveryStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum DiagnosticsOperatorOverrideStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum OperatorInterruptStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum OperatorSteerStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RunCancelStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreadControlAgentStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    UnsupportedControlKind(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentCreateStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RunCreateStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum McpControlAgentStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum McpServerValidationError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum McpServerValidationInputError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum McpManagerValidationProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum McpManagerStatusProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum MemoryManagerValidationProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum MemoryManagerStatusProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpManagerCatalogProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpManagerCatalogSummaryProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreadMemoryAgentStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeBridgeThreadStartAgentStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentStatusStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeBridgeTurnRunStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    MismatchedField {
        field: &'static str,
        expected: String,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum SubagentRecordStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    MismatchedField {
        field: &'static str,
        expected: String,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextBudgetPolicyRequest {
    pub schema_version: String,
    #[serde(default)]
    pub usage_telemetry: Value,
    #[serde(default)]
    pub thresholds: ContextBudgetThresholds,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub tool_id: Option<String>,
    #[serde(default)]
    pub tool_call_id: Option<String>,
    #[serde(default)]
    pub workflow_graph_id: Option<String>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub event_kind: Option<String>,
    #[serde(default)]
    pub component_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ContextBudgetThresholds {
    #[serde(default)]
    pub max_total_tokens: Option<f64>,
    #[serde(default)]
    pub max_cost_usd: Option<f64>,
    #[serde(default)]
    pub max_context_pressure: Option<f64>,
    #[serde(default)]
    pub warn_at_ratio: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextBudgetUsageSummary {
    pub total_tokens: f64,
    pub estimated_cost_usd: f64,
    pub context_pressure: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub scope: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextBudgetCheck {
    pub id: String,
    pub label: String,
    pub actual: f64,
    pub limit: f64,
    pub ratio: f64,
    pub severity: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextBudgetDecision {
    pub policy_decision_id: String,
    pub status: String,
    pub mode: String,
    pub would_block: bool,
    pub summary: String,
    pub checks: Vec<ContextBudgetCheck>,
    pub violations: Vec<ContextBudgetCheck>,
    pub warnings: Vec<ContextBudgetCheck>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextBudgetPolicyRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub mode: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub source: String,
    pub actor: String,
    pub event_kind: String,
    pub component_kind: String,
    pub payload_schema_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_graph_id: Option<String>,
    pub workflow_node_id: String,
    pub tool_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub thresholds: ContextBudgetThresholds,
    pub usage_telemetry: Value,
    pub usage_summary: ContextBudgetUsageSummary,
    pub policy_decision_id: String,
    pub policy_decision: ContextBudgetDecision,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub warnings: Vec<ContextBudgetCheck>,
    pub violations: Vec<ContextBudgetCheck>,
    pub would_block: bool,
    pub runtime_event_kind: String,
    pub runtime_event_status: String,
    pub runtime_event_item_id: String,
    pub runtime_event_idempotency_key: String,
    pub simulation_mode: bool,
    pub summary: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct CompactionPolicyActions {
    #[serde(default)]
    pub ok_action: Option<String>,
    #[serde(default)]
    pub warn_action: Option<String>,
    #[serde(default)]
    pub blocked_action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct CompactionPolicyApproval {
    #[serde(default)]
    pub approval_required: Option<bool>,
    #[serde(default)]
    pub approval_granted: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct CompactionPolicyCompact {
    #[serde(default)]
    pub execute_compaction: Option<bool>,
    #[serde(default)]
    pub compact_workflow_node_id: Option<String>,
    #[serde(default)]
    pub compact_reason: Option<String>,
    #[serde(default)]
    pub compact_scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompactionPolicyRequest {
    pub schema_version: String,
    pub thread_id: String,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub context_budget: Value,
    #[serde(default)]
    pub context_budget_status: Option<String>,
    #[serde(default)]
    pub actions: CompactionPolicyActions,
    #[serde(default)]
    pub approval: CompactionPolicyApproval,
    #[serde(default)]
    pub compact: CompactionPolicyCompact,
    #[serde(default)]
    pub workflow_graph_id: Option<String>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub event_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompactionPolicyRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub action: String,
    pub selected_action: String,
    pub budget_status: String,
    pub thread_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    pub source: String,
    pub actor: String,
    pub event_kind: String,
    pub component_kind: String,
    pub payload_schema_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_graph_id: Option<String>,
    pub workflow_node_id: String,
    pub compact_workflow_node_id: String,
    pub context_budget: Value,
    pub approval_required: bool,
    pub approval_granted: bool,
    pub approval_satisfied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    pub execute_compaction: bool,
    pub compaction_requested: bool,
    pub compaction_executed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction_seq: Option<u64>,
    pub compact_reason: String,
    pub compact_scope: String,
    pub runtime_event_kind: String,
    pub runtime_event_status: String,
    pub runtime_event_item_id: String,
    pub runtime_event_idempotency_key: String,
    pub compact_idempotency_key: String,
    pub continuation_allowed: bool,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub policy_decision_id: String,
    pub summary: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextCompactionPlanRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub agent_id: String,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub requested_by: Option<String>,
    #[serde(default)]
    pub workflow_graph_id: Option<String>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    #[serde(default)]
    pub event_stream_id: Option<String>,
    #[serde(default)]
    pub previous_latest_seq: Option<u64>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextCompactionPlanRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub thread_id: String,
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_stream_id: Option<String>,
    pub item_id: String,
    pub idempotency_key: String,
    pub source: String,
    pub source_event_kind: String,
    pub event_kind: String,
    pub actor: String,
    pub requested_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_graph_id: Option<String>,
    pub workflow_node_id: String,
    pub component_kind: String,
    pub payload_schema_version: String,
    pub payload: Value,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub redaction_profile: String,
    pub compact_hash: String,
    pub reason: String,
    pub scope: String,
    pub previous_latest_seq: u64,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextCompactionStateUpdateRequest {
    pub schema_version: String,
    #[serde(default)]
    pub target_kind: Option<String>,
    pub thread_id: String,
    pub agent_id: String,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub run: Option<Value>,
    pub agent: Value,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
    pub source: String,
    pub reason: String,
    pub scope: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextCompactionStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub target_kind: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub updated_at: String,
    pub operator_control: Value,
    pub context_compaction: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolBudgetRecoveryStateUpdateRequest {
    pub schema_version: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    pub run: Value,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
    pub approval_id: String,
    pub source: String,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolBudgetRecoveryStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub updated_at: String,
    pub operator_control: Value,
    pub run: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticsOperatorOverrideStateUpdateRequest {
    pub schema_version: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    pub run: Value,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
    pub decision_id: String,
    #[serde(default)]
    pub gate_event_id: Option<String>,
    pub source: String,
    #[serde(default)]
    pub approval_required: bool,
    #[serde(default)]
    pub approval_satisfied: bool,
    #[serde(default)]
    pub approval_source: Option<String>,
    #[serde(default)]
    pub snapshot_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticsOperatorOverrideStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub updated_at: String,
    pub operator_control: Value,
    pub run: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorInterruptStateUpdateRequest {
    pub schema_version: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    pub run: Value,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorInterruptStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub updated_at: String,
    pub operator_control: Value,
    pub stop_condition: Value,
    pub run: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorSteerStateUpdateRequest {
    pub schema_version: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    pub run: Value,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
    pub source: String,
    pub guidance: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorSteerStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub updated_at: String,
    pub operator_control: Value,
    pub run: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunCancelStateUpdateRequest {
    pub schema_version: String,
    #[serde(default)]
    pub run_id: Option<String>,
    pub run: Value,
    pub canceled_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunCancelStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub updated_at: String,
    pub stop_condition: Value,
    pub runtime_task: Value,
    pub runtime_job: Value,
    pub runtime_checklist: Value,
    pub run: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadControlAgentStateUpdateRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub agent: Value,
    pub control_kind: String,
    pub controls: Value,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub workspace_trust_warning_event_id: Option<String>,
    #[serde(default)]
    pub workspace_trust_warning_created_at: Option<String>,
    #[serde(default, alias = "modelRoute")]
    pub model_route: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadControlAgentStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub agent_id: String,
    pub updated_at: String,
    pub control: Value,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentCreateStateUpdateRequest {
    pub schema_version: String,
    pub agent: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentCreateStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub agent_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunCreateStateUpdateRequest {
    pub schema_version: String,
    pub run: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunCreateStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub run_id: String,
    pub agent_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub run: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentStatusStateUpdateRequest {
    pub schema_version: String,
    pub agent: Value,
    pub status: String,
    pub operation_kind: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentStatusStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub agent_id: String,
    pub updated_at: String,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpControlAgentStateUpdateRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub agent: Value,
    pub control_kind: String,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpControlAgentStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub agent_id: String,
    pub updated_at: String,
    pub control: Value,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServerValidationRequest {
    pub schema_version: String,
    #[serde(default)]
    pub servers: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServerValidationRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub ok: bool,
    pub issue_count: usize,
    pub warning_count: usize,
    pub issues: Vec<Value>,
    pub warnings: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServerValidationInputRequest {
    pub schema_version: String,
    #[serde(default)]
    pub input: Value,
    #[serde(default)]
    pub workspace_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServerValidationInputRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub workspace_root: Option<String>,
    pub server_count: usize,
    pub servers: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerValidationProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub validation_schema_version: Option<String>,
    pub validation: Value,
    #[serde(default)]
    pub servers: Vec<Value>,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(default)]
    pub resources: Vec<Value>,
    #[serde(default)]
    pub prompts: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerValidationProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub ok: bool,
    pub status: String,
    pub server_count: usize,
    pub tool_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub issue_count: usize,
    pub warning_count: usize,
    pub issues: Vec<Value>,
    pub warnings: Vec<Value>,
    pub servers: Vec<Value>,
    pub tools: Vec<Value>,
    pub resources: Vec<Value>,
    pub prompts: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerStatusProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    pub validation: Value,
    #[serde(default)]
    pub servers: Vec<Value>,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(default)]
    pub resources: Vec<Value>,
    #[serde(default)]
    pub prompts: Vec<Value>,
    #[serde(default)]
    pub enabled_tools: Vec<Value>,
    #[serde(default)]
    pub routes: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerStatusProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub server_count: usize,
    pub tool_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub enabled_server_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_tool_count: Option<usize>,
    pub servers: Vec<Value>,
    pub tools: Vec<Value>,
    pub resources: Vec<Value>,
    pub prompts: Vec<Value>,
    pub validation: Value,
    pub routes: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryManagerValidationProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub validation_schema_version: Option<String>,
    #[serde(default)]
    pub projection: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryManagerValidationProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub ok: bool,
    pub status: String,
    pub issue_count: usize,
    pub warning_count: usize,
    pub record_count: usize,
    pub issues: Vec<Value>,
    pub warnings: Vec<Value>,
    pub policy: Value,
    pub paths: Value,
    pub filters: Value,
    pub records: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryManagerStatusProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    #[serde(default)]
    pub validation_schema_version: Option<String>,
    #[serde(default)]
    pub projection: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryManagerStatusProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub disabled: bool,
    pub injection_enabled: bool,
    pub read_only: bool,
    pub write_requires_approval: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_blocked_reason: Option<String>,
    pub record_count: usize,
    pub scope_count: usize,
    pub memory_key_count: usize,
    pub scopes: Vec<String>,
    pub memory_keys: Vec<String>,
    pub policy: Value,
    pub paths: Value,
    pub filters: Value,
    pub records: Vec<Value>,
    pub validation: Value,
    pub routes: Value,
    pub evidence_refs: Vec<String>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerCatalogProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    #[serde(default)]
    pub servers: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerCatalogProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub server_count: usize,
    pub tool_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub enabled_tool_count: usize,
    pub servers: Vec<Value>,
    pub tools: Vec<Value>,
    pub resources: Vec<Value>,
    pub prompts: Vec<Value>,
    pub enabled_tools: Vec<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerCatalogSummaryProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    #[serde(default)]
    pub server: Value,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(default)]
    pub resources: Vec<Value>,
    #[serde(default)]
    pub prompts: Vec<Value>,
    #[serde(default)]
    pub live_mode: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub preview_limit: Option<usize>,
    #[serde(default)]
    pub deferred: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpManagerCatalogSummaryProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub server_id: Option<String>,
    pub server_label: Option<String>,
    pub transport: Option<String>,
    pub execution_mode: Option<String>,
    pub catalog_hash: String,
    pub tool_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub namespace_count: usize,
    pub namespaces: Vec<String>,
    pub preview_limit: usize,
    pub preview_tool_names: Vec<String>,
    pub deferred: bool,
    pub full_catalog_included: bool,
    pub error_code: Option<String>,
    pub search_route: String,
    pub fetch_route: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadMemoryAgentStateUpdateRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub agent: Value,
    pub control_kind: String,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadMemoryAgentStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub agent_id: String,
    pub updated_at: String,
    pub control: Value,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeBridgeThreadStartAgentStateUpdateRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub agent: Value,
    pub runtime_profile: String,
    pub session_id: String,
    pub bridge_id: String,
    pub status: String,
    pub source: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeBridgeThreadStartAgentStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub agent_id: String,
    pub updated_at: String,
    pub bridge_start: Value,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeBridgeTurnRunStateUpdateRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub agent: Value,
    pub projection: Value,
    pub run: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeBridgeTurnRunStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub run_id: String,
    pub agent_id: String,
    pub updated_at: String,
    pub run: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubagentRecordStateUpdateRequest {
    pub schema_version: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub subagent: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubagentRecordStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub subagent_id: String,
    pub updated_at: String,
    pub subagent: Value,
    pub generated_at: String,
}

#[derive(Debug, Default, Clone)]
pub struct ContextBudgetPolicyCore;

impl ContextBudgetPolicyCore {
    pub fn evaluate(
        &self,
        request: &ContextBudgetPolicyRequest,
    ) -> Result<ContextBudgetPolicyRecord, ContextBudgetPolicyError> {
        request.validate()?;
        let usage_summary = budget_usage_summary(&request.usage_telemetry);
        let warn_at_ratio = request.thresholds.warn_at_ratio.unwrap_or(0.8);
        let checks = vec![
            budget_check(
                "total_tokens",
                "total tokens",
                usage_summary.total_tokens,
                request.thresholds.max_total_tokens,
                warn_at_ratio,
            ),
            budget_check(
                "estimated_cost_usd",
                "estimated cost USD",
                usage_summary.estimated_cost_usd,
                request.thresholds.max_cost_usd,
                warn_at_ratio,
            ),
            budget_check(
                "context_pressure",
                "context pressure",
                usage_summary.context_pressure,
                request.thresholds.max_context_pressure,
                warn_at_ratio,
            ),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let violations = checks
            .iter()
            .filter(|check| check.severity == "violation")
            .cloned()
            .collect::<Vec<_>>();
        let warnings = checks
            .iter()
            .filter(|check| check.severity == "warning")
            .cloned()
            .collect::<Vec<_>>();
        let would_block = !violations.is_empty();
        let mode = budget_mode(request.mode.as_deref());
        let status = if would_block && mode == "block" {
            "blocked"
        } else if would_block || !warnings.is_empty() {
            "warn"
        } else {
            "ok"
        }
        .to_string();
        let scope = optional_trimmed(request.scope.as_deref()).unwrap_or_else(|| {
            if usage_summary.scope.is_empty() {
                "thread".to_string()
            } else {
                usage_summary.scope.clone()
            }
        });
        let thread_id =
            optional_trimmed(request.thread_id.as_deref()).or(usage_summary.thread_id.clone());
        let turn_id = optional_trimmed(request.turn_id.as_deref());
        let run_id = optional_trimmed(request.run_id.as_deref()).or(usage_summary.run_id.clone());
        let workflow_node_id = optional_trimmed(request.workflow_node_id.as_deref())
            .unwrap_or_else(|| "runtime.context-budget".to_string());
        let workflow_graph_id = optional_trimmed(request.workflow_graph_id.as_deref());
        let is_coding_tool =
            request.schema_version == CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION;
        let event_kind = optional_trimmed(request.event_kind.as_deref()).unwrap_or_else(|| {
            if is_coding_tool {
                "RuntimeCodingToolBudget.Evaluate".to_string()
            } else {
                "RuntimeContextBudget.Evaluate".to_string()
            }
        });
        let component_kind =
            optional_trimmed(request.component_kind.as_deref()).unwrap_or_else(|| {
                if is_coding_tool {
                    "coding_tool".to_string()
                } else {
                    "context_budget".to_string()
                }
            });
        let decision_hash = budget_hash(&json!({
            "scope": scope,
            "thread_id": thread_id,
            "run_id": run_id,
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "status": status,
            "mode": mode,
            "checks": checks,
        }))?;
        let decision_short = decision_hash
            .strip_prefix("sha256:")
            .unwrap_or(&decision_hash)
            .chars()
            .take(16)
            .collect::<String>();
        let policy_decision_id = format!(
            "policy_context_budget_{}_{}_{}",
            safe_id(&scope),
            decision_short,
            status
        );
        let receipt_id = format!(
            "receipt_context_budget_{}_{}",
            safe_id(&scope),
            decision_short
        );
        let summary = budget_summary(&status, &violations, &warnings);
        let runtime_event_kind = context_budget_runtime_event_kind(&status);
        let runtime_event_status = context_budget_runtime_event_status(&status);
        let event_scope = turn_id
            .as_deref()
            .or(thread_id.as_deref())
            .unwrap_or(scope.as_str());
        let runtime_event_item_id = format!(
            "{}:item:context-budget:{}",
            event_scope,
            safe_id(&policy_decision_id)
        );
        let runtime_event_idempotency_key = format!(
            "thread:{}:context-budget:{}",
            thread_id.as_deref().unwrap_or(scope.as_str()),
            safe_id(&policy_decision_id)
        );
        let decision = ContextBudgetDecision {
            policy_decision_id: policy_decision_id.clone(),
            status: status.clone(),
            mode: mode.clone(),
            would_block,
            summary: summary.clone(),
            checks: checks.clone(),
            violations: violations.clone(),
            warnings: warnings.clone(),
        };

        Ok(ContextBudgetPolicyRecord {
            schema_version: CONTEXT_BUDGET_POLICY_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_context_budget_policy".to_string(),
            status: status.clone(),
            mode: mode.clone(),
            scope,
            thread_id,
            turn_id,
            run_id,
            source: optional_trimmed(request.source.as_deref())
                .unwrap_or_else(|| "react_flow".to_string()),
            actor: optional_trimmed(request.actor.as_deref())
                .unwrap_or_else(|| "operator".to_string()),
            event_kind,
            component_kind,
            payload_schema_version: CONTEXT_BUDGET_POLICY_RESULT_SCHEMA_VERSION.to_string(),
            workflow_graph_id,
            workflow_node_id,
            tool_id: optional_trimmed(request.tool_id.as_deref()),
            tool_call_id: optional_trimmed(request.tool_call_id.as_deref()),
            thresholds: request.thresholds.clone(),
            usage_telemetry: request.usage_telemetry.clone(),
            usage_summary,
            policy_decision_id: policy_decision_id.clone(),
            policy_decision: decision,
            receipt_refs: vec![receipt_id],
            policy_decision_refs: vec![policy_decision_id],
            warnings,
            violations,
            would_block,
            runtime_event_kind,
            runtime_event_status,
            runtime_event_item_id,
            runtime_event_idempotency_key,
            simulation_mode: mode == "simulate",
            summary,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct CompactionPolicyCore;

impl CompactionPolicyCore {
    pub fn evaluate(
        &self,
        request: &CompactionPolicyRequest,
    ) -> Result<CompactionPolicyRecord, CompactionPolicyError> {
        request.validate()?;
        let budget_status = compaction_budget_status(
            request.context_budget_status.as_deref(),
            Some(&request.context_budget),
        );
        let ok_action = compaction_action(request.actions.ok_action.as_deref(), "noop");
        let warn_action = compaction_action(request.actions.warn_action.as_deref(), "warn");
        let blocked_action =
            compaction_action(request.actions.blocked_action.as_deref(), "compact");
        let selected_action = if budget_status == "blocked" {
            blocked_action
        } else if budget_status == "warn" {
            warn_action
        } else {
            ok_action
        };
        let approval_required = request.approval.approval_required.unwrap_or(false)
            || selected_action == "approval_required";
        let approval_granted = request.approval.approval_granted.unwrap_or(false);
        let execute_compaction = request.compact.execute_compaction.unwrap_or(false);
        let action = if selected_action == "approval_required" && approval_granted {
            "compact".to_string()
        } else if selected_action == "compact" && approval_required && !approval_granted {
            "approval_required".to_string()
        } else {
            selected_action.clone()
        };
        let approval_satisfied = !approval_required || approval_granted;
        let continuation_allowed = action != "stop";
        let workflow_graph_id = optional_trimmed(request.workflow_graph_id.as_deref());
        let workflow_node_id = optional_trimmed(request.workflow_node_id.as_deref())
            .unwrap_or_else(|| "runtime.compaction-policy".to_string());
        let compact_workflow_node_id =
            optional_trimmed(request.compact.compact_workflow_node_id.as_deref())
                .unwrap_or_else(|| "runtime.context-compact".to_string());
        let context_budget_summary = string_field(&request.context_budget, "summary")
            .or_else(|| {
                request
                    .context_budget
                    .get("policy_decision")
                    .and_then(|value| string_field(value, "summary"))
            })
            .unwrap_or_else(|| format!("context budget status {budget_status}"));
        let compact_reason = optional_trimmed(request.compact.compact_reason.as_deref())
            .unwrap_or_else(|| {
                format!("Compaction policy {budget_status}: {context_budget_summary}")
            });
        let compact_scope = optional_trimmed(request.compact.compact_scope.as_deref())
            .unwrap_or_else(|| "thread".to_string());
        let turn_id = optional_trimmed(request.turn_id.as_deref());
        let decision_hash = compaction_hash(&json!({
            "thread_id": request.thread_id,
            "turn_id": turn_id,
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "budget_status": budget_status,
            "selected_action": selected_action,
            "action": action,
            "approval_required": approval_required,
            "approval_granted": approval_granted,
            "execute_compaction": execute_compaction,
        }))?;
        let decision_short = decision_hash
            .strip_prefix("sha256:")
            .unwrap_or(&decision_hash)
            .chars()
            .take(16)
            .collect::<String>();
        let safe_thread_id = safe_id(&request.thread_id);
        let policy_decision_id =
            format!("policy_compaction_{safe_thread_id}_{decision_short}_{action}");
        let receipt_id = format!("receipt_compaction_policy_{safe_thread_id}_{decision_short}");
        let approval_id = if action == "approval_required" {
            Some(format!(
                "approval_compaction_{safe_thread_id}_{decision_short}"
            ))
        } else {
            None
        };
        let status = compaction_status(&action, execute_compaction, approval_satisfied);
        let runtime_event_kind = compaction_runtime_event_kind(&action);
        let runtime_event_status = compaction_runtime_event_status(&action);
        let event_scope = turn_id.as_deref().unwrap_or(request.thread_id.as_str());
        let runtime_event_item_id = format!(
            "{}:item:compaction-policy:{}",
            event_scope,
            safe_id(&policy_decision_id)
        );
        let runtime_event_idempotency_key = format!(
            "thread:{}:compaction-policy:{}",
            request.thread_id,
            safe_id(&policy_decision_id)
        );
        let compact_idempotency_key = format!(
            "thread:{}:compaction-policy:compact:{}",
            request.thread_id,
            safe_id(&policy_decision_id)
        );
        let summary = compaction_summary(&action, execute_compaction);

        Ok(CompactionPolicyRecord {
            schema_version: COMPACTION_POLICY_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_compaction_policy".to_string(),
            status,
            action: action.clone(),
            selected_action,
            budget_status,
            thread_id: request.thread_id.clone(),
            turn_id,
            source: optional_trimmed(request.source.as_deref())
                .unwrap_or_else(|| "react_flow".to_string()),
            actor: optional_trimmed(request.actor.as_deref())
                .unwrap_or_else(|| "operator".to_string()),
            event_kind: optional_trimmed(request.event_kind.as_deref())
                .unwrap_or_else(|| "RuntimeCompactionPolicy.Evaluate".to_string()),
            component_kind: "compaction_policy".to_string(),
            payload_schema_version: COMPACTION_POLICY_RESULT_SCHEMA_VERSION.to_string(),
            workflow_graph_id,
            workflow_node_id,
            compact_workflow_node_id,
            context_budget: request.context_budget.clone(),
            approval_required,
            approval_granted,
            approval_satisfied,
            approval_id,
            execute_compaction,
            compaction_requested: action == "compact",
            compaction_executed: false,
            compaction_event_id: None,
            compaction_seq: None,
            compact_reason,
            compact_scope,
            runtime_event_kind,
            runtime_event_status,
            runtime_event_item_id,
            runtime_event_idempotency_key,
            compact_idempotency_key,
            continuation_allowed,
            receipt_refs: vec![receipt_id],
            policy_decision_refs: vec![policy_decision_id.clone()],
            policy_decision_id,
            summary,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct ContextCompactionPlanCore;

impl ContextCompactionPlanCore {
    pub fn plan(
        &self,
        request: &ContextCompactionPlanRequest,
    ) -> Result<ContextCompactionPlanRecord, ContextCompactionPlanError> {
        request.validate()?;
        let thread_id = optional_trimmed(Some(request.thread_id.as_str())).unwrap();
        let agent_id = optional_trimmed(Some(request.agent_id.as_str())).unwrap();
        let turn_id = optional_trimmed(request.turn_id.as_deref());
        let run_id = optional_trimmed(request.run_id.as_deref());
        let session_id = optional_trimmed(request.session_id.as_deref());
        let workspace_root = optional_trimmed(request.workspace_root.as_deref());
        let source = operator_control_source(request.source.as_deref());
        let actor =
            optional_trimmed(request.actor.as_deref()).unwrap_or_else(|| "user".to_string());
        let requested_by = optional_trimmed(request.requested_by.as_deref())
            .unwrap_or_else(|| "operator".to_string());
        let reason = optional_trimmed(request.reason.as_deref())
            .unwrap_or_else(|| "operator requested context compaction".to_string());
        let scope =
            optional_trimmed(request.scope.as_deref()).unwrap_or_else(|| "thread".to_string());
        let workflow_graph_id = optional_trimmed(request.workflow_graph_id.as_deref());
        let workflow_node_id = optional_trimmed(request.workflow_node_id.as_deref())
            .unwrap_or_else(|| "runtime.context-compact".to_string());
        let event_stream_id = optional_trimmed(request.event_stream_id.as_deref());
        let previous_latest_seq = request.previous_latest_seq.unwrap_or(0);
        let compact_hash = context_compaction_hash(&reason, &scope);
        let item_scope = turn_id.as_deref().unwrap_or(thread_id.as_str());
        let item_id = format!("{item_scope}:item:context-compact:{compact_hash}");
        let idempotency_key = optional_trimmed(request.idempotency_key.as_deref())
            .unwrap_or_else(|| format!("thread:{thread_id}:context.compact:{compact_hash}"));
        let ref_owner = run_id.as_deref().unwrap_or(agent_id.as_str());
        let receipt_ref = format!("receipt_{ref_owner}_context_compaction_{compact_hash}");
        let policy_decision_ref = format!("policy_{ref_owner}_context_compaction_allow");
        let payload = json!({
            "event_kind": "OperatorControl.Compact",
            "reason": reason,
            "scope": scope,
            "requested_by": requested_by,
            "control_surface": source,
            "previous_latest_seq": previous_latest_seq,
            "compacted_tokens": 0,
            "agent_id": agent_id,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "run_id": run_id,
            "session_id": session_id,
        });

        Ok(ContextCompactionPlanRecord {
            schema_version: CONTEXT_COMPACTION_PLAN_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_context_compaction_plan".to_string(),
            status: "planned".to_string(),
            thread_id,
            agent_id,
            turn_id,
            run_id,
            session_id,
            workspace_root,
            event_stream_id,
            item_id,
            idempotency_key,
            source,
            source_event_kind: "OperatorControl.Compact".to_string(),
            event_kind: "context.compacted".to_string(),
            actor,
            requested_by,
            workflow_graph_id,
            workflow_node_id,
            component_kind: "context_compaction".to_string(),
            payload_schema_version: CONTEXT_COMPACTION_PAYLOAD_SCHEMA_VERSION.to_string(),
            payload,
            receipt_refs: vec![receipt_ref],
            policy_decision_refs: vec![policy_decision_ref],
            artifact_refs: Vec::new(),
            rollback_refs: Vec::new(),
            redaction_profile: "internal".to_string(),
            compact_hash,
            reason,
            scope,
            previous_latest_seq,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct ContextCompactionStateUpdateCore;

impl ContextCompactionStateUpdateCore {
    pub fn plan(
        &self,
        request: &ContextCompactionStateUpdateRequest,
    ) -> Result<ContextCompactionStateUpdateRecord, ContextCompactionStateUpdateError> {
        request.validate()?;
        let thread_id = optional_trimmed(Some(request.thread_id.as_str())).unwrap();
        let agent_id = optional_trimmed(Some(request.agent_id.as_str())).unwrap();
        let run_id = optional_trimmed(request.run_id.as_deref());
        let source = optional_trimmed(Some(request.source.as_str()))
            .unwrap_or_else(|| "sdk_client".to_string());
        let reason = optional_trimmed(Some(request.reason.as_str()))
            .unwrap_or_else(|| "operator requested context compaction".to_string());
        let scope =
            optional_trimmed(Some(request.scope.as_str())).unwrap_or_else(|| "thread".to_string());
        let target_kind = context_compaction_state_target_kind(
            request.target_kind.as_deref(),
            request.run.as_ref(),
        );
        let operator_control = json!({
            "control": "compact",
            "source": source.clone(),
            "reason": reason.clone(),
            "scope": scope.clone(),
            "event_id": request.event_id,
            "seq": request.seq,
            "created_at": request.created_at,
        });
        let context_compaction = json!({
            "reason": reason.clone(),
            "scope": scope.clone(),
            "event_id": request.event_id,
            "seq": request.seq,
            "compacted_tokens": 0,
        });

        let (run, agent) = if target_kind == "run" {
            let mut run = object_value(
                request
                    .run
                    .as_ref()
                    .ok_or(ContextCompactionStateUpdateError::MissingField("run"))?,
            )
            .ok_or(ContextCompactionStateUpdateError::MissingField("run"))?;
            run.insert(
                "updatedAt".to_string(),
                Value::String(request.created_at.clone()),
            );
            let mut trace = run.get("trace").and_then(object_value).unwrap_or_default();
            let trace_controls =
                append_operator_control(trace.get("operatorControls"), &operator_control);
            trace.insert("operatorControls".to_string(), trace_controls);
            trace.insert("contextCompaction".to_string(), context_compaction.clone());
            run.insert("trace".to_string(), Value::Object(trace));
            let run_controls =
                append_operator_control(run.get("operatorControls"), &operator_control);
            run.insert("operatorControls".to_string(), run_controls);
            (Some(Value::Object(run)), None)
        } else {
            let mut agent = object_value(&request.agent)
                .ok_or(ContextCompactionStateUpdateError::MissingField("agent"))?;
            agent.insert(
                "updatedAt".to_string(),
                Value::String(request.created_at.clone()),
            );
            (None, Some(Value::Object(agent)))
        };

        Ok(ContextCompactionStateUpdateRecord {
            schema_version: CONTEXT_COMPACTION_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_context_compaction_state_update".to_string(),
            status: "planned".to_string(),
            target_kind,
            operation_kind: "thread.compact".to_string(),
            thread_id,
            agent_id,
            run_id,
            updated_at: request.created_at.clone(),
            operator_control,
            context_compaction,
            run,
            agent,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct CodingToolBudgetRecoveryStateUpdateCore;

impl CodingToolBudgetRecoveryStateUpdateCore {
    pub fn plan(
        &self,
        request: &CodingToolBudgetRecoveryStateUpdateRequest,
    ) -> Result<CodingToolBudgetRecoveryStateUpdateRecord, CodingToolBudgetRecoveryStateUpdateError>
    {
        request.validate()?;
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let run_id = optional_trimmed(request.run_id.as_deref());
        let source = optional_trimmed(Some(request.source.as_str()))
            .unwrap_or_else(|| "runtime_auto".to_string());
        let approval_id = optional_trimmed(Some(request.approval_id.as_str())).unwrap();
        let operator_control = json!({
            "control": "coding_tool_budget_recovery",
            "action": "retry_approved",
            "approval_id": approval_id,
            "status": "completed",
            "source": source,
            "event_id": request.event_id,
            "seq": request.seq,
            "receipt_refs": request.receipt_refs.clone(),
            "policy_decision_refs": request.policy_decision_refs.clone(),
            "created_at": request.created_at,
        });
        let mut run = object_value(&request.run).ok_or(
            CodingToolBudgetRecoveryStateUpdateError::MissingField("run"),
        )?;
        run.insert(
            "updatedAt".to_string(),
            Value::String(request.created_at.clone()),
        );
        let mut trace = run.get("trace").and_then(object_value).unwrap_or_default();
        let trace_controls =
            append_operator_control(trace.get("operatorControls"), &operator_control);
        trace.insert("operatorControls".to_string(), trace_controls);
        run.insert("trace".to_string(), Value::Object(trace));
        let run_controls = append_operator_control(run.get("operatorControls"), &operator_control);
        run.insert("operatorControls".to_string(), run_controls);

        Ok(CodingToolBudgetRecoveryStateUpdateRecord {
            schema_version: CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_RESULT_SCHEMA_VERSION
                .to_string(),
            object: "ioi.runtime_coding_tool_budget_recovery_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "workflow.run.retry_completed".to_string(),
            thread_id,
            run_id,
            updated_at: request.created_at.clone(),
            operator_control,
            run: Value::Object(run),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct DiagnosticsOperatorOverrideStateUpdateCore;

impl DiagnosticsOperatorOverrideStateUpdateCore {
    pub fn plan(
        &self,
        request: &DiagnosticsOperatorOverrideStateUpdateRequest,
    ) -> Result<
        DiagnosticsOperatorOverrideStateUpdateRecord,
        DiagnosticsOperatorOverrideStateUpdateError,
    > {
        request.validate()?;
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let run_id = optional_trimmed(request.run_id.as_deref());
        let decision_id = optional_trimmed(Some(request.decision_id.as_str())).unwrap();
        let source = operator_control_source(Some(request.source.as_str()));
        let gate_event_id = optional_trimmed(request.gate_event_id.as_deref());
        let approval_source =
            optional_trimmed(request.approval_source.as_deref()).unwrap_or_else(|| {
                if request.approval_satisfied {
                    "satisfied".to_string()
                } else {
                    "missing".to_string()
                }
            });
        let snapshot_id = optional_trimmed(request.snapshot_id.as_deref());
        let operator_control = json!({
            "control": "diagnostics_operator_override",
            "source": source,
            "decision_id": decision_id,
            "gate_event_id": gate_event_id,
            "approval_required": request.approval_required,
            "approval_satisfied": request.approval_satisfied,
            "approval_source": approval_source,
            "snapshot_id": snapshot_id,
            "event_id": request.event_id,
            "seq": request.seq,
            "created_at": request.created_at,
        });
        let mut run = object_value(&request.run).ok_or(
            DiagnosticsOperatorOverrideStateUpdateError::MissingField("run"),
        )?;
        let updated_gate = run
            .get("diagnosticsBlockingGate")
            .and_then(object_value)
            .map(|mut gate| {
                gate.insert(
                    "status".to_string(),
                    Value::String("overridden".to_string()),
                );
                gate.insert(
                    "decision".to_string(),
                    Value::String("operator_override".to_string()),
                );
                gate.insert("continuationAllowed".to_string(), Value::Bool(true));
                gate.insert("continuation_allowed".to_string(), Value::Bool(true));
                gate.insert(
                    "approvalRequired".to_string(),
                    Value::Bool(request.approval_required),
                );
                gate.insert(
                    "approval_required".to_string(),
                    Value::Bool(request.approval_required),
                );
                gate.insert(
                    "approvalSatisfied".to_string(),
                    Value::Bool(request.approval_satisfied),
                );
                gate.insert(
                    "approval_satisfied".to_string(),
                    Value::Bool(request.approval_satisfied),
                );
                gate.insert(
                    "operatorOverrideEventId".to_string(),
                    Value::String(request.event_id.clone()),
                );
                gate.insert(
                    "operator_override_event_id".to_string(),
                    Value::String(request.event_id.clone()),
                );
                Value::Object(gate)
            });
        run.insert("status".to_string(), Value::String("completed".to_string()));
        run.remove("turnStatus");
        run.insert(
            "updatedAt".to_string(),
            Value::String(request.created_at.clone()),
        );
        run.insert(
            "result".to_string(),
            Value::String(
                "Operator override granted; blocking diagnostics gate marked continuation-allowed."
                    .to_string(),
            ),
        );
        if let Some(updated_gate) = updated_gate.clone() {
            run.insert("diagnosticsBlockingGate".to_string(), updated_gate);
        }
        let mut trace = run.get("trace").and_then(object_value).unwrap_or_default();
        if let Some(updated_gate) = updated_gate {
            trace.insert("diagnosticsBlockingGate".to_string(), updated_gate);
        }
        let mut stop_condition = trace
            .get("stopCondition")
            .and_then(object_value)
            .unwrap_or_default();
        stop_condition.insert(
            "reason".to_string(),
            Value::String("operator_override_granted".to_string()),
        );
        stop_condition.insert("evidenceSufficient".to_string(), Value::Bool(true));
        stop_condition.insert(
            "rationale".to_string(),
            Value::String(
                "Operator override granted continuation despite blocking diagnostics.".to_string(),
            ),
        );
        trace.insert("stopCondition".to_string(), Value::Object(stop_condition));
        let trace_controls =
            append_operator_control(trace.get("operatorControls"), &operator_control);
        trace.insert("operatorControls".to_string(), trace_controls);
        run.insert("trace".to_string(), Value::Object(trace));
        let run_controls = append_operator_control(run.get("operatorControls"), &operator_control);
        run.insert("operatorControls".to_string(), run_controls);

        Ok(DiagnosticsOperatorOverrideStateUpdateRecord {
            schema_version: DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_RESULT_SCHEMA_VERSION
                .to_string(),
            object: "ioi.runtime_diagnostics_operator_override_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "diagnostics.operator_override.event".to_string(),
            thread_id,
            run_id,
            updated_at: request.created_at.clone(),
            operator_control,
            run: Value::Object(run),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct OperatorInterruptStateUpdateCore;

impl OperatorInterruptStateUpdateCore {
    pub fn plan(
        &self,
        request: &OperatorInterruptStateUpdateRequest,
    ) -> Result<OperatorInterruptStateUpdateRecord, OperatorInterruptStateUpdateError> {
        request.validate()?;
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let turn_id = optional_trimmed(request.turn_id.as_deref());
        let run_id = optional_trimmed(request.run_id.as_deref());
        let source = operator_control_source(Some(request.source.as_str()));
        let reason = optional_trimmed(Some(request.reason.as_str()))
            .unwrap_or_else(|| "operator requested interrupt".to_string());
        let operator_control = json!({
            "control": "interrupt",
            "source": source,
            "reason": reason,
            "event_id": request.event_id,
            "seq": request.seq,
            "created_at": request.created_at,
        });
        let stop_condition = json!({
            "reason": "operator_interrupt",
            "evidenceSufficient": true,
            "rationale": format!("Operator interrupt accepted from {source}: {reason}"),
        });
        let mut run = object_value(&request.run)
            .ok_or(OperatorInterruptStateUpdateError::MissingField("run"))?;
        let prior_status = run
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if matches!(prior_status.as_str(), "queued" | "running" | "blocked") {
            run.insert("status".to_string(), Value::String("canceled".to_string()));
        }
        run.insert(
            "turnStatus".to_string(),
            Value::String("interrupted".to_string()),
        );
        run.insert(
            "updatedAt".to_string(),
            Value::String(request.created_at.clone()),
        );
        run.insert(
            "result".to_string(),
            Value::String(format!("Turn interrupted by operator: {reason}")),
        );
        let mut trace = run.get("trace").and_then(object_value).unwrap_or_default();
        trace.insert(
            "status".to_string(),
            Value::String("interrupted".to_string()),
        );
        trace.insert("stopCondition".to_string(), stop_condition.clone());
        let trace_controls =
            append_operator_control(trace.get("operatorControls"), &operator_control);
        trace.insert("operatorControls".to_string(), trace_controls);
        let mut quality_ledger = trace
            .get("qualityLedger")
            .and_then(object_value)
            .unwrap_or_default();
        let mut labels = quality_ledger
            .get("failureOntologyLabels")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !labels
            .iter()
            .any(|label| label.as_str() == Some("operator_interrupt"))
        {
            labels.push(Value::String("operator_interrupt".to_string()));
        }
        quality_ledger.insert("failureOntologyLabels".to_string(), Value::Array(labels));
        trace.insert("qualityLedger".to_string(), Value::Object(quality_ledger));
        run.insert("trace".to_string(), Value::Object(trace));
        let run_controls = append_operator_control(run.get("operatorControls"), &operator_control);
        run.insert("operatorControls".to_string(), run_controls);

        Ok(OperatorInterruptStateUpdateRecord {
            schema_version: OPERATOR_INTERRUPT_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_operator_interrupt_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "turn.interrupt".to_string(),
            thread_id,
            turn_id,
            run_id,
            updated_at: request.created_at.clone(),
            operator_control,
            stop_condition,
            run: Value::Object(run),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct OperatorSteerStateUpdateCore;

impl OperatorSteerStateUpdateCore {
    pub fn plan(
        &self,
        request: &OperatorSteerStateUpdateRequest,
    ) -> Result<OperatorSteerStateUpdateRecord, OperatorSteerStateUpdateError> {
        request.validate()?;
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let turn_id = optional_trimmed(request.turn_id.as_deref());
        let run_id = optional_trimmed(request.run_id.as_deref());
        let source = operator_control_source(Some(request.source.as_str()));
        let guidance = optional_trimmed(Some(request.guidance.as_str()))
            .unwrap_or_else(|| "operator provided steering guidance".to_string());
        let operator_control = json!({
            "control": "steer",
            "source": source,
            "guidance": guidance,
            "event_id": request.event_id,
            "seq": request.seq,
            "created_at": request.created_at,
        });
        let mut run =
            object_value(&request.run).ok_or(OperatorSteerStateUpdateError::MissingField("run"))?;
        run.insert(
            "updatedAt".to_string(),
            Value::String(request.created_at.clone()),
        );
        let mut trace = run.get("trace").and_then(object_value).unwrap_or_default();
        let trace_controls =
            append_operator_control(trace.get("operatorControls"), &operator_control);
        trace.insert("operatorControls".to_string(), trace_controls);
        run.insert("trace".to_string(), Value::Object(trace));
        let run_controls = append_operator_control(run.get("operatorControls"), &operator_control);
        run.insert("operatorControls".to_string(), run_controls);

        Ok(OperatorSteerStateUpdateRecord {
            schema_version: OPERATOR_STEER_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_operator_steer_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "turn.steer".to_string(),
            thread_id,
            turn_id,
            run_id,
            updated_at: request.created_at.clone(),
            operator_control,
            run: Value::Object(run),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RunCancelStateUpdateCore;

impl RunCancelStateUpdateCore {
    pub fn plan(
        &self,
        request: &RunCancelStateUpdateRequest,
    ) -> Result<RunCancelStateUpdateRecord, RunCancelStateUpdateError> {
        request.validate()?;
        let mut run =
            object_value(&request.run).ok_or(RunCancelStateUpdateError::MissingField("run"))?;
        let run_id = optional_trimmed(request.run_id.as_deref())
            .or_else(|| optional_json_string(&Value::Object(run.clone()), "id"))
            .ok_or(RunCancelStateUpdateError::MissingField("run.id"))?;
        let agent_id = optional_json_string(&Value::Object(run.clone()), "agentId")
            .ok_or(RunCancelStateUpdateError::MissingField("agentId"))?;
        let mode = optional_json_string(&Value::Object(run.clone()), "mode")
            .unwrap_or_else(|| "send".to_string());
        let created_at = optional_json_string(&Value::Object(run.clone()), "createdAt")
            .unwrap_or_else(|| request.canceled_at.clone());
        let events = run
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut canceled_events = events
            .into_iter()
            .filter(|event| {
                !is_terminal_event_type(json_string_value(event, "type").as_deref())
                    && !is_job_terminal_event_type(json_string_value(event, "type").as_deref())
            })
            .collect::<Vec<_>>();
        let has_runtime_task_event = canceled_events
            .iter()
            .any(|event| json_string_value(event, "type").as_deref() == Some("runtime_task"));
        let has_runtime_checklist_event = canceled_events
            .iter()
            .any(|event| json_string_value(event, "type").as_deref() == Some("runtime_checklist"));
        let final_event_count = canceled_events.len()
            + if has_runtime_task_event { 0 } else { 1 }
            + if has_runtime_checklist_event { 0 } else { 1 }
            + 2;
        let runtime_task = runtime_task_record_for_canceled_run(
            &Value::Object(run.clone()),
            &run_id,
            &agent_id,
            &mode,
            &created_at,
            &request.canceled_at,
        );
        let runtime_checklist_receipt_id = format!("receipt_{run_id}_runtime_checklist");
        let mut runtime_job = runtime_job_record_for_canceled_run(
            &Value::Object(run.clone()),
            &runtime_task,
            &run_id,
            &created_at,
            &request.canceled_at,
            final_event_count,
        );
        let runtime_checklist = runtime_checklist_record_for_canceled_run(
            &Value::Object(run.clone()),
            &runtime_task,
            &runtime_job,
            &run_id,
            &created_at,
            &request.canceled_at,
        );
        runtime_job = attach_runtime_checklist_to_job(runtime_job, &runtime_checklist);

        for event in &mut canceled_events {
            match json_string_value(event, "type").as_deref() {
                Some("runtime_task") => {
                    let mut data = object_value(&runtime_task).unwrap_or_default();
                    data.insert(
                        "receiptId".to_string(),
                        Value::String(format!("receipt_{run_id}_runtime_task")),
                    );
                    data.insert(
                        "eventKind".to_string(),
                        Value::String("RuntimeTaskRecord".to_string()),
                    );
                    data.insert(
                        "workflowNodeId".to_string(),
                        Value::String("runtime.runtime-task".to_string()),
                    );
                    if let Some(object) = event.as_object_mut() {
                        object.insert("data".to_string(), Value::Object(data));
                    }
                }
                Some("runtime_checklist") => {
                    let mut data = object_value(&runtime_checklist).unwrap_or_default();
                    data.insert(
                        "receiptId".to_string(),
                        Value::String(runtime_checklist_receipt_id.clone()),
                    );
                    data.insert(
                        "eventKind".to_string(),
                        Value::String("RuntimeChecklistRecord".to_string()),
                    );
                    data.insert(
                        "workflowNodeId".to_string(),
                        Value::String("runtime.runtime-checklist".to_string()),
                    );
                    if let Some(object) = event.as_object_mut() {
                        object.insert("data".to_string(), Value::Object(data));
                    }
                }
                _ => {}
            }
        }
        if !has_runtime_task_event {
            let mut data = object_value(&runtime_task).unwrap_or_default();
            data.insert(
                "receiptId".to_string(),
                Value::String(format!("receipt_{run_id}_runtime_task")),
            );
            data.insert(
                "eventKind".to_string(),
                Value::String("RuntimeTaskRecord".to_string()),
            );
            data.insert(
                "workflowNodeId".to_string(),
                Value::String("runtime.runtime-task".to_string()),
            );
            canceled_events.push(make_run_event(
                &run_id,
                &agent_id,
                canceled_events.len(),
                "runtime_task",
                "Runtime task record written",
                Value::Object(data),
                &request.canceled_at,
            ));
        }
        if !has_runtime_checklist_event {
            let mut data = object_value(&runtime_checklist).unwrap_or_default();
            data.insert(
                "receiptId".to_string(),
                Value::String(runtime_checklist_receipt_id.clone()),
            );
            data.insert(
                "eventKind".to_string(),
                Value::String("RuntimeChecklistRecord".to_string()),
            );
            data.insert(
                "workflowNodeId".to_string(),
                Value::String("runtime.runtime-checklist".to_string()),
            );
            canceled_events.push(make_run_event(
                &run_id,
                &agent_id,
                canceled_events.len(),
                "runtime_checklist",
                "Runtime checklist recorded",
                Value::Object(data),
                &request.canceled_at,
            ));
        }
        let mut job_data = object_value(&runtime_job).unwrap_or_default();
        job_data.insert(
            "lifecycleStatus".to_string(),
            Value::String("canceled".to_string()),
        );
        job_data.insert(
            "receiptId".to_string(),
            Value::String(format!("receipt_{run_id}_runtime_job")),
        );
        job_data.insert(
            "eventKind".to_string(),
            Value::String("JobCanceled".to_string()),
        );
        job_data.insert(
            "workflowNodeId".to_string(),
            Value::String("runtime.runtime-job".to_string()),
        );
        canceled_events.push(make_run_event(
            &run_id,
            &agent_id,
            canceled_events.len(),
            "job_canceled",
            "Runtime job canceled",
            Value::Object(job_data),
            &request.canceled_at,
        ));
        canceled_events.push(make_run_event(
            &run_id,
            &agent_id,
            canceled_events.len(),
            "canceled",
            "Run canceled",
            json!({
                "reason": "operator_cancel",
                "priorStatus": optional_json_string(&Value::Object(run.clone()), "status").unwrap_or_default(),
            }),
            &request.canceled_at,
        ));

        let runtime_checklist_receipt = json!({
            "id": runtime_checklist_receipt_id,
            "kind": "runtime_checklist",
            "summary": runtime_checklist.get("summary").cloned().unwrap_or(Value::Null),
            "redaction": "redacted",
            "evidenceRefs": [
                runtime_checklist.get("checklistId").cloned().unwrap_or(Value::Null),
                runtime_task.get("taskId").cloned().unwrap_or(Value::Null),
                runtime_job.get("jobId").cloned().unwrap_or(Value::Null),
                "RuntimeChecklistNode",
                "runtime.checklists.durable_projection",
            ],
        });
        let mut receipts = run
            .get("receipts")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|receipt| {
                if json_string_value(&receipt, "id")
                    == json_string_value(&runtime_checklist_receipt, "id")
                {
                    runtime_checklist_receipt.clone()
                } else {
                    receipt
                }
            })
            .collect::<Vec<_>>();
        if !receipts.iter().any(|receipt| {
            json_string_value(receipt, "id") == json_string_value(&runtime_checklist_receipt, "id")
        }) {
            receipts.push(runtime_checklist_receipt);
        }
        let stop_condition = json!({
            "reason": "marginal_improvement_too_low",
            "evidenceSufficient": true,
            "rationale": "Cancellation became the single terminal event and replay cursor continuity was preserved.",
        });
        let mut trace = run.get("trace").and_then(object_value).unwrap_or_default();
        trace.insert("events".to_string(), Value::Array(canceled_events.clone()));
        trace.insert("receipts".to_string(), Value::Array(receipts.clone()));
        trace.insert("runtimeTask".to_string(), runtime_task.clone());
        trace.insert("runtimeJob".to_string(), runtime_job.clone());
        trace.insert("runtimeChecklist".to_string(), runtime_checklist.clone());
        trace.insert("stopCondition".to_string(), stop_condition.clone());
        let mut quality_ledger = trace
            .get("qualityLedger")
            .and_then(object_value)
            .unwrap_or_default();
        let mut labels = quality_ledger
            .get("failureOntologyLabels")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !labels
            .iter()
            .any(|label| label.as_str() == Some("operator_cancel"))
        {
            labels.push(Value::String("operator_cancel".to_string()));
        }
        quality_ledger.insert("failureOntologyLabels".to_string(), Value::Array(labels));
        trace.insert("qualityLedger".to_string(), Value::Object(quality_ledger));

        let mut artifacts = run
            .get("artifacts")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(
                |artifact| match json_string_value(&artifact, "name").as_deref() {
                    Some("runtime-task.json") => {
                        artifact_with_content(artifact, runtime_task.clone())
                    }
                    Some("runtime-job.json") => {
                        artifact_with_content(artifact, runtime_job.clone())
                    }
                    Some("runtime-checklist.json") => {
                        artifact_with_content(artifact, runtime_checklist.clone())
                    }
                    _ => artifact,
                },
            )
            .collect::<Vec<_>>();
        if !artifacts.iter().any(|artifact| {
            json_string_value(artifact, "name").as_deref() == Some("runtime-checklist.json")
        }) {
            artifacts.push(runtime_artifact(
                &run_id,
                "runtime-checklist.json",
                "application/json",
                &format!("receipt_{run_id}_runtime_checklist"),
                runtime_checklist.clone(),
                "redacted",
            ));
        }

        run.insert("status".to_string(), Value::String("canceled".to_string()));
        run.insert(
            "updatedAt".to_string(),
            Value::String(request.canceled_at.clone()),
        );
        run.insert("events".to_string(), Value::Array(canceled_events));
        run.insert("trace".to_string(), Value::Object(trace));
        run.insert("receipts".to_string(), Value::Array(receipts));
        run.insert("artifacts".to_string(), Value::Array(artifacts));
        run.insert("runtimeTask".to_string(), runtime_task.clone());
        run.insert("runtimeJob".to_string(), runtime_job.clone());
        run.insert("runtimeChecklist".to_string(), runtime_checklist.clone());
        run.insert(
            "result".to_string(),
            Value::String("Run canceled with terminal event continuity preserved.".to_string()),
        );

        Ok(RunCancelStateUpdateRecord {
            schema_version: RUN_CANCEL_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_run_cancel_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "run.cancel".to_string(),
            run_id: Some(run_id),
            updated_at: request.canceled_at.clone(),
            stop_condition,
            runtime_task,
            runtime_job,
            runtime_checklist,
            run: Value::Object(run),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct ThreadControlAgentStateUpdateCore;

impl ThreadControlAgentStateUpdateCore {
    pub fn plan(
        &self,
        request: &ThreadControlAgentStateUpdateRequest,
    ) -> Result<ThreadControlAgentStateUpdateRecord, ThreadControlAgentStateUpdateError> {
        request.validate()?;
        let mut agent = object_value(&request.agent)
            .ok_or(ThreadControlAgentStateUpdateError::MissingField("agent"))?;
        let agent_id = optional_json_string(&Value::Object(agent.clone()), "id")
            .ok_or(ThreadControlAgentStateUpdateError::MissingField("agent.id"))?;
        let control_kind = normalized_thread_control_kind(request.control_kind.as_str())?;
        let controls = object_value(&request.controls)
            .ok_or(ThreadControlAgentStateUpdateError::MissingField("controls"))?;
        let updated_at = optional_trimmed(request.updated_at.as_deref())
            .or_else(|| optional_trimmed(request.workspace_trust_warning_created_at.as_deref()))
            .unwrap_or_else(|| request.created_at.clone());

        if control_kind != "mode" {
            let model_route = request.model_route.as_ref().and_then(object_value).ok_or(
                ThreadControlAgentStateUpdateError::MissingField("model_route"),
            )?;
            let model_route_value = Value::Object(model_route.clone());
            let selected_model = optional_json_string(&model_route_value, "selected_model").ok_or(
                ThreadControlAgentStateUpdateError::MissingField("model_route.selected_model"),
            )?;
            let requested_model_id = optional_json_string(&model_route_value, "requested_model_id")
                .ok_or(ThreadControlAgentStateUpdateError::MissingField(
                    "model_route.requested_model_id",
                ))?;
            let route_id = optional_json_string(&model_route_value, "route_id").ok_or(
                ThreadControlAgentStateUpdateError::MissingField("model_route.route_id"),
            )?;

            agent.insert("modelId".to_string(), Value::String(selected_model));
            agent.insert(
                "requestedModelId".to_string(),
                Value::String(requested_model_id),
            );
            agent.insert("modelRouteId".to_string(), Value::String(route_id));
            insert_optional_string_field(
                &mut agent,
                "modelRouteEndpointId",
                optional_json_string(&model_route_value, "endpoint_id"),
            );
            insert_optional_string_field(
                &mut agent,
                "modelRouteProviderId",
                optional_json_string(&model_route_value, "provider_id"),
            );
            insert_optional_string_field(
                &mut agent,
                "modelRouteReceiptId",
                optional_json_string(&model_route_value, "receipt_id"),
            );
            agent.insert(
                "modelRouteDecision".to_string(),
                model_route.get("decision").cloned().unwrap_or(Value::Null),
            );
        }

        agent.insert("runtimeControls".to_string(), Value::Object(controls));
        agent.insert("updatedAt".to_string(), Value::String(updated_at.clone()));
        let control = json!({
            "control_kind": control_kind,
            "event_id": request.event_id,
            "seq": request.seq,
            "created_at": request.created_at,
            "workspace_trust_warning_event_id": request.workspace_trust_warning_event_id,
        });

        Ok(ThreadControlAgentStateUpdateRecord {
            schema_version: THREAD_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_thread_control_agent_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: format!("thread.{control_kind}"),
            thread_id: request.thread_id.clone(),
            agent_id,
            updated_at,
            control,
            agent: Value::Object(agent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct AgentCreateStateUpdateCore;

impl AgentCreateStateUpdateCore {
    pub fn plan(
        &self,
        request: &AgentCreateStateUpdateRequest,
    ) -> Result<AgentCreateStateUpdateRecord, AgentCreateStateUpdateError> {
        request.validate()?;
        let agent = object_value(&request.agent)
            .ok_or(AgentCreateStateUpdateError::MissingField("agent"))?;
        let agent_value = Value::Object(agent.clone());
        let agent_id = optional_json_string(&agent_value, "id")
            .ok_or(AgentCreateStateUpdateError::MissingField("agent.id"))?;
        let created_at = optional_json_string(&agent_value, "createdAt")
            .ok_or(AgentCreateStateUpdateError::MissingField("agent.createdAt"))?;
        let updated_at = optional_json_string(&agent_value, "updatedAt")
            .ok_or(AgentCreateStateUpdateError::MissingField("agent.updatedAt"))?;

        Ok(AgentCreateStateUpdateRecord {
            schema_version: AGENT_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_agent_create_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "agent.create".to_string(),
            agent_id,
            created_at,
            updated_at,
            agent: Value::Object(agent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RunCreateStateUpdateCore;

impl RunCreateStateUpdateCore {
    pub fn plan(
        &self,
        request: &RunCreateStateUpdateRequest,
    ) -> Result<RunCreateStateUpdateRecord, RunCreateStateUpdateError> {
        request.validate()?;
        let run =
            object_value(&request.run).ok_or(RunCreateStateUpdateError::MissingField("run"))?;
        let run_value = Value::Object(run.clone());
        let run_id = optional_json_string(&run_value, "id")
            .ok_or(RunCreateStateUpdateError::MissingField("run.id"))?;
        let agent_id = optional_json_string(&run_value, "agentId")
            .ok_or(RunCreateStateUpdateError::MissingField("run.agentId"))?;
        let created_at = optional_json_string(&run_value, "createdAt")
            .ok_or(RunCreateStateUpdateError::MissingField("run.createdAt"))?;
        let updated_at = optional_json_string(&run_value, "updatedAt")
            .ok_or(RunCreateStateUpdateError::MissingField("run.updatedAt"))?;

        Ok(RunCreateStateUpdateRecord {
            schema_version: RUN_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_run_create_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "run.create".to_string(),
            run_id,
            agent_id,
            created_at,
            updated_at,
            run: Value::Object(run),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct AgentStatusStateUpdateCore;

impl AgentStatusStateUpdateCore {
    pub fn plan(
        &self,
        request: &AgentStatusStateUpdateRequest,
    ) -> Result<AgentStatusStateUpdateRecord, AgentStatusStateUpdateError> {
        request.validate()?;
        let mut agent = object_value(&request.agent)
            .ok_or(AgentStatusStateUpdateError::MissingField("agent"))?;
        let agent_id = optional_json_string(&Value::Object(agent.clone()), "id")
            .ok_or(AgentStatusStateUpdateError::MissingField("agent.id"))?;
        agent.insert("status".to_string(), Value::String(request.status.clone()));
        agent.insert(
            "updatedAt".to_string(),
            Value::String(request.updated_at.clone()),
        );

        Ok(AgentStatusStateUpdateRecord {
            schema_version: AGENT_STATUS_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_agent_status_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: request.operation_kind.clone(),
            agent_id,
            updated_at: request.updated_at.clone(),
            agent: Value::Object(agent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpControlAgentStateUpdateCore;

impl McpControlAgentStateUpdateCore {
    pub fn plan(
        &self,
        request: &McpControlAgentStateUpdateRequest,
    ) -> Result<McpControlAgentStateUpdateRecord, McpControlAgentStateUpdateError> {
        request.validate()?;
        let mut agent = object_value(&request.agent)
            .ok_or(McpControlAgentStateUpdateError::MissingField("agent"))?;
        let agent_id = optional_json_string(&Value::Object(agent.clone()), "id")
            .ok_or(McpControlAgentStateUpdateError::MissingField("agent.id"))?;
        let control_kind = optional_trimmed(Some(request.control_kind.as_str())).ok_or(
            McpControlAgentStateUpdateError::MissingField("control_kind"),
        )?;
        agent.insert(
            "updatedAt".to_string(),
            Value::String(request.created_at.clone()),
        );
        let control = json!({
            "control_kind": control_kind,
            "event_id": request.event_id,
            "seq": request.seq,
            "created_at": request.created_at,
        });

        Ok(McpControlAgentStateUpdateRecord {
            schema_version: MCP_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_mcp_control_agent_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: format!("thread.{control_kind}"),
            thread_id: request.thread_id.clone(),
            agent_id,
            updated_at: request.created_at.clone(),
            control,
            agent: Value::Object(agent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpServerValidationCore;

impl McpServerValidationCore {
    pub fn validate(
        &self,
        request: &McpServerValidationRequest,
    ) -> Result<McpServerValidationRecord, McpServerValidationError> {
        request.validate()?;
        let mut issues = Vec::new();
        let mut warnings = Vec::new();

        for server in &request.servers {
            let transport = normalize_mcp_transport(json_string_value(server, "transport"));
            let server_id = json_string_value(server, "id");
            let server_url = json_string_value(server, "server_url")
                .or_else(|| json_string_value(server, "endpoint"));

            if !matches!(transport.as_str(), "stdio" | "http" | "sse") {
                issues.push(mcp_validation_diagnostic(
                    "mcp_transport_unsupported",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "transport": transport,
                        "message": "MCP server transport must be stdio, http, or sse."
                    }),
                ));
            }
            if transport == "stdio" && json_string_value(server, "command").is_none() {
                issues.push(mcp_validation_diagnostic(
                    "mcp_server_transport_missing",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "message": "MCP stdio server must declare a command."
                    }),
                ));
            }
            if matches!(transport.as_str(), "http" | "sse") && server_url.is_none() {
                issues.push(mcp_validation_diagnostic(
                    "mcp_server_transport_missing",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "message": "MCP HTTP/SSE server must declare a remote URL."
                    }),
                ));
            }
            if matches!(transport.as_str(), "http" | "sse")
                && server_url.as_deref().is_some_and(|url| !is_http_url(url))
            {
                issues.push(mcp_validation_diagnostic(
                    "mcp_remote_url_invalid",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "message": "MCP HTTP/SSE server URL must use http:// or https://."
                    }),
                ));
            }
            if matches!(transport.as_str(), "http" | "sse")
                && json_bool_path(server, &["containment", "allow_network_egress"]) == Some(false)
            {
                issues.push(mcp_validation_diagnostic(
                    "mcp_remote_network_blocked",
                    "error",
                    server_id.as_deref(),
                    json!({
                        "message": "MCP HTTP/SSE server requires network egress in containment policy."
                    }),
                ));
            }

            if let Some(secret_refs) = server.get("secret_refs").and_then(Value::as_object) {
                for (key, value) in secret_refs {
                    if value.get("invalidVaultRef").and_then(Value::as_bool) == Some(true) {
                        issues.push(mcp_validation_diagnostic(
                            "mcp_secret_not_vault_ref",
                            "error",
                            server_id.as_deref(),
                            json!({
                                "key": key,
                                "message": "MCP env/header secrets must be represented as vault:// refs before activation."
                            }),
                        ));
                    }
                }
            }

            let allowed_tool_count = server
                .get("allowed_tools")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            if allowed_tool_count == 0 {
                warnings.push(mcp_validation_diagnostic(
                    "mcp_allowed_tools_empty",
                    "warning",
                    server_id.as_deref(),
                    json!({
                        "message": "No allowed_tools list is declared; invocation remains unavailable until tools are narrowed."
                    }),
                ));
            }
        }

        let ok = issues.is_empty();
        Ok(McpServerValidationRecord {
            schema_version: MCP_SERVER_VALIDATION_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_mcp_server_validation".to_string(),
            status: if ok { "pass" } else { "blocked" }.to_string(),
            ok,
            issue_count: issues.len(),
            warning_count: warnings.len(),
            issues,
            warnings,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpServerValidationInputCore;

impl McpServerValidationInputCore {
    pub fn project(
        &self,
        request: &McpServerValidationInputRequest,
    ) -> Result<McpServerValidationInputRecord, McpServerValidationInputError> {
        request.validate()?;
        let workspace_root = request
            .workspace_root
            .as_deref()
            .and_then(|value| optional_trimmed(Some(value)));
        let raw = request.input.get("mcp_json").unwrap_or(&request.input);
        let servers = raw
            .get("mcp_servers")
            .or_else(|| raw.get("servers"))
            .or_else(|| if raw.is_array() { Some(raw) } else { None });
        let records = match servers {
            Some(Value::Array(items)) => items
                .iter()
                .enumerate()
                .map(|(index, server)| {
                    let label = mcp_validation_server_label(server)
                        .unwrap_or_else(|| format!("server_{}", index + 1));
                    normalize_mcp_validation_server_record(
                        &label,
                        server,
                        workspace_root.as_deref(),
                        json_string_value(server, "source")
                            .as_deref()
                            .unwrap_or("validation_input"),
                        json_string_value(server, "source_scope")
                            .as_deref()
                            .unwrap_or("validation"),
                        json_string_value(server, "status")
                            .as_deref()
                            .unwrap_or("configured"),
                    )
                })
                .collect::<Vec<_>>(),
            Some(Value::Object(map)) => map
                .iter()
                .map(|(label, config)| {
                    normalize_mcp_validation_server_record(
                        label,
                        config,
                        workspace_root.as_deref(),
                        "validation_input",
                        "validation",
                        "configured",
                    )
                })
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };

        Ok(McpServerValidationInputRecord {
            schema_version: MCP_SERVER_VALIDATION_INPUT_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_mcp_server_validation_input".to_string(),
            status: "projected".to_string(),
            workspace_root,
            server_count: records.len(),
            servers: records,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpManagerValidationProjectionCore;

impl McpManagerValidationProjectionCore {
    pub fn project(
        &self,
        request: &McpManagerValidationProjectionRequest,
    ) -> Result<McpManagerValidationProjectionRecord, McpManagerValidationProjectionError> {
        request.validate()?;

        let ok = request
            .validation
            .get("ok")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let issues = request
            .validation
            .get("issues")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let warnings = request
            .validation
            .get("warnings")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        Ok(McpManagerValidationProjectionRecord {
            schema_version: request
                .validation_schema_version
                .clone()
                .unwrap_or_else(|| {
                    MCP_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
                }),
            object: "ioi.runtime_mcp_manager_validation".to_string(),
            ok,
            status: if ok { "pass" } else { "blocked" }.to_string(),
            server_count: request.servers.len(),
            tool_count: request.tools.len(),
            resource_count: request.resources.len(),
            prompt_count: request.prompts.len(),
            issue_count: issues.len(),
            warning_count: warnings.len(),
            issues,
            warnings,
            servers: request.servers.clone(),
            tools: request.tools.clone(),
            resources: request.resources.clone(),
            prompts: request.prompts.clone(),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpManagerCatalogProjectionCore;

impl McpManagerCatalogProjectionCore {
    pub fn project(
        &self,
        request: &McpManagerCatalogProjectionRequest,
    ) -> Result<McpManagerCatalogProjectionRecord, McpManagerCatalogProjectionError> {
        request.validate()?;

        let mut tools = Vec::new();
        let mut resources = Vec::new();
        let mut prompts = Vec::new();
        let mut enabled_tools = Vec::new();

        for server in &request.servers {
            let server_tools = mcp_catalog_tools_for_server(server);
            if server.get("enabled").and_then(Value::as_bool) != Some(false) {
                enabled_tools.extend(server_tools.clone());
            }
            tools.extend(server_tools);
            resources.extend(mcp_catalog_resources_for_server(server));
            prompts.extend(mcp_catalog_prompts_for_server(server));
        }

        resources.sort_by(|left, right| {
            mcp_catalog_resource_key(left).cmp(&mcp_catalog_resource_key(right))
        });
        prompts.sort_by(|left, right| {
            mcp_catalog_prompt_key(left).cmp(&mcp_catalog_prompt_key(right))
        });

        Ok(McpManagerCatalogProjectionRecord {
            schema_version: request.status_schema_version.clone().unwrap_or_else(|| {
                MCP_MANAGER_CATALOG_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
            }),
            object: "ioi.runtime_mcp_manager_catalog_projection".to_string(),
            status: "projected".to_string(),
            server_count: request.servers.len(),
            tool_count: tools.len(),
            resource_count: resources.len(),
            prompt_count: prompts.len(),
            enabled_tool_count: enabled_tools.len(),
            servers: request.servers.clone(),
            tools,
            resources,
            prompts,
            enabled_tools,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpManagerCatalogSummaryProjectionCore;

impl McpManagerCatalogSummaryProjectionCore {
    pub fn project(
        &self,
        request: &McpManagerCatalogSummaryProjectionRequest,
    ) -> Result<McpManagerCatalogSummaryProjectionRecord, McpManagerCatalogSummaryProjectionError>
    {
        request.validate()?;

        let mut tool_names = request
            .tools
            .iter()
            .filter_map(|tool| mcp_catalog_field_string(tool, &["tool_name", "name"]))
            .collect::<Vec<_>>();
        tool_names.sort();

        let namespaces = mcp_tool_namespaces(&tool_names);
        let preview_limit = request.preview_limit.unwrap_or(25).clamp(1, 100);
        let deferred = request
            .deferred
            .unwrap_or_else(|| request.tools.len() > preview_limit);
        let preview_tool_names = tool_names
            .iter()
            .take(preview_limit.min(20))
            .cloned()
            .collect::<Vec<_>>();
        let catalog_hash = mcp_catalog_summary_hash(
            &request.server,
            &request.tools,
            &request.resources,
            &request.prompts,
        );

        Ok(McpManagerCatalogSummaryProjectionRecord {
            schema_version: request.status_schema_version.clone().unwrap_or_else(|| {
                MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
            }),
            object: "ioi.runtime_mcp_catalog_summary".to_string(),
            status: request
                .status
                .clone()
                .unwrap_or_else(|| "completed".to_string()),
            server_id: json_string_value(&request.server, "id"),
            server_label: json_string_value(&request.server, "label")
                .or_else(|| json_string_value(&request.server, "name"))
                .or_else(|| json_string_value(&request.server, "id")),
            transport: json_string_value(&request.server, "transport"),
            execution_mode: request.live_mode.clone(),
            catalog_hash,
            tool_count: request.tools.len(),
            resource_count: request.resources.len(),
            prompt_count: request.prompts.len(),
            namespace_count: namespaces.len(),
            namespaces,
            preview_limit,
            preview_tool_names,
            deferred,
            full_catalog_included: !deferred,
            error_code: request.error_code.clone(),
            search_route: "/v1/mcp/tools/search".to_string(),
            fetch_route: "/v1/mcp/tools/{tool_id}".to_string(),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct McpManagerStatusProjectionCore;

impl McpManagerStatusProjectionCore {
    pub fn project(
        &self,
        request: &McpManagerStatusProjectionRequest,
    ) -> Result<McpManagerStatusProjectionRecord, McpManagerStatusProjectionError> {
        request.validate()?;

        let server_count = request.servers.len();
        let tool_count = request.tools.len();
        let resource_count = request.resources.len();
        let prompt_count = request.prompts.len();
        let enabled_server_count = request
            .servers
            .iter()
            .filter(|server| server.get("enabled").and_then(Value::as_bool) != Some(false))
            .count();
        let enabled_tool_count = if request.enabled_tools.is_empty() {
            None
        } else {
            Some(request.enabled_tools.len())
        };
        let ok = request
            .validation
            .get("ok")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let validation = extend_json_object(
            request.validation.clone(),
            json!({
                "server_count": server_count,
                "tool_count": tool_count,
                "resource_count": resource_count,
                "prompt_count": prompt_count,
                "servers": request.servers.clone(),
                "tools": request.tools.clone(),
                "resources": request.resources.clone(),
                "prompts": request.prompts.clone(),
            }),
        );

        Ok(McpManagerStatusProjectionRecord {
            schema_version: request
                .status_schema_version
                .clone()
                .unwrap_or_else(|| MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION.to_string()),
            object: "ioi.runtime_mcp_manager_status".to_string(),
            status: if ok { "ready" } else { "needs_review" }.to_string(),
            server_count,
            tool_count,
            resource_count,
            prompt_count,
            enabled_server_count,
            enabled_tool_count,
            servers: request.servers.clone(),
            tools: request.tools.clone(),
            resources: request.resources.clone(),
            prompts: request.prompts.clone(),
            validation,
            routes: request.routes.clone(),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryManagerValidationProjectionCore;

impl MemoryManagerValidationProjectionCore {
    pub fn project(
        &self,
        request: &MemoryManagerValidationProjectionRequest,
    ) -> Result<MemoryManagerValidationProjectionRecord, MemoryManagerValidationProjectionError>
    {
        request.validate()?;
        let records = memory_projection_records(&request.projection);
        let policy = memory_projection_object(&request.projection, "policy");
        let paths = memory_projection_object(&request.projection, "paths");
        let filters = memory_projection_object(&request.projection, "filters");
        let mut issues = Vec::new();
        let mut warnings = Vec::new();

        validate_memory_manager_policy(&policy, &mut issues, &mut warnings);
        validate_memory_manager_paths(&paths, &mut issues, &mut warnings);
        for record in &records {
            validate_memory_manager_record(record, &mut issues, &mut warnings);
        }

        let ok = issues.is_empty();
        Ok(MemoryManagerValidationProjectionRecord {
            schema_version: request
                .validation_schema_version
                .clone()
                .unwrap_or_else(|| {
                    MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
                }),
            object: "ioi.runtime_memory_manager_validation".to_string(),
            ok,
            status: if ok { "pass" } else { "blocked" }.to_string(),
            issue_count: issues.len(),
            warning_count: warnings.len(),
            record_count: records.len(),
            issues,
            warnings,
            policy,
            paths,
            filters,
            records,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryManagerStatusProjectionCore;

impl MemoryManagerStatusProjectionCore {
    pub fn project(
        &self,
        request: &MemoryManagerStatusProjectionRequest,
    ) -> Result<MemoryManagerStatusProjectionRecord, MemoryManagerStatusProjectionError> {
        request.validate()?;
        let validation = MemoryManagerValidationProjectionCore
            .project(&MemoryManagerValidationProjectionRequest {
                schema_version: MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION
                    .to_string(),
                validation_schema_version: request.validation_schema_version.clone(),
                projection: request.projection.clone(),
            })
            .map_err(|error| match error {
                MemoryManagerValidationProjectionError::InvalidSchemaVersion {
                    expected,
                    actual,
                } => MemoryManagerStatusProjectionError::InvalidSchemaVersion { expected, actual },
            })?;
        let records = memory_projection_records(&request.projection);
        let policy = memory_projection_object(&request.projection, "policy");
        let paths = memory_projection_object(&request.projection, "paths");
        let filters = memory_projection_object(&request.projection, "filters");
        let disabled = json_bool_value(&policy, "disabled").unwrap_or(false);
        let injection_enabled = json_bool_value(&policy, "injection_enabled").unwrap_or(true);
        let read_only = json_bool_value(&policy, "read_only").unwrap_or(false);
        let write_requires_approval =
            json_bool_value(&policy, "write_requires_approval").unwrap_or(false);
        let scopes = memory_unique_strings(
            records
                .iter()
                .filter_map(|record| json_string_value(record, "scope"))
                .collect(),
        );
        let memory_keys = memory_unique_strings(
            records
                .iter()
                .filter_map(|record| json_string_value(record, "memory_key"))
                .collect(),
        );
        let write_blocked_reason = if disabled {
            Some("memory_disabled".to_string())
        } else if read_only {
            Some("memory_read_only".to_string())
        } else if write_requires_approval {
            Some("memory_write_requires_approval".to_string())
        } else {
            None
        };
        let status = if validation.ok {
            if disabled {
                "disabled"
            } else {
                "ready"
            }
        } else {
            "needs_review"
        };
        let validation_value =
            serde_json::to_value(&validation).unwrap_or_else(|_| Value::Object(Default::default()));

        Ok(MemoryManagerStatusProjectionRecord {
            schema_version: request.status_schema_version.clone().unwrap_or_else(|| {
                MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION.to_string()
            }),
            object: "ioi.runtime_memory_manager_status".to_string(),
            status: status.to_string(),
            disabled,
            injection_enabled,
            read_only,
            write_requires_approval,
            write_blocked_reason,
            record_count: records.len(),
            scope_count: scopes.len(),
            memory_key_count: memory_keys.len(),
            scopes,
            memory_keys,
            policy: policy.clone(),
            paths: paths.clone(),
            filters,
            records: records.clone(),
            validation: validation_value,
            routes: json!({
                "records": "/v1/threads/{thread_id}/memory",
                "status": "/v1/threads/{thread_id}/memory/status",
                "validate": "/v1/threads/{thread_id}/memory/validate",
                "policy": "/v1/threads/{thread_id}/memory/policy",
                "path": "/v1/threads/{thread_id}/memory/path",
                "remember": "/v1/threads/{thread_id}/memory",
                "edit": "/v1/threads/{thread_id}/memory/{memory_id}",
                "delete": "/v1/threads/{thread_id}/memory/{memory_id}",
            }),
            evidence_refs: memory_status_evidence_refs(&policy, &paths, &records),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct ThreadMemoryAgentStateUpdateCore;

impl ThreadMemoryAgentStateUpdateCore {
    pub fn plan(
        &self,
        request: &ThreadMemoryAgentStateUpdateRequest,
    ) -> Result<ThreadMemoryAgentStateUpdateRecord, ThreadMemoryAgentStateUpdateError> {
        request.validate()?;
        let mut agent = object_value(&request.agent)
            .ok_or(ThreadMemoryAgentStateUpdateError::MissingField("agent"))?;
        let agent_id = optional_json_string(&Value::Object(agent.clone()), "id")
            .ok_or(ThreadMemoryAgentStateUpdateError::MissingField("agent.id"))?;
        let control_kind = optional_trimmed(Some(request.control_kind.as_str())).ok_or(
            ThreadMemoryAgentStateUpdateError::MissingField("control_kind"),
        )?;
        agent.insert(
            "updatedAt".to_string(),
            Value::String(request.created_at.clone()),
        );
        let control = json!({
            "control_kind": control_kind,
            "event_id": request.event_id,
            "seq": request.seq,
            "created_at": request.created_at,
        });

        Ok(ThreadMemoryAgentStateUpdateRecord {
            schema_version: THREAD_MEMORY_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_thread_memory_agent_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: format!("thread.{control_kind}"),
            thread_id: request.thread_id.clone(),
            agent_id,
            updated_at: request.created_at.clone(),
            control,
            agent: Value::Object(agent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RuntimeBridgeThreadStartAgentStateUpdateCore;

impl RuntimeBridgeThreadStartAgentStateUpdateCore {
    pub fn plan(
        &self,
        request: &RuntimeBridgeThreadStartAgentStateUpdateRequest,
    ) -> Result<
        RuntimeBridgeThreadStartAgentStateUpdateRecord,
        RuntimeBridgeThreadStartAgentStateUpdateError,
    > {
        request.validate()?;
        let mut agent = object_value(&request.agent).ok_or(
            RuntimeBridgeThreadStartAgentStateUpdateError::MissingField("agent"),
        )?;
        let agent_id = optional_json_string(&Value::Object(agent.clone()), "id").ok_or(
            RuntimeBridgeThreadStartAgentStateUpdateError::MissingField("agent.id"),
        )?;
        agent.insert(
            "runtimeProfile".to_string(),
            Value::String(request.runtime_profile.clone()),
        );
        agent.insert(
            "runtimeSessionId".to_string(),
            Value::String(request.session_id.clone()),
        );
        agent.insert(
            "runtimeBridgeId".to_string(),
            Value::String(request.bridge_id.clone()),
        );
        agent.insert(
            "runtimeBridgeStatus".to_string(),
            Value::String(request.status.clone()),
        );
        agent.insert(
            "runtimeBridgeSource".to_string(),
            Value::String(request.source.clone()),
        );
        agent.insert("fixtureProfile".to_string(), Value::Null);
        agent.insert(
            "updatedAt".to_string(),
            Value::String(request.updated_at.clone()),
        );
        let bridge_start = json!({
            "runtime_profile": request.runtime_profile,
            "session_id": request.session_id,
            "bridge_id": request.bridge_id,
            "status": request.status,
            "source": request.source,
            "updated_at": request.updated_at,
        });

        Ok(RuntimeBridgeThreadStartAgentStateUpdateRecord {
            schema_version: RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION
                .to_string(),
            object: "ioi.runtime_bridge_thread_start_agent_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "thread.runtime_bridge.start".to_string(),
            thread_id: request.thread_id.clone(),
            agent_id,
            updated_at: request.updated_at.clone(),
            bridge_start,
            agent: Value::Object(agent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RuntimeBridgeTurnRunStateUpdateCore;

impl RuntimeBridgeTurnRunStateUpdateCore {
    pub fn plan(
        &self,
        request: &RuntimeBridgeTurnRunStateUpdateRequest,
    ) -> Result<RuntimeBridgeTurnRunStateUpdateRecord, RuntimeBridgeTurnRunStateUpdateError> {
        request.validate()?;
        let run = object_value(&request.run)
            .ok_or(RuntimeBridgeTurnRunStateUpdateError::MissingField("run"))?;
        let run_value = Value::Object(run.clone());
        let projection = object_value(&request.projection).ok_or(
            RuntimeBridgeTurnRunStateUpdateError::MissingField("projection"),
        )?;
        let projection_value = Value::Object(projection);
        let run_id = optional_json_string(&run_value, "id")
            .ok_or(RuntimeBridgeTurnRunStateUpdateError::MissingField("run.id"))?;
        let agent_id = optional_json_string(&run_value, "agentId").ok_or(
            RuntimeBridgeTurnRunStateUpdateError::MissingField("run.agentId"),
        )?;
        let updated_at = optional_json_string(&run_value, "updatedAt").ok_or(
            RuntimeBridgeTurnRunStateUpdateError::MissingField("run.updatedAt"),
        )?;
        let projection_run_id = optional_json_string(&projection_value, "run_id").ok_or(
            RuntimeBridgeTurnRunStateUpdateError::MissingField("projection.run_id"),
        )?;
        if projection_run_id != run_id {
            return Err(RuntimeBridgeTurnRunStateUpdateError::MismatchedField {
                field: "projection.run_id",
                expected: run_id,
                actual: projection_run_id,
            });
        }

        Ok(RuntimeBridgeTurnRunStateUpdateRecord {
            schema_version: RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_bridge_turn_run_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "turn.runtime_bridge.submit".to_string(),
            thread_id: request.thread_id.clone(),
            run_id,
            agent_id,
            updated_at,
            run: Value::Object(run),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct SubagentRecordStateUpdateCore;

impl SubagentRecordStateUpdateCore {
    pub fn plan(
        &self,
        request: &SubagentRecordStateUpdateRequest,
    ) -> Result<SubagentRecordStateUpdateRecord, SubagentRecordStateUpdateError> {
        request.validate()?;
        let subagent = object_value(&request.subagent)
            .ok_or(SubagentRecordStateUpdateError::MissingField("subagent"))?;
        let subagent_value = Value::Object(subagent.clone());
        let subagent_id = optional_json_string(&subagent_value, "subagent_id").ok_or(
            SubagentRecordStateUpdateError::MissingField("subagent.subagent_id"),
        )?;
        let updated_at = optional_json_string(&subagent_value, "updated_at").ok_or(
            SubagentRecordStateUpdateError::MissingField("subagent.updated_at"),
        )?;

        Ok(SubagentRecordStateUpdateRecord {
            schema_version: SUBAGENT_RECORD_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_subagent_record_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: request.operation_kind.clone(),
            thread_id: request.thread_id.clone(),
            subagent_id,
            updated_at,
            subagent: Value::Object(subagent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

impl CompactionPolicyRequest {
    pub fn validate(&self) -> Result<(), CompactionPolicyError> {
        if self.schema_version != COMPACTION_POLICY_REQUEST_SCHEMA_VERSION {
            return Err(CompactionPolicyError::InvalidSchemaVersion {
                expected: COMPACTION_POLICY_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(CompactionPolicyError::MissingField("thread_id"));
        }
        if !self.context_budget.is_object() {
            return Err(CompactionPolicyError::MissingField("context_budget"));
        }
        Ok(())
    }
}

impl ContextCompactionPlanRequest {
    pub fn validate(&self) -> Result<(), ContextCompactionPlanError> {
        if self.schema_version != CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION {
            return Err(ContextCompactionPlanError::InvalidSchemaVersion {
                expected: CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(ContextCompactionPlanError::MissingField("thread_id"));
        }
        if optional_trimmed(Some(self.agent_id.as_str())).is_none() {
            return Err(ContextCompactionPlanError::MissingField("agent_id"));
        }
        Ok(())
    }
}

impl ContextCompactionStateUpdateRequest {
    pub fn validate(&self) -> Result<(), ContextCompactionStateUpdateError> {
        if self.schema_version != CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(ContextCompactionStateUpdateError::InvalidSchemaVersion {
                expected: CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(ContextCompactionStateUpdateError::MissingField("thread_id"));
        }
        if optional_trimmed(Some(self.agent_id.as_str())).is_none() {
            return Err(ContextCompactionStateUpdateError::MissingField("agent_id"));
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(ContextCompactionStateUpdateError::MissingField("event_id"));
        }
        if self.seq == 0 {
            return Err(ContextCompactionStateUpdateError::MissingField("seq"));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(ContextCompactionStateUpdateError::MissingField(
                "created_at",
            ));
        }
        if !self.agent.is_object() {
            return Err(ContextCompactionStateUpdateError::MissingField("agent"));
        }
        if context_compaction_state_target_kind(self.target_kind.as_deref(), self.run.as_ref())
            == "run"
            && !matches!(self.run.as_ref(), Some(value) if value.is_object())
        {
            return Err(ContextCompactionStateUpdateError::MissingField("run"));
        }
        Ok(())
    }
}

impl CodingToolBudgetRecoveryStateUpdateRequest {
    pub fn validate(&self) -> Result<(), CodingToolBudgetRecoveryStateUpdateError> {
        if self.schema_version != CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(
                CodingToolBudgetRecoveryStateUpdateError::InvalidSchemaVersion {
                    expected: CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        if !self.run.is_object() {
            return Err(CodingToolBudgetRecoveryStateUpdateError::MissingField(
                "run",
            ));
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(CodingToolBudgetRecoveryStateUpdateError::MissingField(
                "event_id",
            ));
        }
        if self.seq == 0 {
            return Err(CodingToolBudgetRecoveryStateUpdateError::MissingField(
                "seq",
            ));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(CodingToolBudgetRecoveryStateUpdateError::MissingField(
                "created_at",
            ));
        }
        if optional_trimmed(Some(self.approval_id.as_str())).is_none() {
            return Err(CodingToolBudgetRecoveryStateUpdateError::MissingField(
                "approval_id",
            ));
        }
        Ok(())
    }
}

impl DiagnosticsOperatorOverrideStateUpdateRequest {
    pub fn validate(&self) -> Result<(), DiagnosticsOperatorOverrideStateUpdateError> {
        if self.schema_version != DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION
        {
            return Err(
                DiagnosticsOperatorOverrideStateUpdateError::InvalidSchemaVersion {
                    expected: DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        if !self.run.is_object() {
            return Err(DiagnosticsOperatorOverrideStateUpdateError::MissingField(
                "run",
            ));
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(DiagnosticsOperatorOverrideStateUpdateError::MissingField(
                "event_id",
            ));
        }
        if self.seq == 0 {
            return Err(DiagnosticsOperatorOverrideStateUpdateError::MissingField(
                "seq",
            ));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(DiagnosticsOperatorOverrideStateUpdateError::MissingField(
                "created_at",
            ));
        }
        if optional_trimmed(Some(self.decision_id.as_str())).is_none() {
            return Err(DiagnosticsOperatorOverrideStateUpdateError::MissingField(
                "decision_id",
            ));
        }
        Ok(())
    }
}

impl OperatorInterruptStateUpdateRequest {
    pub fn validate(&self) -> Result<(), OperatorInterruptStateUpdateError> {
        if self.schema_version != OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(OperatorInterruptStateUpdateError::InvalidSchemaVersion {
                expected: OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if !self.run.is_object() {
            return Err(OperatorInterruptStateUpdateError::MissingField("run"));
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(OperatorInterruptStateUpdateError::MissingField("event_id"));
        }
        if self.seq == 0 {
            return Err(OperatorInterruptStateUpdateError::MissingField("seq"));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(OperatorInterruptStateUpdateError::MissingField(
                "created_at",
            ));
        }
        Ok(())
    }
}

impl OperatorSteerStateUpdateRequest {
    pub fn validate(&self) -> Result<(), OperatorSteerStateUpdateError> {
        if self.schema_version != OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(OperatorSteerStateUpdateError::InvalidSchemaVersion {
                expected: OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if !self.run.is_object() {
            return Err(OperatorSteerStateUpdateError::MissingField("run"));
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(OperatorSteerStateUpdateError::MissingField("event_id"));
        }
        if self.seq == 0 {
            return Err(OperatorSteerStateUpdateError::MissingField("seq"));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(OperatorSteerStateUpdateError::MissingField("created_at"));
        }
        Ok(())
    }
}

impl RunCancelStateUpdateRequest {
    pub fn validate(&self) -> Result<(), RunCancelStateUpdateError> {
        if self.schema_version != RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(RunCancelStateUpdateError::InvalidSchemaVersion {
                expected: RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if !self.run.is_object() {
            return Err(RunCancelStateUpdateError::MissingField("run"));
        }
        if optional_trimmed(Some(self.canceled_at.as_str())).is_none() {
            return Err(RunCancelStateUpdateError::MissingField("canceled_at"));
        }
        Ok(())
    }
}

impl ThreadControlAgentStateUpdateRequest {
    pub fn validate(&self) -> Result<(), ThreadControlAgentStateUpdateError> {
        if self.schema_version != THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(ThreadControlAgentStateUpdateError::InvalidSchemaVersion {
                expected: THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(ThreadControlAgentStateUpdateError::MissingField(
                "thread_id",
            ));
        }
        if !self.agent.is_object() {
            return Err(ThreadControlAgentStateUpdateError::MissingField("agent"));
        }
        if !self.controls.is_object() {
            return Err(ThreadControlAgentStateUpdateError::MissingField("controls"));
        }
        let control_kind = normalized_thread_control_kind(self.control_kind.as_str())?;
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(ThreadControlAgentStateUpdateError::MissingField("event_id"));
        }
        if self.seq == 0 {
            return Err(ThreadControlAgentStateUpdateError::MissingField("seq"));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(ThreadControlAgentStateUpdateError::MissingField(
                "created_at",
            ));
        }
        if control_kind != "mode" && self.model_route.as_ref().and_then(object_value).is_none() {
            return Err(ThreadControlAgentStateUpdateError::MissingField(
                "model_route",
            ));
        }
        Ok(())
    }
}

impl AgentCreateStateUpdateRequest {
    pub fn validate(&self) -> Result<(), AgentCreateStateUpdateError> {
        if self.schema_version != AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(AgentCreateStateUpdateError::InvalidSchemaVersion {
                expected: AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        let agent =
            object_value(&self.agent).ok_or(AgentCreateStateUpdateError::MissingField("agent"))?;
        let agent_value = Value::Object(agent);
        for field in ["id", "status", "runtime", "cwd", "createdAt", "updatedAt"] {
            if optional_json_string(&agent_value, field).is_none() {
                return Err(AgentCreateStateUpdateError::MissingField(match field {
                    "id" => "agent.id",
                    "status" => "agent.status",
                    "runtime" => "agent.runtime",
                    "cwd" => "agent.cwd",
                    "createdAt" => "agent.createdAt",
                    "updatedAt" => "agent.updatedAt",
                    _ => "agent",
                }));
            }
        }
        if !agent_value
            .get("runtimeControls")
            .is_some_and(Value::is_object)
        {
            return Err(AgentCreateStateUpdateError::MissingField(
                "agent.runtimeControls",
            ));
        }
        Ok(())
    }
}

impl RunCreateStateUpdateRequest {
    pub fn validate(&self) -> Result<(), RunCreateStateUpdateError> {
        if self.schema_version != RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(RunCreateStateUpdateError::InvalidSchemaVersion {
                expected: RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        let run = object_value(&self.run).ok_or(RunCreateStateUpdateError::MissingField("run"))?;
        let run_value = Value::Object(run);
        for field in ["id", "agentId", "status", "mode", "createdAt", "updatedAt"] {
            if optional_json_string(&run_value, field).is_none() {
                return Err(RunCreateStateUpdateError::MissingField(match field {
                    "id" => "run.id",
                    "agentId" => "run.agentId",
                    "status" => "run.status",
                    "mode" => "run.mode",
                    "createdAt" => "run.createdAt",
                    "updatedAt" => "run.updatedAt",
                    _ => "run",
                }));
            }
        }
        if !run_value.get("usage").is_some_and(Value::is_object) {
            return Err(RunCreateStateUpdateError::MissingField("run.usage"));
        }
        if !run_value
            .get("usage_telemetry")
            .is_some_and(Value::is_object)
        {
            return Err(RunCreateStateUpdateError::MissingField(
                "run.usage_telemetry",
            ));
        }
        let trace = run_value
            .get("trace")
            .and_then(Value::as_object)
            .ok_or(RunCreateStateUpdateError::MissingField("run.trace"))?;
        if !trace.get("usage_telemetry").is_some_and(Value::is_object) {
            return Err(RunCreateStateUpdateError::MissingField(
                "run.trace.usage_telemetry",
            ));
        }
        Ok(())
    }
}

impl AgentStatusStateUpdateRequest {
    pub fn validate(&self) -> Result<(), AgentStatusStateUpdateError> {
        if self.schema_version != AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(AgentStatusStateUpdateError::InvalidSchemaVersion {
                expected: AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        let agent =
            object_value(&self.agent).ok_or(AgentStatusStateUpdateError::MissingField("agent"))?;
        let agent_value = Value::Object(agent);
        if optional_json_string(&agent_value, "id").is_none() {
            return Err(AgentStatusStateUpdateError::MissingField("agent.id"));
        }
        if optional_trimmed(Some(self.status.as_str())).is_none() {
            return Err(AgentStatusStateUpdateError::MissingField("status"));
        }
        if optional_trimmed(Some(self.operation_kind.as_str())).is_none() {
            return Err(AgentStatusStateUpdateError::MissingField("operation_kind"));
        }
        if optional_trimmed(Some(self.updated_at.as_str())).is_none() {
            return Err(AgentStatusStateUpdateError::MissingField("updated_at"));
        }
        Ok(())
    }
}

impl McpControlAgentStateUpdateRequest {
    pub fn validate(&self) -> Result<(), McpControlAgentStateUpdateError> {
        if self.schema_version != MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(McpControlAgentStateUpdateError::InvalidSchemaVersion {
                expected: MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(McpControlAgentStateUpdateError::MissingField("thread_id"));
        }
        if !self.agent.is_object() {
            return Err(McpControlAgentStateUpdateError::MissingField("agent"));
        }
        if optional_trimmed(Some(self.control_kind.as_str())).is_none() {
            return Err(McpControlAgentStateUpdateError::MissingField(
                "control_kind",
            ));
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(McpControlAgentStateUpdateError::MissingField("event_id"));
        }
        if self.seq == 0 {
            return Err(McpControlAgentStateUpdateError::MissingField("seq"));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(McpControlAgentStateUpdateError::MissingField("created_at"));
        }
        let agent_value = Value::Object(object_value(&self.agent).unwrap_or_default());
        if optional_json_string(&agent_value, "id").is_none() {
            return Err(McpControlAgentStateUpdateError::MissingField("agent.id"));
        }
        Ok(())
    }
}

impl McpServerValidationRequest {
    pub fn validate(&self) -> Result<(), McpServerValidationError> {
        if self.schema_version != MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION {
            return Err(McpServerValidationError::InvalidSchemaVersion {
                expected: MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpServerValidationInputRequest {
    pub fn validate(&self) -> Result<(), McpServerValidationInputError> {
        if self.schema_version != MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION {
            return Err(McpServerValidationInputError::InvalidSchemaVersion {
                expected: MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpManagerStatusProjectionRequest {
    pub fn validate(&self) -> Result<(), McpManagerStatusProjectionError> {
        if self.schema_version != MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(McpManagerStatusProjectionError::InvalidSchemaVersion {
                expected: MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpManagerValidationProjectionRequest {
    pub fn validate(&self) -> Result<(), McpManagerValidationProjectionError> {
        if self.schema_version != MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(McpManagerValidationProjectionError::InvalidSchemaVersion {
                expected: MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl MemoryManagerValidationProjectionRequest {
    pub fn validate(&self) -> Result<(), MemoryManagerValidationProjectionError> {
        if self.schema_version != MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(
                MemoryManagerValidationProjectionError::InvalidSchemaVersion {
                    expected: MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        Ok(())
    }
}

impl MemoryManagerStatusProjectionRequest {
    pub fn validate(&self) -> Result<(), MemoryManagerStatusProjectionError> {
        if self.schema_version != MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(MemoryManagerStatusProjectionError::InvalidSchemaVersion {
                expected: MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpManagerCatalogProjectionRequest {
    pub fn validate(&self) -> Result<(), McpManagerCatalogProjectionError> {
        if self.schema_version != MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(McpManagerCatalogProjectionError::InvalidSchemaVersion {
                expected: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

impl McpManagerCatalogSummaryProjectionRequest {
    pub fn validate(&self) -> Result<(), McpManagerCatalogSummaryProjectionError> {
        if self.schema_version != MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(
                McpManagerCatalogSummaryProjectionError::InvalidSchemaVersion {
                    expected: MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        Ok(())
    }
}

impl ThreadMemoryAgentStateUpdateRequest {
    pub fn validate(&self) -> Result<(), ThreadMemoryAgentStateUpdateError> {
        if self.schema_version != THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(ThreadMemoryAgentStateUpdateError::InvalidSchemaVersion {
                expected: THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("thread_id"));
        }
        if !self.agent.is_object() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("agent"));
        }
        if optional_trimmed(Some(self.control_kind.as_str())).is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField(
                "control_kind",
            ));
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("event_id"));
        }
        if self.seq == 0 {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("seq"));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField(
                "created_at",
            ));
        }
        let agent_value = Value::Object(object_value(&self.agent).unwrap_or_default());
        if optional_json_string(&agent_value, "id").is_none() {
            return Err(ThreadMemoryAgentStateUpdateError::MissingField("agent.id"));
        }
        Ok(())
    }
}

impl RuntimeBridgeThreadStartAgentStateUpdateRequest {
    pub fn validate(&self) -> Result<(), RuntimeBridgeThreadStartAgentStateUpdateError> {
        if self.schema_version
            != RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION
        {
            return Err(
                RuntimeBridgeThreadStartAgentStateUpdateError::InvalidSchemaVersion {
                    expected: RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(RuntimeBridgeThreadStartAgentStateUpdateError::MissingField(
                "thread_id",
            ));
        }
        if !self.agent.is_object() {
            return Err(RuntimeBridgeThreadStartAgentStateUpdateError::MissingField(
                "agent",
            ));
        }
        for (field, value) in [
            ("runtime_profile", self.runtime_profile.as_str()),
            ("session_id", self.session_id.as_str()),
            ("bridge_id", self.bridge_id.as_str()),
            ("status", self.status.as_str()),
            ("source", self.source.as_str()),
            ("updated_at", self.updated_at.as_str()),
        ] {
            if optional_trimmed(Some(value)).is_none() {
                return Err(RuntimeBridgeThreadStartAgentStateUpdateError::MissingField(
                    field,
                ));
            }
        }
        let agent_value = Value::Object(object_value(&self.agent).unwrap_or_default());
        if optional_json_string(&agent_value, "id").is_none() {
            return Err(RuntimeBridgeThreadStartAgentStateUpdateError::MissingField(
                "agent.id",
            ));
        }
        Ok(())
    }
}

impl RuntimeBridgeTurnRunStateUpdateRequest {
    pub fn validate(&self) -> Result<(), RuntimeBridgeTurnRunStateUpdateError> {
        if self.schema_version != RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(RuntimeBridgeTurnRunStateUpdateError::InvalidSchemaVersion {
                expected: RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(RuntimeBridgeTurnRunStateUpdateError::MissingField(
                "thread_id",
            ));
        }
        let agent = object_value(&self.agent)
            .ok_or(RuntimeBridgeTurnRunStateUpdateError::MissingField("agent"))?;
        let agent_value = Value::Object(agent);
        let agent_id = optional_json_string(&agent_value, "id").ok_or(
            RuntimeBridgeTurnRunStateUpdateError::MissingField("agent.id"),
        )?;
        let projection = object_value(&self.projection).ok_or(
            RuntimeBridgeTurnRunStateUpdateError::MissingField("projection"),
        )?;
        let projection_value = Value::Object(projection);
        let run = object_value(&self.run)
            .ok_or(RuntimeBridgeTurnRunStateUpdateError::MissingField("run"))?;
        let run_value = Value::Object(run);
        for field in ["id", "agentId", "mode", "status", "createdAt", "updatedAt"] {
            if optional_json_string(&run_value, field).is_none() {
                return Err(RuntimeBridgeTurnRunStateUpdateError::MissingField(
                    match field {
                        "id" => "run.id",
                        "agentId" => "run.agentId",
                        "mode" => "run.mode",
                        "status" => "run.status",
                        "createdAt" => "run.createdAt",
                        "updatedAt" => "run.updatedAt",
                        _ => "run",
                    },
                ));
            }
        }
        let run_agent_id = optional_json_string(&run_value, "agentId").unwrap_or_default();
        if run_agent_id != agent_id {
            return Err(RuntimeBridgeTurnRunStateUpdateError::MismatchedField {
                field: "run.agentId",
                expected: agent_id,
                actual: run_agent_id,
            });
        }
        if optional_json_string(&projection_value, "run_id").is_none() {
            return Err(RuntimeBridgeTurnRunStateUpdateError::MissingField(
                "projection.run_id",
            ));
        }
        Ok(())
    }
}

impl SubagentRecordStateUpdateRequest {
    pub fn validate(&self) -> Result<(), SubagentRecordStateUpdateError> {
        if self.schema_version != SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(SubagentRecordStateUpdateError::InvalidSchemaVersion {
                expected: SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if !matches!(
            self.operation_kind.as_str(),
            "subagent.spawn"
                | "subagent.wait"
                | "subagent.input"
                | "subagent.resume"
                | "subagent.assign"
                | "subagent.cancel"
        ) {
            return Err(SubagentRecordStateUpdateError::MissingField(
                "operation_kind",
            ));
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(SubagentRecordStateUpdateError::MissingField("thread_id"));
        }
        let subagent = object_value(&self.subagent)
            .ok_or(SubagentRecordStateUpdateError::MissingField("subagent"))?;
        let subagent_value = Value::Object(subagent);
        for field in ["subagent_id", "parent_thread_id", "status", "updated_at"] {
            if optional_json_string(&subagent_value, field).is_none() {
                return Err(SubagentRecordStateUpdateError::MissingField(match field {
                    "subagent_id" => "subagent.subagent_id",
                    "parent_thread_id" => "subagent.parent_thread_id",
                    "status" => "subagent.status",
                    "updated_at" => "subagent.updated_at",
                    _ => "subagent",
                }));
            }
        }
        let parent_thread_id =
            optional_json_string(&subagent_value, "parent_thread_id").unwrap_or_default();
        if parent_thread_id != self.thread_id {
            return Err(SubagentRecordStateUpdateError::MismatchedField {
                field: "subagent.parent_thread_id",
                expected: self.thread_id.clone(),
                actual: parent_thread_id,
            });
        }
        Ok(())
    }
}

impl ContextBudgetPolicyRequest {
    pub fn validate(&self) -> Result<(), ContextBudgetPolicyError> {
        if self.schema_version != CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION
            && self.schema_version != CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION
        {
            return Err(ContextBudgetPolicyError::InvalidSchemaVersion {
                expected: CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if !self.usage_telemetry.is_object() {
            return Err(ContextBudgetPolicyError::MissingField("usage_telemetry"));
        }
        Ok(())
    }
}

fn budget_usage_summary(value: &Value) -> ContextBudgetUsageSummary {
    if let Some(entries) = value.get("usage").and_then(Value::as_array) {
        let total_tokens = entries
            .iter()
            .map(|entry| number_field(entry, "total_tokens"))
            .sum();
        let estimated_cost_usd = entries
            .iter()
            .map(|entry| number_field(entry, "estimated_cost_usd"))
            .sum();
        let context_pressure = entries
            .iter()
            .map(|entry| number_field(entry, "context_pressure"))
            .fold(0.0, f64::max);
        return ContextBudgetUsageSummary {
            total_tokens,
            estimated_cost_usd,
            context_pressure,
            thread_id: string_field(value, "thread_id"),
            run_id: string_field(value, "run_id"),
            scope: string_field(value, "scope").unwrap_or_else(|| "workflow".to_string()),
        };
    }
    ContextBudgetUsageSummary {
        total_tokens: number_field(value, "total_tokens"),
        estimated_cost_usd: number_field(value, "estimated_cost_usd"),
        context_pressure: number_field(value, "context_pressure"),
        thread_id: string_field(value, "thread_id"),
        run_id: string_field(value, "run_id"),
        scope: string_field(value, "scope").unwrap_or_else(|| "thread".to_string()),
    }
}

fn budget_check(
    id: &str,
    label: &str,
    actual: f64,
    limit: Option<f64>,
    warn_at_ratio: f64,
) -> Option<ContextBudgetCheck> {
    let limit = limit?;
    if limit <= 0.0 {
        return None;
    }
    let ratio = ((actual / limit) * 10000.0).round() / 10000.0;
    let severity = if actual > limit {
        "violation"
    } else if actual >= limit * warn_at_ratio {
        "warning"
    } else {
        "ok"
    };
    Some(ContextBudgetCheck {
        id: id.to_string(),
        label: label.to_string(),
        actual,
        limit,
        ratio,
        severity: severity.to_string(),
    })
}

fn budget_mode(value: Option<&str>) -> String {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("warn") => "warn".to_string(),
        Some("block") => "block".to_string(),
        _ => "simulate".to_string(),
    }
}

fn budget_summary(
    status: &str,
    violations: &[ContextBudgetCheck],
    warnings: &[ContextBudgetCheck],
) -> String {
    if status == "blocked" {
        return format!(
            "Context budget blocked: {} exceeded.",
            violations
                .iter()
                .map(|check| check.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if status == "warn" {
        return format!(
            "Context budget warning: {} near or over limit.",
            violations
                .iter()
                .chain(warnings.iter())
                .map(|check| check.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    "Context budget is within policy.".to_string()
}

fn context_budget_runtime_event_kind(status: &str) -> String {
    if status == "blocked" {
        "policy.blocked".to_string()
    } else {
        "context_budget.evaluated".to_string()
    }
}

fn context_budget_runtime_event_status(status: &str) -> String {
    if status == "blocked" {
        "blocked".to_string()
    } else {
        "completed".to_string()
    }
}

fn number_field(value: &Value, key: &str) -> f64 {
    value
        .get(key)
        .and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str()?.parse::<f64>().ok())
        })
        .filter(|value| value.is_finite() && *value >= 0.0)
        .unwrap_or(0.0)
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn safe_id(value: &str) -> String {
    let mut output = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    while output.contains("__") {
        output = output.replace("__", "_");
    }
    output.trim_matches('_').to_string()
}

fn mcp_catalog_server_label(server: &Value) -> String {
    optional_trimmed(server.get("label").and_then(Value::as_str))
        .or_else(|| optional_trimmed(server.get("name").and_then(Value::as_str)))
        .or_else(|| optional_trimmed(server.get("id").and_then(Value::as_str)))
        .unwrap_or_else(|| "mcp".to_string())
}

fn mcp_catalog_server_status(server: &Value) -> String {
    if server.get("enabled").and_then(Value::as_bool) == Some(false) {
        "disabled".to_string()
    } else {
        optional_trimmed(server.get("status").and_then(Value::as_str))
            .unwrap_or_else(|| "configured".to_string())
    }
}

fn mcp_catalog_server_transport(server: &Value) -> String {
    optional_trimmed(server.get("transport").and_then(Value::as_str))
        .unwrap_or_else(|| "stdio".to_string())
}

fn mcp_catalog_items(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter(|item| !item.is_null())
            .cloned()
            .collect(),
        Some(Value::Object(map)) => map
            .iter()
            .map(|(name, entry)| {
                if let Value::Object(entry_map) = entry {
                    let mut item = serde_json::Map::new();
                    item.insert("name".to_string(), Value::String(name.clone()));
                    item.extend(entry_map.clone());
                    Value::Object(item)
                } else {
                    json!({
                        "name": name,
                        "uri": match entry {
                            Value::Null => name.clone(),
                            Value::String(text) => text.clone(),
                            other => other.to_string(),
                        },
                    })
                }
            })
            .collect(),
        Some(value) if !value.is_null() => vec![value.clone()],
        _ => Vec::new(),
    }
}

fn mcp_catalog_value_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .and_then(|text| optional_trimmed(Some(text)))
        .or_else(|| match value {
            Value::Null | Value::Array(_) | Value::Object(_) => None,
            other => optional_trimmed(Some(other.to_string().as_str())),
        })
}

fn mcp_catalog_field_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .and_then(|text| optional_trimmed(Some(text)))
    })
}

fn mcp_catalog_tools_for_server(server: &Value) -> Vec<Value> {
    let server_label = mcp_catalog_server_label(server);
    let safe_server = safe_id(&server_label);
    let server_id = server.get("id").cloned().unwrap_or(Value::Null);
    let status = mcp_catalog_server_status(server);
    let transport = mcp_catalog_server_transport(server);

    mcp_catalog_items(server.get("allowed_tools"))
        .into_iter()
        .map(|tool| {
            let tool_name = mcp_catalog_field_string(&tool, &["name", "tool_name", "toolName"])
                .or_else(|| mcp_catalog_value_string(&tool))
                .unwrap_or_else(|| "tool".to_string());
            let safe_tool = safe_id(&tool_name);
            json!({
                "schema_version": MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
                "stable_tool_id": format!("mcp.{safe_server}.{safe_tool}"),
                "display_name": format!("{server_label}.{tool_name}"),
                "pack": "mcp",
                "server_id": server_id.clone(),
                "server_label": server_label,
                "tool_name": tool_name,
                "description": mcp_catalog_field_string(&tool, &["description"]),
                "status": status,
                "transport": transport,
                "primitive_capabilities": ["prim:connector.invoke"],
                "authority_scope_requirements": ["scope:mcp.invoke"],
                "effect_class": "connector_call",
                "risk_domain": "connector",
                "input_schema": tool.get("input_schema").or_else(|| tool.get("inputSchema")).cloned().unwrap_or_else(|| json!({ "type": "object" })),
                "output_schema": tool.get("output_schema").or_else(|| tool.get("outputSchema")).cloned().unwrap_or_else(|| json!({ "type": "object" })),
                "evidence_requirements": ["mcp_containment_receipt"],
                "workflow_node_type": "McpToolNode",
                "workflow_config_fields": ["server_id", "tool_name", "allowed_tools", "containment"],
                "workflow_node_id": format!("runtime.mcp-tool.{safe_server}.{safe_tool}"),
                "receipt_refs": [],
            })
        })
        .collect()
}

fn mcp_catalog_resources_for_server(server: &Value) -> Vec<Value> {
    let server_label = mcp_catalog_server_label(server);
    let safe_server = safe_id(&server_label);
    let server_id = server.get("id").cloned().unwrap_or(Value::Null);
    let status = mcp_catalog_server_status(server);
    let transport = mcp_catalog_server_transport(server);

    mcp_catalog_items(
        server
            .get("resources")
            .or_else(|| server.get("allowed_resources")),
    )
    .into_iter()
    .map(|resource| {
        let uri = mcp_catalog_field_string(&resource, &["uri", "url", "resource_uri"])
            .or_else(|| mcp_catalog_value_string(&resource))
            .unwrap_or_else(|| format!("resource://{safe_server}/unknown"));
        let name =
            mcp_catalog_field_string(&resource, &["name", "title"]).unwrap_or_else(|| uri.clone());
        let safe_uri = safe_id(&uri);
        json!({
            "schema_version": MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
            "stable_resource_id": format!("mcp.{safe_server}.resource.{safe_uri}"),
            "display_name": format!("{server_label}.{name}"),
            "pack": "mcp",
            "server_id": server_id.clone(),
            "server_label": server_label,
            "uri": uri,
            "name": name,
            "description": mcp_catalog_field_string(&resource, &["description"]),
            "mime_type": mcp_catalog_field_string(&resource, &["mime_type", "mimeType"]),
            "status": status,
            "transport": transport,
            "primitive_capabilities": ["prim:connector.resource.read"],
            "authority_scope_requirements": ["scope:mcp.resource.read"],
            "effect_class": "read_only_catalog",
            "risk_domain": "connector",
            "evidence_requirements": ["mcp_resource_catalog_receipt"],
            "workflow_node_type": "McpResourceNode",
            "workflow_config_fields": ["server_id", "uri", "containment"],
            "workflow_node_id": format!("runtime.mcp-resource.{safe_server}.{safe_uri}"),
            "receipt_refs": [],
        })
    })
    .collect()
}

fn mcp_catalog_prompts_for_server(server: &Value) -> Vec<Value> {
    let server_label = mcp_catalog_server_label(server);
    let safe_server = safe_id(&server_label);
    let server_id = server.get("id").cloned().unwrap_or(Value::Null);
    let status = mcp_catalog_server_status(server);
    let transport = mcp_catalog_server_transport(server);

    mcp_catalog_items(
        server
            .get("prompts")
            .or_else(|| server.get("allowed_prompts")),
    )
    .into_iter()
    .map(|prompt| {
        let name = mcp_catalog_field_string(&prompt, &["name", "title"])
            .or_else(|| mcp_catalog_value_string(&prompt))
            .unwrap_or_else(|| "prompt".to_string());
        let safe_prompt = safe_id(&name);
        let arguments = prompt
            .get("arguments")
            .filter(|value| value.is_array())
            .cloned()
            .unwrap_or_else(|| json!([]));
        json!({
            "schema_version": MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
            "stable_prompt_id": format!("mcp.{safe_server}.prompt.{safe_prompt}"),
            "display_name": format!("{server_label}.{name}"),
            "pack": "mcp",
            "server_id": server_id.clone(),
            "server_label": server_label,
            "name": name,
            "description": mcp_catalog_field_string(&prompt, &["description"]),
            "arguments": arguments.clone(),
            "prompt_arguments": arguments,
            "status": status,
            "transport": transport,
            "primitive_capabilities": ["prim:connector.prompt.read"],
            "authority_scope_requirements": ["scope:mcp.prompt.read"],
            "effect_class": "read_only_catalog",
            "risk_domain": "connector",
            "evidence_requirements": ["mcp_prompt_catalog_receipt"],
            "workflow_node_type": "McpPromptNode",
            "workflow_config_fields": ["server_id", "prompt_name", "containment"],
            "workflow_node_id": format!("runtime.mcp-prompt.{safe_server}.{safe_prompt}"),
            "receipt_refs": [],
        })
    })
    .collect()
}

fn mcp_catalog_resource_key(resource: &Value) -> String {
    mcp_catalog_field_string(resource, &["stable_resource_id"]).unwrap_or_else(|| {
        format!(
            "{}:{}",
            mcp_catalog_field_string(resource, &["server_id"])
                .unwrap_or_else(|| "mcp.unknown".to_string()),
            mcp_catalog_field_string(resource, &["uri"]).unwrap_or_else(|| "resource".to_string())
        )
    })
}

fn mcp_catalog_prompt_key(prompt: &Value) -> String {
    mcp_catalog_field_string(prompt, &["stable_prompt_id"]).unwrap_or_else(|| {
        format!(
            "{}:{}",
            mcp_catalog_field_string(prompt, &["server_id"])
                .unwrap_or_else(|| "mcp.unknown".to_string()),
            mcp_catalog_field_string(prompt, &["name"]).unwrap_or_else(|| "prompt".to_string())
        )
    })
}

fn mcp_catalog_summary_hash(
    server: &Value,
    tools: &[Value],
    resources: &[Value],
    prompts: &[Value],
) -> String {
    let payload = json!({
        "server_id": json_string_value(server, "id"),
        "tools": tools.iter().map(|tool| {
            json!({
                "stable_tool_id": json_string_value(tool, "stable_tool_id"),
                "tool_name": json_string_value(tool, "tool_name"),
                "description": json_string_value(tool, "description"),
                "input_schema": tool.get("input_schema").cloned().unwrap_or(Value::Null),
            })
        }).collect::<Vec<_>>(),
        "resources": resources.iter().map(|resource| {
            json!({
                "stable_resource_id": json_string_value(resource, "stable_resource_id"),
                "uri": json_string_value(resource, "uri"),
                "name": json_string_value(resource, "name"),
            })
        }).collect::<Vec<_>>(),
        "prompts": prompts.iter().map(|prompt| {
            json!({
                "stable_prompt_id": json_string_value(prompt, "stable_prompt_id"),
                "name": json_string_value(prompt, "name"),
            })
        }).collect::<Vec<_>>(),
    });
    let bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| payload.to_string().into_bytes());
    hex::encode(Sha256::digest(bytes))
}

fn mcp_tool_namespaces(tool_names: &[String]) -> Vec<String> {
    let mut namespaces = tool_names
        .iter()
        .filter_map(|name| {
            let namespace = name
                .split("__")
                .next()
                .unwrap_or(name)
                .split(['.', ':', '/', '-'])
                .next()
                .unwrap_or(name);
            optional_trimmed(Some(namespace))
        })
        .collect::<Vec<_>>();
    namespaces.sort();
    namespaces.dedup();
    namespaces.truncate(25);
    namespaces
}

fn budget_hash(value: &Value) -> Result<String, ContextBudgetPolicyError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ContextBudgetPolicyError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn compaction_budget_status(value: Option<&str>, context_budget: Option<&Value>) -> String {
    let status = optional_trimmed(value)
        .or_else(|| context_budget.and_then(|value| string_field(value, "status")))
        .or_else(|| {
            context_budget
                .and_then(|value| value.get("policy_decision"))
                .and_then(|value| string_field(value, "status"))
        })
        .map(|value| value.to_ascii_lowercase());
    match status.as_deref() {
        Some("blocked") | Some("block") => "blocked".to_string(),
        Some("warn") | Some("warning") => "warn".to_string(),
        _ => "ok".to_string(),
    }
}

fn compaction_action(value: Option<&str>, fallback: &str) -> String {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("noop") => "noop".to_string(),
        Some("warn") => "warn".to_string(),
        Some("compact") => "compact".to_string(),
        Some("stop") => "stop".to_string(),
        Some("approval_required") => "approval_required".to_string(),
        _ => fallback.to_string(),
    }
}

fn operator_control_source(value: Option<&str>) -> String {
    if let Some(source) = optional_trimmed(value) {
        if matches!(
            source.as_str(),
            "cli_tui" | "react_flow" | "sdk_client" | "runtime_auto" | "mcp_serve"
        ) {
            return source;
        }
    }
    "sdk_client".to_string()
}

fn context_compaction_state_target_kind(value: Option<&str>, run: Option<&Value>) -> String {
    match value
        .and_then(|value| optional_trimmed(Some(value)))
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("agent") => "agent".to_string(),
        Some("run") => "run".to_string(),
        _ if run.is_some() => "run".to_string(),
        _ => "agent".to_string(),
    }
}

fn object_value(value: &Value) -> Option<serde_json::Map<String, Value>> {
    value.as_object().cloned()
}

fn insert_optional_string_field(
    target: &mut serde_json::Map<String, Value>,
    key: &str,
    value: Option<String>,
) {
    target.insert(
        key.to_string(),
        value.map(Value::String).unwrap_or(Value::Null),
    );
}

fn normalized_thread_control_kind(
    value: &str,
) -> Result<String, ThreadControlAgentStateUpdateError> {
    match optional_trimmed(Some(value))
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "mode" => Ok("mode".to_string()),
        "model" => Ok("model".to_string()),
        "thinking" => Ok("thinking".to_string()),
        other => Err(ThreadControlAgentStateUpdateError::UnsupportedControlKind(
            other.to_string(),
        )),
    }
}

fn append_operator_control(existing: Option<&Value>, control: &Value) -> Value {
    let control_event_id = control
        .get("event_id")
        .or_else(|| control.get("eventId"))
        .and_then(Value::as_str);
    let mut entries = existing
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let exists = control_event_id.is_some_and(|event_id| {
        entries.iter().any(|entry| {
            entry
                .get("event_id")
                .or_else(|| entry.get("eventId"))
                .and_then(Value::as_str)
                == Some(event_id)
        })
    });
    if !exists {
        entries.push(control.clone());
    }
    Value::Array(entries)
}

fn json_string_value(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| optional_trimmed(Some(value)))
}

fn optional_json_string(value: &Value, key: &str) -> Option<String> {
    json_string_value(value, key)
}

fn json_bool_value(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn extend_json_object(base: Value, extension: Value) -> Value {
    let mut object = match base {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    if let Value::Object(extension) = extension {
        object.extend(extension);
    }
    Value::Object(object)
}

fn memory_projection_object(projection: &Value, key: &str) -> Value {
    projection
        .get(key)
        .and_then(Value::as_object)
        .cloned()
        .map(Value::Object)
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()))
}

fn memory_projection_records(projection: &Value) -> Vec<Value> {
    projection
        .get("records")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn validate_memory_manager_policy(
    policy: &Value,
    issues: &mut Vec<Value>,
    warnings: &mut Vec<Value>,
) {
    if !policy.is_object() {
        issues.push(memory_diagnostic(
            "memory_policy_missing",
            "error",
            "Memory status requires an effective policy.",
            json!({}),
        ));
        return;
    }
    if json_string_value(policy, "id").is_none() {
        issues.push(memory_diagnostic(
            "memory_policy_id_missing",
            "error",
            "Memory policy must have a stable id.",
            json!({}),
        ));
    }
    if let Some(scope) = json_string_value(policy, "scope") {
        if !matches!(
            scope.as_str(),
            "global" | "workspace" | "thread" | "workflow" | "subagent"
        ) {
            issues.push(memory_diagnostic(
                "memory_policy_scope_invalid",
                "error",
                "Memory policy scope is not supported.",
                json!({ "memory_scope": scope }),
            ));
        }
    }
    if let Some(redaction) = json_string_value(policy, "redaction") {
        if !matches!(redaction.as_str(), "none" | "redacted") {
            issues.push(memory_diagnostic(
                "memory_policy_redaction_invalid",
                "error",
                "Memory policy redaction must be none or redacted.",
                json!({}),
            ));
        }
    }
    if let Some(retention) = json_string_value(policy, "retention") {
        if !matches!(retention.as_str(), "persistent" | "session" | "ephemeral") {
            warnings.push(memory_diagnostic(
                "memory_policy_retention_unknown",
                "warning",
                "Memory retention is not one of the governed presets.",
                json!({}),
            ));
        }
    }
    if let Some(inheritance) = json_string_value(policy, "subagent_inheritance") {
        if !matches!(
            inheritance.as_str(),
            "none" | "explicit" | "read_only" | "full"
        ) {
            issues.push(memory_diagnostic(
                "memory_subagent_inheritance_invalid",
                "error",
                "Subagent memory inheritance mode is not supported.",
                json!({}),
            ));
        }
    }
    let disabled = json_bool_value(policy, "disabled").unwrap_or(false);
    let injection_enabled = json_bool_value(policy, "injection_enabled").unwrap_or(true);
    let read_only = json_bool_value(policy, "read_only").unwrap_or(false);
    let write_requires_approval =
        json_bool_value(policy, "write_requires_approval").unwrap_or(false);
    if disabled && injection_enabled {
        warnings.push(memory_diagnostic(
            "memory_disabled_with_injection_enabled",
            "warning",
            "Disabled memory should also disable prompt injection.",
            json!({}),
        ));
    }
    if read_only && write_requires_approval {
        warnings.push(memory_diagnostic(
            "memory_read_only_with_approval_required",
            "warning",
            "Read-only memory makes write approval unreachable.",
            json!({}),
        ));
    }
}

fn validate_memory_manager_paths(
    paths: &Value,
    issues: &mut Vec<Value>,
    warnings: &mut Vec<Value>,
) {
    for (canonical, label) in [("records_path", "records"), ("policies_path", "policies")] {
        let value = json_string_value(paths, canonical);
        if value.is_none() {
            issues.push(memory_diagnostic(
                &format!("memory_{label}_path_missing"),
                "error",
                &format!("Memory {label} path is missing."),
                json!({}),
            ));
            continue;
        }
        warnings.push(memory_diagnostic(
            &format!("memory_{label}_path_unverified_by_rust_core"),
            "warning",
            &format!("Memory {label} path is projected by Rust but disk access remains outside this pure projection core."),
            json!({ "path": value }),
        ));
    }
}

fn validate_memory_manager_record(
    record: &Value,
    issues: &mut Vec<Value>,
    warnings: &mut Vec<Value>,
) {
    if !record.is_object() {
        issues.push(memory_diagnostic(
            "memory_record_invalid",
            "error",
            "Memory record must be an object.",
            json!({}),
        ));
        return;
    }
    let record_id = json_string_value(record, "id");
    if record_id.is_none() {
        issues.push(memory_diagnostic(
            "memory_record_id_missing",
            "error",
            "Memory record id is required.",
            json!({}),
        ));
    }
    if json_string_value(record, "fact").is_none() {
        issues.push(memory_diagnostic(
            "memory_record_fact_missing",
            "error",
            "Memory record fact text is required.",
            json!({ "memory_record_id": record_id.clone() }),
        ));
    }
    if let Some(scope) = json_string_value(record, "scope") {
        if !matches!(
            scope.as_str(),
            "global" | "workspace" | "thread" | "workflow" | "subagent"
        ) {
            issues.push(memory_diagnostic(
                "memory_record_scope_invalid",
                "error",
                "Memory record scope is not supported.",
                json!({
                    "memory_record_id": record_id.clone(),
                    "memory_scope": scope,
                }),
            ));
        }
    }
    let fact_hash = json_string_value(record, "fact_hash");
    if json_string_value(record, "redaction").as_deref() == Some("redacted") && fact_hash.is_none()
    {
        warnings.push(memory_diagnostic(
            "memory_record_redacted_hash_missing",
            "warning",
            "Redacted memory records should include a fact hash.",
            json!({ "memory_record_id": record_id }),
        ));
    }
}

fn memory_diagnostic(code: &str, severity: &str, message: &str, extra: Value) -> Value {
    extend_json_object(
        json!({
            "code": code,
            "severity": severity,
            "message": message,
        }),
        extra,
    )
}

fn memory_unique_strings(values: Vec<String>) -> Vec<String> {
    let mut values: Vec<String> = values
        .into_iter()
        .filter_map(|value| optional_trimmed(Some(value.as_str())))
        .collect();
    values.sort();
    values.dedup();
    values
}

fn memory_status_evidence_refs(policy: &Value, paths: &Value, records: &[Value]) -> Vec<String> {
    let mut refs = vec![
        "runtime_memory_manager",
        "memory.status",
        "rust_memory_manager_status_projection_command",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    if let Some(policy_id) = json_string_value(policy, "id") {
        refs.push(policy_id);
    }
    if let Some(effective_policy_id) = json_string_value(paths, "effective_policy_id") {
        refs.push(effective_policy_id);
    }
    for record in records {
        if let Some(record_id) = json_string_value(record, "id") {
            refs.push(record_id);
        }
    }
    memory_unique_strings(refs)
}

fn json_bool_path(value: &Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

fn normalize_mcp_transport(value: Option<String>) -> String {
    match value
        .unwrap_or_else(|| "stdio".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "streamable_http" | "streamable-http" | "http-json-rpc" => "http".to_string(),
        "server-sent-events" | "eventsource" => "sse".to_string(),
        other => other.to_string(),
    }
}

fn is_http_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn mcp_validation_diagnostic(
    code: &str,
    severity: &str,
    server_id: Option<&str>,
    detail: Value,
) -> Value {
    let mut diagnostic = object_value(&detail).unwrap_or_default();
    diagnostic.insert("code".to_string(), Value::String(code.to_string()));
    diagnostic.insert("severity".to_string(), Value::String(severity.to_string()));
    diagnostic.insert(
        "server_id".to_string(),
        server_id
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    Value::Object(diagnostic)
}

fn mcp_validation_server_label(server: &Value) -> Option<String> {
    json_string_value(server, "label")
        .or_else(|| json_string_value(server, "name"))
        .or_else(|| json_string_value(server, "id"))
}

fn normalize_mcp_validation_server_record(
    label: &str,
    config: &Value,
    workspace_root: Option<&str>,
    source: &str,
    source_scope: &str,
    status: &str,
) -> Value {
    let name = optional_trimmed(Some(label))
        .or_else(|| json_string_value(config, "label"))
        .or_else(|| json_string_value(config, "name"))
        .unwrap_or_else(|| "mcp".to_string());
    let id = json_string_value(config, "id").unwrap_or_else(|| format!("mcp.{}", safe_id(&name)));
    let server_url = json_string_value(config, "server_url")
        .or_else(|| json_string_value(config, "url"))
        .or_else(|| json_string_value(config, "endpoint"));
    let transport = normalize_mcp_transport(json_string_value(config, "transport").or_else(|| {
        server_url.as_ref().map(|url| {
            if url.contains("/sse") {
                "sse".to_string()
            } else {
                "http".to_string()
            }
        })
    }));
    let enabled = config.get("enabled").and_then(Value::as_bool) != Some(false)
        && config.get("disabled").and_then(Value::as_bool) != Some(true);
    let allowed_tools = normalize_mcp_allowed_tools(config);
    let resources = normalize_mcp_catalog_items_for_validation(
        config
            .get("resources")
            .or_else(|| config.get("allowed_resources")),
        "resource",
    );
    let prompts = normalize_mcp_catalog_items_for_validation(
        config
            .get("prompts")
            .or_else(|| config.get("allowed_prompts")),
        "prompt",
    );
    let headers = config
        .get("headers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let env = config
        .get("env")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let header_secret_refs = public_mcp_secret_refs(&headers, "header");
    let env_secret_refs = public_mcp_secret_refs(&env, "env");
    let secret_refs = merge_json_objects(&env_secret_refs, &header_secret_refs);
    let header_names = {
        let mut names = headers.keys().cloned().collect::<Vec<_>>();
        names.sort();
        names
    };
    let containment_mode = json_string_value(config, "containment_mode")
        .or_else(|| json_path_string(config, &["containment", "mode"]))
        .unwrap_or_else(|| "sandboxed".to_string());
    let allow_network_egress = config
        .get("allow_network_egress")
        .and_then(Value::as_bool)
        .or_else(|| json_bool_path(config, &["containment", "allow_network_egress"]))
        .unwrap_or(server_url.is_some());
    let allow_child_processes = config
        .get("allow_child_processes")
        .and_then(Value::as_bool)
        .or_else(|| json_bool_path(config, &["containment", "allow_child_processes"]))
        .unwrap_or_else(|| json_string_value(config, "command").is_some());
    let source_path = json_string_value(config, "source_path");
    let config_source = json_string_value(config, "source").unwrap_or_else(|| source.to_string());
    let config_source_scope =
        json_string_value(config, "source_scope").unwrap_or_else(|| source_scope.to_string());
    let config_compatibility = json_string_value(config, "config_compatibility");
    let mut evidence_refs = vec![
        "mcp.manager.validation_input".to_string(),
        config_source.clone(),
        config_source_scope.clone(),
        id.clone(),
    ];
    if let Some(path) = &source_path {
        evidence_refs.push(path.clone());
    }
    if let Some(compatibility) = &config_compatibility {
        evidence_refs.push(compatibility.clone());
    }
    evidence_refs.sort();
    evidence_refs.dedup();

    json!({
        "schema_version": MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION,
        "id": id,
        "label": name,
        "name": name,
        "enabled": enabled,
        "status": json_string_value(config, "status").unwrap_or_else(|| status.to_string()),
        "transport": transport,
        "command": json_string_value(config, "command"),
        "args": config.get("args").and_then(Value::as_array).map(|items| {
            items.iter().map(|item| {
                item.as_str().map(ToString::to_string).unwrap_or_else(|| item.to_string())
            }).collect::<Vec<_>>()
        }).unwrap_or_default(),
        "server_url": server_url,
        "endpoint": server_url,
        "header_names": header_names,
        "header_secret_refs": header_secret_refs,
        "env_secret_refs": env_secret_refs,
        "source": config_source,
        "source_path": source_path,
        "source_scope": config_source_scope,
        "config_compatibility": config_compatibility,
        "workspace_root": workspace_root,
        "allowed_tools": allowed_tools,
        "tool_count": allowed_tools.len(),
        "resources": resources,
        "resource_count": resources.len(),
        "prompts": prompts,
        "prompt_count": prompts.len(),
        "containment": {
            "mode": containment_mode,
            "allow_network_egress": allow_network_egress,
            "allow_child_processes": allow_child_processes,
            "workspace_root": workspace_root,
        },
        "secret_refs": secret_refs,
        "vault_boundary": {
            "required": !secret_refs.as_object().unwrap_or(&serde_json::Map::new()).is_empty(),
            "header_ref_count": header_secret_refs.as_object().map(|map| map.len()).unwrap_or(0),
            "env_ref_count": env_secret_refs.as_object().map(|map| map.len()).unwrap_or(0),
            "secret_values_included": false,
            "runtime_resolution": "execution_time_only",
        },
        "health": {
            "status": if json_string_value(config, "status").as_deref() == Some("connected") { "connected" } else { "not_connected" },
            "live_probe": false,
            "reason": "read_only_catalog_status",
        },
        "evidence_refs": evidence_refs,
    })
}

fn normalize_mcp_allowed_tools(config: &Value) -> Vec<String> {
    let mut tools = Vec::new();
    if let Some(items) = config.get("allowed_tools").and_then(Value::as_array) {
        for item in items {
            if let Some(text) = item.as_str().and_then(|text| optional_trimmed(Some(text))) {
                tools.push(text);
            } else if let Some(name) = mcp_catalog_field_string(item, &["name", "tool_name"]) {
                tools.push(name);
            }
        }
    }
    if let Some(map) = config.get("tools").and_then(Value::as_object) {
        tools.extend(map.keys().cloned());
    }
    tools.sort();
    tools.dedup();
    tools
}

fn normalize_mcp_catalog_items_for_validation(
    value: Option<&Value>,
    fallback_key: &str,
) -> Vec<Value> {
    mcp_catalog_items(value)
        .into_iter()
        .enumerate()
        .map(|(index, item)| {
            if item.is_object() {
                item
            } else {
                json!({ fallback_key: mcp_catalog_value_string(&item).unwrap_or_else(|| format!("{fallback_key}_{index}")) })
            }
        })
        .collect()
}

fn public_mcp_secret_refs(source: &serde_json::Map<String, Value>, prefix: &str) -> Value {
    let mut refs = serde_json::Map::new();
    for (key, value) in source {
        match value {
            Value::String(text) if text.starts_with("vault://") => {
                refs.insert(key.clone(), Value::String(text.clone()));
            }
            Value::Object(object) if object.contains_key("secret_ref") => {
                refs.insert(
                    key.clone(),
                    object.get("secret_ref").cloned().unwrap_or(Value::Null),
                );
            }
            Value::Object(object) if object.contains_key("invalidVaultRef") => {
                refs.insert(key.clone(), Value::Object(object.clone()));
            }
            Value::Null => {}
            _ => {
                refs.insert(
                    key.clone(),
                    json!({
                        "invalidVaultRef": true,
                        "source": prefix,
                    }),
                );
            }
        }
    }
    Value::Object(refs)
}

fn merge_json_objects(left: &Value, right: &Value) -> Value {
    let mut merged = left.as_object().cloned().unwrap_or_default();
    if let Some(right) = right.as_object() {
        merged.extend(right.clone());
    }
    Value::Object(merged)
}

fn json_path_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current
        .as_str()
        .and_then(|entry| optional_trimmed(Some(entry)))
}

fn is_terminal_event_type(value: Option<&str>) -> bool {
    matches!(value, Some("completed" | "canceled" | "failed" | "error"))
}

fn is_job_terminal_event_type(value: Option<&str>) -> bool {
    matches!(value, Some("job_completed" | "job_failed" | "job_canceled"))
}

fn task_family_for_mode(mode: &str) -> &'static str {
    match mode {
        "plan" => "planning",
        "dry_run" => "safety_preview",
        "handoff" => "delegation",
        "learn" => "learning",
        _ => "local_daemon_agentgres",
    }
}

fn strategy_for_mode(mode: &str) -> &'static str {
    match mode {
        "plan" => "daemon_plan_with_postconditions",
        "dry_run" => "daemon_dry_run_before_effect",
        "handoff" => "daemon_handoff_with_state_preservation",
        "learn" => "daemon_bounded_learning_gate",
        _ => "local_daemon_agentgres_execution",
    }
}

fn thread_id_for_agent(agent_id: &str) -> String {
    agent_id
        .strip_prefix("agent_")
        .map(|suffix| format!("thread_{suffix}"))
        .unwrap_or_else(|| format!("thread_{agent_id}"))
}

fn turn_id_for_run(run_id: &str) -> String {
    run_id
        .strip_prefix("run_")
        .map(|suffix| format!("turn_{suffix}"))
        .unwrap_or_else(|| format!("turn_{run_id}"))
}

fn compact_string_values(values: Vec<Option<String>>) -> Vec<Value> {
    values
        .into_iter()
        .flatten()
        .filter(|value| !value.trim().is_empty())
        .map(Value::String)
        .collect()
}

fn unique_string_values(values: Vec<String>) -> Vec<Value> {
    let mut unique = Vec::<String>::new();
    for value in values {
        let text = value.trim();
        if !text.is_empty() && !unique.iter().any(|candidate| candidate == text) {
            unique.push(text.to_string());
        }
    }
    unique.into_iter().map(Value::String).collect()
}

fn string_or_null(value: Option<&str>) -> Value {
    value
        .filter(|entry| !entry.trim().is_empty())
        .map(|entry| Value::String(entry.to_string()))
        .unwrap_or(Value::Null)
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn runtime_task_record_for_canceled_run(
    run: &Value,
    run_id: &str,
    agent_id: &str,
    mode: &str,
    created_at: &str,
    updated_at: &str,
) -> Value {
    let task_family = json_path_string(run, &["trace", "qualityLedger", "taskFamily"])
        .unwrap_or_else(|| task_family_for_mode(mode).to_string());
    let selected_strategy = json_path_string(run, &["trace", "qualityLedger", "selectedStrategy"])
        .unwrap_or_else(|| strategy_for_mode(mode).to_string());
    let model_route_decision_id = run
        .get("modelRouteDecision")
        .or_else(|| {
            run.get("trace")
                .and_then(|trace| trace.get("modelRouteDecision"))
        })
        .and_then(|value| json_string_value(value, "decision_id"));
    let active_skill_hook_manifest_id = run
        .get("activeSkillHookManifest")
        .or_else(|| {
            run.get("trace")
                .and_then(|trace| trace.get("activeSkillHookManifest"))
        })
        .and_then(|value| json_string_value(value, "manifestId"));
    json!({
        "schemaVersion": "ioi.agent-runtime.task-record.v1",
        "object": "ioi.runtime_task",
        "taskId": format!("task_{run_id}"),
        "runId": run_id,
        "agentId": agent_id,
        "threadId": thread_id_for_agent(agent_id),
        "turnId": turn_id_for_run(run_id),
        "status": "canceled",
        "mode": mode,
        "taskFamily": task_family,
        "selectedStrategy": selected_strategy,
        "summary": format!("Runtime task for {task_family} is canceled."),
        "promptHash": sha256_hex(optional_json_string(run, "objective").unwrap_or_default().as_str()),
        "promptIncluded": false,
        "objectivePreviewIncluded": false,
        "modelRouteDecisionId": string_or_null(model_route_decision_id.as_deref()),
        "activeSkillHookManifestId": string_or_null(active_skill_hook_manifest_id.as_deref()),
        "createdAt": created_at,
        "updatedAt": updated_at,
        "durable": true,
        "replayable": true,
        "cancelable": false,
        "cancelEndpoint": format!("/v1/tasks/task_{run_id}/cancel"),
        "endpoints": {
            "self": format!("/v1/tasks/task_{run_id}"),
            "cancel": format!("/v1/tasks/task_{run_id}/cancel"),
            "run": format!("/v1/runs/{run_id}"),
            "job": format!("/v1/jobs/job_{run_id}"),
            "events": format!("/v1/runs/{run_id}/events"),
            "trace": format!("/v1/runs/{run_id}/trace"),
        },
        "workflowNodeId": "runtime.runtime-task",
        "redaction": {
            "profile": "runtime_task_safe",
            "promptIncluded": false,
            "secretValuesIncluded": false,
        },
        "evidenceRefs": compact_string_values(vec![
            Some("runtime_task".to_string()),
            Some("runtime.tasks.durable_projection".to_string()),
            Some("RuntimeTaskNode".to_string()),
            Some(format!("run:{run_id}")),
            active_skill_hook_manifest_id,
        ]),
    })
}

fn runtime_job_record_for_canceled_run(
    run: &Value,
    runtime_task: &Value,
    run_id: &str,
    created_at: &str,
    updated_at: &str,
    event_count: usize,
) -> Value {
    let task_id =
        json_string_value(runtime_task, "taskId").unwrap_or_else(|| format!("task_{run_id}"));
    let artifact_names = run
        .get("artifacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|artifact| json_string_value(&artifact, "name"))
        .map(Value::String)
        .collect::<Vec<_>>();
    let receipt_kinds = run
        .get("receipts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|receipt| json_string_value(&receipt, "kind"))
        .map(Value::String)
        .collect::<Vec<_>>();
    let queued_at = run
        .get("runtimeJob")
        .and_then(|job| json_string_value(job, "queuedAt"))
        .unwrap_or_else(|| created_at.to_string());
    let started_at = run
        .get("runtimeJob")
        .and_then(|job| json_string_value(job, "startedAt"))
        .unwrap_or_else(|| created_at.to_string());
    let progress = json!({
        "completedSteps": 1,
        "totalSteps": 1,
        "percent": 100,
    });
    let endpoints = json!({
        "self": format!("/v1/jobs/job_{run_id}"),
        "cancel": format!("/v1/jobs/job_{run_id}/cancel"),
        "run": format!("/v1/runs/{run_id}"),
        "events": format!("/v1/runs/{run_id}/events"),
        "trace": format!("/v1/runs/{run_id}/trace"),
    });
    let redaction = json!({
        "profile": "runtime_job_safe",
        "promptIncluded": false,
        "secretValuesIncluded": false,
    });
    let evidence_refs = json!([
        "runtime_job",
        "runtime.jobs.durable_projection",
        "RuntimeJobNode",
        task_id,
        format!("run:{run_id}"),
    ]);
    json!({
        "schemaVersion": "ioi.agent-runtime.job-record.v1",
        "object": "ioi.runtime_job",
        "jobId": format!("job_{run_id}"),
        "taskId": task_id,
        "runId": run_id,
        "agentId": runtime_task.get("agentId").cloned().unwrap_or(Value::Null),
        "threadId": runtime_task.get("threadId").cloned().unwrap_or(Value::Null),
        "turnId": runtime_task.get("turnId").cloned().unwrap_or(Value::Null),
        "status": "canceled",
        "lifecycle": ["queued", "started", "canceled"],
        "summary": format!("Runtime job job_{run_id} is canceled."),
        "queueName": "local-agentgres",
        "runner": "local-daemon-agentgres",
        "jobType": "agent_run",
        "priority": "normal",
        "background": true,
        "durable": true,
        "replayable": true,
        "createdAt": created_at,
        "updatedAt": updated_at,
        "queuedAt": queued_at,
        "startedAt": started_at,
        "completedAt": updated_at,
        "progress": progress,
        "eventCount": event_count,
        "terminalEventCount": 1,
        "artifactNames": artifact_names,
        "receiptKinds": receipt_kinds,
        "checklistId": Value::Null,
        "checklistStatus": Value::Null,
        "checklistItemCount": Value::Null,
        "checklistCompletedItemCount": Value::Null,
        "failure": Value::Null,
        "cancellation": json!({ "reason": "operator_cancel" }),
        "retryCount": 0,
        "cancelable": false,
        "cancelEndpoint": format!("/v1/jobs/job_{run_id}/cancel"),
        "endpoints": endpoints,
        "workflowNodeId": "runtime.runtime-job",
        "redaction": redaction,
        "evidenceRefs": evidence_refs,
    })
}

fn runtime_checklist_record_for_canceled_run(
    _run: &Value,
    runtime_task: &Value,
    runtime_job: &Value,
    run_id: &str,
    created_at: &str,
    updated_at: &str,
) -> Value {
    let checklist_id = format!("checklist_{run_id}");
    let task_id =
        json_string_value(runtime_task, "taskId").unwrap_or_else(|| format!("task_{run_id}"));
    let job_id = json_string_value(runtime_job, "jobId").unwrap_or_else(|| format!("job_{run_id}"));
    let items = vec![
        checklist_item(
            &checklist_id,
            "task_record",
            "Runtime task record durable",
            "passed",
            vec![
                task_id.clone(),
                "RuntimeTaskNode".to_string(),
                "runtime.tasks.durable_projection".to_string(),
            ],
        ),
        checklist_item(
            &checklist_id,
            "job_record",
            "Runtime job record durable",
            "passed",
            vec![
                job_id.clone(),
                "RuntimeJobNode".to_string(),
                "runtime.jobs.durable_projection".to_string(),
            ],
        ),
        checklist_item(
            &checklist_id,
            "job_queued",
            "Job queued event emitted",
            "passed",
            vec!["JobQueued".to_string()],
        ),
        checklist_item(
            &checklist_id,
            "job_started",
            "Job started event emitted",
            "passed",
            vec!["JobStarted".to_string()],
        ),
        checklist_item(
            &checklist_id,
            "job_terminal",
            "Job canceled event emitted",
            "canceled",
            vec!["JobCanceled".to_string()],
        ),
        checklist_item(
            &checklist_id,
            "artifacts",
            "Runtime task/job/checklist artifacts attached",
            "passed",
            vec![
                "runtime-task.json".to_string(),
                "runtime-job.json".to_string(),
                "runtime-checklist.json".to_string(),
            ],
        ),
    ];
    let redaction = json!({
        "profile": "runtime_checklist_safe",
        "promptIncluded": false,
        "secretValuesIncluded": false,
    });
    let evidence_refs = json!([
        "runtime_checklist",
        "runtime.checklists.durable_projection",
        "RuntimeChecklistNode",
        task_id,
        job_id,
        format!("run:{run_id}"),
    ]);
    json!({
        "schemaVersion": "ioi.agent-runtime.checklist-record.v1",
        "object": "ioi.runtime_checklist",
        "checklistId": checklist_id,
        "taskId": task_id,
        "jobId": job_id,
        "runId": run_id,
        "agentId": runtime_task.get("agentId").cloned().unwrap_or(Value::Null),
        "threadId": runtime_task.get("threadId").cloned().unwrap_or(Value::Null),
        "turnId": runtime_task.get("turnId").cloned().unwrap_or(Value::Null),
        "status": "canceled",
        "summary": format!("Runtime checklist for job_{run_id} is canceled."),
        "durable": true,
        "replayable": true,
        "readOnly": true,
        "itemCount": items.len(),
        "completedItemCount": items
            .iter()
            .filter(|item| json_string_value(item, "status").as_deref() == Some("passed"))
            .count(),
        "canceledItemCount": items
            .iter()
            .filter(|item| json_string_value(item, "status").as_deref() == Some("canceled"))
            .count(),
        "failedItemCount": 0,
        "blockedItemCount": 0,
        "items": items,
        "requiredItemIds": [
            format!("{checklist_id}:task_record"),
            format!("{checklist_id}:job_record"),
            format!("{checklist_id}:job_queued"),
            format!("{checklist_id}:job_started"),
            format!("{checklist_id}:job_terminal"),
            format!("{checklist_id}:artifacts"),
        ],
        "createdAt": created_at,
        "updatedAt": updated_at,
        "workflowNodeId": "runtime.runtime-checklist",
        "redaction": redaction,
        "evidenceRefs": evidence_refs,
    })
}

fn checklist_item(
    checklist_id: &str,
    suffix: &str,
    label: &str,
    status: &str,
    evidence_refs: Vec<String>,
) -> Value {
    json!({
        "itemId": format!("{checklist_id}:{suffix}"),
        "label": label,
        "status": status,
        "evidenceRefs": unique_string_values(evidence_refs),
    })
}

fn attach_runtime_checklist_to_job(mut runtime_job: Value, runtime_checklist: &Value) -> Value {
    let artifact_names = runtime_job
        .get("artifactNames")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .chain(std::iter::once("runtime-checklist.json".to_string()))
        .collect::<Vec<_>>();
    let receipt_kinds = runtime_job
        .get("receiptKinds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .chain(std::iter::once("runtime_checklist".to_string()))
        .collect::<Vec<_>>();
    let evidence_refs = runtime_job
        .get("evidenceRefs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .chain(
            runtime_checklist
                .get("checklistId")
                .and_then(Value::as_str)
                .map(str::to_string),
        )
        .chain(std::iter::once("runtime_checklist".to_string()))
        .collect::<Vec<_>>();
    if let Some(job) = runtime_job.as_object_mut() {
        job.insert(
            "checklistId".to_string(),
            runtime_checklist
                .get("checklistId")
                .cloned()
                .unwrap_or(Value::Null),
        );
        job.insert(
            "checklistStatus".to_string(),
            runtime_checklist
                .get("status")
                .cloned()
                .unwrap_or(Value::Null),
        );
        job.insert(
            "checklistItemCount".to_string(),
            runtime_checklist
                .get("itemCount")
                .cloned()
                .unwrap_or(Value::Null),
        );
        job.insert(
            "checklistCompletedItemCount".to_string(),
            runtime_checklist
                .get("completedItemCount")
                .cloned()
                .unwrap_or(Value::Null),
        );
        job.insert(
            "artifactNames".to_string(),
            Value::Array(unique_string_values(artifact_names)),
        );
        job.insert(
            "receiptKinds".to_string(),
            Value::Array(unique_string_values(receipt_kinds)),
        );
        job.insert(
            "evidenceRefs".to_string(),
            Value::Array(unique_string_values(evidence_refs)),
        );
    }
    runtime_job
}

fn make_run_event(
    run_id: &str,
    agent_id: &str,
    index: usize,
    event_type: &str,
    summary: &str,
    data: Value,
    created_at: &str,
) -> Value {
    json!({
        "id": format!("{run_id}:event:{:03}:{event_type}", index),
        "runId": run_id,
        "agentId": agent_id,
        "type": event_type,
        "cursor": format!("{run_id}:{index}"),
        "createdAt": created_at,
        "summary": summary,
        "data": data,
    })
}

fn artifact_with_content(mut artifact: Value, content: Value) -> Value {
    if let Some(object) = artifact.as_object_mut() {
        object.insert("content".to_string(), content);
    }
    artifact
}

fn runtime_artifact(
    run_id: &str,
    name: &str,
    media_type: &str,
    receipt_id: &str,
    content: Value,
    redaction: &str,
) -> Value {
    json!({
        "artifactId": format!("artifact_{run_id}_{name}"),
        "name": name,
        "mediaType": media_type,
        "receiptId": receipt_id,
        "content": content,
        "redaction": redaction,
    })
}

fn compaction_status(action: &str, execute_compaction: bool, approval_satisfied: bool) -> String {
    match action {
        "stop" => "blocked".to_string(),
        "approval_required" => "waiting".to_string(),
        "compact" if execute_compaction && approval_satisfied => "compacted".to_string(),
        "compact" => "compact_pending".to_string(),
        "warn" => "warn".to_string(),
        _ => "ok".to_string(),
    }
}

fn compaction_runtime_event_kind(action: &str) -> String {
    match action {
        "stop" => "policy.blocked".to_string(),
        "approval_required" => "approval.required".to_string(),
        _ => "compaction_policy.evaluated".to_string(),
    }
}

fn compaction_runtime_event_status(action: &str) -> String {
    match action {
        "stop" => "blocked".to_string(),
        "approval_required" => "waiting".to_string(),
        _ => "completed".to_string(),
    }
}

fn compaction_summary(action: &str, execute_compaction: bool) -> String {
    match action {
        "stop" => "Compaction policy blocked continuation.".to_string(),
        "approval_required" => {
            "Compaction policy requires operator approval before compacting.".to_string()
        }
        "compact" if execute_compaction => {
            "Compaction policy executed context compaction.".to_string()
        }
        "compact" => "Compaction policy selected context compaction.".to_string(),
        "warn" => "Compaction policy emitted a warning.".to_string(),
        _ => "Compaction policy allowed continuation.".to_string(),
    }
}

fn compaction_hash(value: &Value) -> Result<String, CompactionPolicyError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| CompactionPolicyError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn context_compaction_hash(reason: &str, scope: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{reason}:{scope}").as_bytes());
    hex::encode(hasher.finalize()).chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget_request() -> ContextBudgetPolicyRequest {
        ContextBudgetPolicyRequest {
            schema_version: CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION.to_string(),
            usage_telemetry: json!({
                "total_tokens": 120,
                "estimated_cost_usd": 0.03,
                "context_pressure": 0.2,
            }),
            thresholds: ContextBudgetThresholds {
                max_total_tokens: Some(100.0),
                max_cost_usd: None,
                max_context_pressure: None,
                warn_at_ratio: Some(0.8),
            },
            mode: Some("block".to_string()),
            scope: Some("thread".to_string()),
            thread_id: Some("thread_budget".to_string()),
            turn_id: Some("turn_budget".to_string()),
            run_id: None,
            tool_id: Some("file.inspect".to_string()),
            tool_call_id: Some("call_budget".to_string()),
            workflow_graph_id: Some("graph_budget".to_string()),
            workflow_node_id: Some("node_budget".to_string()),
            source: Some("react_flow".to_string()),
            actor: None,
            event_kind: None,
            component_kind: None,
        }
    }

    fn compaction_request() -> CompactionPolicyRequest {
        CompactionPolicyRequest {
            schema_version: COMPACTION_POLICY_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_budget".to_string(),
            turn_id: Some("turn_budget".to_string()),
            context_budget: json!({
                "status": "blocked",
                "summary": "Context budget blocked: total tokens exceeded.",
            }),
            context_budget_status: None,
            actions: CompactionPolicyActions {
                ok_action: Some("noop".to_string()),
                warn_action: Some("warn".to_string()),
                blocked_action: Some("compact".to_string()),
            },
            approval: CompactionPolicyApproval {
                approval_required: Some(true),
                approval_granted: Some(false),
            },
            compact: CompactionPolicyCompact {
                execute_compaction: Some(false),
                compact_workflow_node_id: Some("node_compact".to_string()),
                compact_reason: None,
                compact_scope: Some("thread".to_string()),
            },
            workflow_graph_id: Some("graph_budget".to_string()),
            workflow_node_id: Some("node_policy".to_string()),
            source: Some("react_flow".to_string()),
            actor: Some("operator".to_string()),
            event_kind: None,
        }
    }

    fn context_compaction_plan_request() -> ContextCompactionPlanRequest {
        ContextCompactionPlanRequest {
            schema_version: CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_budget".to_string(),
            agent_id: "agent_budget".to_string(),
            turn_id: Some("turn_budget".to_string()),
            run_id: Some("run_budget".to_string()),
            session_id: Some("session_budget".to_string()),
            workspace_root: Some("/workspace".to_string()),
            reason: Some("trim context".to_string()),
            scope: Some("thread".to_string()),
            source: Some("react_flow".to_string()),
            actor: None,
            requested_by: Some("operator_one".to_string()),
            workflow_graph_id: Some("graph_budget".to_string()),
            workflow_node_id: Some("node_compact".to_string()),
            event_stream_id: Some("thread_budget:events".to_string()),
            previous_latest_seq: Some(7),
            idempotency_key: None,
        }
    }

    fn context_compaction_state_update_request() -> ContextCompactionStateUpdateRequest {
        ContextCompactionStateUpdateRequest {
            schema_version: CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            target_kind: Some("run".to_string()),
            thread_id: "thread_budget".to_string(),
            agent_id: "agent_budget".to_string(),
            run_id: Some("run_budget".to_string()),
            run: Some(json!({
                "id": "run_budget",
                "agentId": "agent_budget",
                "trace": {},
            })),
            agent: json!({
                "id": "agent_budget",
                "cwd": "/workspace",
            }),
            event_id: "event_budget".to_string(),
            seq: 8,
            created_at: "2026-06-06T03:40:00.000Z".to_string(),
            source: "react_flow".to_string(),
            reason: "trim context".to_string(),
            scope: "thread".to_string(),
        }
    }

    fn coding_tool_budget_recovery_state_update_request(
    ) -> CodingToolBudgetRecoveryStateUpdateRequest {
        CodingToolBudgetRecoveryStateUpdateRequest {
            schema_version: CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION
                .to_string(),
            thread_id: Some("thread_budget".to_string()),
            run_id: Some("run_budget".to_string()),
            run: json!({
                "id": "run_budget",
                "agentId": "agent_budget",
                "trace": {},
            }),
            event_id: "event_retry".to_string(),
            seq: 9,
            created_at: "2026-06-06T04:05:00.000Z".to_string(),
            approval_id: "approval_budget".to_string(),
            source: "runtime_auto".to_string(),
            receipt_refs: vec!["receipt_retry".to_string()],
            policy_decision_refs: vec!["policy_retry".to_string()],
        }
    }

    fn diagnostics_operator_override_state_update_request(
    ) -> DiagnosticsOperatorOverrideStateUpdateRequest {
        DiagnosticsOperatorOverrideStateUpdateRequest {
            schema_version: DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION
                .to_string(),
            thread_id: Some("thread_budget".to_string()),
            run_id: Some("run_blocked".to_string()),
            run: json!({
                "id": "run_blocked",
                "agentId": "agent_budget",
                "status": "blocked",
                "turnStatus": "waiting_for_input",
                "diagnosticsBlockingGate": {
                    "status": "blocked"
                },
                "trace": {
                    "stopCondition": {
                        "reason": "lsp_diagnostics_blocked"
                    }
                },
                "operatorControls": []
            }),
            event_id: "event_override".to_string(),
            seq: 10,
            created_at: "2026-06-06T04:15:00.000Z".to_string(),
            decision_id: "decision_override".to_string(),
            gate_event_id: Some("event_gate".to_string()),
            source: "runtime_auto".to_string(),
            approval_required: true,
            approval_satisfied: true,
            approval_source: Some("boolean_confirmation".to_string()),
            snapshot_id: Some("snapshot_alpha".to_string()),
        }
    }

    fn operator_interrupt_state_update_request() -> OperatorInterruptStateUpdateRequest {
        OperatorInterruptStateUpdateRequest {
            schema_version: OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: Some("thread_budget".to_string()),
            turn_id: Some("turn_budget".to_string()),
            run_id: Some("run_budget".to_string()),
            run: json!({
                "id": "run_budget",
                "agentId": "agent_budget",
                "status": "running",
                "turnStatus": "running",
                "trace": {
                    "qualityLedger": {
                        "failureOntologyLabels": ["existing_label"]
                    }
                },
                "operatorControls": []
            }),
            event_id: "event_interrupt".to_string(),
            seq: 11,
            created_at: "2026-06-06T04:25:00.000Z".to_string(),
            source: "runtime_auto".to_string(),
            reason: "operator_stop".to_string(),
        }
    }

    fn operator_steer_state_update_request() -> OperatorSteerStateUpdateRequest {
        OperatorSteerStateUpdateRequest {
            schema_version: OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: Some("thread_budget".to_string()),
            turn_id: Some("turn_budget".to_string()),
            run_id: Some("run_budget".to_string()),
            run: json!({
                "id": "run_budget",
                "agentId": "agent_budget",
                "status": "running",
                "turnStatus": "running",
                "trace": {},
                "operatorControls": []
            }),
            event_id: "event_steer".to_string(),
            seq: 12,
            created_at: "2026-06-06T04:35:00.000Z".to_string(),
            source: "react_flow".to_string(),
            guidance: "focus on the failing bridge assertion".to_string(),
        }
    }

    fn run_cancel_state_update_request() -> RunCancelStateUpdateRequest {
        RunCancelStateUpdateRequest {
            schema_version: RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            run_id: Some("run_cancel_one".to_string()),
            canceled_at: "2026-06-06T04:45:00.000Z".to_string(),
            run: json!({
                "id": "run_cancel_one",
                "agentId": "agent_one",
                "status": "running",
                "objective": "Cancel this run",
                "mode": "send",
                "createdAt": "2026-06-04T00:00:00.000Z",
                "updatedAt": "2026-06-04T00:00:01.000Z",
                "runtimeJob": {
                    "queuedAt": "2026-06-04T00:00:00.000Z",
                    "startedAt": "2026-06-04T00:00:00.500Z"
                },
                "events": [
                    {
                        "id": "run_cancel_one:event:000:runtime_task",
                        "type": "runtime_task",
                        "data": { "status": "running", "receiptId": "old_task_receipt" }
                    },
                    {
                        "id": "run_cancel_one:event:001:delta",
                        "type": "delta",
                        "data": { "text": "partial" }
                    },
                    {
                        "id": "run_cancel_one:event:002:job_completed",
                        "type": "job_completed",
                        "data": { "status": "completed" }
                    },
                    {
                        "id": "run_cancel_one:event:003:completed",
                        "type": "completed",
                        "data": { "status": "completed" }
                    }
                ],
                "trace": {
                    "events": [],
                    "receipts": [],
                    "qualityLedger": {
                        "failureOntologyLabels": ["existing_label"]
                    }
                },
                "receipts": [{ "id": "receipt_existing", "kind": "existing" }],
                "artifacts": [
                    {
                        "name": "runtime-task.json",
                        "content": { "status": "running" }
                    }
                ]
            }),
        }
    }

    fn thread_control_agent_state_update_request(
        control_kind: &str,
    ) -> ThreadControlAgentStateUpdateRequest {
        ThreadControlAgentStateUpdateRequest {
            schema_version: THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            agent: json!({
                "id": "agent_1",
                "cwd": "/workspace",
                "modelId": "previous-model",
                "runtimeControls": {
                    "mode": "agent",
                    "approvalMode": "suggest",
                    "model": {
                        "id": "auto",
                    "routeId": "route.local-first"
                    }
                }
            }),
            control_kind: control_kind.to_string(),
            controls: json!({
                "mode": "review",
                "approvalMode": "human_required",
                "model": {
                    "id": "auto",
                    "routeId": "route.local-first",
                    "selectedModel": "local-model",
                    "endpointId": "endpoint_1",
                    "providerId": "provider_1",
                    "receiptId": "receipt_route_1"
                },
                "updatedAt": "2026-06-06T05:00:00.000Z"
            }),
            event_id: "evt_thread_control".to_string(),
            seq: 7,
            created_at: "2026-06-06T05:00:00.000Z".to_string(),
            updated_at: None,
            workspace_trust_warning_event_id: None,
            workspace_trust_warning_created_at: None,
            model_route: Some(json!({
                "requested_model_id": "auto",
                "selected_model": "local-model",
                "route_id": "route.local-first",
                "endpoint_id": "endpoint_1",
                "provider_id": "provider_1",
                "receipt_id": "receipt_route_1",
                "decision": {
                    "route_id": "route.local-first",
                    "workflow_node_id": "runtime.model-router.custom"
                }
            })),
        }
    }

    fn agent_create_state_update_request() -> AgentCreateStateUpdateRequest {
        AgentCreateStateUpdateRequest {
            schema_version: AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            agent: json!({
                "id": "agent_create_one",
                "status": "active",
                "runtime": "local",
                "cwd": "/workspace",
                "modelId": "local-model",
                "runtimeControls": {
                    "mode": "agent",
                    "approvalMode": "suggest"
                },
                "createdAt": "2026-06-06T05:15:00.000Z",
                "updatedAt": "2026-06-06T05:15:00.000Z"
            }),
        }
    }

    fn run_create_state_update_request() -> RunCreateStateUpdateRequest {
        RunCreateStateUpdateRequest {
            schema_version: RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            run: json!({
                "id": "run_create_one",
                "agentId": "agent_create_one",
                "status": "completed",
                "mode": "send",
                "createdAt": "2026-06-06T05:16:00.000Z",
                "updatedAt": "2026-06-06T05:16:00.000Z",
                "usage": {
                    "total_tokens": 7
                },
                "usage_telemetry": {
                    "total_tokens": 7
                },
                "trace": {
                    "usage_telemetry": {
                        "total_tokens": 7
                    }
                }
            }),
        }
    }

    fn agent_status_state_update_request() -> AgentStatusStateUpdateRequest {
        AgentStatusStateUpdateRequest {
            schema_version: AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            agent: json!({
                "id": "agent_status_one",
                "status": "active",
                "createdAt": "2026-06-06T05:15:00.000Z",
                "updatedAt": "2026-06-06T05:15:00.000Z"
            }),
            status: "archived".to_string(),
            operation_kind: "agent.archive".to_string(),
            updated_at: "2026-06-06T06:25:00.000Z".to_string(),
        }
    }

    fn mcp_control_agent_state_update_request() -> McpControlAgentStateUpdateRequest {
        McpControlAgentStateUpdateRequest {
            schema_version: MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            agent: json!({
                "id": "agent_1",
                "cwd": "/workspace",
                "mcpRegistry": {
                    "servers": [
                        { "id": "mcp.docs", "enabled": true }
                    ]
                },
                "updatedAt": "2026-06-06T05:00:00.000Z"
            }),
            control_kind: "mcp_add".to_string(),
            event_id: "event_mcp_add".to_string(),
            seq: 4,
            created_at: "2026-06-06T05:45:00.000Z".to_string(),
        }
    }

    fn mcp_server_validation_request() -> McpServerValidationRequest {
        McpServerValidationRequest {
            schema_version: MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION.to_string(),
            servers: vec![
                json!({
                    "id": "mcp.docs",
                    "transport": "stdio",
                    "command": "npx",
                    "allowed_tools": ["search"]
                }),
                json!({
                    "id": "mcp.remote",
                    "transport": "http",
                    "server_url": "https://mcp.example.test",
                    "allowed_tools": ["fetch"],
                    "containment": {
                        "allow_network_egress": true
                    }
                }),
            ],
        }
    }

    fn mcp_server_validation_input_request() -> McpServerValidationInputRequest {
        McpServerValidationInputRequest {
            schema_version: MCP_SERVER_VALIDATION_INPUT_REQUEST_SCHEMA_VERSION.to_string(),
            workspace_root: Some("/workspace".to_string()),
            input: json!({
                "mcp_json": {
                    "mcp_servers": {
                        "docs": {
                            "transport": "stdio",
                            "command": "npx",
                            "tools": {
                                "search": { "description": "Search docs" }
                            },
                            "sourcePath": "/retired/mcp.json",
                            "source_scope": "validation"
                        }
                    }
                },
                "mcpJson": {
                    "mcpServers": {
                        "retired": { "transport": "stdio", "command": "retired" }
                    }
                }
            }),
        }
    }

    fn thread_memory_agent_state_update_request() -> ThreadMemoryAgentStateUpdateRequest {
        ThreadMemoryAgentStateUpdateRequest {
            schema_version: THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            agent: json!({
                "id": "agent_1",
                "cwd": "/workspace",
                "updatedAt": "2026-06-06T05:00:00.000Z"
            }),
            control_kind: "memory_status".to_string(),
            event_id: "event_memory_status".to_string(),
            seq: 6,
            created_at: "2026-06-06T06:05:00.000Z".to_string(),
        }
    }

    fn runtime_bridge_thread_start_agent_state_update_request(
    ) -> RuntimeBridgeThreadStartAgentStateUpdateRequest {
        RuntimeBridgeThreadStartAgentStateUpdateRequest {
            schema_version: RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION
                .to_string(),
            thread_id: "thread_1".to_string(),
            agent: json!({
                "id": "agent_1",
                "cwd": "/workspace",
                "fixtureProfile": "fixture.local",
                "updatedAt": "2026-06-06T05:00:00.000Z"
            }),
            runtime_profile: "runtime_service".to_string(),
            session_id: "session_runtime".to_string(),
            bridge_id: "bridge_runtime".to_string(),
            status: "active".to_string(),
            source: "runtime_service".to_string(),
            updated_at: "2026-06-06T06:15:00.000Z".to_string(),
        }
    }

    fn runtime_bridge_turn_run_state_update_request() -> RuntimeBridgeTurnRunStateUpdateRequest {
        RuntimeBridgeTurnRunStateUpdateRequest {
            schema_version: RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            agent: json!({
                "id": "agent_1",
                "cwd": "/workspace"
            }),
            projection: json!({
                "run_id": "run_runtime_bridge",
                "turn_id": "turn_runtime_bridge"
            }),
            run: json!({
                "id": "run_runtime_bridge",
                "agentId": "agent_1",
                "mode": "send",
                "status": "completed",
                "createdAt": "2026-06-06T06:34:00.000Z",
                "updatedAt": "2026-06-06T06:35:00.000Z"
            }),
        }
    }

    fn subagent_record_state_update_request() -> SubagentRecordStateUpdateRequest {
        SubagentRecordStateUpdateRequest {
            schema_version: SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            operation_kind: "subagent.wait".to_string(),
            thread_id: "thread_1".to_string(),
            subagent: json!({
                "schema_version": "ioi.runtime.subagent.v1",
                "object": "ioi.runtime_subagent",
                "subagent_id": "subagent_1",
                "parent_thread_id": "thread_1",
                "status": "completed",
                "lifecycle_status": "completed",
                "updated_at": "2026-06-06T07:04:00.000Z"
            }),
        }
    }

    #[test]
    fn rust_policy_blocks_context_budget_excess() {
        let mut request = budget_request();
        request.schema_version = CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION.to_string();
        request.tool_id = None;
        request.tool_call_id = None;

        let record = ContextBudgetPolicyCore
            .evaluate(&request)
            .expect("budget record");

        assert_eq!(
            record.schema_version,
            CONTEXT_BUDGET_POLICY_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "blocked");
        assert_eq!(record.event_kind, "RuntimeContextBudget.Evaluate");
        assert_eq!(record.component_kind, "context_budget");
        assert_eq!(record.workflow_node_id, "node_budget");
        assert_eq!(record.turn_id.as_deref(), Some("turn_budget"));
        assert_eq!(record.usage_summary.total_tokens, 120.0);
        assert_eq!(record.violations[0].id, "total_tokens");
        assert!(record
            .policy_decision_id
            .starts_with("policy_context_budget_thread_"));
        assert_eq!(
            record.policy_decision_refs,
            vec![record.policy_decision_id.clone()]
        );
        assert_eq!(record.runtime_event_kind, "policy.blocked");
        assert_eq!(record.runtime_event_status, "blocked");
        assert!(record
            .runtime_event_item_id
            .starts_with("turn_budget:item:context-budget:policy_context_budget_thread_"));
        assert!(record
            .runtime_event_idempotency_key
            .starts_with("thread:thread_budget:context-budget:policy_context_budget_thread_"));
    }

    #[test]
    fn rust_policy_blocks_coding_tool_budget_excess() {
        let record = ContextBudgetPolicyCore
            .evaluate(&budget_request())
            .expect("coding-tool budget record");

        assert_eq!(record.status, "blocked");
        assert_eq!(record.event_kind, "RuntimeCodingToolBudget.Evaluate");
        assert_eq!(record.component_kind, "coding_tool");
        assert_eq!(record.tool_id.as_deref(), Some("file.inspect"));
        assert_eq!(record.tool_call_id.as_deref(), Some("call_budget"));
    }

    #[test]
    fn rust_policy_warns_coding_tool_budget_near_limit() {
        let mut request = budget_request();
        request.usage_telemetry = json!({ "total_tokens": 90 });
        request.mode = Some("warn".to_string());

        let record = ContextBudgetPolicyCore
            .evaluate(&request)
            .expect("budget warning");

        assert_eq!(record.status, "warn");
        assert_eq!(record.runtime_event_kind, "context_budget.evaluated");
        assert_eq!(record.runtime_event_status, "completed");
        assert_eq!(record.warnings[0].severity, "warning");
        assert!(record.violations.is_empty());
    }

    #[test]
    fn rust_policy_rejects_invalid_budget_schema() {
        let mut request = budget_request();
        request.schema_version = "legacy.schema".to_string();

        let error = ContextBudgetPolicyCore
            .evaluate(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            ContextBudgetPolicyError::InvalidSchemaVersion {
                expected: CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_requires_compaction_approval_before_compacting() {
        let record = CompactionPolicyCore
            .evaluate(&compaction_request())
            .expect("compaction policy");

        assert_eq!(
            record.schema_version,
            COMPACTION_POLICY_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.budget_status, "blocked");
        assert_eq!(record.selected_action, "compact");
        assert_eq!(record.action, "approval_required");
        assert_eq!(record.status, "waiting");
        assert!(record.approval_required);
        assert!(!record.approval_satisfied);
        assert!(record
            .approval_id
            .as_deref()
            .expect("approval id")
            .starts_with("approval_compaction_thread_budget_"));
        assert!(record
            .policy_decision_id
            .starts_with("policy_compaction_thread_budget_"));
        assert_eq!(record.runtime_event_kind, "approval.required");
        assert_eq!(record.runtime_event_status, "waiting");
        assert!(record
            .runtime_event_item_id
            .starts_with("turn_budget:item:compaction-policy:policy_compaction_thread_budget_"));
        assert!(record.runtime_event_idempotency_key.starts_with(
            "thread:thread_budget:compaction-policy:policy_compaction_thread_budget_"
        ));
        assert!(record.compact_idempotency_key.starts_with(
            "thread:thread_budget:compaction-policy:compact:policy_compaction_thread_budget_"
        ));
        assert_eq!(
            record.policy_decision_refs,
            vec![record.policy_decision_id.clone()]
        );
    }

    #[test]
    fn rust_policy_compacts_when_approval_is_granted() {
        let mut request = compaction_request();
        request.approval.approval_granted = Some(true);
        request.compact.execute_compaction = Some(true);

        let record = CompactionPolicyCore
            .evaluate(&request)
            .expect("approved compaction policy");

        assert_eq!(record.action, "compact");
        assert_eq!(record.status, "compacted");
        assert_eq!(record.runtime_event_kind, "compaction_policy.evaluated");
        assert_eq!(record.runtime_event_status, "completed");
        assert!(record.approval_satisfied);
        assert!(record.execute_compaction);
        assert!(record.compaction_requested);
        assert_eq!(
            record.summary,
            "Compaction policy executed context compaction."
        );
    }

    #[test]
    fn rust_policy_plans_context_compaction_event_record() {
        let record = ContextCompactionPlanCore
            .plan(&context_compaction_plan_request())
            .expect("context compaction plan");

        assert_eq!(
            record.schema_version,
            CONTEXT_COMPACTION_PLAN_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.event_kind, "context.compacted");
        assert_eq!(record.source_event_kind, "OperatorControl.Compact");
        assert_eq!(record.component_kind, "context_compaction");
        assert_eq!(
            record.payload_schema_version,
            CONTEXT_COMPACTION_PAYLOAD_SCHEMA_VERSION
        );
        assert!(record
            .item_id
            .starts_with("turn_budget:item:context-compact:"));
        assert!(record
            .idempotency_key
            .starts_with("thread:thread_budget:context.compact:"));
        assert!(record
            .receipt_refs
            .first()
            .expect("receipt ref")
            .starts_with("receipt_run_budget_context_compaction_"));
        assert_eq!(
            record.policy_decision_refs,
            vec!["policy_run_budget_context_compaction_allow".to_string()]
        );
        assert_eq!(record.payload["reason"], "trim context");
        assert_eq!(record.payload["requested_by"], "operator_one");
        assert_eq!(record.payload["previous_latest_seq"], 7);
        assert_eq!(record.payload["run_id"], "run_budget");
        assert_eq!(record.payload["session_id"], "session_budget");
    }

    #[test]
    fn rust_policy_plans_runless_context_compaction_against_agent_ref() {
        let mut request = context_compaction_plan_request();
        request.turn_id = None;
        request.run_id = None;
        request.idempotency_key = Some("custom-context-compact".to_string());

        let record = ContextCompactionPlanCore
            .plan(&request)
            .expect("runless context compaction plan");

        assert!(record
            .item_id
            .starts_with("thread_budget:item:context-compact:"));
        assert_eq!(record.idempotency_key, "custom-context-compact");
        assert!(record
            .receipt_refs
            .first()
            .expect("receipt ref")
            .starts_with("receipt_agent_budget_context_compaction_"));
        assert_eq!(
            record.policy_decision_refs,
            vec!["policy_agent_budget_context_compaction_allow".to_string()]
        );
        assert!(record.payload["run_id"].is_null());
        assert!(record.payload["turn_id"].is_null());
    }

    #[test]
    fn rust_policy_plans_context_compaction_run_state_update() {
        let record = ContextCompactionStateUpdateCore
            .plan(&context_compaction_state_update_request())
            .expect("context compaction state update");

        assert_eq!(
            record.schema_version,
            CONTEXT_COMPACTION_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.target_kind, "run");
        assert_eq!(record.operation_kind, "thread.compact");
        assert_eq!(record.operator_control["event_id"], "event_budget");
        assert!(record.operator_control.get("eventId").is_none());
        assert!(record.operator_control.get("createdAt").is_none());
        assert_eq!(record.operator_control["seq"], 8);
        assert_eq!(record.context_compaction["reason"], "trim context");
        assert_eq!(record.context_compaction["event_id"], "event_budget");
        assert_eq!(record.context_compaction["compacted_tokens"], 0);
        assert!(record.context_compaction.get("eventId").is_none());
        assert!(record.context_compaction.get("compactedTokens").is_none());
        let run = record.run.expect("updated run");
        assert_eq!(run["updatedAt"], "2026-06-06T03:40:00.000Z");
        assert_eq!(
            run["trace"]["contextCompaction"]["event_id"],
            "event_budget"
        );
        assert_eq!(run["trace"]["operatorControls"][0]["control"], "compact");
        assert_eq!(run["operatorControls"][0]["event_id"], "event_budget");
        assert!(record.agent.is_none());
    }

    #[test]
    fn rust_policy_plans_context_compaction_runless_agent_update() {
        let mut request = context_compaction_state_update_request();
        request.target_kind = Some("agent".to_string());
        request.run = None;
        request.run_id = None;

        let record = ContextCompactionStateUpdateCore
            .plan(&request)
            .expect("runless context compaction state update");

        assert_eq!(record.target_kind, "agent");
        assert!(record.run.is_none());
        let agent = record.agent.expect("updated agent");
        assert_eq!(agent["updatedAt"], "2026-06-06T03:40:00.000Z");
    }

    #[test]
    fn rust_policy_plans_coding_tool_budget_recovery_state_update() {
        let record = CodingToolBudgetRecoveryStateUpdateCore
            .plan(&coding_tool_budget_recovery_state_update_request())
            .expect("coding tool budget recovery state update");

        assert_eq!(
            record.schema_version,
            CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "workflow.run.retry_completed");
        assert_eq!(record.operator_control["approval_id"], "approval_budget");
        assert_eq!(record.operator_control["receipt_refs"][0], "receipt_retry");
        assert!(record.operator_control.get("approvalId").is_none());
        assert!(record.operator_control.get("eventId").is_none());
        assert!(record.operator_control.get("receiptRefs").is_none());
        assert!(record.operator_control.get("policyDecisionRefs").is_none());
        assert!(record.operator_control.get("createdAt").is_none());
        assert_eq!(record.run["updatedAt"], "2026-06-06T04:05:00.000Z");
        assert_eq!(
            record.run["trace"]["operatorControls"][0]["control"],
            "coding_tool_budget_recovery"
        );
        assert_eq!(record.run["operatorControls"][0]["event_id"], "event_retry");
    }

    #[test]
    fn rust_policy_plans_diagnostics_operator_override_state_update() {
        let record = DiagnosticsOperatorOverrideStateUpdateCore
            .plan(&diagnostics_operator_override_state_update_request())
            .expect("diagnostics operator override state update");

        assert_eq!(
            record.schema_version,
            DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "diagnostics.operator_override.event");
        assert_eq!(
            record.operator_control["control"],
            "diagnostics_operator_override"
        );
        assert_eq!(record.operator_control["decision_id"], "decision_override");
        for field in [
            "decisionId",
            "gateEventId",
            "approvalRequired",
            "approvalSatisfied",
            "approvalSource",
            "snapshotId",
            "eventId",
            "createdAt",
        ] {
            assert!(record.operator_control.get(field).is_none());
        }
        assert_eq!(record.run["status"], "completed");
        assert!(record.run.get("turnStatus").is_none());
        assert_eq!(
            record.run["diagnosticsBlockingGate"]["status"],
            "overridden"
        );
        assert_eq!(
            record.run["diagnosticsBlockingGate"]["continuation_allowed"],
            true
        );
        assert_eq!(
            record.run["trace"]["stopCondition"]["reason"],
            "operator_override_granted"
        );
        assert_eq!(
            record.run["trace"]["operatorControls"][0]["event_id"],
            "event_override"
        );
    }

    #[test]
    fn rust_policy_plans_operator_interrupt_state_update() {
        let record = OperatorInterruptStateUpdateCore
            .plan(&operator_interrupt_state_update_request())
            .expect("operator interrupt state update");

        assert_eq!(
            record.schema_version,
            OPERATOR_INTERRUPT_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "turn.interrupt");
        assert_eq!(record.operator_control["control"], "interrupt");
        assert_eq!(record.operator_control["reason"], "operator_stop");
        assert_eq!(record.operator_control["event_id"], "event_interrupt");
        assert!(record.operator_control.get("eventId").is_none());
        assert!(record.operator_control.get("createdAt").is_none());
        assert_eq!(record.stop_condition["reason"], "operator_interrupt");
        assert_eq!(record.run["status"], "canceled");
        assert_eq!(record.run["turnStatus"], "interrupted");
        assert_eq!(
            record.run["trace"]["operatorControls"][0]["event_id"],
            "event_interrupt"
        );
        assert_eq!(
            record.run["operatorControls"][0]["event_id"],
            "event_interrupt"
        );
        assert!(
            record.run["trace"]["qualityLedger"]["failureOntologyLabels"]
                .as_array()
                .expect("failure labels")
                .iter()
                .any(|label| label.as_str() == Some("operator_interrupt"))
        );
    }

    #[test]
    fn rust_policy_plans_operator_steer_state_update() {
        let record = OperatorSteerStateUpdateCore
            .plan(&operator_steer_state_update_request())
            .expect("operator steer state update");

        assert_eq!(
            record.schema_version,
            OPERATOR_STEER_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "turn.steer");
        assert_eq!(record.operator_control["control"], "steer");
        assert_eq!(
            record.operator_control["guidance"],
            "focus on the failing bridge assertion"
        );
        assert_eq!(record.operator_control["event_id"], "event_steer");
        assert!(record.operator_control.get("eventId").is_none());
        assert!(record.operator_control.get("createdAt").is_none());
        assert_eq!(record.run["status"], "running");
        assert_eq!(record.run["turnStatus"], "running");
        assert_eq!(record.run["updatedAt"], "2026-06-06T04:35:00.000Z");
        assert_eq!(
            record.run["trace"]["operatorControls"][0]["event_id"],
            "event_steer"
        );
        assert_eq!(record.run["operatorControls"][0]["event_id"], "event_steer");
    }

    #[test]
    fn rust_policy_rejects_invalid_compaction_schema() {
        let mut request = compaction_request();
        request.schema_version = "legacy.schema".to_string();

        let error = CompactionPolicyCore
            .evaluate(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            CompactionPolicyError::InvalidSchemaVersion {
                expected: COMPACTION_POLICY_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_plans_run_cancel_state_update() {
        let record = RunCancelStateUpdateCore
            .plan(&run_cancel_state_update_request())
            .expect("run cancel state update");

        assert_eq!(
            record.schema_version,
            RUN_CANCEL_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "run.cancel");
        assert_eq!(record.run["status"], "canceled");
        assert_eq!(record.run["updatedAt"], "2026-06-06T04:45:00.000Z");
        assert_eq!(
            record.run["result"],
            "Run canceled with terminal event continuity preserved."
        );
        let event_types = record.run["events"]
            .as_array()
            .expect("events")
            .iter()
            .map(|event| event["type"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            event_types,
            vec![
                "runtime_task",
                "delta",
                "runtime_checklist",
                "job_canceled",
                "canceled",
            ]
        );
        assert_eq!(record.runtime_task["status"], "canceled");
        assert_eq!(record.runtime_job["eventCount"], 5);
        assert_eq!(record.runtime_checklist["status"], "canceled");
        assert_eq!(record.stop_condition["evidenceSufficient"], true);
        assert!(
            record.run["trace"]["qualityLedger"]["failureOntologyLabels"]
                .as_array()
                .expect("failure labels")
                .iter()
                .any(|label| label.as_str() == Some("operator_cancel"))
        );
        assert_eq!(
            record.run["receipts"]
                .as_array()
                .expect("receipts")
                .last()
                .and_then(|receipt| receipt.get("id"))
                .and_then(Value::as_str),
            Some("receipt_run_cancel_one_runtime_checklist")
        );
        assert_eq!(
            record.run["artifacts"]
                .as_array()
                .expect("artifacts")
                .iter()
                .find(|artifact| artifact["name"] == "runtime-checklist.json")
                .and_then(|artifact| artifact["content"]["status"].as_str()),
            Some("canceled")
        );
    }

    #[test]
    fn rust_policy_plans_thread_mode_agent_state_update() {
        let mut request = thread_control_agent_state_update_request("mode");
        request.model_route = None;
        request.workspace_trust_warning_event_id = Some("evt_workspace_warning".to_string());
        request.workspace_trust_warning_created_at = Some("2026-06-06T05:00:01.000Z".to_string());

        let record = ThreadControlAgentStateUpdateCore
            .plan(&request)
            .expect("thread mode agent state update");

        assert_eq!(
            record.schema_version,
            THREAD_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "thread.mode");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.agent_id, "agent_1");
        assert_eq!(record.updated_at, "2026-06-06T05:00:01.000Z");
        assert_eq!(record.control["control_kind"], "mode");
        assert_eq!(record.control["event_id"], "evt_thread_control");
        assert!(record.control.get("controlKind").is_none());
        assert!(record.control.get("eventId").is_none());
        assert!(record.control.get("createdAt").is_none());
        assert_eq!(
            record.control["workspace_trust_warning_event_id"],
            "evt_workspace_warning"
        );
        assert!(record.control.get("workspaceTrustWarningEventId").is_none());
        assert_eq!(record.agent["runtimeControls"]["mode"], "review");
        assert_eq!(record.agent["updatedAt"], "2026-06-06T05:00:01.000Z");
        assert_eq!(record.agent["modelId"], "previous-model");
    }

    #[test]
    fn rust_policy_plans_thread_model_agent_state_update() {
        let request = thread_control_agent_state_update_request("thinking");

        let record = ThreadControlAgentStateUpdateCore
            .plan(&request)
            .expect("thread model agent state update");

        assert_eq!(record.operation_kind, "thread.thinking");
        assert_eq!(record.updated_at, "2026-06-06T05:00:00.000Z");
        assert_eq!(
            record.agent["runtimeControls"]["model"]["selectedModel"],
            "local-model"
        );
        assert_eq!(record.agent["modelId"], "local-model");
        assert_eq!(record.agent["requestedModelId"], "auto");
        assert_eq!(record.agent["modelRouteId"], "route.local-first");
        assert_eq!(record.agent["modelRouteEndpointId"], "endpoint_1");
        assert_eq!(record.agent["modelRouteProviderId"], "provider_1");
        assert_eq!(record.agent["modelRouteReceiptId"], "receipt_route_1");
        assert_eq!(
            record.agent["modelRouteDecision"]["workflow_node_id"],
            "runtime.model-router.custom"
        );
    }

    #[test]
    fn rust_policy_rejects_retired_thread_control_model_route_aliases() {
        let mut request = thread_control_agent_state_update_request("thinking");
        request.model_route = Some(json!({
            "requestedModelId": "auto",
            "selectedModel": "retired-model",
            "routeId": "route.retired",
            "endpointId": "endpoint_retired",
            "providerId": "provider_retired",
            "receiptId": "receipt_retired",
        }));

        let error = ThreadControlAgentStateUpdateCore
            .plan(&request)
            .expect_err("retired thread-control model-route aliases must not plan state");

        assert_eq!(
            error,
            ThreadControlAgentStateUpdateError::MissingField("model_route.selected_model")
        );
    }

    #[test]
    fn rust_policy_plans_agent_create_state_update() {
        let record = AgentCreateStateUpdateCore
            .plan(&agent_create_state_update_request())
            .expect("agent create state update");

        assert_eq!(
            record.schema_version,
            AGENT_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "agent.create");
        assert_eq!(record.agent_id, "agent_create_one");
        assert_eq!(record.created_at, "2026-06-06T05:15:00.000Z");
        assert_eq!(record.updated_at, "2026-06-06T05:15:00.000Z");
        assert_eq!(record.agent["runtimeControls"]["mode"], "agent");
    }

    #[test]
    fn rust_policy_plans_run_create_state_update() {
        let record = RunCreateStateUpdateCore
            .plan(&run_create_state_update_request())
            .expect("run create state update");

        assert_eq!(
            record.schema_version,
            RUN_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "run.create");
        assert_eq!(record.run_id, "run_create_one");
        assert_eq!(record.agent_id, "agent_create_one");
        assert_eq!(record.created_at, "2026-06-06T05:16:00.000Z");
        assert_eq!(record.run["usage_telemetry"]["total_tokens"], 7);
        assert_eq!(record.run["trace"]["usage_telemetry"]["total_tokens"], 7);
    }

    #[test]
    fn rust_policy_plans_agent_status_state_update() {
        let record = AgentStatusStateUpdateCore
            .plan(&agent_status_state_update_request())
            .expect("agent status state update");

        assert_eq!(
            record.schema_version,
            AGENT_STATUS_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "agent.archive");
        assert_eq!(record.agent_id, "agent_status_one");
        assert_eq!(record.updated_at, "2026-06-06T06:25:00.000Z");
        assert_eq!(record.agent["status"], "archived");
        assert_eq!(record.agent["updatedAt"], "2026-06-06T06:25:00.000Z");
    }

    #[test]
    fn rust_policy_plans_mcp_control_agent_state_update() {
        let record = McpControlAgentStateUpdateCore
            .plan(&mcp_control_agent_state_update_request())
            .expect("mcp control agent state update");

        assert_eq!(
            record.schema_version,
            MCP_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "thread.mcp_add");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.agent_id, "agent_1");
        assert_eq!(record.updated_at, "2026-06-06T05:45:00.000Z");
        assert_eq!(record.control["control_kind"], "mcp_add");
        assert_eq!(record.control["event_id"], "event_mcp_add");
        assert!(record.control.get("controlKind").is_none());
        assert!(record.control.get("eventId").is_none());
        assert!(record.control.get("createdAt").is_none());
        assert_eq!(record.agent["updatedAt"], "2026-06-06T05:45:00.000Z");
        assert_eq!(record.agent["mcpRegistry"]["servers"][0]["id"], "mcp.docs");
    }

    #[test]
    fn rust_policy_validates_mcp_servers() {
        let record = McpServerValidationCore
            .validate(&mcp_server_validation_request())
            .expect("mcp server validation");

        assert_eq!(
            record.schema_version,
            MCP_SERVER_VALIDATION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_server_validation");
        assert_eq!(record.status, "pass");
        assert!(record.ok);
        assert_eq!(record.issue_count, 0);
        assert_eq!(record.warning_count, 0);
        assert!(record.issues.is_empty());
        assert!(record.warnings.is_empty());
    }

    #[test]
    fn rust_policy_projects_mcp_server_validation_input() {
        let record = McpServerValidationInputCore
            .project(&mcp_server_validation_input_request())
            .expect("mcp server validation input");

        assert_eq!(
            record.schema_version,
            MCP_SERVER_VALIDATION_INPUT_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_server_validation_input");
        assert_eq!(record.status, "projected");
        assert_eq!(record.workspace_root.as_deref(), Some("/workspace"));
        assert_eq!(record.server_count, 1);
        assert_eq!(record.servers[0]["id"], "mcp.docs");
        assert_eq!(record.servers[0]["label"], "docs");
        assert_eq!(record.servers[0]["workspace_root"], "/workspace");
        assert_eq!(record.servers[0]["source_scope"], "validation");
        assert_eq!(record.servers[0]["tool_count"], 1);
        assert_eq!(record.servers[0]["allowed_tools"][0], "search");
        assert!(record.servers[0].get("sourcePath").is_none());
        assert!(record.servers[0].get("sourceScope").is_none());
    }

    #[test]
    fn rust_policy_projects_mcp_manager_status() {
        let validation = McpServerValidationCore
            .validate(&mcp_server_validation_request())
            .expect("mcp server validation");
        let request = McpManagerStatusProjectionRequest {
            schema_version: MCP_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            status_schema_version: Some("ioi.runtime.mcp-manager-status.v1".to_string()),
            validation: serde_json::to_value(validation).expect("validation value"),
            servers: vec![
                json!({
                    "id": "mcp.docs",
                    "enabled": true,
                }),
                json!({
                    "id": "mcp.disabled",
                    "enabled": false,
                }),
            ],
            tools: vec![json!({ "stable_tool_id": "mcp.docs.search" })],
            resources: vec![json!({ "uri": "mcp.docs://root" })],
            prompts: vec![json!({ "name": "ask" })],
            enabled_tools: vec![json!({ "stable_tool_id": "mcp.docs.search" })],
            routes: json!({
                "search_tools": "/v1/mcp/tools/search",
            }),
        };

        let record = McpManagerStatusProjectionCore
            .project(&request)
            .expect("mcp manager status projection");

        assert_eq!(
            record.schema_version,
            MCP_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_manager_status");
        assert_eq!(record.status, "ready");
        assert_eq!(record.server_count, 2);
        assert_eq!(record.tool_count, 1);
        assert_eq!(record.resource_count, 1);
        assert_eq!(record.prompt_count, 1);
        assert_eq!(record.enabled_server_count, 1);
        assert_eq!(record.enabled_tool_count, Some(1));
        assert_eq!(record.validation["server_count"], 2);
        assert_eq!(
            record.validation["tools"][0]["stable_tool_id"],
            "mcp.docs.search"
        );
        assert_eq!(record.routes["search_tools"], "/v1/mcp/tools/search");
        assert!(record.validation.get("serverCount").is_none());
        assert!(record.routes.get("searchTools").is_none());
    }

    #[test]
    fn rust_policy_projects_memory_manager_validation() {
        let request = MemoryManagerValidationProjectionRequest {
            schema_version: MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            validation_schema_version: Some(
                MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            ),
            projection: json!({
                "policy": {
                    "id": "policy.thread",
                    "scope": "thread",
                    "injection_enabled": true,
                    "read_only": false,
                    "write_requires_approval": true,
                    "readOnly": true
                },
                "paths": {
                    "records_path": "/state/memory",
                    "policies_path": "/state/policies",
                    "recordsPath": "/retired/memory"
                },
                "filters": {
                    "scope": "thread"
                },
                "records": [{
                    "id": "memory.one",
                    "fact": "Remember the runtime boundary.",
                    "scope": "thread",
                    "memory_key": "project",
                    "redaction": "redacted"
                }]
            }),
        };

        let record = MemoryManagerValidationProjectionCore
            .project(&request)
            .expect("memory manager validation projection");

        assert_eq!(
            record.schema_version,
            MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_memory_manager_validation");
        assert!(record.ok);
        assert_eq!(record.status, "pass");
        assert_eq!(record.record_count, 1);
        assert_eq!(record.warning_count, 3);
        assert!(record
            .warnings
            .iter()
            .any(|warning| warning["code"] == "memory_record_redacted_hash_missing"));
        assert!(record.policy.get("readOnly").is_some());
        assert_eq!(record.policy["read_only"], false);
        assert_eq!(record.paths["records_path"], "/state/memory");
    }

    #[test]
    fn rust_policy_projects_memory_manager_status() {
        let request = MemoryManagerStatusProjectionRequest {
            schema_version: MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            status_schema_version: Some(
                MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            ),
            validation_schema_version: Some(
                MEMORY_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            ),
            projection: json!({
                "policy": {
                    "id": "policy.thread",
                    "scope": "thread",
                    "injection_enabled": true,
                    "read_only": false,
                    "write_requires_approval": true,
                    "writeRequiresApproval": false
                },
                "paths": {
                    "records_path": "/state/memory",
                    "policies_path": "/state/policies",
                    "effective_policy_id": "policy.thread",
                    "effectivePolicyId": "policy.retired"
                },
                "records": [{
                    "id": "memory.one",
                    "fact": "Remember the runtime boundary.",
                    "scope": "thread",
                    "memoryKey": "retired.project",
                    "memory_key": "project"
                }]
            }),
        };

        let record = MemoryManagerStatusProjectionCore
            .project(&request)
            .expect("memory manager status projection");

        assert_eq!(
            record.schema_version,
            MEMORY_MANAGER_STATUS_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_memory_manager_status");
        assert_eq!(record.status, "ready");
        assert_eq!(record.record_count, 1);
        assert_eq!(record.scope_count, 1);
        assert_eq!(record.memory_key_count, 1);
        assert_eq!(record.memory_keys, vec!["project".to_string()]);
        assert_eq!(record.write_requires_approval, true);
        assert_eq!(
            record.write_blocked_reason.as_deref(),
            Some("memory_write_requires_approval")
        );
        assert_eq!(
            record.validation["object"],
            "ioi.runtime_memory_manager_validation"
        );
        assert_eq!(
            record.routes["status"],
            "/v1/threads/{thread_id}/memory/status"
        );
        assert!(record.evidence_refs.contains(&"policy.thread".to_string()));
        assert!(!record.evidence_refs.contains(&"policy.retired".to_string()));
        assert!(record.evidence_refs.contains(&"memory.one".to_string()));
    }

    #[test]
    fn rust_policy_projects_mcp_manager_catalog_rows() {
        let request = McpManagerCatalogProjectionRequest {
            schema_version: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            status_schema_version: None,
            servers: vec![
                json!({
                    "id": "mcp.docs",
                    "label": "Docs",
                    "enabled": true,
                    "transport": "stdio",
                    "allowed_tools": [
                        {
                            "name": "search",
                            "description": "Search docs",
                            "input_schema": { "type": "object" }
                        }
                    ],
                    "resources": [
                        {
                            "uri": "docs://index",
                            "name": "index",
                            "mime_type": "text/plain"
                        }
                    ],
                    "prompts": [
                        {
                            "name": "summarize",
                            "arguments": [{ "name": "topic" }]
                        }
                    ]
                }),
                json!({
                    "id": "mcp.disabled",
                    "label": "Disabled",
                    "enabled": false,
                    "allowed_tools": ["noop"]
                }),
            ],
        };

        let record = McpManagerCatalogProjectionCore
            .project(&request)
            .expect("mcp manager catalog projection");

        assert_eq!(
            record.schema_version,
            MCP_MANAGER_CATALOG_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_manager_catalog_projection");
        assert_eq!(record.status, "projected");
        assert_eq!(record.server_count, 2);
        assert_eq!(record.tool_count, 2);
        assert_eq!(record.enabled_tool_count, 1);
        assert_eq!(record.resource_count, 1);
        assert_eq!(record.prompt_count, 1);
        assert_eq!(record.tools[0]["stable_tool_id"], "mcp.Docs.search");
        assert_eq!(record.tools[1]["status"], "disabled");
        assert_eq!(
            record.resources[0]["stable_resource_id"],
            "mcp.Docs.resource.docs_index"
        );
        assert_eq!(
            record.prompts[0]["stable_prompt_id"],
            "mcp.Docs.prompt.summarize"
        );
        assert!(record.tools[0].get("stableToolId").is_none());
        assert!(record.resources[0].get("stableResourceId").is_none());
        assert!(record.prompts[0].get("stablePromptId").is_none());
    }

    #[test]
    fn rust_policy_projects_mcp_manager_catalog_summary() {
        let catalog = McpManagerCatalogProjectionCore
            .project(&McpManagerCatalogProjectionRequest {
                schema_version: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
                status_schema_version: None,
                servers: vec![json!({
                    "id": "mcp.docs",
                    "label": "Docs",
                    "transport": "stdio",
                    "enabled": true,
                    "allowed_tools": [{ "name": "search.index" }],
                    "resources": [{ "uri": "docs://index" }],
                    "prompts": [{ "name": "summarize" }]
                })],
            })
            .expect("mcp catalog projection");
        let request = McpManagerCatalogSummaryProjectionRequest {
            schema_version: MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_REQUEST_SCHEMA_VERSION
                .to_string(),
            status_schema_version: None,
            server: catalog.servers[0].clone(),
            tools: catalog.tools.clone(),
            resources: catalog.resources.clone(),
            prompts: catalog.prompts.clone(),
            live_mode: Some("declared_catalog".to_string()),
            status: None,
            error_code: None,
            preview_limit: Some(25),
            deferred: Some(false),
        };

        let record = McpManagerCatalogSummaryProjectionCore
            .project(&request)
            .expect("mcp catalog summary projection");

        assert_eq!(
            record.schema_version,
            MCP_MANAGER_CATALOG_SUMMARY_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_catalog_summary");
        assert_eq!(record.status, "completed");
        assert_eq!(record.server_id.as_deref(), Some("mcp.docs"));
        assert_eq!(record.server_label.as_deref(), Some("Docs"));
        assert_eq!(record.execution_mode.as_deref(), Some("declared_catalog"));
        assert_eq!(record.tool_count, 1);
        assert_eq!(record.resource_count, 1);
        assert_eq!(record.prompt_count, 1);
        assert_eq!(record.namespace_count, 1);
        assert_eq!(record.namespaces[0], "search");
        assert_eq!(record.preview_tool_names[0], "search.index");
        assert_eq!(record.search_route, "/v1/mcp/tools/search");
        assert_eq!(record.fetch_route, "/v1/mcp/tools/{tool_id}");
        assert!(!record.catalog_hash.is_empty());
    }

    #[test]
    fn rust_policy_projects_mcp_manager_validation_envelope() {
        let validation = McpServerValidationCore
            .validate(&mcp_server_validation_request())
            .expect("mcp server validation");
        let catalog = McpManagerCatalogProjectionCore
            .project(&McpManagerCatalogProjectionRequest {
                schema_version: MCP_MANAGER_CATALOG_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
                status_schema_version: None,
                servers: vec![json!({
                    "id": "mcp.docs",
                    "label": "Docs",
                    "enabled": true,
                    "allowed_tools": [{ "name": "search" }],
                    "resources": [{ "uri": "docs://index" }],
                    "prompts": [{ "name": "summarize" }]
                })],
            })
            .expect("mcp catalog projection");
        let request = McpManagerValidationProjectionRequest {
            schema_version: MCP_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            validation_schema_version: Some("ioi.runtime.mcp-manager-validation.v1".to_string()),
            validation: serde_json::to_value(validation).expect("validation value"),
            servers: catalog.servers.clone(),
            tools: catalog.tools.clone(),
            resources: catalog.resources.clone(),
            prompts: catalog.prompts.clone(),
        };

        let record = McpManagerValidationProjectionCore
            .project(&request)
            .expect("mcp validation projection");

        assert_eq!(
            record.schema_version,
            MCP_MANAGER_VALIDATION_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.runtime_mcp_manager_validation");
        assert!(record.ok);
        assert_eq!(record.status, "pass");
        assert_eq!(record.server_count, 1);
        assert_eq!(record.tool_count, 1);
        assert_eq!(record.resource_count, 1);
        assert_eq!(record.prompt_count, 1);
        assert_eq!(record.issue_count, 0);
        assert_eq!(record.warning_count, 0);
        assert_eq!(record.tools[0]["stable_tool_id"], "mcp.Docs.search");
        assert!(record.tools[0].get("stableToolId").is_none());
    }

    #[test]
    fn rust_policy_rejects_invalid_mcp_server_records() {
        let mut request = mcp_server_validation_request();
        request.servers = vec![
            json!({
                "id": "mcp.bad-stdio",
                "transport": "stdio",
                "allowed_tools": []
            }),
            json!({
                "id": "mcp.remote",
                "transport": "http",
                "server_url": "file:///tmp/socket",
                "allowed_tools": ["fetch"],
                "containment": {
                    "allow_network_egress": false
                }
            }),
            json!({
                "id": "mcp.secret",
                "transport": "stdio",
                "command": "npx",
                "allowed_tools": ["secret"],
                "secret_refs": {
                    "Authorization": { "invalidVaultRef": true }
                },
                "secretRefs": {
                    "Authorization": { "invalidVaultRef": false }
                }
            }),
        ];

        let record = McpServerValidationCore
            .validate(&request)
            .expect("mcp server validation");

        assert_eq!(record.status, "blocked");
        assert!(!record.ok);
        assert_eq!(record.issue_count, 4);
        assert_eq!(record.warning_count, 1);
        let codes = record
            .issues
            .iter()
            .filter_map(|issue| issue["code"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            vec![
                "mcp_server_transport_missing",
                "mcp_remote_url_invalid",
                "mcp_remote_network_blocked",
                "mcp_secret_not_vault_ref",
            ]
        );
        assert_eq!(record.issues[3]["server_id"], "mcp.secret");
        assert_eq!(record.issues[3]["key"], "Authorization");
        assert!(record.issues[3].get("serverId").is_none());
        assert_eq!(record.warnings[0]["code"], "mcp_allowed_tools_empty");
        assert!(record.warnings[0].get("serverId").is_none());
    }

    #[test]
    fn rust_policy_rejects_invalid_mcp_server_validation_schema() {
        let mut request = mcp_server_validation_request();
        request.schema_version = "legacy.mcp-validation".to_string();

        let error = McpServerValidationCore
            .validate(&request)
            .expect_err("invalid schema should be rejected");

        assert_eq!(
            error,
            McpServerValidationError::InvalidSchemaVersion {
                expected: MCP_SERVER_VALIDATION_REQUEST_SCHEMA_VERSION,
                actual: "legacy.mcp-validation".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_plans_thread_memory_agent_state_update() {
        let record = ThreadMemoryAgentStateUpdateCore
            .plan(&thread_memory_agent_state_update_request())
            .expect("thread memory agent state update");

        assert_eq!(
            record.schema_version,
            THREAD_MEMORY_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "thread.memory_status");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.agent_id, "agent_1");
        assert_eq!(record.updated_at, "2026-06-06T06:05:00.000Z");
        assert_eq!(record.control["control_kind"], "memory_status");
        assert_eq!(record.control["event_id"], "event_memory_status");
        assert!(record.control.get("controlKind").is_none());
        assert!(record.control.get("eventId").is_none());
        assert!(record.control.get("createdAt").is_none());
        assert_eq!(record.agent["updatedAt"], "2026-06-06T06:05:00.000Z");
    }

    #[test]
    fn rust_policy_plans_runtime_bridge_thread_start_agent_state_update() {
        let record = RuntimeBridgeThreadStartAgentStateUpdateCore
            .plan(&runtime_bridge_thread_start_agent_state_update_request())
            .expect("runtime bridge thread start agent state update");

        assert_eq!(
            record.schema_version,
            RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "thread.runtime_bridge.start");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.agent_id, "agent_1");
        assert_eq!(record.updated_at, "2026-06-06T06:15:00.000Z");
        assert_eq!(record.bridge_start["session_id"], "session_runtime");
        assert_eq!(record.bridge_start["bridge_id"], "bridge_runtime");
        for field in ["runtimeProfile", "sessionId", "bridgeId", "updatedAt"] {
            assert!(record.bridge_start.get(field).is_none());
        }
        assert_eq!(record.agent["runtimeProfile"], "runtime_service");
        assert_eq!(record.agent["runtimeSessionId"], "session_runtime");
        assert_eq!(record.agent["runtimeBridgeId"], "bridge_runtime");
        assert_eq!(record.agent["fixtureProfile"], Value::Null);
    }

    #[test]
    fn rust_policy_plans_runtime_bridge_turn_run_state_update() {
        let record = RuntimeBridgeTurnRunStateUpdateCore
            .plan(&runtime_bridge_turn_run_state_update_request())
            .expect("runtime bridge turn run state update");

        assert_eq!(
            record.schema_version,
            RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "turn.runtime_bridge.submit");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.run_id, "run_runtime_bridge");
        assert_eq!(record.agent_id, "agent_1");
        assert_eq!(record.updated_at, "2026-06-06T06:35:00.000Z");
        assert_eq!(record.run["id"], "run_runtime_bridge");
    }

    #[test]
    fn rust_policy_rejects_invalid_mcp_control_agent_state_update_schema() {
        let mut request = mcp_control_agent_state_update_request();
        request.schema_version = "legacy.mcp-control-state-update".to_string();

        let error = McpControlAgentStateUpdateCore
            .plan(&request)
            .expect_err("invalid schema should be rejected");

        assert_eq!(
            error,
            McpControlAgentStateUpdateError::InvalidSchemaVersion {
                expected: MCP_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.mcp-control-state-update".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_thread_memory_agent_state_update_schema() {
        let mut request = thread_memory_agent_state_update_request();
        request.schema_version = "legacy.thread-memory-state-update".to_string();

        let error = ThreadMemoryAgentStateUpdateCore
            .plan(&request)
            .expect_err("invalid schema should be rejected");

        assert_eq!(
            error,
            ThreadMemoryAgentStateUpdateError::InvalidSchemaVersion {
                expected: THREAD_MEMORY_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.thread-memory-state-update".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_runtime_bridge_thread_start_agent_state_update_schema() {
        let mut request = runtime_bridge_thread_start_agent_state_update_request();
        request.schema_version = "legacy.runtime-bridge-start-state-update".to_string();

        let error = RuntimeBridgeThreadStartAgentStateUpdateCore
            .plan(&request)
            .expect_err("invalid schema should be rejected");

        assert_eq!(
            error,
            RuntimeBridgeThreadStartAgentStateUpdateError::InvalidSchemaVersion {
                expected: RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.runtime-bridge-start-state-update".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_runtime_bridge_turn_run_state_update_schema() {
        let mut request = runtime_bridge_turn_run_state_update_request();
        request.schema_version = "legacy.runtime-bridge-turn-run-state-update".to_string();

        let error = RuntimeBridgeTurnRunStateUpdateCore
            .plan(&request)
            .expect_err("invalid schema should be rejected");

        assert_eq!(
            error,
            RuntimeBridgeTurnRunStateUpdateError::InvalidSchemaVersion {
                expected: RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.runtime-bridge-turn-run-state-update".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_plans_subagent_record_state_update() {
        let record = SubagentRecordStateUpdateCore
            .plan(&subagent_record_state_update_request())
            .expect("subagent record state update");

        assert_eq!(
            record.schema_version,
            SUBAGENT_RECORD_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "subagent.wait");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.subagent_id, "subagent_1");
        assert_eq!(record.updated_at, "2026-06-06T07:04:00.000Z");
        assert_eq!(record.subagent["subagent_id"], "subagent_1");
    }

    #[test]
    fn rust_policy_rejects_subagent_record_state_update_thread_mismatch() {
        let mut request = subagent_record_state_update_request();
        request.thread_id = "thread_other".to_string();

        let error = SubagentRecordStateUpdateCore
            .plan(&request)
            .expect_err("thread mismatch should be rejected");

        assert_eq!(
            error,
            SubagentRecordStateUpdateError::MismatchedField {
                field: "subagent.parent_thread_id",
                expected: "thread_other".to_string(),
                actual: "thread_1".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_context_compaction_plan_schema() {
        let mut request = context_compaction_plan_request();
        request.schema_version = "legacy.schema".to_string();

        let error = ContextCompactionPlanCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            ContextCompactionPlanError::InvalidSchemaVersion {
                expected: CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_context_compaction_state_update_schema() {
        let mut request = context_compaction_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = ContextCompactionStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            ContextCompactionStateUpdateError::InvalidSchemaVersion {
                expected: CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_coding_tool_budget_recovery_state_update_schema() {
        let mut request = coding_tool_budget_recovery_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = CodingToolBudgetRecoveryStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            CodingToolBudgetRecoveryStateUpdateError::InvalidSchemaVersion {
                expected: CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_diagnostics_operator_override_state_update_schema() {
        let mut request = diagnostics_operator_override_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = DiagnosticsOperatorOverrideStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            DiagnosticsOperatorOverrideStateUpdateError::InvalidSchemaVersion {
                expected: DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_operator_interrupt_state_update_schema() {
        let mut request = operator_interrupt_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = OperatorInterruptStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            OperatorInterruptStateUpdateError::InvalidSchemaVersion {
                expected: OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_operator_steer_state_update_schema() {
        let mut request = operator_steer_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = OperatorSteerStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            OperatorSteerStateUpdateError::InvalidSchemaVersion {
                expected: OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_run_cancel_state_update_schema() {
        let mut request = run_cancel_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = RunCancelStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            RunCancelStateUpdateError::InvalidSchemaVersion {
                expected: RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_thread_control_agent_state_update_schema() {
        let mut request = thread_control_agent_state_update_request("mode");
        request.schema_version = "legacy.schema".to_string();

        let error = ThreadControlAgentStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            ThreadControlAgentStateUpdateError::InvalidSchemaVersion {
                expected: THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_agent_create_state_update_schema() {
        let mut request = agent_create_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = AgentCreateStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            AgentCreateStateUpdateError::InvalidSchemaVersion {
                expected: AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_run_create_state_update_schema() {
        let mut request = run_create_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = RunCreateStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            RunCreateStateUpdateError::InvalidSchemaVersion {
                expected: RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_agent_status_state_update_schema() {
        let mut request = agent_status_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = AgentStatusStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            AgentStatusStateUpdateError::InvalidSchemaVersion {
                expected: AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }
}
