use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    CODING_TOOL_BUDGET_BLOCK_REQUEST_SCHEMA_VERSION,
    CODING_TOOL_BUDGET_BLOCK_RESULT_SCHEMA_VERSION,
    CODING_TOOL_BUDGET_POLICY_REQUEST_SCHEMA_VERSION, COMPACTION_POLICY_REQUEST_SCHEMA_VERSION,
    COMPACTION_POLICY_RESULT_SCHEMA_VERSION, CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION,
    CONTEXT_BUDGET_POLICY_RESULT_SCHEMA_VERSION, CONTEXT_COMPACTION_PAYLOAD_SCHEMA_VERSION,
    CONTEXT_COMPACTION_PLAN_REQUEST_SCHEMA_VERSION, CONTEXT_COMPACTION_PLAN_RESULT_SCHEMA_VERSION,
    CONTEXT_COMPACTION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    CONTEXT_COMPACTION_STATE_UPDATE_RESULT_SCHEMA_VERSION,
};

const CODING_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-result.v1";
const CODING_TOOL_PACK_ID: &str = "ioi.tool_pack.coding";

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
    RetiredField(&'static str),
    StateDirRequired,
    ReplayReadFailed(String),
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
pub enum CodingToolBudgetBlockError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPolicyCommandError {
    code: &'static str,
    message: String,
}

impl ContextPolicyCommandError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolBudgetBlockRequest {
    pub schema_version: String,
    pub thread_id: String,
    #[serde(default)]
    pub turn_id: Option<String>,
    pub tool_id: String,
    pub tool_call_id: String,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub workflow_graph_id: Option<String>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub input_summary: Value,
    #[serde(default)]
    pub budget_policy: Value,
    #[serde(default)]
    pub rollback_refs: Vec<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolBudgetBlockRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    pub tool_id: String,
    pub tool_call_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_graph_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_node_id: Option<String>,
    pub reason: String,
    pub context_budget_status: String,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub result: Value,
    pub event: Value,
    pub projection_source: String,
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
    pub state_dir: Option<String>,
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

#[derive(Debug, Deserialize)]
pub struct ContextBudgetPolicyBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub request: ContextBudgetPolicyRequest,
}

#[derive(Debug, Deserialize)]
pub struct CompactionPolicyBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub request: CompactionPolicyRequest,
}

#[derive(Debug, Deserialize)]
pub struct ContextCompactionPlanBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub request: ContextCompactionPlanRequest,
}

#[derive(Debug, Deserialize)]
pub struct ContextCompactionStateUpdateBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub request: ContextCompactionStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct CodingToolBudgetBlockBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub request: CodingToolBudgetBlockRequest,
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

impl CodingToolBudgetBlockCore {
    pub fn plan(
        &self,
        request: &CodingToolBudgetBlockRequest,
    ) -> Result<CodingToolBudgetBlockRecord, CodingToolBudgetBlockError> {
        request.validate()?;
        let thread_id = optional_trimmed(Some(request.thread_id.as_str())).unwrap();
        let turn_id = optional_trimmed(request.turn_id.as_deref());
        let tool_id = optional_trimmed(Some(request.tool_id.as_str())).unwrap();
        let tool_call_id = optional_trimmed(Some(request.tool_call_id.as_str())).unwrap();
        let workflow_graph_id = optional_trimmed(request.workflow_graph_id.as_deref());
        let workflow_node_id = optional_trimmed(request.workflow_node_id.as_deref());
        let workspace_root = optional_trimmed(request.workspace_root.as_deref());
        let source = optional_trimmed(request.source.as_deref())
            .unwrap_or_else(|| "runtime_auto".to_string());
        let reason = "coding_tool_budget_exceeded".to_string();
        let context_budget_status =
            string_field(&request.budget_policy, "status").unwrap_or_else(|| "blocked".to_string());
        let receipt_id = optional_trimmed(request.receipt_id.as_deref()).unwrap_or_else(|| {
            format!(
                "receipt_coding_tool_budget_block_{}_{}",
                safe_id(&tool_id),
                short_sha256_hex(&format!("{thread_id}:{tool_id}:{tool_call_id}"), 12)
            )
        });
        let idempotency_key = optional_trimmed(request.idempotency_key.as_deref())
            .unwrap_or_else(|| format!("thread:{thread_id}:coding-tool:{tool_call_id}"));
        let receipt_refs = unique_strings(
            request
                .receipt_refs
                .iter()
                .cloned()
                .chain(value_string_array(&request.budget_policy, "receipt_refs"))
                .chain(std::iter::once(receipt_id.clone()))
                .collect(),
        );
        let policy_decision_refs = unique_strings(
            request
                .policy_decision_refs
                .iter()
                .cloned()
                .chain(value_string_array(
                    &request.budget_policy,
                    "policy_decision_refs",
                ))
                .chain(string_field(&request.budget_policy, "policy_decision_id"))
                .collect(),
        );
        let artifact_refs = unique_strings(request.artifact_refs.clone());
        let rollback_refs = unique_strings(request.rollback_refs.clone());
        let input_summary = if request.input_summary.is_object() {
            request.input_summary.clone()
        } else {
            Value::Object(serde_json::Map::new())
        };
        let error = json!({
            "code": "coding_tool_budget_exceeded",
            "message": "Coding tool execution is blocked by the Rust budget policy.",
            "details": {
                "thread_id": thread_id,
                "turn_id": turn_id,
                "tool_id": tool_id,
                "tool_call_id": tool_call_id,
                "workflow_graph_id": workflow_graph_id,
                "workflow_node_id": workflow_node_id,
                "reason": reason,
                "context_budget_status": context_budget_status,
                "budget_usage_telemetry": request.budget_policy.get("usage_telemetry").cloned().unwrap_or(Value::Null),
                "policy_decision_refs": policy_decision_refs,
            }
        });
        let result = json!({
            "schema_version": CODING_TOOL_RESULT_SCHEMA_VERSION,
            "tool_name": tool_id,
            "status": "blocked",
            "blocked": true,
            "reason": reason,
            "context_budget_status": context_budget_status,
            "context_budget": request.budget_policy.clone(),
            "budget_usage_telemetry": request.budget_policy.get("usage_telemetry").cloned().unwrap_or(Value::Null),
            "error": error.clone(),
            "receipt_refs": receipt_refs.clone(),
            "policy_decision_refs": policy_decision_refs.clone(),
            "artifact_refs": artifact_refs.clone(),
            "shell_fallback_used": false,
            "rust_budget_block": true,
        });
        let event_stream_id = format!("{thread_id}:events");
        let turn_or_thread = turn_id.as_deref().unwrap_or(thread_id.as_str());
        let item_id = format!(
            "{turn_or_thread}:item:coding-tool:{}:{}",
            safe_id(&tool_id),
            short_sha256_hex(&tool_call_id, 12)
        );
        let payload_summary = json!({
            "schema_version": CODING_TOOL_RESULT_SCHEMA_VERSION,
            "event_kind": "CodingToolResult",
            "tool_pack": CODING_TOOL_PACK_ID,
            "tool_name": tool_id,
            "tool_call_id": tool_call_id,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "workspace_root": workspace_root,
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "status": "blocked",
            "summary": "Coding tool blocked by budget policy.",
            "shell_fallback_used": false,
            "input_summary": input_summary,
            "result_summary": {
                "status": "blocked",
                "reason": reason,
                "context_budget_status": context_budget_status,
            },
            "result": result.clone(),
            "error": error,
            "rollback_refs": rollback_refs.clone(),
            "context_budget_status": context_budget_status,
            "context_budget": request.budget_policy.clone(),
            "budget_usage_telemetry": request.budget_policy.get("usage_telemetry").cloned().unwrap_or(Value::Null),
            "receipt_id": receipt_id,
            "receipt_count": receipt_refs.len(),
            "artifact_count": artifact_refs.len(),
            "receipt_refs": receipt_refs.clone(),
            "policy_decision_refs": policy_decision_refs.clone(),
            "step_module_backend": Value::Null,
            "step_module_invocation": Value::Null,
            "step_module_result": Value::Null,
            "step_module_error": Value::Null,
            "rust_budget_block": true,
        });
        let event = json!({
            "event_stream_id": event_stream_id,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "item_id": item_id,
            "idempotency_key": idempotency_key,
            "source": source,
            "source_event_kind": "coding_tool.budget.blocked",
            "event_kind": "tool.blocked",
            "status": "blocked",
            "actor": "runtime",
            "workspace_root": workspace_root,
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "component_kind": "coding_tool",
            "tool_call_id": tool_call_id,
            "artifact_refs": artifact_refs,
            "receipt_refs": receipt_refs,
            "rollback_refs": rollback_refs,
            "payload_schema_version": CODING_TOOL_RESULT_SCHEMA_VERSION,
            "payload_summary": payload_summary,
        });

        Ok(CodingToolBudgetBlockRecord {
            schema_version: CODING_TOOL_BUDGET_BLOCK_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_coding_tool_budget_block".to_string(),
            status: "blocked".to_string(),
            operation_kind: "coding_tool.budget.block".to_string(),
            thread_id,
            turn_id,
            tool_id,
            tool_call_id,
            workflow_graph_id,
            workflow_node_id,
            reason,
            context_budget_status,
            receipt_refs,
            policy_decision_refs,
            artifact_refs,
            rollback_refs,
            result,
            event,
            projection_source: "rust_daemon_core_coding_tool_budget_block".to_string(),
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
        let previous_latest_seq = super::latest_runtime_event_seq_from_state_dir(
            request.state_dir.as_deref(),
            Some(request.thread_id.as_str()),
            request.event_stream_id.as_deref(),
        )
        .map_err(ContextCompactionPlanError::ReplayReadFailed)?;
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

#[derive(Debug, Default, Clone)]
pub struct CodingToolBudgetBlockCore;

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

pub fn evaluate_context_budget_policy_response(
    request: ContextBudgetPolicyBridgeRequest,
) -> Result<Value, ContextPolicyCommandError> {
    evaluate_context_budget_policy_response_with(
        request,
        "rust_context_budget_policy_command",
        "context_budget_policy_invalid",
    )
}

pub fn evaluate_coding_tool_budget_policy_response(
    request: ContextBudgetPolicyBridgeRequest,
) -> Result<Value, ContextPolicyCommandError> {
    evaluate_context_budget_policy_response_with(
        request,
        "rust_coding_tool_budget_policy_command",
        "coding_tool_budget_policy_invalid",
    )
}

pub fn plan_coding_tool_budget_block_response(
    request: CodingToolBudgetBlockBridgeRequest,
) -> Result<Value, ContextPolicyCommandError> {
    let record = CodingToolBudgetBlockCore
        .plan(&request.request)
        .map_err(|error| {
            ContextPolicyCommandError::new("coding_tool_budget_block_invalid", format!("{error:?}"))
        })?;
    let record_value = serde_json::to_value(record.clone()).unwrap_or(Value::Null);
    Ok(json!({
        "source": "rust_coding_tool_budget_block_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record_value,
        "status": record.status,
        "operation_kind": record.operation_kind,
        "thread_id": record.thread_id,
        "turn_id": record.turn_id,
        "tool_id": record.tool_id,
        "tool_call_id": record.tool_call_id,
        "workflow_graph_id": record.workflow_graph_id,
        "workflow_node_id": record.workflow_node_id,
        "reason": record.reason,
        "context_budget_status": record.context_budget_status,
        "receipt_refs": record.receipt_refs,
        "policy_decision_refs": record.policy_decision_refs,
        "artifact_refs": record.artifact_refs,
        "rollback_refs": record.rollback_refs,
        "result": record.result,
        "event": record.event,
    }))
}

fn evaluate_context_budget_policy_response_with(
    request: ContextBudgetPolicyBridgeRequest,
    source: &'static str,
    error_code: &'static str,
) -> Result<Value, ContextPolicyCommandError> {
    let record = ContextBudgetPolicyCore
        .evaluate(&request.request)
        .map_err(|error| ContextPolicyCommandError::new(error_code, format!("{error:?}")))?;
    Ok(policy_record_response(
        source,
        request.backend,
        record,
        &[
            "status",
            "mode",
            "usage_telemetry",
            "usage_summary",
            "policy_decision_id",
            "policy_decision",
            "receipt_refs",
            "policy_decision_refs",
            "warnings",
            "violations",
            "would_block",
            "runtime_event_kind",
            "runtime_event_status",
            "runtime_event_item_id",
            "runtime_event_idempotency_key",
            "summary",
        ],
    ))
}

pub fn evaluate_compaction_policy_response(
    request: CompactionPolicyBridgeRequest,
) -> Result<Value, ContextPolicyCommandError> {
    let record = CompactionPolicyCore
        .evaluate(&request.request)
        .map_err(|error| {
            ContextPolicyCommandError::new("compaction_policy_invalid", format!("{error:?}"))
        })?;
    Ok(policy_record_response(
        "rust_compaction_policy_command",
        request.backend,
        record,
        &[
            "status",
            "action",
            "selected_action",
            "budget_status",
            "policy_decision_id",
            "receipt_refs",
            "policy_decision_refs",
            "approval_id",
            "approval_required",
            "approval_granted",
            "approval_satisfied",
            "execute_compaction",
            "compaction_requested",
            "compact_reason",
            "compact_scope",
            "runtime_event_kind",
            "runtime_event_status",
            "runtime_event_item_id",
            "runtime_event_idempotency_key",
            "compact_idempotency_key",
            "compact_workflow_node_id",
            "continuation_allowed",
            "summary",
        ],
    ))
}

pub fn plan_context_compaction_response(
    request: ContextCompactionPlanBridgeRequest,
) -> Result<Value, ContextPolicyCommandError> {
    let record = ContextCompactionPlanCore
        .plan(&request.request)
        .map_err(|error| {
            ContextPolicyCommandError::new("context_compaction_plan_invalid", format!("{error:?}"))
        })?;
    let record_value = serde_json::to_value(record.clone()).unwrap_or(Value::Null);
    let mut response = command_response_base(
        "rust_context_compaction_plan_command",
        request.backend,
        record_value.clone(),
    );
    copy_fields(
        &mut response,
        &record_value,
        &[
            "status",
            "actor",
            "item_id",
            "idempotency_key",
            "compact_hash",
            "source_event_kind",
            "event_kind",
            "component_kind",
            "payload_schema_version",
            "payload",
            "receipt_refs",
            "policy_decision_refs",
            "artifact_refs",
            "rollback_refs",
            "redaction_profile",
            "reason",
            "scope",
            "requested_by",
            "previous_latest_seq",
        ],
    );
    response.insert(
        "event_source".to_string(),
        record_value.get("source").cloned().unwrap_or(Value::Null),
    );
    Ok(Value::Object(response))
}

pub fn plan_context_compaction_state_update_response(
    request: ContextCompactionStateUpdateBridgeRequest,
) -> Result<Value, ContextPolicyCommandError> {
    let record = ContextCompactionStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            ContextPolicyCommandError::new(
                "context_compaction_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(policy_record_response(
        "rust_context_compaction_state_update_command",
        request.backend,
        record,
        &[
            "status",
            "target_kind",
            "operation_kind",
            "updated_at",
            "operator_control",
            "context_compaction",
            "run",
            "agent",
        ],
    ))
}

fn policy_record_response<T>(
    source: &'static str,
    backend: Option<String>,
    record: T,
    fields: &[&str],
) -> Value
where
    T: Serialize + Clone,
{
    let record_value = serde_json::to_value(record.clone()).unwrap_or(Value::Null);
    let mut response = command_response_base(source, backend, record_value.clone());
    copy_fields(&mut response, &record_value, fields);
    Value::Object(response)
}

fn command_response_base(
    source: &'static str,
    backend: Option<String>,
    record_value: Value,
) -> serde_json::Map<String, Value> {
    let mut response = serde_json::Map::new();
    response.insert("source".to_string(), Value::String(source.to_string()));
    response.insert(
        "backend".to_string(),
        Value::String(backend.unwrap_or_else(|| "rust_policy".to_string())),
    );
    response.insert("record".to_string(), record_value);
    response
}

fn copy_fields(
    response: &mut serde_json::Map<String, Value>,
    record_value: &Value,
    fields: &[&str],
) {
    for field in fields {
        response.insert(
            (*field).to_string(),
            record_value.get(*field).cloned().unwrap_or(Value::Null),
        );
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

impl CodingToolBudgetBlockRequest {
    pub fn validate(&self) -> Result<(), CodingToolBudgetBlockError> {
        if self.schema_version != CODING_TOOL_BUDGET_BLOCK_REQUEST_SCHEMA_VERSION {
            return Err(CodingToolBudgetBlockError::InvalidSchemaVersion {
                expected: CODING_TOOL_BUDGET_BLOCK_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(CodingToolBudgetBlockError::MissingField("thread_id"));
        }
        if optional_trimmed(Some(self.tool_id.as_str())).is_none() {
            return Err(CodingToolBudgetBlockError::MissingField("tool_id"));
        }
        if optional_trimmed(Some(self.tool_call_id.as_str())).is_none() {
            return Err(CodingToolBudgetBlockError::MissingField("tool_call_id"));
        }
        if !self.budget_policy.is_object() {
            return Err(CodingToolBudgetBlockError::MissingField("budget_policy"));
        }
        Ok(())
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
        if self.previous_latest_seq.is_some() {
            return Err(ContextCompactionPlanError::RetiredField(
                "previous_latest_seq",
            ));
        }
        if optional_trimmed(self.state_dir.as_deref()).is_none() {
            return Err(ContextCompactionPlanError::StateDirRequired);
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

fn value_string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|entry| optional_trimmed(Some(entry)))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut output = Vec::new();
    for value in values {
        let Some(value) = optional_trimmed(Some(value.as_str())) else {
            continue;
        };
        if !output.iter().any(|existing| existing == &value) {
            output.push(value);
        }
    }
    output
}

fn short_sha256_hex(value: &str, len: usize) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
        .chars()
        .take(len)
        .collect()
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
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_context_state_dir(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let state_dir =
            std::env::temp_dir().join(format!("ioi-context-lifecycle-{label}-{suffix}"));
        let _ = fs::remove_dir_all(&state_dir);
        fs::create_dir_all(state_dir.join("events")).expect("create events dir");
        state_dir
    }

    fn seed_context_event_state(
        state_dir: &Path,
        thread_id: &str,
        event_stream_id: &str,
        seq: u64,
    ) {
        let event = json!({
            "event_stream_id": event_stream_id,
            "thread_id": thread_id,
            "event_id": format!("event_seed_{seq}"),
            "seq": seq,
            "idempotency_key": format!("seed:{seq}"),
            "event_kind": "seed.event"
        });
        fs::write(
            state_dir.join("events").join("thread_budget.jsonl"),
            format!("{event}\n"),
        )
        .expect("seed context event");
    }

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

    fn budget_block_request() -> CodingToolBudgetBlockRequest {
        CodingToolBudgetBlockRequest {
            schema_version: CODING_TOOL_BUDGET_BLOCK_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_budget".to_string(),
            turn_id: Some("turn_budget".to_string()),
            tool_id: "file.inspect".to_string(),
            tool_call_id: "call_budget".to_string(),
            workspace_root: Some("/workspace".to_string()),
            workflow_graph_id: Some("graph_budget".to_string()),
            workflow_node_id: Some("node_budget".to_string()),
            source: Some("runtime_auto".to_string()),
            idempotency_key: Some("thread:thread_budget:coding-tool:call_budget".to_string()),
            receipt_id: Some("receipt_coding_tool_budget_block_file_inspect".to_string()),
            input_summary: json!({
                "path": "README.md",
            }),
            budget_policy: serde_json::to_value(
                ContextBudgetPolicyCore
                    .evaluate(&budget_request())
                    .expect("coding-tool budget policy"),
            )
            .expect("budget policy value"),
            rollback_refs: vec!["rollback_budget".to_string()],
            receipt_refs: vec!["receipt_invocation".to_string()],
            policy_decision_refs: vec!["policy_invocation".to_string()],
            artifact_refs: vec!["artifact_budget".to_string()],
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
        let state_dir = temp_context_state_dir("compaction-plan");
        seed_context_event_state(&state_dir, "thread_budget", "thread_budget:events", 7);
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
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            previous_latest_seq: None,
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
    fn rust_policy_shapes_context_budget_command_response() {
        let mut request = budget_request();
        request.schema_version = CONTEXT_BUDGET_POLICY_REQUEST_SCHEMA_VERSION.to_string();
        request.tool_id = None;
        request.tool_call_id = None;

        let response = evaluate_context_budget_policy_response(ContextBudgetPolicyBridgeRequest {
            backend: Some("rust_policy".to_string()),
            request,
        })
        .expect("context budget policy command response");

        assert_eq!(response["source"], "rust_context_budget_policy_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "blocked");
        assert_eq!(
            response["record"]["event_kind"],
            "RuntimeContextBudget.Evaluate"
        );
        assert_eq!(response["record"]["component_kind"], "context_budget");
        assert_eq!(response["usage_summary"]["total_tokens"], 120.0);
        assert_eq!(response["violations"][0]["id"], "total_tokens");
        assert_eq!(response["runtime_event_kind"], "policy.blocked");
        assert_eq!(response["runtime_event_status"], "blocked");
        assert!(response["runtime_event_item_id"]
            .as_str()
            .expect("runtime event item id")
            .starts_with("turn_budget:item:context-budget:policy_context_budget_thread_"));
        assert!(response["runtime_event_idempotency_key"]
            .as_str()
            .expect("runtime event idempotency key")
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
    fn rust_policy_shapes_coding_tool_budget_command_response() {
        let response =
            evaluate_coding_tool_budget_policy_response(ContextBudgetPolicyBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: budget_request(),
            })
            .expect("coding-tool budget policy command response");

        assert_eq!(response["source"], "rust_coding_tool_budget_policy_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["usage_summary"]["total_tokens"], 120.0);
        assert_eq!(response["violations"][0]["id"], "total_tokens");
        assert!(response["policy_decision_id"]
            .as_str()
            .expect("policy decision")
            .starts_with("policy_context_budget_thread_"));
        assert_eq!(
            response["policy_decision_refs"][0],
            response["policy_decision_id"]
        );
    }

    #[test]
    fn rust_policy_plans_coding_tool_budget_block_result_event() {
        let record = CodingToolBudgetBlockCore
            .plan(&budget_block_request())
            .expect("coding-tool budget block");

        assert_eq!(
            record.schema_version,
            CODING_TOOL_BUDGET_BLOCK_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "blocked");
        assert_eq!(record.operation_kind, "coding_tool.budget.block");
        assert_eq!(record.reason, "coding_tool_budget_exceeded");
        assert_eq!(record.context_budget_status, "blocked");
        assert!(record
            .receipt_refs
            .contains(&"receipt_coding_tool_budget_block_file_inspect".to_string()));
        assert!(record
            .receipt_refs
            .contains(&"receipt_invocation".to_string()));
        assert!(record
            .policy_decision_refs
            .contains(&"policy_invocation".to_string()));
        assert_eq!(
            record.result["schema_version"],
            CODING_TOOL_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.result["status"], "blocked");
        assert_eq!(record.result["rust_budget_block"], true);
        assert_eq!(record.result["context_budget_status"], "blocked");
        assert_eq!(record.event["event_stream_id"], "thread_budget:events");
        assert_eq!(record.event["event_kind"], "tool.blocked");
        assert_eq!(record.event["status"], "blocked");
        assert_eq!(
            record.event["payload_summary"]["context_budget_status"],
            "blocked"
        );
        assert_eq!(record.event["payload_summary"]["rust_budget_block"], true);
    }

    #[test]
    fn rust_core_shapes_coding_tool_budget_block_command_response() {
        let response = plan_coding_tool_budget_block_response(CodingToolBudgetBlockBridgeRequest {
            backend: Some("rust_policy".to_string()),
            request: budget_block_request(),
        })
        .expect("coding-tool budget block command response");

        assert_eq!(response["source"], "rust_coding_tool_budget_block_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["operation_kind"], "coding_tool.budget.block");
        assert_eq!(response["reason"], "coding_tool_budget_exceeded");
        assert_eq!(response["context_budget_status"], "blocked");
        assert_eq!(response["result"]["status"], "blocked");
        assert_eq!(response["event"]["event_kind"], "tool.blocked");
        assert_eq!(
            response["record"]["schema_version"],
            CODING_TOOL_BUDGET_BLOCK_RESULT_SCHEMA_VERSION
        );
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
    fn rust_policy_shapes_compaction_policy_command_response() {
        let response = evaluate_compaction_policy_response(CompactionPolicyBridgeRequest {
            backend: Some("rust_policy".to_string()),
            request: compaction_request(),
        })
        .expect("compaction policy command response");

        assert_eq!(response["source"], "rust_compaction_policy_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "waiting");
        assert_eq!(response["action"], "approval_required");
        assert_eq!(response["selected_action"], "compact");
        assert_eq!(response["budget_status"], "blocked");
        assert_eq!(response["runtime_event_kind"], "approval.required");
        assert_eq!(response["runtime_event_status"], "waiting");
        assert!(response["runtime_event_item_id"]
            .as_str()
            .expect("runtime event item id")
            .starts_with("turn_budget:item:compaction-policy:policy_compaction_thread_budget_"));
        assert!(response["compact_idempotency_key"]
            .as_str()
            .expect("compact idempotency key")
            .starts_with(
                "thread:thread_budget:compaction-policy:compact:policy_compaction_thread_budget_"
            ));
        assert!(response["approval_id"]
            .as_str()
            .expect("approval id")
            .starts_with("approval_compaction_thread_budget_"));
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
    fn rust_policy_shapes_context_compaction_command_response() {
        let response = plan_context_compaction_response(ContextCompactionPlanBridgeRequest {
            backend: Some("rust_policy".to_string()),
            request: context_compaction_plan_request(),
        })
        .expect("context compaction command response");

        assert_eq!(response["source"], "rust_context_compaction_plan_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["event_kind"], "context.compacted");
        assert_eq!(response["component_kind"], "context_compaction");
        assert_eq!(
            response["payload_schema_version"],
            CONTEXT_COMPACTION_PAYLOAD_SCHEMA_VERSION
        );
        assert!(response["item_id"]
            .as_str()
            .expect("item id")
            .starts_with("turn_budget:item:context-compact:"));
        assert!(response["idempotency_key"]
            .as_str()
            .expect("idempotency key")
            .starts_with("thread:thread_budget:context.compact:"));
        assert!(response["receipt_refs"][0]
            .as_str()
            .expect("receipt ref")
            .starts_with("receipt_run_budget_context_compaction_"));
        assert_eq!(
            response["policy_decision_refs"][0],
            "policy_run_budget_context_compaction_allow"
        );
        assert_eq!(response["payload"]["reason"], "trim context");
        assert_eq!(response["payload"]["requested_by"], "operator_one");
        assert_eq!(response["payload"]["previous_latest_seq"], 7);
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
    fn rust_policy_shapes_context_compaction_state_update_command_response() {
        let response = plan_context_compaction_state_update_response(
            ContextCompactionStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: context_compaction_state_update_request(),
            },
        )
        .expect("context compaction state update command response");

        assert_eq!(
            response["source"],
            "rust_context_compaction_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["target_kind"], "run");
        assert_eq!(response["operation_kind"], "thread.compact");
        assert_eq!(response["operator_control"]["event_id"], "event_budget");
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(
            response["run"]["trace"]["contextCompaction"]["event_id"],
            "event_budget"
        );
        assert!(response["run"]["trace"]["contextCompaction"]
            .get("eventId")
            .is_none());
        assert_eq!(
            response["run"]["trace"]["contextCompaction"]["reason"],
            "trim context"
        );
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["control"],
            "compact"
        );
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
}
