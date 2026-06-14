use ioi_types::app::{ActionRequest, ActionTarget, ApprovalAuthority, ApprovalGrant};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf};
use url::Url;

pub const CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-approval-request.v1";
pub const CODING_TOOL_APPROVAL_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-approval-result.v1";
pub const CODING_TOOL_APPROVAL_MANIFEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-approval-manifest.v1";
pub const CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-approval-satisfaction-request.v1";
pub const CODING_TOOL_APPROVAL_SATISFACTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-approval-satisfaction-result.v1";
pub const CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-approval-satisfaction-projection-request.v1";
pub const CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-approval-satisfaction-projection.v1";
pub const CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-approval-block-request.v1";
pub const CODING_TOOL_APPROVAL_BLOCK_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-approval-block-result.v1";
pub const APPROVAL_QUEUE_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.approval-queue-projection-request.v1";
pub const APPROVAL_QUEUE_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.approval-queue-projection.v1";
pub const APPROVAL_DECISION_AUTHORITY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.approval-decision-authority-request.v1";
pub const APPROVAL_DECISION_AUTHORITY_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.approval-decision-authority.v1";
pub const CODING_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-result.v1";
pub const CODING_TOOL_PACK_ID: &str = "ioi.tool_pack.coding";
pub const WORKFLOW_TOOL_APPROVAL_POLICY_SCHEMA_VERSION: &str =
    "ioi.runtime.workflow-tool-approval-policy.v1";
pub const APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.approval-request-state-update-request.v1";
pub const APPROVAL_REQUEST_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.approval-request-state-update.v1";
pub const APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.approval-decision-state-update-request.v1";
pub const APPROVAL_DECISION_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.approval-decision-state-update.v1";
pub const APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.approval-revoke-state-update-request.v1";
pub const APPROVAL_REVOKE_STATE_UPDATE_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.approval-revoke-state-update.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalScopeContext {
    pub target_label: String,
    #[serde(default)]
    pub labels: Vec<String>,
}

impl ApprovalScopeContext {
    pub fn new(target_label: impl Into<String>) -> Self {
        let target_label = target_label.into();
        Self {
            labels: vec![target_label.clone()],
            target_label,
        }
    }

    pub fn from_action_request(request: &ActionRequest) -> Self {
        let mut context = Self::new(request.target.canonical_label());
        context.push_label(format!("target:{}", context.target_label));
        context.push_label(format!("agent:{}", request.context.agent_id));
        if let Some(session_id) = request.context.session_id {
            context.push_label(format!("session:{}", hex::encode(session_id)));
        }
        if let Some(window_id) = request.context.window_id {
            context.push_label(format!("window:{}", window_id));
        }
        context.extend_from_params(&request.target, &request.params);
        context
    }

    pub fn with_operation_label(mut self, label: impl Into<String>) -> Self {
        self.push_label(label);
        self
    }

    pub fn push_label(&mut self, label: impl Into<String>) {
        let label = normalize_scope_label(label.into());
        if !label.is_empty() && !self.labels.iter().any(|existing| existing == &label) {
            self.labels.push(label);
        }
    }

    fn extend_from_params(&mut self, target: &ActionTarget, params: &[u8]) {
        let Ok(value) = serde_json::from_slice::<Value>(params) else {
            return;
        };
        if let Some(tool) = value
            .get("tool_name")
            .or_else(|| value.get("tool"))
            .and_then(Value::as_str)
        {
            self.push_label(format!("tool:{}", tool));
        }
        if let Some(connector) = value
            .get("connector_id")
            .or_else(|| value.get("connector"))
            .and_then(Value::as_str)
        {
            self.push_label(format!("connector:{}", connector));
        }
        for key in ["url", "endpoint", "merchant_url"] {
            if let Some(url) = value.get(key).and_then(Value::as_str) {
                if let Some(host) = host_label(url) {
                    self.push_label(format!("domain:{}", host));
                }
            }
        }
        for key in ["path", "source_path", "destination_path", "cwd"] {
            if let Some(path) = value.get(key).and_then(Value::as_str) {
                self.push_label(format!("path:{}", path));
            }
        }
        if matches!(target, ActionTarget::WalletSend | ActionTarget::WalletSign) {
            self.push_label("wallet_network.approval");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeMatchDecision {
    pub allowed: bool,
    pub matched_scope: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodingToolApprovalError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CodingToolApprovalSatisfactionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CodingToolApprovalSatisfactionProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    RetiredCandidateTransport(&'static str),
    StateDirRequired,
    ReplayReadFailed(String),
    ReplayRecordInvalid(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CodingToolApprovalBlockError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalQueueProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    RetiredCandidateTransport(&'static str),
    StateDirRequired,
    ReplayReadFailed(String),
    ReplayRecordInvalid(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalDecisionAuthorityError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    MissingWalletNetworkAuthority,
    MissingAuthorityReceipt,
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalRequestStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    RetiredCandidateTransport(&'static str),
    StateDirRequired,
    ReplayReadFailed(String),
    ReplayRecordInvalid(String),
    TargetNotFound(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalDecisionStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    RetiredCandidateTransport(&'static str),
    StateDirRequired,
    ReplayReadFailed(String),
    ReplayRecordInvalid(String),
    TargetNotFound(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalRevokeStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    RetiredCandidateTransport(&'static str),
    StateDirRequired,
    ReplayReadFailed(String),
    ReplayRecordInvalid(String),
    TargetNotFound(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalCommandError {
    code: &'static str,
    message: String,
}

impl ApprovalCommandError {
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
pub struct CodingToolApprovalRequest {
    pub schema_version: String,
    pub thread_id: String,
    #[serde(default)]
    pub turn_id: Option<String>,
    pub tool_id: String,
    pub tool_call_id: String,
    #[serde(default)]
    pub effect_class: Option<String>,
    #[serde(default)]
    pub risk_domain: Option<String>,
    #[serde(default)]
    pub authority_scope_requirements: Vec<String>,
    #[serde(default)]
    pub primitive_capabilities: Vec<String>,
    #[serde(default)]
    pub thread_mode: Option<String>,
    #[serde(default)]
    pub approval_mode: Option<String>,
    #[serde(default)]
    pub trust_profile: Option<String>,
    #[serde(default)]
    pub requested_mode: Option<String>,
    #[serde(default)]
    pub normalized_requested_mode: Option<String>,
    #[serde(default)]
    pub requested_approval_mode: Option<String>,
    #[serde(default)]
    pub ui_override_requested: bool,
    #[serde(default)]
    pub workflow_graph_id: Option<String>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    #[serde(default)]
    pub workflow_policy: CodingToolWorkflowApprovalRequest,
    #[serde(default)]
    pub input_summary: Value,
    #[serde(default)]
    pub input: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CodingToolWorkflowApprovalRequest {
    #[serde(default)]
    pub node_approval_override: Option<String>,
    #[serde(default)]
    pub approval_mode: Option<String>,
    #[serde(default)]
    pub trust_profile: Option<String>,
    #[serde(default)]
    pub requires_approval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingToolWorkflowApprovalPolicy {
    pub schema_version: String,
    pub source: String,
    pub requires_approval: bool,
    pub node_approval_override: String,
    pub approval_mode: Option<String>,
    pub trust_profile: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolApprovalManifest {
    pub schema_version: String,
    pub object: String,
    pub action: String,
    pub status: String,
    pub approval_required: bool,
    pub policy_reason: String,
    pub daemon_enforced: bool,
    pub ui_override_ignored: bool,
    pub workflow_policy: CodingToolWorkflowApprovalPolicy,
    pub thread_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    pub tool_id: String,
    pub tool_call_id: String,
    pub effect_class: String,
    pub risk_domain: String,
    pub authority_scope_requirements: Vec<String>,
    pub primitive_capabilities: Vec<String>,
    pub thread_mode: String,
    pub approval_mode: String,
    pub trust_profile: String,
    pub workflow_trust_profile: String,
    pub node_requires_approval: bool,
    pub node_approval_override: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_requested_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_approval_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_graph_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_node_id: Option<String>,
    pub input_summary: Value,
    pub input_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolApprovalPlan {
    pub schema_version: String,
    pub source: String,
    pub approval_required: bool,
    pub workflow_policy: CodingToolWorkflowApprovalPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<CodingToolApprovalManifest>,
    pub input_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolApprovalSatisfactionRequest {
    pub schema_version: String,
    pub thread_id: String,
    #[serde(default)]
    pub approval_id: Option<String>,
    #[serde(default)]
    pub approval_manifest: Value,
    #[serde(default)]
    pub approval_request: Value,
    #[serde(default)]
    pub latest_decision: Value,
    #[serde(default)]
    pub lease_state: Value,
    #[serde(default)]
    pub expected_head: Option<String>,
    #[serde(default)]
    pub state_root_before: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolApprovalSatisfactionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    pub satisfied: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_head: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_root_before: Option<String>,
    pub projection_source: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolApprovalSatisfactionProjectionRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub approval_id: String,
    #[serde(default)]
    pub approval_manifest: Value,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub run: Value,
    #[serde(default)]
    pub agent: Value,
    #[serde(default)]
    pub expected_head: Option<String>,
    #[serde(default)]
    pub state_root_before: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolApprovalSatisfactionProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub approval_id: String,
    pub approval_request: Value,
    pub latest_decision: Value,
    pub lease_state: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_head: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_root_before: Option<String>,
    pub projection_source: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalQueueProjectionRequest {
    pub schema_version: String,
    pub thread_id: String,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub run: Value,
    #[serde(default)]
    pub runs: Vec<Value>,
    #[serde(default)]
    pub agent: Value,
    #[serde(default)]
    pub include_resolved: bool,
    #[serde(default)]
    pub expected_head: Option<String>,
    #[serde(default)]
    pub state_root_before: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalQueueProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub approvals: Vec<Value>,
    pub pending_count: usize,
    pub resolved_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_head: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_root_before: Option<String>,
    pub projection_source: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalDecisionAuthorityRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub approval_id: String,
    pub decision: String,
    #[serde(default)]
    pub target_kind: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub actor_ref: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
    #[serde(default)]
    pub approval_manifest: Value,
    #[serde(default)]
    pub approval_request: Value,
    #[serde(default)]
    pub authority_context: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalDecisionAuthorityRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub approval_id: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub idempotency_key: String,
    pub wallet_network_grant_refs: Vec<String>,
    pub authority_receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub direct_truth_write_allowed: bool,
    pub authority_hash: String,
    pub projection_source: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolApprovalBlockRequest {
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
    pub approval_manifest: Value,
    #[serde(default)]
    pub approval_gate: Value,
    #[serde(default)]
    pub input_summary: Value,
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
pub struct CodingToolApprovalBlockRecord {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    pub reason: String,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub result: Value,
    pub event: Value,
    pub projection_source: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequestStateUpdateRequest {
    pub schema_version: String,
    #[serde(default)]
    pub target_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub agent: Value,
    #[serde(default)]
    pub run: Value,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
    pub approval_id: String,
    pub source: String,
    pub reason: String,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequestStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub target_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub updated_at: String,
    pub operator_control: Value,
    pub run: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalDecisionStateUpdateRequest {
    pub schema_version: String,
    #[serde(default)]
    pub target_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub agent: Value,
    #[serde(default)]
    pub run: Value,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
    pub approval_id: String,
    #[serde(default)]
    pub lease_id: Option<String>,
    pub lease_status: String,
    pub decision: String,
    pub status: String,
    pub source: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
    #[serde(default)]
    pub authority_record: Value,
    #[serde(default)]
    pub authority_hash: Option<String>,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalDecisionStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub target_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub updated_at: String,
    pub operator_control: Value,
    pub run: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<Value>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRevokeStateUpdateRequest {
    pub schema_version: String,
    #[serde(default)]
    pub target_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub agent: Value,
    #[serde(default)]
    pub run: Value,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
    pub approval_id: String,
    #[serde(default)]
    pub lease_id: Option<String>,
    pub source: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
    #[serde(default)]
    pub authority_record: Value,
    #[serde(default)]
    pub authority_hash: Option<String>,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRevokeStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub target_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub updated_at: String,
    pub operator_control: Value,
    pub run: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<Value>,
    pub generated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CodingToolApprovalProtocolRequest {
    pub request: CodingToolApprovalRequest,
}

#[derive(Debug, Deserialize)]
pub struct CodingToolApprovalSatisfactionProtocolRequest {
    pub request: CodingToolApprovalSatisfactionRequest,
}

#[derive(Debug, Deserialize)]
pub struct CodingToolApprovalSatisfactionProjectionProtocolRequest {
    pub request: CodingToolApprovalSatisfactionProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub struct ApprovalQueueProjectionProtocolRequest {
    pub request: ApprovalQueueProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub struct ApprovalDecisionAuthorityProtocolRequest {
    pub request: ApprovalDecisionAuthorityRequest,
}

#[derive(Debug, Deserialize)]
pub struct CodingToolApprovalBlockProtocolRequest {
    pub request: CodingToolApprovalBlockRequest,
}

#[derive(Debug, Deserialize)]
pub struct ApprovalRequestStateUpdateProtocolRequest {
    pub request: ApprovalRequestStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct ApprovalDecisionStateUpdateProtocolRequest {
    pub request: ApprovalDecisionStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct ApprovalRevokeStateUpdateProtocolRequest {
    pub request: ApprovalRevokeStateUpdateRequest,
}

#[derive(Debug, Default, Clone)]
pub struct CodingToolApprovalCore;

#[derive(Debug, Default, Clone)]
pub struct ApprovalRequestStateUpdateCore;

#[derive(Debug, Default, Clone)]
pub struct ApprovalDecisionStateUpdateCore;

#[derive(Debug, Default, Clone)]
pub struct ApprovalRevokeStateUpdateCore;

#[derive(Debug, Default, Clone)]
pub struct CodingToolApprovalSatisfactionCore;

#[derive(Debug, Default, Clone)]
pub struct CodingToolApprovalSatisfactionProjectionCore;

#[derive(Debug, Default, Clone)]
pub struct ApprovalQueueProjectionCore;

#[derive(Debug, Default, Clone)]
pub struct ApprovalDecisionAuthorityCore;

#[derive(Debug, Default, Clone)]
pub struct CodingToolApprovalBlockCore;

impl ApprovalRequestStateUpdateCore {
    pub fn plan(
        &self,
        request: &ApprovalRequestStateUpdateRequest,
    ) -> Result<ApprovalRequestStateUpdateRecord, ApprovalRequestStateUpdateError> {
        request.validate()?;
        let target_kind = approval_state_update_target_kind(request.target_kind.as_deref());
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let requested_run_id = optional_trimmed(request.run_id.as_deref());
        let target = approval_state_update_target_from_state_dir(
            request.state_dir.as_deref(),
            &target_kind,
            thread_id.as_deref(),
            requested_run_id.as_deref(),
        )
        .map_err(approval_request_state_update_replay_error)?;
        let run_id = target.run_id.clone();
        let source = optional_trimmed(Some(request.source.as_str()))
            .unwrap_or_else(|| "sdk_client".to_string());
        let reason = optional_trimmed(Some(request.reason.as_str()))
            .unwrap_or_else(|| "operator requested approval".to_string());
        let approval_id = optional_trimmed(Some(request.approval_id.as_str())).unwrap();
        let operator_control = json!({
            "control": "approval_request",
            "approval_id": approval_id,
            "status": "waiting_for_approval",
            "source": source,
            "reason": reason,
            "event_id": request.event_id,
            "seq": request.seq,
            "receipt_refs": request.receipt_refs.clone(),
            "policy_decision_refs": request.policy_decision_refs.clone(),
            "created_at": request.created_at,
        });
        let (run, agent) = if target_kind == "run" {
            let mut run = object_value(&target.run)
                .ok_or(ApprovalRequestStateUpdateError::MissingField("run"))?;
            let prior_status = run
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            run.insert(
                "updatedAt".to_string(),
                Value::String(request.created_at.clone()),
            );
            run.insert(
                "turnStatus".to_string(),
                Value::String("waiting_for_approval".to_string()),
            );
            if matches!(prior_status.as_str(), "queued" | "running") {
                run.insert("status".to_string(), Value::String("blocked".to_string()));
            }
            let mut trace = run.get("trace").and_then(object_value).unwrap_or_default();
            trace.insert(
                "operatorControls".to_string(),
                append_operator_control(trace.get("operatorControls"), &operator_control),
            );
            trace.insert(
                "approvalRequests".to_string(),
                append_operator_control(trace.get("approvalRequests"), &operator_control),
            );
            run.insert("trace".to_string(), Value::Object(trace));
            run.insert(
                "operatorControls".to_string(),
                append_operator_control(run.get("operatorControls"), &operator_control),
            );
            run.insert(
                "approvalRequests".to_string(),
                append_operator_control(run.get("approvalRequests"), &operator_control),
            );
            (Value::Object(run), None)
        } else {
            let mut agent = target
                .agent
                .as_ref()
                .and_then(object_value)
                .ok_or(ApprovalRequestStateUpdateError::MissingField("agent"))?;
            agent.insert(
                "updatedAt".to_string(),
                Value::String(request.created_at.clone()),
            );
            (Value::Null, Some(Value::Object(agent)))
        };

        Ok(ApprovalRequestStateUpdateRecord {
            schema_version: APPROVAL_REQUEST_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_approval_request_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "approval.required".to_string(),
            target_kind,
            thread_id,
            run_id,
            updated_at: request.created_at.clone(),
            operator_control,
            run,
            agent,
            generated_at: "rust_authority_core".to_string(),
        })
    }
}

impl ApprovalDecisionStateUpdateCore {
    pub fn plan(
        &self,
        request: &ApprovalDecisionStateUpdateRequest,
    ) -> Result<ApprovalDecisionStateUpdateRecord, ApprovalDecisionStateUpdateError> {
        request.validate()?;
        let target_kind = approval_state_update_target_kind(request.target_kind.as_deref());
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let requested_run_id = optional_trimmed(request.run_id.as_deref());
        let target = approval_state_update_target_from_state_dir(
            request.state_dir.as_deref(),
            &target_kind,
            thread_id.as_deref(),
            requested_run_id.as_deref(),
        )
        .map_err(approval_decision_state_update_replay_error)?;
        let run_id = target.run_id.clone();
        let source = optional_trimmed(Some(request.source.as_str()))
            .unwrap_or_else(|| "sdk_client".to_string());
        let approval_id = optional_trimmed(Some(request.approval_id.as_str())).unwrap();
        let lease_id = optional_trimmed(request.lease_id.as_deref());
        let lease_status = optional_trimmed(Some(request.lease_status.as_str())).unwrap();
        let decision = normalized_approval_decision(Some(request.decision.as_str())).unwrap();
        let status = optional_trimmed(Some(request.status.as_str())).unwrap();
        let reason = optional_trimmed(request.reason.as_deref());
        let authority_record = authority_record_value(&request.authority_record);
        let authority_hash =
            approval_authority_hash(request.authority_hash.as_deref(), &authority_record);
        let authority_grant_refs =
            approval_authority_grant_refs(&request.authority_grant_refs, &authority_record);
        let authority_receipt_refs =
            approval_authority_receipt_refs(&request.authority_receipt_refs, &authority_record);
        let receipt_refs = unique_trimmed_values(
            request
                .receipt_refs
                .iter()
                .cloned()
                .chain(authority_receipt_refs.iter().cloned())
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let policy_decision_refs = approval_authority_policy_decision_refs(
            &request.policy_decision_refs,
            &authority_record,
        );
        let operator_control = json!({
            "control": "approval_decision",
            "approval_id": approval_id,
            "lease_id": lease_id,
            "lease_status": lease_status,
            "decision": decision,
            "status": status,
            "source": source,
            "reason": reason,
            "event_id": request.event_id,
            "seq": request.seq,
            "receipt_refs": receipt_refs,
            "policy_decision_refs": policy_decision_refs,
            "authority": authority_record,
            "authority_hash": authority_hash,
            "authority_grant_refs": authority_grant_refs,
            "authority_receipt_refs": authority_receipt_refs,
            "created_at": request.created_at,
        });
        let (run, agent) = if target_kind == "run" {
            let mut run = object_value(&target.run)
                .ok_or(ApprovalDecisionStateUpdateError::MissingField("run"))?;
            run.insert(
                "updatedAt".to_string(),
                Value::String(request.created_at.clone()),
            );
            if decision == "reject" {
                run.insert(
                    "turnStatus".to_string(),
                    Value::String("waiting_for_input".to_string()),
                );
            }
            let mut trace = run.get("trace").and_then(object_value).unwrap_or_default();
            trace.insert(
                "operatorControls".to_string(),
                append_operator_control(trace.get("operatorControls"), &operator_control),
            );
            trace.insert(
                "approvalDecisions".to_string(),
                append_operator_control(trace.get("approvalDecisions"), &operator_control),
            );
            run.insert("trace".to_string(), Value::Object(trace));
            run.insert(
                "operatorControls".to_string(),
                append_operator_control(run.get("operatorControls"), &operator_control),
            );
            run.insert(
                "approvalDecisions".to_string(),
                append_operator_control(run.get("approvalDecisions"), &operator_control),
            );
            (Value::Object(run), None)
        } else {
            let mut agent = target
                .agent
                .as_ref()
                .and_then(object_value)
                .ok_or(ApprovalDecisionStateUpdateError::MissingField("agent"))?;
            agent.insert(
                "updatedAt".to_string(),
                Value::String(request.created_at.clone()),
            );
            (Value::Null, Some(Value::Object(agent)))
        };

        Ok(ApprovalDecisionStateUpdateRecord {
            schema_version: APPROVAL_DECISION_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_approval_decision_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: format!("approval.{decision}"),
            target_kind,
            thread_id,
            run_id,
            updated_at: request.created_at.clone(),
            operator_control,
            run,
            agent,
            generated_at: "rust_authority_core".to_string(),
        })
    }
}

impl ApprovalRevokeStateUpdateCore {
    pub fn plan(
        &self,
        request: &ApprovalRevokeStateUpdateRequest,
    ) -> Result<ApprovalRevokeStateUpdateRecord, ApprovalRevokeStateUpdateError> {
        request.validate()?;
        let target_kind = approval_state_update_target_kind(request.target_kind.as_deref());
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let requested_run_id = optional_trimmed(request.run_id.as_deref());
        let target = approval_state_update_target_from_state_dir(
            request.state_dir.as_deref(),
            &target_kind,
            thread_id.as_deref(),
            requested_run_id.as_deref(),
        )
        .map_err(approval_revoke_state_update_replay_error)?;
        let run_id = target.run_id.clone();
        let source = optional_trimmed(Some(request.source.as_str()))
            .unwrap_or_else(|| "sdk_client".to_string());
        let approval_id = optional_trimmed(Some(request.approval_id.as_str())).unwrap();
        let lease_id = optional_trimmed(request.lease_id.as_deref());
        let reason = optional_trimmed(request.reason.as_deref());
        let authority_record = authority_record_value(&request.authority_record);
        let authority_hash =
            approval_authority_hash(request.authority_hash.as_deref(), &authority_record);
        let authority_grant_refs =
            approval_authority_grant_refs(&request.authority_grant_refs, &authority_record);
        let authority_receipt_refs =
            approval_authority_receipt_refs(&request.authority_receipt_refs, &authority_record);
        let receipt_refs = unique_trimmed_values(
            request
                .receipt_refs
                .iter()
                .cloned()
                .chain(authority_receipt_refs.iter().cloned())
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let policy_decision_refs = approval_authority_policy_decision_refs(
            &request.policy_decision_refs,
            &authority_record,
        );
        let operator_control = json!({
            "control": "approval_revoke",
            "approval_id": approval_id,
            "lease_id": lease_id,
            "lease_status": "revoked",
            "decision": "revoke",
            "status": "revoked",
            "source": source,
            "reason": reason,
            "event_id": request.event_id,
            "seq": request.seq,
            "receipt_refs": receipt_refs,
            "policy_decision_refs": policy_decision_refs,
            "authority": authority_record,
            "authority_hash": authority_hash,
            "authority_grant_refs": authority_grant_refs,
            "authority_receipt_refs": authority_receipt_refs,
            "created_at": request.created_at,
        });
        let (run, agent) = if target_kind == "run" {
            let mut run = object_value(&target.run)
                .ok_or(ApprovalRevokeStateUpdateError::MissingField("run"))?;
            run.insert(
                "updatedAt".to_string(),
                Value::String(request.created_at.clone()),
            );
            run.insert(
                "turnStatus".to_string(),
                Value::String("waiting_for_input".to_string()),
            );
            let mut trace = run.get("trace").and_then(object_value).unwrap_or_default();
            trace.insert(
                "operatorControls".to_string(),
                append_operator_control(trace.get("operatorControls"), &operator_control),
            );
            trace.insert(
                "approvalDecisions".to_string(),
                append_operator_control(trace.get("approvalDecisions"), &operator_control),
            );
            trace.insert(
                "approvalRevocations".to_string(),
                append_operator_control(trace.get("approvalRevocations"), &operator_control),
            );
            run.insert("trace".to_string(), Value::Object(trace));
            run.insert(
                "operatorControls".to_string(),
                append_operator_control(run.get("operatorControls"), &operator_control),
            );
            run.insert(
                "approvalDecisions".to_string(),
                append_operator_control(run.get("approvalDecisions"), &operator_control),
            );
            run.insert(
                "approvalRevocations".to_string(),
                append_operator_control(run.get("approvalRevocations"), &operator_control),
            );
            (Value::Object(run), None)
        } else {
            let mut agent = target
                .agent
                .as_ref()
                .and_then(object_value)
                .ok_or(ApprovalRevokeStateUpdateError::MissingField("agent"))?;
            agent.insert(
                "updatedAt".to_string(),
                Value::String(request.created_at.clone()),
            );
            (Value::Null, Some(Value::Object(agent)))
        };

        Ok(ApprovalRevokeStateUpdateRecord {
            schema_version: APPROVAL_REVOKE_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_approval_revoke_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "approval.revoke".to_string(),
            target_kind,
            thread_id,
            run_id,
            updated_at: request.created_at.clone(),
            operator_control,
            run,
            agent,
            generated_at: "rust_authority_core".to_string(),
        })
    }
}

impl CodingToolApprovalCore {
    pub fn plan_manifest(
        &self,
        request: &CodingToolApprovalRequest,
    ) -> Result<CodingToolApprovalPlan, CodingToolApprovalError> {
        request.validate()?;
        let effect_class = normalized_string(request.effect_class.as_deref(), "unknown");
        let risk_domain = normalized_string(request.risk_domain.as_deref(), "unknown");
        let thread_mode = normalized_string(request.thread_mode.as_deref(), "agent");
        let approval_mode = normalized_string(request.approval_mode.as_deref(), "suggest");
        let trust_profile = normalized_string(request.trust_profile.as_deref(), "local_private");
        let workflow_policy = workflow_approval_policy(&request.workflow_policy);
        let input_hash = value_hash(&request.input)?;

        if effect_class.eq_ignore_ascii_case("local_read") {
            return Ok(CodingToolApprovalPlan {
                schema_version: CODING_TOOL_APPROVAL_RESULT_SCHEMA_VERSION.to_string(),
                source: "rust_authority_coding_tool_approval_core".to_string(),
                approval_required: false,
                workflow_policy,
                manifest: None,
                input_hash,
            });
        }

        let mode_requires_approval = thread_mode == "plan" || thread_mode == "review";
        let approval_mode_requires_approval =
            approval_mode == "human_required" || approval_mode == "policy_required";
        let requested_approval_mode = optional_trimmed(request.requested_approval_mode.as_deref())
            .or_else(|| workflow_policy.approval_mode.clone());
        let workflow_approval_mode_requires_approval = requested_approval_mode
            .as_deref()
            .map(|mode| mode == "human_required" || mode == "policy_required")
            .unwrap_or(false);
        let approval_required = mode_requires_approval
            || approval_mode_requires_approval
            || workflow_policy.requires_approval
            || workflow_approval_mode_requires_approval;

        if !approval_required {
            return Ok(CodingToolApprovalPlan {
                schema_version: CODING_TOOL_APPROVAL_RESULT_SCHEMA_VERSION.to_string(),
                source: "rust_authority_coding_tool_approval_core".to_string(),
                approval_required: false,
                workflow_policy,
                manifest: None,
                input_hash,
            });
        }

        let requested_mode = optional_trimmed(request.requested_mode.as_deref());
        let normalized_requested_mode =
            optional_trimmed(request.normalized_requested_mode.as_deref()).or_else(|| {
                requested_mode
                    .as_deref()
                    .map(|mode| mode.to_ascii_lowercase().replace('-', "_"))
            });
        let policy_reason = if mode_requires_approval {
            if thread_mode == "review" {
                "thread_review_mode_requires_approval".to_string()
            } else {
                "thread_plan_mode_requires_approval".to_string()
            }
        } else if approval_mode_requires_approval {
            format!("approval_mode_{approval_mode}_requires_approval")
        } else {
            workflow_policy.reason.clone()
        };
        let ui_override_ignored = request.ui_override_requested
            || requested_approval_mode
                .as_deref()
                .map(|mode| mode != approval_mode)
                .unwrap_or(false)
            || normalized_requested_mode
                .as_deref()
                .map(|mode| mode != thread_mode)
                .unwrap_or(false);

        let manifest = CodingToolApprovalManifest {
            schema_version: CODING_TOOL_APPROVAL_MANIFEST_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_coding_tool_approval_manifest".to_string(),
            action: "coding_tool.invoke".to_string(),
            status: "approval_required".to_string(),
            approval_required: true,
            policy_reason,
            daemon_enforced: true,
            ui_override_ignored,
            workflow_policy: workflow_policy.clone(),
            thread_id: request.thread_id.trim().to_string(),
            turn_id: optional_trimmed(request.turn_id.as_deref()),
            tool_id: request.tool_id.trim().to_string(),
            tool_call_id: request.tool_call_id.trim().to_string(),
            effect_class,
            risk_domain,
            authority_scope_requirements: unique_trimmed(&request.authority_scope_requirements),
            primitive_capabilities: unique_trimmed(&request.primitive_capabilities),
            thread_mode: thread_mode.clone(),
            approval_mode,
            trust_profile,
            workflow_trust_profile: workflow_policy.trust_profile.clone(),
            node_requires_approval: workflow_policy.requires_approval,
            node_approval_override: workflow_policy.node_approval_override.clone(),
            requested_mode,
            normalized_requested_mode,
            requested_approval_mode,
            workflow_graph_id: optional_trimmed(request.workflow_graph_id.as_deref()),
            workflow_node_id: optional_trimmed(request.workflow_node_id.as_deref()),
            input_summary: request.input_summary.clone(),
            input_hash: input_hash.clone(),
        };

        Ok(CodingToolApprovalPlan {
            schema_version: CODING_TOOL_APPROVAL_RESULT_SCHEMA_VERSION.to_string(),
            source: "rust_authority_coding_tool_approval_core".to_string(),
            approval_required: true,
            workflow_policy,
            manifest: Some(manifest),
            input_hash,
        })
    }
}

impl CodingToolApprovalSatisfactionProjectionCore {
    pub fn project(
        &self,
        request: &CodingToolApprovalSatisfactionProjectionRequest,
    ) -> Result<
        CodingToolApprovalSatisfactionProjectionRecord,
        CodingToolApprovalSatisfactionProjectionError,
    > {
        request.validate()?;
        reject_approval_satisfaction_candidate_transport(request)?;
        let thread_id = optional_trimmed(Some(request.thread_id.as_str())).unwrap();
        let approval_id = optional_trimmed(Some(request.approval_id.as_str())).unwrap();
        let sources =
            approval_satisfaction_projection_sources_from_state_dir(request.state_dir.as_deref())?;
        let approval_request =
            latest_approval_projection_request(&sources, &thread_id, approval_id.as_str())
                .map(|record| {
                    approval_request_projection_value(
                        record,
                        thread_id.as_str(),
                        approval_id.as_str(),
                        &request.approval_manifest,
                    )
                })
                .unwrap_or(Value::Null);
        let latest_decision =
            latest_approval_projection_decision(&sources, &thread_id, approval_id.as_str())
                .map(|record| {
                    approval_decision_projection_value(
                        record,
                        thread_id.as_str(),
                        approval_id.as_str(),
                    )
                })
                .unwrap_or(Value::Null);
        let lease_state = approval_projection_lease_state(&latest_decision);

        Ok(CodingToolApprovalSatisfactionProjectionRecord {
            schema_version: CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_RESULT_SCHEMA_VERSION
                .to_string(),
            object: "ioi.runtime_coding_tool_approval_satisfaction_projection".to_string(),
            status: "projected".to_string(),
            operation_kind: "coding_tool.approval.satisfaction_projection".to_string(),
            thread_id,
            approval_id,
            approval_request,
            latest_decision,
            lease_state,
            expected_head: optional_trimmed(request.expected_head.as_deref()),
            state_root_before: optional_trimmed(request.state_root_before.as_deref()),
            projection_source: "rust_daemon_core_approval_projection".to_string(),
            generated_at: "rust_authority_core".to_string(),
        })
    }
}

impl ApprovalQueueProjectionCore {
    pub fn project(
        &self,
        request: &ApprovalQueueProjectionRequest,
    ) -> Result<ApprovalQueueProjectionRecord, ApprovalQueueProjectionError> {
        request.validate()?;
        reject_approval_queue_candidate_transport(request)?;
        let thread_id = optional_trimmed(Some(request.thread_id.as_str())).unwrap();
        let sources =
            approval_queue_projection_sources_from_state_dir(request.state_dir.as_deref())?;
        let request_records = approval_projection_candidates_from_sources(
            &sources,
            &thread_id,
            &["approvalRequests"],
            &["approval_request"],
            "approval.required",
        );
        let decision_records = approval_projection_candidates_from_sources(
            &sources,
            &thread_id,
            &["approvalDecisions", "approvalRevocations"],
            &["approval_decision", "approval_revoke"],
            "approval.decision",
        );
        let mut latest_requests: BTreeMap<String, (u64, usize, Value)> = BTreeMap::new();
        for (index, record) in request_records.into_iter().enumerate() {
            let Some(approval_id) = value_string(&record, "approval_id") else {
                continue;
            };
            if !approval_record_matches_thread(&record, &thread_id) {
                continue;
            }
            let seq = approval_projection_seq(&record);
            let replace = latest_requests
                .get(&approval_id)
                .map(|(latest_seq, latest_index, _)| {
                    seq > *latest_seq || (seq == *latest_seq && index >= *latest_index)
                })
                .unwrap_or(true);
            if replace {
                latest_requests.insert(approval_id, (seq, index, record));
            }
        }

        let mut approvals = Vec::new();
        let mut pending_count = 0usize;
        let mut resolved_count = 0usize;
        for (approval_id, (_, _, approval_request)) in latest_requests {
            let latest_decision = latest_approval_queue_decision(
                &decision_records,
                approval_id.as_str(),
                approval_projection_seq(&approval_request),
                &thread_id,
            )
            .unwrap_or(Value::Null);
            let status = approval_queue_status(&latest_decision);
            if status == "pending" {
                pending_count += 1;
            } else {
                resolved_count += 1;
            }
            if status != "pending" && !request.include_resolved {
                continue;
            }
            approvals.push(approval_queue_entry(
                &thread_id,
                approval_id.as_str(),
                approval_request,
                latest_decision,
                status,
            ));
        }

        Ok(ApprovalQueueProjectionRecord {
            schema_version: APPROVAL_QUEUE_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_approval_queue_projection".to_string(),
            status: "projected".to_string(),
            operation_kind: "approval.queue_projection".to_string(),
            thread_id,
            approvals,
            pending_count,
            resolved_count,
            expected_head: optional_trimmed(request.expected_head.as_deref()),
            state_root_before: optional_trimmed(request.state_root_before.as_deref()),
            projection_source: "rust_daemon_core_approval_queue_projection".to_string(),
            generated_at: "rust_authority_core".to_string(),
        })
    }
}

impl ApprovalDecisionAuthorityCore {
    pub fn authorize(
        &self,
        request: &ApprovalDecisionAuthorityRequest,
    ) -> Result<ApprovalDecisionAuthorityRecord, ApprovalDecisionAuthorityError> {
        request.validate()?;
        let thread_id = optional_trimmed(Some(request.thread_id.as_str())).unwrap();
        let approval_id = optional_trimmed(Some(request.approval_id.as_str())).unwrap();
        let decision =
            normalized_approval_control_decision(Some(request.decision.as_str())).unwrap();
        let wallet_network_grant_refs = unique_trimmed_values(
            request
                .authority_grant_refs
                .iter()
                .filter(|grant_ref| is_wallet_network_grant_ref(grant_ref))
                .cloned()
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let authority_receipt_refs = unique_trimmed(&request.authority_receipt_refs);
        let policy_decision_refs = unique_trimmed(&request.policy_decision_refs);
        let idempotency_key = optional_trimmed(request.idempotency_key.as_deref())
            .unwrap_or_else(|| format!("approval:{thread_id}:{approval_id}:{decision}"));
        let mut record = ApprovalDecisionAuthorityRecord {
            schema_version: APPROVAL_DECISION_AUTHORITY_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_approval_decision_authority".to_string(),
            status: "authorized".to_string(),
            operation_kind: "approval.decision.authority".to_string(),
            thread_id,
            approval_id,
            decision,
            target_kind: optional_trimmed(request.target_kind.as_deref()),
            run_id: optional_trimmed(request.run_id.as_deref()),
            actor_ref: optional_trimmed(request.actor_ref.as_deref()),
            source: optional_trimmed(request.source.as_deref()),
            idempotency_key,
            wallet_network_grant_refs,
            authority_receipt_refs,
            policy_decision_refs,
            direct_truth_write_allowed: false,
            authority_hash: String::new(),
            projection_source: "rust_daemon_core_wallet_network_approval_authority".to_string(),
            generated_at: "rust_authority_core".to_string(),
        };
        record.authority_hash = approval_decision_authority_hash(&record)?;
        Ok(record)
    }
}

impl CodingToolApprovalSatisfactionCore {
    pub fn plan(
        &self,
        request: &CodingToolApprovalSatisfactionRequest,
    ) -> Result<CodingToolApprovalSatisfactionRecord, CodingToolApprovalSatisfactionError> {
        request.validate()?;
        let thread_id = optional_trimmed(Some(request.thread_id.as_str())).unwrap();
        let approval_id = optional_trimmed(request.approval_id.as_deref());
        let expected_head = optional_trimmed(request.expected_head.as_deref());
        let state_root_before = optional_trimmed(request.state_root_before.as_deref());

        let Some(approval_id_value) = approval_id.clone() else {
            return Ok(approval_satisfaction_record(
                thread_id,
                None,
                false,
                "approval_id_missing",
                &Value::Null,
                &request.lease_state,
                Vec::new(),
                Vec::new(),
                expected_head,
                state_root_before,
            ));
        };

        if !request.approval_request.is_object() {
            return Ok(approval_satisfaction_record(
                thread_id,
                Some(approval_id_value),
                false,
                "approval_request_missing",
                &Value::Null,
                &request.lease_state,
                Vec::new(),
                Vec::new(),
                expected_head,
                state_root_before,
            ));
        }

        let requested_approval_id = value_string(&request.approval_request, "approval_id");
        if requested_approval_id.as_deref() != Some(approval_id_value.as_str()) {
            return Ok(approval_satisfaction_record(
                thread_id,
                Some(approval_id_value),
                false,
                "approval_request_mismatch",
                &Value::Null,
                &request.lease_state,
                approval_receipt_refs(&request.approval_request, &Value::Null),
                approval_policy_decision_refs(&request.approval_request, &Value::Null),
                expected_head,
                state_root_before,
            ));
        }

        if let Some(request_thread_id) = value_string(&request.approval_request, "thread_id") {
            if request_thread_id != thread_id {
                return Ok(approval_satisfaction_record(
                    thread_id,
                    Some(approval_id_value),
                    false,
                    "approval_request_thread_mismatch",
                    &Value::Null,
                    &request.lease_state,
                    approval_receipt_refs(&request.approval_request, &Value::Null),
                    approval_policy_decision_refs(&request.approval_request, &Value::Null),
                    expected_head,
                    state_root_before,
                ));
            }
        }

        if !approval_manifests_satisfy(
            request
                .approval_request
                .get("payload_summary")
                .and_then(|payload| payload.get("approval_manifest"))
                .unwrap_or(&Value::Null),
            &request.approval_manifest,
        ) {
            return Ok(approval_satisfaction_record(
                thread_id,
                Some(approval_id_value),
                false,
                "approval_manifest_mismatch",
                &Value::Null,
                &request.lease_state,
                approval_receipt_refs(&request.approval_request, &Value::Null),
                approval_policy_decision_refs(&request.approval_request, &Value::Null),
                expected_head,
                state_root_before,
            ));
        }

        if !request.latest_decision.is_object() {
            return Ok(approval_satisfaction_record(
                thread_id,
                Some(approval_id_value),
                false,
                "approval_decision_missing",
                &Value::Null,
                &request.lease_state,
                approval_receipt_refs(&request.approval_request, &Value::Null),
                approval_policy_decision_refs(&request.approval_request, &Value::Null),
                expected_head,
                state_root_before,
            ));
        }

        if value_string(&request.latest_decision, "approval_id").as_deref()
            != Some(approval_id_value.as_str())
        {
            return Ok(approval_satisfaction_record(
                thread_id,
                Some(approval_id_value),
                false,
                "approval_decision_mismatch",
                &request.latest_decision,
                &request.lease_state,
                approval_receipt_refs(&request.approval_request, &request.latest_decision),
                approval_policy_decision_refs(&request.approval_request, &request.latest_decision),
                expected_head,
                state_root_before,
            ));
        }

        let request_seq = value_u64(&request.approval_request, "seq");
        let decision_seq = value_u64(&request.latest_decision, "seq");
        if request_seq.is_some() && decision_seq.is_some() && decision_seq <= request_seq {
            return Ok(approval_satisfaction_record(
                thread_id,
                Some(approval_id_value),
                false,
                "approval_decision_not_after_request",
                &request.latest_decision,
                &request.lease_state,
                approval_receipt_refs(&request.approval_request, &request.latest_decision),
                approval_policy_decision_refs(&request.approval_request, &request.latest_decision),
                expected_head,
                state_root_before,
            ));
        }

        let decision_kind = value_string(&request.latest_decision, "event_kind")
            .or_else(|| value_string(&request.latest_decision, "decision"))
            .or_else(|| value_string(&request.latest_decision, "status"))
            .unwrap_or_default();
        let normalized_decision = decision_kind.to_ascii_lowercase();
        if normalized_decision != "approval.approved"
            && normalized_decision != "approve"
            && normalized_decision != "approved"
        {
            let reason = approval_event_reason(&request.latest_decision).unwrap_or_else(|| {
                if normalized_decision.contains("revok") {
                    "approval_revoked".to_string()
                } else {
                    "approval_rejected".to_string()
                }
            });
            return Ok(approval_satisfaction_record(
                thread_id,
                Some(approval_id_value),
                false,
                reason,
                &request.latest_decision,
                &request.lease_state,
                approval_receipt_refs(&request.approval_request, &request.latest_decision),
                approval_policy_decision_refs(&request.approval_request, &request.latest_decision),
                expected_head,
                state_root_before,
            ));
        }

        if approval_lease_expired(&request.lease_state) {
            return Ok(approval_satisfaction_record(
                thread_id,
                Some(approval_id_value),
                false,
                "approval_lease_expired",
                &request.latest_decision,
                &request.lease_state,
                approval_receipt_refs(&request.approval_request, &request.latest_decision),
                approval_policy_decision_refs(&request.approval_request, &request.latest_decision),
                expected_head,
                state_root_before,
            ));
        }

        Ok(approval_satisfaction_record(
            thread_id,
            Some(approval_id_value),
            true,
            approval_event_reason(&request.latest_decision)
                .unwrap_or_else(|| "approval_approved".to_string()),
            &request.latest_decision,
            &request.lease_state,
            approval_receipt_refs(&request.approval_request, &request.latest_decision),
            approval_policy_decision_refs(&request.approval_request, &request.latest_decision),
            expected_head,
            state_root_before,
        ))
    }
}

impl CodingToolApprovalBlockCore {
    pub fn plan(
        &self,
        request: &CodingToolApprovalBlockRequest,
    ) -> Result<CodingToolApprovalBlockRecord, CodingToolApprovalBlockError> {
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
        let approval_id = value_string(&request.approval_gate, "approval_id");
        let reason = value_string(&request.approval_gate, "reason")
            .unwrap_or_else(|| "approval_not_satisfied".to_string());
        let receipt_id = optional_trimmed(request.receipt_id.as_deref()).unwrap_or_else(|| {
            format!(
                "receipt_coding_tool_approval_block_{}_{}",
                safe_id(&tool_id),
                short_sha256_hex(&format!("{thread_id}:{tool_id}:{tool_call_id}"), 12)
            )
        });
        let idempotency_key = optional_trimmed(request.idempotency_key.as_deref())
            .unwrap_or_else(|| format!("thread:{thread_id}:coding-tool:{tool_call_id}"));
        let receipt_refs = unique_trimmed_values(
            request
                .receipt_refs
                .iter()
                .cloned()
                .chain(array_strings(&request.approval_gate, "receipt_refs"))
                .chain(std::iter::once(receipt_id.clone()))
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let policy_decision_refs = unique_trimmed_values(
            request
                .policy_decision_refs
                .iter()
                .cloned()
                .chain(array_strings(
                    &request.approval_gate,
                    "policy_decision_refs",
                ))
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let artifact_refs = unique_trimmed(&request.artifact_refs);
        let rollback_refs = unique_trimmed(&request.rollback_refs);
        let error = json!({
            "code": "coding_tool_approval_required",
            "message": "Coding tool execution is blocked until Rust authority records a satisfied approval.",
            "details": {
                "thread_id": thread_id,
                "turn_id": turn_id,
                "tool_id": tool_id,
                "tool_call_id": tool_call_id,
                "workflow_graph_id": workflow_graph_id,
                "workflow_node_id": workflow_node_id,
                "approval_id": approval_id,
                "reason": reason,
            }
        });
        let result = json!({
            "schema_version": CODING_TOOL_RESULT_SCHEMA_VERSION,
            "tool_name": tool_id,
            "status": "blocked",
            "blocked": true,
            "reason": reason,
            "approval_required": true,
            "approval_satisfied": false,
            "approval_id": approval_id,
            "approval_manifest": request.approval_manifest.clone(),
            "approval_gate": request.approval_gate.clone(),
            "error": error.clone(),
            "receipt_refs": receipt_refs.clone(),
            "policy_decision_refs": policy_decision_refs.clone(),
            "artifact_refs": artifact_refs.clone(),
            "shell_fallback_used": false,
            "rust_authority_block": true,
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
            "summary": "Coding tool blocked pending approval.",
            "shell_fallback_used": false,
            "input_summary": request.input_summary.clone(),
            "result_summary": {
                "status": "blocked",
                "reason": reason,
                "approval_id": approval_id,
            },
            "result": result.clone(),
            "error": error,
            "rollback_refs": rollback_refs.clone(),
            "approval_required": true,
            "approval_satisfied": false,
            "approval_id": approval_id,
            "approval_manifest": request.approval_manifest.clone(),
            "approval_gate": request.approval_gate.clone(),
            "approval_decision_event_id": value_string(&request.approval_gate, "decision_event_id"),
            "approval_receipt_refs": receipt_refs.clone(),
            "approval_policy_decision_refs": policy_decision_refs.clone(),
            "receipt_id": receipt_id,
            "receipt_count": receipt_refs.len(),
            "artifact_count": artifact_refs.len(),
            "step_module_backend": Value::Null,
            "step_module_invocation": Value::Null,
            "step_module_result": Value::Null,
            "step_module_error": Value::Null,
            "rust_authority_block": true,
        });
        let event = json!({
            "event_stream_id": event_stream_id,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "item_id": item_id,
            "idempotency_key": idempotency_key,
            "source": source,
            "source_event_kind": "coding_tool.approval.blocked",
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

        Ok(CodingToolApprovalBlockRecord {
            schema_version: CODING_TOOL_APPROVAL_BLOCK_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_coding_tool_approval_block".to_string(),
            status: "blocked".to_string(),
            operation_kind: "coding_tool.approval.block".to_string(),
            thread_id,
            turn_id,
            tool_id,
            tool_call_id,
            workflow_graph_id,
            workflow_node_id,
            approval_id,
            reason,
            receipt_refs,
            policy_decision_refs,
            artifact_refs,
            rollback_refs,
            result,
            event,
            projection_source: "rust_daemon_core_coding_tool_approval_block".to_string(),
            generated_at: "rust_authority_core".to_string(),
        })
    }
}

pub fn plan_coding_tool_approval_manifest_protocol_response(
    request: CodingToolApprovalProtocolRequest,
) -> Result<Value, ApprovalCommandError> {
    let plan = CodingToolApprovalCore
        .plan_manifest(&request.request)
        .map_err(|error| {
            ApprovalCommandError::new(
                "coding_tool_approval_manifest_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_coding_tool_approval_protocol",
        "backend": "rust_authority",
        "plan": plan.clone(),
        "approval_required": plan.approval_required,
        "workflow_policy": plan.workflow_policy.clone(),
        "manifest": plan.manifest.clone(),
        "input_hash": plan.input_hash.clone(),
    }))
}

pub fn plan_coding_tool_approval_satisfaction_protocol_response(
    request: CodingToolApprovalSatisfactionProtocolRequest,
) -> Result<Value, ApprovalCommandError> {
    let record = CodingToolApprovalSatisfactionCore
        .plan(&request.request)
        .map_err(|error| {
            ApprovalCommandError::new(
                "coding_tool_approval_satisfaction_invalid",
                format!("{error:?}"),
            )
        })?;
    let record_value = serde_json::to_value(record.clone()).unwrap_or(Value::Null);
    Ok(json!({
        "source": "rust_coding_tool_approval_satisfaction_protocol",
        "backend": "rust_authority",
        "record": record_value,
        "status": record.status,
        "operation_kind": record.operation_kind,
        "satisfied": record.satisfied,
        "approval_id": record.approval_id,
        "decision_event_id": record.decision_event_id,
        "decision_seq": record.decision_seq,
        "lease_id": record.lease_id,
        "expires_at": record.expires_at,
        "reason": record.reason,
        "receipt_refs": record.receipt_refs,
        "policy_decision_refs": record.policy_decision_refs,
        "expected_head": record.expected_head,
        "state_root_before": record.state_root_before,
    }))
}

pub fn project_coding_tool_approval_satisfaction_protocol_response(
    request: CodingToolApprovalSatisfactionProjectionProtocolRequest,
) -> Result<Value, ApprovalCommandError> {
    let record = CodingToolApprovalSatisfactionProjectionCore
        .project(&request.request)
        .map_err(|error| {
            ApprovalCommandError::new(
                "coding_tool_approval_satisfaction_projection_invalid",
                format!("{error:?}"),
            )
        })?;
    let record_value = serde_json::to_value(record.clone()).unwrap_or(Value::Null);
    Ok(json!({
        "source": "rust_coding_tool_approval_satisfaction_projection_protocol",
        "backend": "rust_authority",
        "record": record_value,
        "status": record.status,
        "operation_kind": record.operation_kind,
        "thread_id": record.thread_id,
        "approval_id": record.approval_id,
        "approval_request": record.approval_request,
        "latest_decision": record.latest_decision,
        "lease_state": record.lease_state,
        "expected_head": record.expected_head,
        "state_root_before": record.state_root_before,
    }))
}

pub fn project_approval_queue_protocol_response(
    request: ApprovalQueueProjectionProtocolRequest,
) -> Result<Value, ApprovalCommandError> {
    let record = ApprovalQueueProjectionCore
        .project(&request.request)
        .map_err(|error| {
            ApprovalCommandError::new("approval_queue_projection_invalid", format!("{error:?}"))
        })?;
    let record_value = serde_json::to_value(record.clone()).unwrap_or(Value::Null);
    Ok(json!({
        "source": "rust_approval_queue_projection_protocol",
        "backend": "rust_authority",
        "record": record_value,
        "status": record.status,
        "operation_kind": record.operation_kind,
        "thread_id": record.thread_id,
        "approvals": record.approvals,
        "pending_count": record.pending_count,
        "resolved_count": record.resolved_count,
        "expected_head": record.expected_head,
        "state_root_before": record.state_root_before,
    }))
}

pub fn authorize_approval_decision_protocol_response(
    request: ApprovalDecisionAuthorityProtocolRequest,
) -> Result<Value, ApprovalCommandError> {
    let record = ApprovalDecisionAuthorityCore
        .authorize(&request.request)
        .map_err(|error| {
            ApprovalCommandError::new("approval_decision_authority_invalid", format!("{error:?}"))
        })?;
    let record_value = serde_json::to_value(record.clone()).unwrap_or(Value::Null);
    Ok(json!({
        "schema_version": APPROVAL_DECISION_AUTHORITY_RESULT_SCHEMA_VERSION,
        "object": "ioi.runtime_approval_decision_authority",
        "status": record.status,
        "operation_kind": record.operation_kind,
        "source": "rust_approval_decision_authority_protocol",
        "backend": "rust_authority",
        "record": record_value,
        "authority": record.clone(),
        "thread_id": record.thread_id,
        "approval_id": record.approval_id,
        "decision": record.decision,
        "target_kind": record.target_kind,
        "run_id": record.run_id,
        "actor_ref": record.actor_ref,
        "idempotency_key": record.idempotency_key,
        "wallet_network_grant_refs": record.wallet_network_grant_refs,
        "authority_receipt_refs": record.authority_receipt_refs,
        "policy_decision_refs": record.policy_decision_refs,
        "direct_truth_write_allowed": record.direct_truth_write_allowed,
        "authority_hash": record.authority_hash,
    }))
}

pub fn plan_coding_tool_approval_block_protocol_response(
    request: CodingToolApprovalBlockProtocolRequest,
) -> Result<Value, ApprovalCommandError> {
    let record = CodingToolApprovalBlockCore
        .plan(&request.request)
        .map_err(|error| {
            ApprovalCommandError::new("coding_tool_approval_block_invalid", format!("{error:?}"))
        })?;
    let record_value = serde_json::to_value(record.clone()).unwrap_or(Value::Null);
    Ok(json!({
        "source": "rust_coding_tool_approval_block_protocol",
        "backend": "rust_authority",
        "record": record_value,
        "status": record.status,
        "operation_kind": record.operation_kind,
        "thread_id": record.thread_id,
        "turn_id": record.turn_id,
        "tool_id": record.tool_id,
        "tool_call_id": record.tool_call_id,
        "workflow_graph_id": record.workflow_graph_id,
        "workflow_node_id": record.workflow_node_id,
        "approval_id": record.approval_id,
        "reason": record.reason,
        "receipt_refs": record.receipt_refs,
        "policy_decision_refs": record.policy_decision_refs,
        "artifact_refs": record.artifact_refs,
        "rollback_refs": record.rollback_refs,
        "result": record.result,
        "event": record.event,
    }))
}

pub fn plan_approval_request_state_update_protocol_response(
    request: ApprovalRequestStateUpdateProtocolRequest,
) -> Result<Value, ApprovalCommandError> {
    let record = ApprovalRequestStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            ApprovalCommandError::new(
                "approval_request_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(state_update_response(
        "rust_approval_request_state_update_protocol",
        record,
    ))
}

pub fn plan_approval_decision_state_update_protocol_response(
    request: ApprovalDecisionStateUpdateProtocolRequest,
) -> Result<Value, ApprovalCommandError> {
    let record = ApprovalDecisionStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            ApprovalCommandError::new(
                "approval_decision_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(state_update_response(
        "rust_approval_decision_state_update_protocol",
        record,
    ))
}

pub fn plan_approval_revoke_state_update_protocol_response(
    request: ApprovalRevokeStateUpdateProtocolRequest,
) -> Result<Value, ApprovalCommandError> {
    let record = ApprovalRevokeStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            ApprovalCommandError::new("approval_revoke_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(state_update_response(
        "rust_approval_revoke_state_update_protocol",
        record,
    ))
}

fn state_update_response<T>(source: &'static str, record: T) -> Value
where
    T: Serialize + Clone,
{
    let record_value = serde_json::to_value(record.clone()).unwrap_or(Value::Null);
    json!({
        "source": source,
        "backend": "rust_authority",
        "record": record_value.clone(),
        "status": record_value.get("status").cloned().unwrap_or(Value::Null),
        "operation_kind": record_value.get("operation_kind").cloned().unwrap_or(Value::Null),
        "target_kind": record_value.get("target_kind").cloned().unwrap_or(Value::Null),
        "updated_at": record_value.get("updated_at").cloned().unwrap_or(Value::Null),
        "operator_control": record_value
            .get("operator_control")
            .cloned()
            .unwrap_or(Value::Null),
        "run": record_value.get("run").cloned().unwrap_or(Value::Null),
        "agent": record_value.get("agent").cloned().unwrap_or(Value::Null),
    })
}

impl CodingToolApprovalRequest {
    pub fn validate(&self) -> Result<(), CodingToolApprovalError> {
        if self.schema_version != CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION {
            return Err(CodingToolApprovalError::InvalidSchemaVersion {
                expected: CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_coding_tool_field("thread_id", &self.thread_id)?;
        require_coding_tool_field("tool_id", &self.tool_id)?;
        require_coding_tool_field("tool_call_id", &self.tool_call_id)?;
        Ok(())
    }
}

impl CodingToolApprovalSatisfactionRequest {
    pub fn validate(&self) -> Result<(), CodingToolApprovalSatisfactionError> {
        if self.schema_version != CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION {
            return Err(CodingToolApprovalSatisfactionError::InvalidSchemaVersion {
                expected: CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(CodingToolApprovalSatisfactionError::MissingField(
                "thread_id",
            ));
        }
        if !self.approval_manifest.is_object() {
            return Err(CodingToolApprovalSatisfactionError::MissingField(
                "approval_manifest",
            ));
        }
        Ok(())
    }
}

impl CodingToolApprovalSatisfactionProjectionRequest {
    pub fn validate(&self) -> Result<(), CodingToolApprovalSatisfactionProjectionError> {
        if self.schema_version
            != CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION
        {
            return Err(
                CodingToolApprovalSatisfactionProjectionError::InvalidSchemaVersion {
                    expected: CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(CodingToolApprovalSatisfactionProjectionError::MissingField(
                "thread_id",
            ));
        }
        if optional_trimmed(Some(self.approval_id.as_str())).is_none() {
            return Err(CodingToolApprovalSatisfactionProjectionError::MissingField(
                "approval_id",
            ));
        }
        if !self.approval_manifest.is_object() {
            return Err(CodingToolApprovalSatisfactionProjectionError::MissingField(
                "approval_manifest",
            ));
        }
        Ok(())
    }
}

impl ApprovalQueueProjectionRequest {
    pub fn validate(&self) -> Result<(), ApprovalQueueProjectionError> {
        if self.schema_version != APPROVAL_QUEUE_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(ApprovalQueueProjectionError::InvalidSchemaVersion {
                expected: APPROVAL_QUEUE_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(ApprovalQueueProjectionError::MissingField("thread_id"));
        }
        Ok(())
    }
}

impl ApprovalDecisionAuthorityRequest {
    pub fn validate(&self) -> Result<(), ApprovalDecisionAuthorityError> {
        if self.schema_version != APPROVAL_DECISION_AUTHORITY_REQUEST_SCHEMA_VERSION {
            return Err(ApprovalDecisionAuthorityError::InvalidSchemaVersion {
                expected: APPROVAL_DECISION_AUTHORITY_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(ApprovalDecisionAuthorityError::MissingField("thread_id"));
        }
        if optional_trimmed(Some(self.approval_id.as_str())).is_none() {
            return Err(ApprovalDecisionAuthorityError::MissingField("approval_id"));
        }
        if normalized_approval_control_decision(Some(self.decision.as_str())).is_none() {
            return Err(ApprovalDecisionAuthorityError::MissingField("decision"));
        }
        if self
            .authority_grant_refs
            .iter()
            .all(|grant_ref| !is_wallet_network_grant_ref(grant_ref))
        {
            return Err(ApprovalDecisionAuthorityError::MissingWalletNetworkAuthority);
        }
        if unique_trimmed(&self.authority_receipt_refs).is_empty() {
            return Err(ApprovalDecisionAuthorityError::MissingAuthorityReceipt);
        }
        Ok(())
    }
}

impl CodingToolApprovalBlockRequest {
    pub fn validate(&self) -> Result<(), CodingToolApprovalBlockError> {
        if self.schema_version != CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION {
            return Err(CodingToolApprovalBlockError::InvalidSchemaVersion {
                expected: CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_coding_tool_approval_block_field("thread_id", &self.thread_id)?;
        require_coding_tool_approval_block_field("tool_id", &self.tool_id)?;
        require_coding_tool_approval_block_field("tool_call_id", &self.tool_call_id)?;
        if !self.approval_manifest.is_object() {
            return Err(CodingToolApprovalBlockError::MissingField(
                "approval_manifest",
            ));
        }
        if !self.approval_gate.is_object() {
            return Err(CodingToolApprovalBlockError::MissingField("approval_gate"));
        }
        Ok(())
    }
}

impl ApprovalRequestStateUpdateRequest {
    pub fn validate(&self) -> Result<(), ApprovalRequestStateUpdateError> {
        if self.schema_version != APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(ApprovalRequestStateUpdateError::InvalidSchemaVersion {
                expected: APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if !self.run.is_null() {
            return Err(ApprovalRequestStateUpdateError::RetiredCandidateTransport(
                "run",
            ));
        }
        if !self.agent.is_null() {
            return Err(ApprovalRequestStateUpdateError::RetiredCandidateTransport(
                "agent",
            ));
        }
        if optional_trimmed(self.state_dir.as_deref()).is_none() {
            return Err(ApprovalRequestStateUpdateError::StateDirRequired);
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(ApprovalRequestStateUpdateError::MissingField("event_id"));
        }
        if self.seq == 0 {
            return Err(ApprovalRequestStateUpdateError::MissingField("seq"));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(ApprovalRequestStateUpdateError::MissingField("created_at"));
        }
        if optional_trimmed(Some(self.approval_id.as_str())).is_none() {
            return Err(ApprovalRequestStateUpdateError::MissingField("approval_id"));
        }
        Ok(())
    }
}

impl ApprovalDecisionStateUpdateRequest {
    pub fn validate(&self) -> Result<(), ApprovalDecisionStateUpdateError> {
        if self.schema_version != APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(ApprovalDecisionStateUpdateError::InvalidSchemaVersion {
                expected: APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if !self.run.is_null() {
            return Err(ApprovalDecisionStateUpdateError::RetiredCandidateTransport(
                "run",
            ));
        }
        if !self.agent.is_null() {
            return Err(ApprovalDecisionStateUpdateError::RetiredCandidateTransport(
                "agent",
            ));
        }
        if optional_trimmed(self.state_dir.as_deref()).is_none() {
            return Err(ApprovalDecisionStateUpdateError::StateDirRequired);
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(ApprovalDecisionStateUpdateError::MissingField("event_id"));
        }
        if self.seq == 0 {
            return Err(ApprovalDecisionStateUpdateError::MissingField("seq"));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(ApprovalDecisionStateUpdateError::MissingField("created_at"));
        }
        if optional_trimmed(Some(self.approval_id.as_str())).is_none() {
            return Err(ApprovalDecisionStateUpdateError::MissingField(
                "approval_id",
            ));
        }
        if normalized_approval_decision(Some(self.decision.as_str())).is_none() {
            return Err(ApprovalDecisionStateUpdateError::MissingField("decision"));
        }
        if optional_trimmed(Some(self.lease_status.as_str())).is_none() {
            return Err(ApprovalDecisionStateUpdateError::MissingField(
                "lease_status",
            ));
        }
        if optional_trimmed(Some(self.status.as_str())).is_none() {
            return Err(ApprovalDecisionStateUpdateError::MissingField("status"));
        }
        if !approval_authority_state_binding_present(
            &self.authority_record,
            self.authority_hash.as_deref(),
            &self.authority_grant_refs,
            &self.authority_receipt_refs,
        ) {
            return Err(ApprovalDecisionStateUpdateError::MissingField(
                "authority_record",
            ));
        }
        Ok(())
    }
}

impl ApprovalRevokeStateUpdateRequest {
    pub fn validate(&self) -> Result<(), ApprovalRevokeStateUpdateError> {
        if self.schema_version != APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(ApprovalRevokeStateUpdateError::InvalidSchemaVersion {
                expected: APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if !self.run.is_null() {
            return Err(ApprovalRevokeStateUpdateError::RetiredCandidateTransport(
                "run",
            ));
        }
        if !self.agent.is_null() {
            return Err(ApprovalRevokeStateUpdateError::RetiredCandidateTransport(
                "agent",
            ));
        }
        if optional_trimmed(self.state_dir.as_deref()).is_none() {
            return Err(ApprovalRevokeStateUpdateError::StateDirRequired);
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(ApprovalRevokeStateUpdateError::MissingField("event_id"));
        }
        if self.seq == 0 {
            return Err(ApprovalRevokeStateUpdateError::MissingField("seq"));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(ApprovalRevokeStateUpdateError::MissingField("created_at"));
        }
        if optional_trimmed(Some(self.approval_id.as_str())).is_none() {
            return Err(ApprovalRevokeStateUpdateError::MissingField("approval_id"));
        }
        if !approval_authority_state_binding_present(
            &self.authority_record,
            self.authority_hash.as_deref(),
            &self.authority_grant_refs,
            &self.authority_receipt_refs,
        ) {
            return Err(ApprovalRevokeStateUpdateError::MissingField(
                "authority_record",
            ));
        }
        Ok(())
    }
}

pub struct AuthorityScopeMatcher;

impl AuthorityScopeMatcher {
    pub fn evaluate(
        authority: &ApprovalAuthority,
        context: &ApprovalScopeContext,
    ) -> ScopeMatchDecision {
        if authority.scope_allowlist.is_empty() {
            return ScopeMatchDecision {
                allowed: false,
                matched_scope: None,
                reason: Some("approval_authority_scope_allowlist_empty".to_string()),
            };
        }

        for scope in &authority.scope_allowlist {
            let normalized_scope = normalize_scope_label(scope);
            if normalized_scope == "*" {
                return ScopeMatchDecision {
                    allowed: true,
                    matched_scope: Some(scope.clone()),
                    reason: None,
                };
            }
            if context
                .labels
                .iter()
                .any(|label| scope_pattern_matches(&normalized_scope, label))
            {
                return ScopeMatchDecision {
                    allowed: true,
                    matched_scope: Some(scope.clone()),
                    reason: None,
                };
            }
        }

        ScopeMatchDecision {
            allowed: false,
            matched_scope: None,
            reason: Some(format!(
                "approval_grant_out_of_scope:target={}",
                context.target_label
            )),
        }
    }

    pub fn validate(
        authority: &ApprovalAuthority,
        context: &ApprovalScopeContext,
    ) -> Result<(), String> {
        let decision = Self::evaluate(authority, context);
        if decision.allowed {
            Ok(())
        } else {
            Err(decision
                .reason
                .unwrap_or_else(|| "approval_grant_out_of_scope".to_string()))
        }
    }

    pub fn validate_grant_for_request(
        authority: &ApprovalAuthority,
        grant: &ApprovalGrant,
        request: &ActionRequest,
        operation_label: &str,
    ) -> Result<(), String> {
        if grant.window_id.is_some() && grant.window_id != request.context.window_id {
            return Err("approval_grant_window_scope_mismatch".to_string());
        }
        let context = ApprovalScopeContext::from_action_request(request)
            .with_operation_label(operation_label.to_string());
        Self::validate(authority, &context)
    }
}

fn normalize_scope_label(label: impl AsRef<str>) -> String {
    label.as_ref().trim().to_ascii_lowercase()
}

fn scope_pattern_matches(pattern: &str, label: &str) -> bool {
    if pattern == label {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("::*") {
        return label.starts_with(&format!("{}::", prefix));
    }
    if let Some(prefix) = pattern.strip_suffix(":*") {
        return label.starts_with(&format!("{}:", prefix));
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return label.starts_with(prefix);
    }
    false
}

fn host_label(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Url::parse(trimmed)
        .or_else(|_| Url::parse(&format!("https://{}", trimmed)))
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_ascii_lowercase()))
}

fn workflow_approval_policy(
    request: &CodingToolWorkflowApprovalRequest,
) -> CodingToolWorkflowApprovalPolicy {
    let node_approval_override =
        normalized_string(request.node_approval_override.as_deref(), "inherit");
    let approval_mode = optional_trimmed(request.approval_mode.as_deref());
    let trust_profile = normalized_string(request.trust_profile.as_deref(), "local_private");
    let node_requires_approval = node_approval_override == "require_approval";
    let approval_mode_requires_approval = approval_mode
        .as_deref()
        .map(|mode| mode == "human_required" || mode == "policy_required")
        .unwrap_or(false);
    let trust_requires_approval = matches!(
        trust_profile.as_str(),
        "untrusted" | "restricted" | "review_required"
    );
    let requires_approval = request.requires_approval
        || node_requires_approval
        || approval_mode_requires_approval
        || trust_requires_approval;
    let reason = if request.requires_approval || node_requires_approval {
        "workflow_node_requires_approval"
    } else if approval_mode_requires_approval {
        "workflow_approval_mode_requires_approval"
    } else if trust_requires_approval {
        "workflow_trust_profile_requires_approval"
    } else {
        "workflow_approval_mode_requires_approval"
    };

    CodingToolWorkflowApprovalPolicy {
        schema_version: WORKFLOW_TOOL_APPROVAL_POLICY_SCHEMA_VERSION.to_string(),
        source: "react_flow".to_string(),
        requires_approval,
        node_approval_override,
        approval_mode,
        trust_profile,
        reason: reason.to_string(),
    }
}

fn normalized_string(value: Option<&str>, fallback: &str) -> String {
    optional_trimmed(value)
        .unwrap_or_else(|| fallback.to_string())
        .to_ascii_lowercase()
        .replace('-', "_")
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn normalized_approval_decision(value: Option<&str>) -> Option<String> {
    match optional_trimmed(value)?.to_ascii_lowercase().as_str() {
        "approve" => Some("approve".to_string()),
        "reject" => Some("reject".to_string()),
        _ => None,
    }
}

fn normalized_approval_control_decision(value: Option<&str>) -> Option<String> {
    match optional_trimmed(value)?.to_ascii_lowercase().as_str() {
        "approve" | "approved" => Some("approve".to_string()),
        "reject" | "rejected" | "deny" | "denied" => Some("reject".to_string()),
        "revoke" | "revoked" => Some("revoke".to_string()),
        _ => None,
    }
}

fn is_wallet_network_grant_ref(grant_ref: &str) -> bool {
    let normalized = grant_ref.trim().to_ascii_lowercase();
    normalized.starts_with("wallet.network://grant/")
        || normalized.starts_with("grant://wallet.network/")
        || normalized.starts_with("wallet-network://grant/")
}

fn approval_decision_authority_hash(
    record: &ApprovalDecisionAuthorityRecord,
) -> Result<String, ApprovalDecisionAuthorityError> {
    let mut canonical = record.clone();
    canonical.authority_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| ApprovalDecisionAuthorityError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn authority_record_value(value: &Value) -> Value {
    if value.is_object() {
        value.clone()
    } else {
        Value::Null
    }
}

fn approval_authority_hash(request_hash: Option<&str>, authority_record: &Value) -> Option<String> {
    optional_trimmed(request_hash).or_else(|| value_string(authority_record, "authority_hash"))
}

fn approval_authority_grant_refs(request_refs: &[String], authority_record: &Value) -> Vec<String> {
    unique_trimmed_values(
        request_refs
            .iter()
            .cloned()
            .chain(array_strings(authority_record, "wallet_network_grant_refs"))
            .chain(array_strings(authority_record, "authority_grant_refs"))
            .collect::<Vec<_>>()
            .as_slice(),
    )
}

fn approval_authority_receipt_refs(
    request_refs: &[String],
    authority_record: &Value,
) -> Vec<String> {
    unique_trimmed_values(
        request_refs
            .iter()
            .cloned()
            .chain(array_strings(authority_record, "authority_receipt_refs"))
            .collect::<Vec<_>>()
            .as_slice(),
    )
}

fn approval_authority_policy_decision_refs(
    request_refs: &[String],
    authority_record: &Value,
) -> Vec<String> {
    unique_trimmed_values(
        request_refs
            .iter()
            .cloned()
            .chain(array_strings(authority_record, "policy_decision_refs"))
            .collect::<Vec<_>>()
            .as_slice(),
    )
}

fn approval_authority_state_binding_present(
    authority_record: &Value,
    authority_hash: Option<&str>,
    authority_grant_refs: &[String],
    authority_receipt_refs: &[String],
) -> bool {
    approval_authority_hash(authority_hash, authority_record).is_some()
        && approval_authority_grant_refs(authority_grant_refs, authority_record)
            .iter()
            .any(|grant_ref| is_wallet_network_grant_ref(grant_ref))
        && !approval_authority_receipt_refs(authority_receipt_refs, authority_record).is_empty()
}

fn approval_state_update_target_kind(value: Option<&str>) -> String {
    match optional_trimmed(value).as_deref() {
        Some("agent") => "agent".to_string(),
        Some("run") => "run".to_string(),
        _ => "run".to_string(),
    }
}

fn object_value(value: &Value) -> Option<serde_json::Map<String, Value>> {
    value.as_object().cloned()
}

fn append_operator_control(existing: Option<&Value>, control: &Value) -> Value {
    let control_event_id = control.get("event_id").and_then(Value::as_str);
    let mut entries = existing
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let exists = control_event_id.is_some_and(|event_id| {
        entries
            .iter()
            .any(|entry| entry.get("event_id").and_then(Value::as_str) == Some(event_id))
    });
    if !exists {
        entries.push(control.clone());
    }
    Value::Array(entries)
}

fn latest_approval_projection_request(
    sources: &ApprovalProjectionSources,
    thread_id: &str,
    approval_id: &str,
) -> Option<Value> {
    latest_approval_projection_record(
        approval_projection_candidates_from_sources(
            sources,
            thread_id,
            &["approvalRequests"],
            &["approval_request"],
            "approval.required",
        ),
        approval_id,
    )
}

fn latest_approval_projection_decision(
    sources: &ApprovalProjectionSources,
    thread_id: &str,
    approval_id: &str,
) -> Option<Value> {
    latest_approval_projection_record(
        approval_projection_candidates_from_sources(
            sources,
            thread_id,
            &["approvalDecisions", "approvalRevocations"],
            &["approval_decision", "approval_revoke"],
            "approval.decision",
        ),
        approval_id,
    )
}

fn append_approval_projection_source(
    records: &mut Vec<Value>,
    source: &Value,
    array_names: &[&str],
    control_names: &[&str],
) {
    append_approval_projection_container(records, source, array_names, control_names);
    if let Some(trace) = source.get("trace") {
        append_approval_projection_container(records, trace, array_names, control_names);
    }
}

fn append_approval_projection_container(
    records: &mut Vec<Value>,
    container: &Value,
    array_names: &[&str],
    control_names: &[&str],
) {
    for array_name in array_names {
        if let Some(items) = container.get(*array_name).and_then(Value::as_array) {
            records.extend(items.iter().filter(|item| item.is_object()).cloned());
        }
    }
    if let Some(items) = container.get("operatorControls").and_then(Value::as_array) {
        records.extend(items.iter().filter_map(|item| {
            let control = value_string(item, "control")?;
            if control_names.iter().any(|candidate| control == *candidate) {
                Some(item.clone())
            } else {
                None
            }
        }));
    }
}

fn latest_approval_projection_record(records: Vec<Value>, approval_id: &str) -> Option<Value> {
    let mut latest: Option<(u64, usize, Value)> = None;
    for (index, record) in records.into_iter().enumerate() {
        if value_string(&record, "approval_id").as_deref() != Some(approval_id) {
            continue;
        }
        let seq = approval_projection_seq(&record);
        let should_replace = latest
            .as_ref()
            .map(|(latest_seq, latest_index, _)| {
                seq > *latest_seq || (seq == *latest_seq && index >= *latest_index)
            })
            .unwrap_or(true);
        if should_replace {
            latest = Some((seq, index, record));
        }
    }
    latest.map(|(_, _, record)| record)
}

fn approval_projection_seq(record: &Value) -> u64 {
    value_u64(record, "seq")
        .or_else(|| {
            record
                .get("seq")
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<u64>().ok())
        })
        .unwrap_or(0)
}

fn approval_request_projection_value(
    value: Value,
    thread_id: &str,
    approval_id: &str,
    approval_manifest: &Value,
) -> Value {
    let mut record = object_value(&value).unwrap_or_default();
    insert_missing_string(&mut record, "thread_id", thread_id);
    insert_missing_string(&mut record, "approval_id", approval_id);
    insert_missing_string(&mut record, "event_kind", "approval.required");
    let mut payload = record
        .get("payload_summary")
        .and_then(object_value)
        .unwrap_or_default();
    if !payload.contains_key("approval_manifest") {
        payload.insert("approval_manifest".to_string(), approval_manifest.clone());
    }
    record.insert("payload_summary".to_string(), Value::Object(payload));
    Value::Object(record)
}

fn approval_decision_projection_value(value: Value, thread_id: &str, approval_id: &str) -> Value {
    let mut record = object_value(&value).unwrap_or_default();
    insert_missing_string(&mut record, "thread_id", thread_id);
    insert_missing_string(&mut record, "approval_id", approval_id);
    if !map_has_non_empty_string(&record, "event_kind") {
        record.insert(
            "event_kind".to_string(),
            Value::String(approval_decision_event_kind(&Value::Object(record.clone()))),
        );
    }
    Value::Object(record)
}

fn approval_decision_event_kind(record: &Value) -> String {
    let control = value_string(record, "control")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let decision = value_string(record, "decision")
        .or_else(|| value_string(record, "status"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    if control.contains("revoke") || decision.contains("revoke") || decision == "revoked" {
        "approval.revoked".to_string()
    } else if decision == "approve" || decision == "approved" || decision == "active" {
        "approval.approved".to_string()
    } else if decision == "reject" || decision == "rejected" || decision == "denied" {
        "approval.rejected".to_string()
    } else {
        "approval.decision".to_string()
    }
}

fn approval_projection_lease_state(latest_decision: &Value) -> Value {
    if !latest_decision.is_object() {
        return Value::Null;
    }
    let lease_status = value_string(latest_decision, "lease_status")
        .or_else(|| value_string(latest_decision, "status"))
        .unwrap_or_else(|| "unknown".to_string());
    let normalized_status = lease_status.to_ascii_lowercase();
    let expired = matches!(
        normalized_status.as_str(),
        "expired" | "revoked" | "rejected" | "denied"
    );
    json!({
        "approval_id": value_string(latest_decision, "approval_id"),
        "decision_event_id": value_string(latest_decision, "event_id"),
        "decision_seq": value_u64(latest_decision, "seq"),
        "lease_id": value_string(latest_decision, "lease_id"),
        "lease_status": lease_status,
        "status": lease_status,
        "expires_at": value_string(latest_decision, "expires_at"),
        "expired": expired,
    })
}

struct ApprovalProjectionSources {
    agents: Vec<Value>,
    runs: Vec<Value>,
}

fn reject_approval_satisfaction_candidate_transport(
    request: &CodingToolApprovalSatisfactionProjectionRequest,
) -> Result<(), CodingToolApprovalSatisfactionProjectionError> {
    if !request.agent.is_null() {
        return Err(
            CodingToolApprovalSatisfactionProjectionError::RetiredCandidateTransport("agent"),
        );
    }
    if !request.run.is_null() {
        return Err(
            CodingToolApprovalSatisfactionProjectionError::RetiredCandidateTransport("run"),
        );
    }
    Ok(())
}

fn reject_approval_queue_candidate_transport(
    request: &ApprovalQueueProjectionRequest,
) -> Result<(), ApprovalQueueProjectionError> {
    if !request.agent.is_null() {
        return Err(ApprovalQueueProjectionError::RetiredCandidateTransport(
            "agent",
        ));
    }
    if !request.run.is_null() {
        return Err(ApprovalQueueProjectionError::RetiredCandidateTransport(
            "run",
        ));
    }
    if !request.runs.is_empty() {
        return Err(ApprovalQueueProjectionError::RetiredCandidateTransport(
            "runs",
        ));
    }
    Ok(())
}

fn approval_queue_projection_sources_from_state_dir(
    state_dir: Option<&str>,
) -> Result<ApprovalProjectionSources, ApprovalQueueProjectionError> {
    let state_root = approval_queue_projection_state_root(state_dir)?;
    Ok(ApprovalProjectionSources {
        agents: approval_queue_state_dir_records(state_root.join("agents"), "agents")?,
        runs: approval_queue_state_dir_records(state_root.join("runs"), "runs")?,
    })
}

fn approval_satisfaction_projection_sources_from_state_dir(
    state_dir: Option<&str>,
) -> Result<ApprovalProjectionSources, CodingToolApprovalSatisfactionProjectionError> {
    let state_root = approval_satisfaction_projection_state_root(state_dir)?;
    Ok(ApprovalProjectionSources {
        agents: approval_satisfaction_state_dir_records(state_root.join("agents"), "agents")?,
        runs: approval_satisfaction_state_dir_records(state_root.join("runs"), "runs")?,
    })
}

fn approval_queue_projection_state_root(
    state_dir: Option<&str>,
) -> Result<PathBuf, ApprovalQueueProjectionError> {
    optional_trimmed(state_dir)
        .map(PathBuf::from)
        .ok_or(ApprovalQueueProjectionError::StateDirRequired)
}

fn approval_satisfaction_projection_state_root(
    state_dir: Option<&str>,
) -> Result<PathBuf, CodingToolApprovalSatisfactionProjectionError> {
    optional_trimmed(state_dir)
        .map(PathBuf::from)
        .ok_or(CodingToolApprovalSatisfactionProjectionError::StateDirRequired)
}

fn approval_queue_state_dir_records(
    dir: PathBuf,
    label: &'static str,
) -> Result<Vec<Value>, ApprovalQueueProjectionError> {
    approval_state_dir_records(dir, label, "approval queue").map_err(|error| match error {
        ApprovalProjectionReplayError::ReadFailed(message) => {
            ApprovalQueueProjectionError::ReplayReadFailed(message)
        }
        ApprovalProjectionReplayError::RecordInvalid(message) => {
            ApprovalQueueProjectionError::ReplayRecordInvalid(message)
        }
    })
}

fn approval_satisfaction_state_dir_records(
    dir: PathBuf,
    label: &'static str,
) -> Result<Vec<Value>, CodingToolApprovalSatisfactionProjectionError> {
    approval_state_dir_records(dir, label, "approval satisfaction").map_err(|error| match error {
        ApprovalProjectionReplayError::ReadFailed(message) => {
            CodingToolApprovalSatisfactionProjectionError::ReplayReadFailed(message)
        }
        ApprovalProjectionReplayError::RecordInvalid(message) => {
            CodingToolApprovalSatisfactionProjectionError::ReplayRecordInvalid(message)
        }
    })
}

enum ApprovalProjectionReplayError {
    ReadFailed(String),
    RecordInvalid(String),
}

enum ApprovalStateUpdateReplayError {
    StateDirRequired,
    ReadFailed(String),
    RecordInvalid(String),
    TargetNotFound(&'static str),
}

struct ApprovalStateUpdateTarget {
    run: Value,
    agent: Option<Value>,
    run_id: Option<String>,
}

fn approval_request_state_update_replay_error(
    error: ApprovalStateUpdateReplayError,
) -> ApprovalRequestStateUpdateError {
    match error {
        ApprovalStateUpdateReplayError::StateDirRequired => {
            ApprovalRequestStateUpdateError::StateDirRequired
        }
        ApprovalStateUpdateReplayError::ReadFailed(message) => {
            ApprovalRequestStateUpdateError::ReplayReadFailed(message)
        }
        ApprovalStateUpdateReplayError::RecordInvalid(message) => {
            ApprovalRequestStateUpdateError::ReplayRecordInvalid(message)
        }
        ApprovalStateUpdateReplayError::TargetNotFound(kind) => {
            ApprovalRequestStateUpdateError::TargetNotFound(kind)
        }
    }
}

fn approval_decision_state_update_replay_error(
    error: ApprovalStateUpdateReplayError,
) -> ApprovalDecisionStateUpdateError {
    match error {
        ApprovalStateUpdateReplayError::StateDirRequired => {
            ApprovalDecisionStateUpdateError::StateDirRequired
        }
        ApprovalStateUpdateReplayError::ReadFailed(message) => {
            ApprovalDecisionStateUpdateError::ReplayReadFailed(message)
        }
        ApprovalStateUpdateReplayError::RecordInvalid(message) => {
            ApprovalDecisionStateUpdateError::ReplayRecordInvalid(message)
        }
        ApprovalStateUpdateReplayError::TargetNotFound(kind) => {
            ApprovalDecisionStateUpdateError::TargetNotFound(kind)
        }
    }
}

fn approval_revoke_state_update_replay_error(
    error: ApprovalStateUpdateReplayError,
) -> ApprovalRevokeStateUpdateError {
    match error {
        ApprovalStateUpdateReplayError::StateDirRequired => {
            ApprovalRevokeStateUpdateError::StateDirRequired
        }
        ApprovalStateUpdateReplayError::ReadFailed(message) => {
            ApprovalRevokeStateUpdateError::ReplayReadFailed(message)
        }
        ApprovalStateUpdateReplayError::RecordInvalid(message) => {
            ApprovalRevokeStateUpdateError::ReplayRecordInvalid(message)
        }
        ApprovalStateUpdateReplayError::TargetNotFound(kind) => {
            ApprovalRevokeStateUpdateError::TargetNotFound(kind)
        }
    }
}

fn approval_state_update_target_from_state_dir(
    state_dir: Option<&str>,
    target_kind: &str,
    thread_id: Option<&str>,
    run_id: Option<&str>,
) -> Result<ApprovalStateUpdateTarget, ApprovalStateUpdateReplayError> {
    let sources = approval_state_update_sources_from_state_dir(state_dir)?;
    if target_kind == "agent" {
        let thread_id = thread_id.ok_or(ApprovalStateUpdateReplayError::TargetNotFound("agent"))?;
        let agent = sources
            .agents
            .into_iter()
            .find(|agent| approval_state_update_agent_matches_thread(agent, thread_id))
            .ok_or(ApprovalStateUpdateReplayError::TargetNotFound("agent"))?;
        return Ok(ApprovalStateUpdateTarget {
            run: Value::Null,
            agent: Some(agent),
            run_id: None,
        });
    }
    let run = if let Some(run_id) = run_id {
        sources.runs.into_iter().find(|run| {
            approval_state_update_run_id(run).as_deref() == Some(run_id)
                && thread_id
                    .map(|thread_id| approval_state_update_run_matches_thread(run, thread_id))
                    .unwrap_or(true)
        })
    } else {
        let thread_id = thread_id.ok_or(ApprovalStateUpdateReplayError::TargetNotFound("run"))?;
        sources
            .runs
            .into_iter()
            .filter(|run| approval_state_update_run_matches_thread(run, thread_id))
            .enumerate()
            .max_by(|(left_index, left), (right_index, right)| {
                approval_state_update_run_sort_key(left)
                    .cmp(&approval_state_update_run_sort_key(right))
                    .then_with(|| left_index.cmp(right_index))
            })
            .map(|(_, run)| run)
    }
    .ok_or(ApprovalStateUpdateReplayError::TargetNotFound("run"))?;
    let run_id = approval_state_update_run_id(&run);
    Ok(ApprovalStateUpdateTarget {
        run,
        agent: None,
        run_id,
    })
}

fn approval_state_update_sources_from_state_dir(
    state_dir: Option<&str>,
) -> Result<ApprovalProjectionSources, ApprovalStateUpdateReplayError> {
    let state_root = optional_trimmed(state_dir)
        .map(PathBuf::from)
        .ok_or(ApprovalStateUpdateReplayError::StateDirRequired)?;
    Ok(ApprovalProjectionSources {
        agents: approval_state_update_records(state_root.join("agents"), "agents")?,
        runs: approval_state_update_records(state_root.join("runs"), "runs")?,
    })
}

fn approval_state_update_records(
    dir: PathBuf,
    label: &'static str,
) -> Result<Vec<Value>, ApprovalStateUpdateReplayError> {
    approval_state_dir_records(dir, label, "approval state update").map_err(|error| match error {
        ApprovalProjectionReplayError::ReadFailed(message) => {
            ApprovalStateUpdateReplayError::ReadFailed(message)
        }
        ApprovalProjectionReplayError::RecordInvalid(message) => {
            ApprovalStateUpdateReplayError::RecordInvalid(message)
        }
    })
}

fn approval_state_dir_records(
    dir: PathBuf,
    label: &'static str,
    projection_label: &'static str,
) -> Result<Vec<Value>, ApprovalProjectionReplayError> {
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(ApprovalProjectionReplayError::ReadFailed(format!(
                "failed to read {projection_label} {label} state_dir {}: {error}",
                dir.display()
            )));
        }
    };
    let mut records = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            ApprovalProjectionReplayError::ReadFailed(format!(
                "failed to read {projection_label} {label} state_dir entry: {error}"
            ))
        })?;
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let contents = fs::read_to_string(&path).map_err(|error| {
            ApprovalProjectionReplayError::ReadFailed(format!(
                "failed to read {projection_label} {label} record {}: {error}",
                path.display()
            ))
        })?;
        let record: Value = serde_json::from_str(&contents).map_err(|error| {
            ApprovalProjectionReplayError::RecordInvalid(format!(
                "failed to parse {projection_label} {label} record {}: {error}",
                path.display()
            ))
        })?;
        if !record.is_object() {
            return Err(ApprovalProjectionReplayError::RecordInvalid(format!(
                "{projection_label} {label} record {} must be an object",
                path.display()
            )));
        }
        records.push(record);
    }
    Ok(records)
}

fn approval_projection_candidates_from_sources(
    sources: &ApprovalProjectionSources,
    thread_id: &str,
    array_names: &[&str],
    control_names: &[&str],
    default_event_kind: &str,
) -> Vec<Value> {
    let mut records = Vec::new();
    for agent in &sources.agents {
        append_approval_projection_source_from_replay(
            &mut records,
            agent,
            None,
            thread_id,
            array_names,
            control_names,
            default_event_kind,
        );
    }
    for run in &sources.runs {
        append_approval_projection_source_from_replay(
            &mut records,
            run,
            approval_projection_source_run_id(run),
            thread_id,
            array_names,
            control_names,
            default_event_kind,
        );
    }
    records
}

fn append_approval_projection_source_from_replay(
    records: &mut Vec<Value>,
    source: &Value,
    run_id: Option<String>,
    thread_id: &str,
    array_names: &[&str],
    control_names: &[&str],
    default_event_kind: &str,
) {
    let mut candidates = Vec::new();
    append_approval_projection_source(&mut candidates, source, array_names, control_names);
    for candidate in candidates {
        records.push(approval_replay_projection_value(
            candidate,
            thread_id,
            run_id.as_deref(),
            default_event_kind,
        ));
    }
}

fn approval_projection_source_run_id(source: &Value) -> Option<String> {
    value_string(source, "id").or_else(|| value_string(source, "run_id"))
}

fn approval_state_update_run_id(source: &Value) -> Option<String> {
    value_string(source, "id").or_else(|| value_string(source, "run_id"))
}

fn approval_state_update_run_matches_thread(run: &Value, thread_id: &str) -> bool {
    value_string(run, "thread_id")
        .or_else(|| value_string(run, "threadId"))
        .map(|candidate| candidate == thread_id)
        .unwrap_or_else(|| {
            value_string(run, "agentId")
                .or_else(|| value_string(run, "agent_id"))
                .map(|agent_id| {
                    approval_state_update_thread_id_for_agent_id(&agent_id) == thread_id
                })
                .unwrap_or(false)
        })
}

fn approval_state_update_agent_matches_thread(agent: &Value, thread_id: &str) -> bool {
    value_string(agent, "thread_id")
        .or_else(|| value_string(agent, "threadId"))
        .map(|candidate| candidate == thread_id)
        .unwrap_or_else(|| {
            value_string(agent, "id")
                .or_else(|| value_string(agent, "agent_id"))
                .map(|agent_id| {
                    approval_state_update_thread_id_for_agent_id(&agent_id) == thread_id
                })
                .unwrap_or(false)
        })
}

fn approval_state_update_thread_id_for_agent_id(agent_id: &str) -> String {
    agent_id
        .strip_prefix("agent_")
        .map(|suffix| format!("thread_{suffix}"))
        .unwrap_or_else(|| agent_id.to_string())
}

fn approval_state_update_run_sort_key(run: &Value) -> String {
    value_string(run, "createdAt")
        .or_else(|| value_string(run, "created_at"))
        .or_else(|| value_string(run, "updatedAt"))
        .or_else(|| value_string(run, "updated_at"))
        .or_else(|| approval_state_update_run_id(run))
        .unwrap_or_default()
}

fn approval_replay_projection_value(
    value: Value,
    thread_id: &str,
    run_id: Option<&str>,
    default_event_kind: &str,
) -> Value {
    let mut record = object_value(&value).unwrap_or_default();
    insert_missing_string(&mut record, "thread_id", thread_id);
    if let Some(run_id) = run_id {
        insert_missing_string(&mut record, "run_id", run_id);
    }
    if !map_has_non_empty_string(&record, "event_kind") {
        let event_kind = if default_event_kind == "approval.decision" {
            approval_decision_event_kind(&Value::Object(record.clone()))
        } else {
            default_event_kind.to_string()
        };
        record.insert("event_kind".to_string(), Value::String(event_kind));
    }
    Value::Object(record)
}

fn approval_record_matches_thread(record: &Value, thread_id: &str) -> bool {
    value_string(record, "thread_id")
        .map(|candidate| candidate == thread_id)
        .unwrap_or(true)
}

fn latest_approval_queue_decision(
    records: &[Value],
    approval_id: &str,
    request_seq: u64,
    thread_id: &str,
) -> Option<Value> {
    let mut latest: Option<(u64, usize, Value)> = None;
    for (index, record) in records.iter().enumerate() {
        if value_string(record, "approval_id").as_deref() != Some(approval_id)
            || !approval_record_matches_thread(record, thread_id)
        {
            continue;
        }
        let seq = approval_projection_seq(record);
        if seq != 0 && request_seq != 0 && seq <= request_seq {
            continue;
        }
        let should_replace = latest
            .as_ref()
            .map(|(latest_seq, latest_index, _)| {
                seq > *latest_seq || (seq == *latest_seq && index >= *latest_index)
            })
            .unwrap_or(true);
        if should_replace {
            latest = Some((seq, index, record.clone()));
        }
    }
    latest.map(|(_, _, record)| record)
}

fn approval_queue_status(latest_decision: &Value) -> &'static str {
    if !latest_decision.is_object() {
        return "pending";
    }
    let event_kind = approval_decision_event_kind(latest_decision);
    if event_kind == "approval.revoked" {
        "revoked"
    } else if event_kind == "approval.approved" {
        "approved"
    } else if event_kind == "approval.rejected" {
        "rejected"
    } else {
        "resolved"
    }
}

fn approval_queue_decision(status: &str, latest_decision: &Value) -> Value {
    match status {
        "approved" => Value::String("approve".to_string()),
        "rejected" => Value::String("reject".to_string()),
        "revoked" => Value::String("revoke".to_string()),
        "pending" => Value::Null,
        _ => value_string(latest_decision, "decision")
            .or_else(|| value_string(latest_decision, "status"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    }
}

fn approval_queue_entry(
    thread_id: &str,
    approval_id: &str,
    approval_request: Value,
    latest_decision: Value,
    status: &'static str,
) -> Value {
    let lease_state = approval_projection_lease_state(&latest_decision);
    json!({
        "schema_version": "ioi.runtime.approval-queue-entry.v1",
        "thread_id": thread_id,
        "run_id": value_string(&approval_request, "run_id"),
        "approval_id": approval_id,
        "status": status,
        "decision": approval_queue_decision(status, &latest_decision),
        "request_event_id": value_string(&approval_request, "event_id"),
        "request_seq": value_u64(&approval_request, "seq"),
        "decision_event_id": value_string(&latest_decision, "event_id"),
        "decision_seq": value_u64(&latest_decision, "seq"),
        "lease_id": value_string(&lease_state, "lease_id"),
        "lease_status": value_string(&lease_state, "lease_status"),
        "reason": approval_event_reason(&latest_decision)
            .or_else(|| approval_event_reason(&approval_request)),
        "receipt_refs": approval_receipt_refs(&approval_request, &latest_decision),
        "policy_decision_refs": approval_policy_decision_refs(&approval_request, &latest_decision),
        "approval_request": approval_request,
        "latest_decision": latest_decision,
        "lease_state": lease_state,
    })
}

fn insert_missing_string(map: &mut serde_json::Map<String, Value>, key: &'static str, value: &str) {
    if !map_has_non_empty_string(map, key) {
        map.insert(key.to_string(), Value::String(value.to_string()));
    }
}

fn map_has_non_empty_string(map: &serde_json::Map<String, Value>, key: &str) -> bool {
    map.get(key)
        .and_then(Value::as_str)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn approval_satisfaction_record(
    thread_id: String,
    approval_id: Option<String>,
    satisfied: bool,
    reason: impl Into<String>,
    latest_decision: &Value,
    lease_state: &Value,
    receipt_refs: Vec<String>,
    policy_decision_refs: Vec<String>,
    expected_head: Option<String>,
    state_root_before: Option<String>,
) -> CodingToolApprovalSatisfactionRecord {
    CodingToolApprovalSatisfactionRecord {
        schema_version: CODING_TOOL_APPROVAL_SATISFACTION_RESULT_SCHEMA_VERSION.to_string(),
        object: "ioi.runtime_coding_tool_approval_satisfaction".to_string(),
        status: if satisfied { "satisfied" } else { "blocked" }.to_string(),
        operation_kind: "coding_tool.approval.satisfaction".to_string(),
        thread_id,
        approval_id,
        satisfied,
        reason: reason.into(),
        decision_event_id: value_string(latest_decision, "event_id"),
        decision_seq: value_u64(latest_decision, "seq"),
        lease_id: value_string(lease_state, "lease_id"),
        expires_at: value_string(lease_state, "expires_at"),
        receipt_refs,
        policy_decision_refs,
        expected_head,
        state_root_before,
        projection_source: "rust_daemon_core_approval_projection".to_string(),
        generated_at: "rust_authority_core".to_string(),
    }
}

fn approval_manifests_satisfy(requested: &Value, retry: &Value) -> bool {
    if !requested.is_object() || !retry.is_object() {
        return false;
    }
    for key in [
        "thread_id",
        "tool_id",
        "tool_call_id",
        "effect_class",
        "input_hash",
    ] {
        let left = value_string(requested, key);
        let right = value_string(retry, key);
        if left.is_none() || right.is_none() || left != right {
            return false;
        }
    }
    let requested_node = value_string(requested, "workflow_node_id");
    let retry_node = value_string(retry, "workflow_node_id");
    if requested_node.is_some() && retry_node.is_some() && requested_node != retry_node {
        return false;
    }
    true
}

fn approval_event_reason(event: &Value) -> Option<String> {
    event
        .get("payload_summary")
        .and_then(|payload| value_string(payload, "reason"))
        .or_else(|| value_string(event, "reason"))
}

fn approval_lease_expired(lease_state: &Value) -> bool {
    if lease_state.get("expired").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    matches!(
        value_string(lease_state, "status")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "expired" | "revoked"
    )
}

fn approval_receipt_refs(approval_request: &Value, latest_decision: &Value) -> Vec<String> {
    unique_trimmed_values(
        array_strings(approval_request, "receipt_refs")
            .into_iter()
            .chain(array_strings(latest_decision, "receipt_refs"))
            .chain(
                approval_request
                    .get("payload_summary")
                    .map(|payload| array_strings(payload, "receipt_refs"))
                    .unwrap_or_default(),
            )
            .chain(
                latest_decision
                    .get("payload_summary")
                    .map(|payload| array_strings(payload, "receipt_refs"))
                    .unwrap_or_default(),
            )
            .collect::<Vec<_>>()
            .as_slice(),
    )
}

fn approval_policy_decision_refs(approval_request: &Value, latest_decision: &Value) -> Vec<String> {
    unique_trimmed_values(
        array_strings(approval_request, "policy_decision_refs")
            .into_iter()
            .chain(array_strings(latest_decision, "policy_decision_refs"))
            .chain(
                approval_request
                    .get("payload_summary")
                    .map(|payload| array_strings(payload, "policy_decision_refs"))
                    .unwrap_or_default(),
            )
            .chain(
                latest_decision
                    .get("payload_summary")
                    .map(|payload| array_strings(payload, "policy_decision_refs"))
                    .unwrap_or_default(),
            )
            .collect::<Vec<_>>()
            .as_slice(),
    )
}

fn value_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|text| optional_trimmed(Some(text)))
}

fn value_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn array_strings(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|item| optional_trimmed(Some(item)))
                .collect()
        })
        .unwrap_or_default()
}

fn unique_trimmed_values(values: &[String]) -> Vec<String> {
    values.iter().fold(Vec::new(), |mut unique, value| {
        let trimmed = value.trim();
        if !trimmed.is_empty() && !unique.iter().any(|existing| existing == trimmed) {
            unique.push(trimmed.to_string());
        }
        unique
    })
}

fn unique_trimmed(values: &[String]) -> Vec<String> {
    values.iter().fold(Vec::new(), |mut unique, value| {
        let trimmed = value.trim();
        if !trimmed.is_empty() && !unique.iter().any(|existing| existing == trimmed) {
            unique.push(trimmed.to_string());
        }
        unique
    })
}

fn safe_id(value: &str) -> String {
    let safe = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if safe.is_empty() {
        "runtime".to_string()
    } else {
        safe
    }
}

fn short_sha256_hex(value: &str, chars: usize) -> String {
    let hash = hex::encode(Sha256::digest(value.as_bytes()));
    hash.chars().take(chars).collect()
}

fn require_coding_tool_field(
    field: &'static str,
    value: &str,
) -> Result<(), CodingToolApprovalError> {
    if value.trim().is_empty() {
        Err(CodingToolApprovalError::MissingField(field))
    } else {
        Ok(())
    }
}

fn require_coding_tool_approval_block_field(
    field: &'static str,
    value: &str,
) -> Result<(), CodingToolApprovalBlockError> {
    if value.trim().is_empty() {
        Err(CodingToolApprovalBlockError::MissingField(field))
    } else {
        Ok(())
    }
}

fn value_hash(value: &Value) -> Result<String, CodingToolApprovalError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| CodingToolApprovalError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{ActionContext, SignatureSuite};
    use std::{
        env, fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn authority(scopes: Vec<&str>) -> ApprovalAuthority {
        ApprovalAuthority {
            schema_version: 1,
            authority_id: [7u8; 32],
            public_key: vec![1, 2, 3],
            signature_suite: SignatureSuite::ED25519,
            expires_at: 10,
            revoked: false,
            scope_allowlist: scopes.into_iter().map(str::to_string).collect(),
        }
    }

    fn coding_tool_request(effect_class: &str) -> CodingToolApprovalRequest {
        CodingToolApprovalRequest {
            schema_version: CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            turn_id: Some("turn_1".to_string()),
            tool_id: "file.apply_patch".to_string(),
            tool_call_id: "call_1".to_string(),
            effect_class: Some(effect_class.to_string()),
            risk_domain: Some("workspace".to_string()),
            authority_scope_requirements: vec![
                "workspace.write".to_string(),
                "workspace.write".to_string(),
            ],
            primitive_capabilities: vec!["fs.write".to_string()],
            thread_mode: Some("plan".to_string()),
            approval_mode: Some("suggest".to_string()),
            trust_profile: Some("local_private".to_string()),
            requested_mode: Some("agent".to_string()),
            normalized_requested_mode: Some("agent".to_string()),
            requested_approval_mode: Some("human_required".to_string()),
            ui_override_requested: true,
            workflow_graph_id: Some("graph_1".to_string()),
            workflow_node_id: Some("node_1".to_string()),
            workflow_policy: CodingToolWorkflowApprovalRequest {
                node_approval_override: Some("inherit".to_string()),
                approval_mode: Some("human_required".to_string()),
                trust_profile: Some("restricted".to_string()),
                requires_approval: false,
            },
            input_summary: serde_json::json!({ "path": "src/app.js" }),
            input: serde_json::json!({ "path": "src/app.js", "dry_run": false }),
        }
    }

    fn approval_request_state_update_request() -> ApprovalRequestStateUpdateRequest {
        let state_dir = temp_state_dir("request-state-update");
        let run = json!({
            "id": "run_alpha",
            "agentId": "agent_alpha",
            "createdAt": "2026-06-06T04:00:00.000Z",
            "status": "running",
            "turnStatus": "running",
            "trace": {},
        });
        write_state_record(&state_dir, "runs", "run_alpha", run);
        ApprovalRequestStateUpdateRequest {
            schema_version: APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            target_kind: None,
            thread_id: Some("thread_alpha".to_string()),
            run_id: Some("run_alpha".to_string()),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            agent: Value::Null,
            run: Value::Null,
            event_id: "event_approval".to_string(),
            seq: 3,
            created_at: "2026-06-06T04:30:00.000Z".to_string(),
            approval_id: "approval_alpha".to_string(),
            source: "runtime_auto".to_string(),
            reason: "Need permission".to_string(),
            receipt_refs: vec!["receipt_approval".to_string()],
            policy_decision_refs: vec!["policy_approval".to_string()],
        }
    }

    fn approval_decision_state_update_request() -> ApprovalDecisionStateUpdateRequest {
        let state_dir = temp_state_dir("decision-state-update");
        let run = json!({
            "id": "run_alpha",
            "agentId": "agent_alpha",
            "createdAt": "2026-06-06T04:00:00.000Z",
            "status": "blocked",
            "turnStatus": "waiting_for_approval",
            "trace": {},
        });
        write_state_record(&state_dir, "runs", "run_alpha", run);
        ApprovalDecisionStateUpdateRequest {
            schema_version: APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            target_kind: None,
            thread_id: Some("thread_alpha".to_string()),
            run_id: Some("run_alpha".to_string()),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            agent: Value::Null,
            run: Value::Null,
            event_id: "event_decision".to_string(),
            seq: 4,
            created_at: "2026-06-06T04:35:00.000Z".to_string(),
            approval_id: "approval_alpha".to_string(),
            lease_id: Some("lease_alpha".to_string()),
            lease_status: "active".to_string(),
            decision: "approve".to_string(),
            status: "approved".to_string(),
            source: "runtime_auto".to_string(),
            reason: Some("Looks good".to_string()),
            receipt_refs: vec!["receipt_decision".to_string()],
            policy_decision_refs: vec!["policy_decision".to_string()],
            authority_record: json!({
                "schema_version": APPROVAL_DECISION_AUTHORITY_RESULT_SCHEMA_VERSION,
                "object": "ioi.runtime_approval_decision_authority",
                "status": "authorized",
                "operation_kind": "approval.decision.authority",
                "thread_id": "thread_alpha",
                "approval_id": "approval_alpha",
                "decision": "approve",
                "wallet_network_grant_refs": ["wallet.network://grant/approval/approval_alpha"],
                "authority_receipt_refs": ["receipt://wallet.network/approval/approval_alpha"],
                "policy_decision_refs": ["policy_wallet_approval"],
                "direct_truth_write_allowed": false,
                "authority_hash": "sha256:approval-authority",
            }),
            authority_hash: None,
            authority_grant_refs: vec![],
            authority_receipt_refs: vec![],
        }
    }

    fn approval_revoke_state_update_request() -> ApprovalRevokeStateUpdateRequest {
        let state_dir = temp_state_dir("revoke-state-update");
        let run = json!({
            "id": "run_alpha",
            "agentId": "agent_alpha",
            "createdAt": "2026-06-06T04:00:00.000Z",
            "status": "blocked",
            "turnStatus": "waiting_for_approval",
            "trace": {},
        });
        write_state_record(&state_dir, "runs", "run_alpha", run);
        ApprovalRevokeStateUpdateRequest {
            schema_version: APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            target_kind: None,
            thread_id: Some("thread_alpha".to_string()),
            run_id: Some("run_alpha".to_string()),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            agent: Value::Null,
            run: Value::Null,
            event_id: "event_revoke".to_string(),
            seq: 5,
            created_at: "2026-06-06T04:40:00.000Z".to_string(),
            approval_id: "approval_alpha".to_string(),
            lease_id: Some("lease_alpha".to_string()),
            source: "runtime_auto".to_string(),
            reason: Some("Changed my mind".to_string()),
            receipt_refs: vec!["receipt_revoke".to_string()],
            policy_decision_refs: vec!["policy_revoke".to_string()],
            authority_record: json!({
                "schema_version": APPROVAL_DECISION_AUTHORITY_RESULT_SCHEMA_VERSION,
                "object": "ioi.runtime_approval_decision_authority",
                "status": "authorized",
                "operation_kind": "approval.decision.authority",
                "thread_id": "thread_alpha",
                "approval_id": "approval_alpha",
                "decision": "revoke",
                "wallet_network_grant_refs": ["wallet.network://grant/approval/approval_alpha"],
                "authority_receipt_refs": ["receipt://wallet.network/approval/approval_alpha"],
                "policy_decision_refs": ["policy_wallet_approval"],
                "direct_truth_write_allowed": false,
                "authority_hash": "sha256:approval-authority-revoke",
            }),
            authority_hash: None,
            authority_grant_refs: vec![],
            authority_receipt_refs: vec![],
        }
    }

    fn approval_decision_authority_request(decision: &str) -> ApprovalDecisionAuthorityRequest {
        ApprovalDecisionAuthorityRequest {
            schema_version: APPROVAL_DECISION_AUTHORITY_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_alpha".to_string(),
            approval_id: "approval_alpha".to_string(),
            decision: decision.to_string(),
            target_kind: Some("run".to_string()),
            run_id: Some("run_alpha".to_string()),
            actor_ref: Some("operator://local/heath".to_string()),
            source: Some("sdk_client".to_string()),
            idempotency_key: Some("approval:thread_alpha:approval_alpha:approve".to_string()),
            authority_grant_refs: vec![
                "wallet.network://grant/approval/approval_alpha".to_string(),
                "grant://local-debug-only".to_string(),
            ],
            authority_receipt_refs: vec![
                "receipt://wallet.network/approval/approval_alpha".to_string()
            ],
            policy_decision_refs: vec!["policy_wallet_approval".to_string()],
            approval_manifest: json!({
                "thread_id": "thread_alpha",
                "approval_id": "approval_alpha",
            }),
            approval_request: json!({
                "event_id": "event_approval",
                "approval_id": "approval_alpha",
            }),
            authority_context: json!({
                "surface": "runtime.approval_control",
            }),
        }
    }

    fn approval_satisfaction_request() -> CodingToolApprovalSatisfactionRequest {
        let plan = CodingToolApprovalCore
            .plan_manifest(&coding_tool_request("workspace_write"))
            .expect("approval manifest plan");
        let manifest = serde_json::to_value(plan.manifest.expect("approval manifest"))
            .expect("manifest value");
        CodingToolApprovalSatisfactionRequest {
            schema_version: CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            approval_id: Some("approval_alpha".to_string()),
            approval_manifest: manifest.clone(),
            approval_request: json!({
                "event_id": "event_approval",
                "seq": 3,
                "thread_id": "thread_1",
                "approval_id": "approval_alpha",
                "event_kind": "approval.required",
                "receipt_refs": ["receipt_request"],
                "policy_decision_refs": ["policy_request"],
                "payload_summary": {
                    "approval_manifest": manifest,
                    "receipt_refs": ["receipt_request_payload"],
                    "policy_decision_refs": ["policy_request_payload"]
                }
            }),
            latest_decision: json!({
                "event_id": "event_decision",
                "seq": 4,
                "thread_id": "thread_1",
                "approval_id": "approval_alpha",
                "event_kind": "approval.approved",
                "receipt_refs": ["receipt_decision"],
                "policy_decision_refs": ["policy_decision"],
                "payload_summary": {
                    "reason": "approval_approved",
                    "receipt_refs": ["receipt_decision_payload"],
                    "policy_decision_refs": ["policy_decision_payload"]
                }
            }),
            lease_state: json!({
                "expired": false,
                "lease_id": "lease_alpha",
                "expires_at": "2026-06-06T04:45:00.000Z"
            }),
            expected_head: Some("agentgres://head/before".to_string()),
            state_root_before: Some("state://root/before".to_string()),
        }
    }

    fn approval_satisfaction_projection_request() -> CodingToolApprovalSatisfactionProjectionRequest
    {
        let request_record = ApprovalRequestStateUpdateCore
            .plan(&approval_request_state_update_request())
            .expect("approval request state");
        let decision_request = approval_decision_state_update_request();
        let decision_state_dir =
            PathBuf::from(decision_request.state_dir.as_deref().expect("state_dir"));
        write_state_record(&decision_state_dir, "runs", "run_alpha", request_record.run);
        let decision_record = ApprovalDecisionStateUpdateCore
            .plan(&decision_request)
            .expect("approval decision state");
        let state_dir = temp_state_dir("satisfaction");
        write_state_record(&state_dir, "runs", "run_alpha", decision_record.run);
        CodingToolApprovalSatisfactionProjectionRequest {
            schema_version: CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION
                .to_string(),
            thread_id: "thread_alpha".to_string(),
            approval_id: "approval_alpha".to_string(),
            approval_manifest: json!({
                "schema_version": CODING_TOOL_APPROVAL_MANIFEST_SCHEMA_VERSION,
                "thread_id": "thread_alpha",
                "tool_id": "file.apply_patch",
                "tool_call_id": "call_1",
                "effect_class": "workspace_write",
                "input_hash": "sha256:projection",
            }),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            run: Value::Null,
            agent: Value::Null,
            expected_head: Some("agentgres://head/projection-before".to_string()),
            state_root_before: Some("state://root/projection-before".to_string()),
        }
    }

    fn temp_state_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = env::temp_dir().join(format!(
            "ioi-approval-queue-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create approval queue temp state dir");
        dir
    }

    fn write_state_record(state_dir: &Path, dir: &str, id: &str, record: Value) {
        let target_dir = state_dir.join(dir);
        fs::create_dir_all(&target_dir).expect("create approval queue state dir");
        fs::write(
            target_dir.join(format!("{id}.json")),
            serde_json::to_vec_pretty(&record).expect("serialize approval queue state record"),
        )
        .expect("write approval queue state record");
    }

    fn approval_queue_projection_request(include_resolved: bool) -> ApprovalQueueProjectionRequest {
        let mut first_request = approval_request_state_update_request();
        first_request.approval_id = "approval_alpha".to_string();
        first_request.event_id = "event_approval_alpha".to_string();
        first_request.seq = 3;
        let first_record = ApprovalRequestStateUpdateCore
            .plan(&first_request)
            .expect("first approval request state");
        let mut decision_request = approval_decision_state_update_request();
        let decision_state_dir =
            PathBuf::from(decision_request.state_dir.as_deref().expect("state_dir"));
        write_state_record(&decision_state_dir, "runs", "run_alpha", first_record.run);
        decision_request.approval_id = "approval_alpha".to_string();
        decision_request.event_id = "event_decision_alpha".to_string();
        decision_request.seq = 4;
        decision_request.receipt_refs = vec!["receipt_decision_alpha".to_string()];
        let decision_record = ApprovalDecisionStateUpdateCore
            .plan(&decision_request)
            .expect("approval decision state");
        let mut second_request = approval_request_state_update_request();
        let second_state_dir =
            PathBuf::from(second_request.state_dir.as_deref().expect("state_dir"));
        write_state_record(&second_state_dir, "runs", "run_alpha", decision_record.run);
        second_request.approval_id = "approval_beta".to_string();
        second_request.event_id = "event_approval_beta".to_string();
        second_request.seq = 5;
        second_request.reason = "Need another permission".to_string();
        second_request.receipt_refs = vec!["receipt_request_beta".to_string()];
        let second_record = ApprovalRequestStateUpdateCore
            .plan(&second_request)
            .expect("second approval request state");
        let state_dir = temp_state_dir(if include_resolved {
            "resolved"
        } else {
            "pending"
        });
        write_state_record(&state_dir, "runs", "run_alpha", second_record.run);

        ApprovalQueueProjectionRequest {
            schema_version: APPROVAL_QUEUE_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_alpha".to_string(),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            run: Value::Null,
            runs: vec![],
            agent: Value::Null,
            include_resolved,
            expected_head: Some("agentgres://head/queue-before".to_string()),
            state_root_before: Some("state://root/queue-before".to_string()),
        }
    }

    fn approval_block_request() -> CodingToolApprovalBlockRequest {
        let satisfaction = CodingToolApprovalSatisfactionCore
            .plan(&approval_satisfaction_request())
            .expect("approval satisfaction");
        let mut blocked_gate = serde_json::to_value(satisfaction).expect("satisfaction value");
        blocked_gate["satisfied"] = Value::Bool(false);
        blocked_gate["status"] = Value::String("blocked".to_string());
        blocked_gate["reason"] = Value::String("approval_required".to_string());
        CodingToolApprovalBlockRequest {
            schema_version: CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            turn_id: Some("turn_1".to_string()),
            tool_id: "file.apply_patch".to_string(),
            tool_call_id: "call_1".to_string(),
            workspace_root: Some("/workspace/project".to_string()),
            workflow_graph_id: Some("graph_1".to_string()),
            workflow_node_id: Some("node_1".to_string()),
            source: Some("runtime_auto".to_string()),
            idempotency_key: Some("thread:thread_1:coding-tool:call_1".to_string()),
            receipt_id: Some("receipt_coding_tool_file_apply_patch".to_string()),
            approval_manifest: approval_satisfaction_request().approval_manifest,
            approval_gate: blocked_gate,
            input_summary: json!({ "path": "src/app.js" }),
            rollback_refs: vec!["rollback_request".to_string()],
            receipt_refs: vec!["receipt_invocation".to_string()],
            policy_decision_refs: vec!["policy_invocation".to_string()],
            artifact_refs: vec![],
        }
    }

    #[test]
    fn rust_authority_plans_coding_tool_approval_manifest() {
        let plan = CodingToolApprovalCore
            .plan_manifest(&coding_tool_request("workspace_write"))
            .expect("approval manifest");
        let manifest = plan.manifest.expect("manifest required");

        assert_eq!(
            plan.schema_version,
            CODING_TOOL_APPROVAL_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            manifest.schema_version,
            CODING_TOOL_APPROVAL_MANIFEST_SCHEMA_VERSION
        );
        assert!(plan.approval_required);
        assert_eq!(manifest.policy_reason, "thread_plan_mode_requires_approval");
        assert_eq!(manifest.thread_mode, "plan");
        assert_eq!(manifest.workflow_trust_profile, "restricted");
        assert_eq!(
            manifest.authority_scope_requirements,
            vec!["workspace.write"]
        );
        assert_eq!(manifest.ui_override_ignored, true);
        assert!(manifest.input_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_authority_omits_local_read_coding_tool_approval_manifest() {
        let mut request = coding_tool_request("local_read");
        request.thread_mode = Some("agent".to_string());
        request.approval_mode = Some("suggest".to_string());
        request.workflow_policy.requires_approval = false;
        request.workflow_policy.approval_mode = None;
        request.workflow_policy.trust_profile = Some("local_private".to_string());

        let plan = CodingToolApprovalCore
            .plan_manifest(&request)
            .expect("local read plan");

        assert!(!plan.approval_required);
        assert!(plan.manifest.is_none());
        assert_eq!(plan.workflow_policy.requires_approval, false);
    }

    #[test]
    fn rust_authority_rejects_invalid_coding_tool_approval_schema() {
        let mut request = coding_tool_request("workspace_write");
        request.schema_version = "legacy.schema".to_string();

        let error = CodingToolApprovalCore
            .plan_manifest(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            CodingToolApprovalError::InvalidSchemaVersion {
                expected: CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_core_shapes_coding_tool_approval_protocol_response() {
        let response = plan_coding_tool_approval_manifest_protocol_response(
            CodingToolApprovalProtocolRequest {
                request: coding_tool_request("workspace_write"),
            },
        )
        .expect("approval protocol response");

        assert_eq!(response["source"], "rust_coding_tool_approval_protocol");
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["approval_required"], true);
        assert_eq!(
            response["manifest"]["schema_version"],
            CODING_TOOL_APPROVAL_MANIFEST_SCHEMA_VERSION
        );
        assert!(response["input_hash"]
            .as_str()
            .expect("input hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn rust_authority_plans_coding_tool_approval_satisfaction() {
        let record = CodingToolApprovalSatisfactionCore
            .plan(&approval_satisfaction_request())
            .expect("approval satisfaction");

        assert_eq!(
            record.schema_version,
            CODING_TOOL_APPROVAL_SATISFACTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "satisfied");
        assert_eq!(record.operation_kind, "coding_tool.approval.satisfaction");
        assert_eq!(record.satisfied, true);
        assert_eq!(record.approval_id.as_deref(), Some("approval_alpha"));
        assert_eq!(record.decision_event_id.as_deref(), Some("event_decision"));
        assert_eq!(record.decision_seq, Some(4));
        assert_eq!(record.lease_id.as_deref(), Some("lease_alpha"));
        assert_eq!(
            record.receipt_refs,
            vec![
                "receipt_request",
                "receipt_decision",
                "receipt_request_payload",
                "receipt_decision_payload"
            ]
        );
        assert_eq!(
            record.policy_decision_refs,
            vec![
                "policy_request",
                "policy_decision",
                "policy_request_payload",
                "policy_decision_payload"
            ]
        );
        assert_eq!(
            record.expected_head.as_deref(),
            Some("agentgres://head/before")
        );
        assert_eq!(
            record.state_root_before.as_deref(),
            Some("state://root/before")
        );
    }

    #[test]
    fn rust_authority_blocks_coding_tool_approval_satisfaction_mismatch() {
        let mut request = approval_satisfaction_request();
        request.approval_manifest["input_hash"] = Value::String("sha256:other".to_string());

        let record = CodingToolApprovalSatisfactionCore
            .plan(&request)
            .expect("blocked satisfaction");

        assert_eq!(record.status, "blocked");
        assert_eq!(record.satisfied, false);
        assert_eq!(record.reason, "approval_manifest_mismatch");
        assert!(record.decision_event_id.is_none());
    }

    #[test]
    fn rust_authority_blocks_expired_coding_tool_approval_lease() {
        let mut request = approval_satisfaction_request();
        request.lease_state["expired"] = Value::Bool(true);

        let record = CodingToolApprovalSatisfactionCore
            .plan(&request)
            .expect("expired approval");

        assert_eq!(record.status, "blocked");
        assert_eq!(record.satisfied, false);
        assert_eq!(record.reason, "approval_lease_expired");
        assert_eq!(record.decision_event_id.as_deref(), Some("event_decision"));
        assert_eq!(record.lease_id.as_deref(), Some("lease_alpha"));
    }

    #[test]
    fn rust_core_shapes_coding_tool_approval_satisfaction_protocol_response() {
        let response = plan_coding_tool_approval_satisfaction_protocol_response(
            CodingToolApprovalSatisfactionProtocolRequest {
                request: approval_satisfaction_request(),
            },
        )
        .expect("approval satisfaction protocol response");

        assert_eq!(
            response["source"],
            "rust_coding_tool_approval_satisfaction_protocol"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["satisfied"], true);
        assert_eq!(response["approval_id"], "approval_alpha");
        assert_eq!(response["decision_event_id"], "event_decision");
        assert_eq!(
            response["record"]["schema_version"],
            CODING_TOOL_APPROVAL_SATISFACTION_RESULT_SCHEMA_VERSION
        );
    }

    #[test]
    fn rust_authority_projects_coding_tool_approval_satisfaction_from_state_dir_replay() {
        let request = approval_satisfaction_projection_request();
        let record = CodingToolApprovalSatisfactionProjectionCore
            .project(&request)
            .expect("approval satisfaction projection");

        assert_eq!(
            record.schema_version,
            CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "projected");
        assert_eq!(
            record.operation_kind,
            "coding_tool.approval.satisfaction_projection"
        );
        assert_eq!(record.approval_request["approval_id"], "approval_alpha");
        assert_eq!(record.approval_request["thread_id"], "thread_alpha");
        assert_eq!(
            record.approval_request["payload_summary"]["approval_manifest"]["input_hash"],
            "sha256:projection"
        );
        assert_eq!(record.latest_decision["event_id"], "event_decision");
        assert_eq!(record.latest_decision["event_kind"], "approval.approved");
        assert_eq!(record.lease_state["lease_id"], "lease_alpha");
        assert_eq!(record.lease_state["status"], "active");
        assert_eq!(record.lease_state["expired"], false);

        let satisfaction = CodingToolApprovalSatisfactionCore
            .plan(&CodingToolApprovalSatisfactionRequest {
                schema_version: CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION
                    .to_string(),
                thread_id: record.thread_id.clone(),
                approval_id: Some(record.approval_id.clone()),
                approval_manifest: request.approval_manifest,
                approval_request: record.approval_request,
                latest_decision: record.latest_decision,
                lease_state: record.lease_state,
                expected_head: record.expected_head,
                state_root_before: record.state_root_before,
            })
            .expect("approval satisfaction");

        assert_eq!(satisfaction.status, "satisfied");
        assert_eq!(satisfaction.satisfied, true);
        assert_eq!(
            satisfaction.expected_head.as_deref(),
            Some("agentgres://head/projection-before")
        );
    }

    #[test]
    fn rust_authority_projects_revoked_approval_as_latest_decision() {
        let request_record = ApprovalRequestStateUpdateCore
            .plan(&approval_request_state_update_request())
            .expect("approval request state");
        let decision_request = approval_decision_state_update_request();
        let decision_state_dir =
            PathBuf::from(decision_request.state_dir.as_deref().expect("state_dir"));
        write_state_record(&decision_state_dir, "runs", "run_alpha", request_record.run);
        let decision_record = ApprovalDecisionStateUpdateCore
            .plan(&decision_request)
            .expect("approval decision state");
        let revoke_request = approval_revoke_state_update_request();
        let revoke_state_dir =
            PathBuf::from(revoke_request.state_dir.as_deref().expect("state_dir"));
        write_state_record(&revoke_state_dir, "runs", "run_alpha", decision_record.run);
        let revoke_record = ApprovalRevokeStateUpdateCore
            .plan(&revoke_request)
            .expect("approval revoke state");
        let request = approval_satisfaction_projection_request();
        let state_dir = PathBuf::from(request.state_dir.as_deref().expect("projection state_dir"));
        write_state_record(&state_dir, "runs", "run_alpha", revoke_record.run);

        let record = CodingToolApprovalSatisfactionProjectionCore
            .project(&request)
            .expect("approval satisfaction projection");

        assert_eq!(record.latest_decision["event_id"], "event_revoke");
        assert_eq!(record.latest_decision["event_kind"], "approval.revoked");
        assert_eq!(record.lease_state["status"], "revoked");
        assert_eq!(record.lease_state["expired"], true);

        let satisfaction = CodingToolApprovalSatisfactionCore
            .plan(&CodingToolApprovalSatisfactionRequest {
                schema_version: CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION
                    .to_string(),
                thread_id: record.thread_id.clone(),
                approval_id: Some(record.approval_id.clone()),
                approval_manifest: request.approval_manifest,
                approval_request: record.approval_request,
                latest_decision: record.latest_decision,
                lease_state: record.lease_state,
                expected_head: record.expected_head,
                state_root_before: record.state_root_before,
            })
            .expect("approval satisfaction");

        assert_eq!(satisfaction.status, "blocked");
        assert_eq!(satisfaction.reason, "Changed my mind");
    }

    #[test]
    fn rust_core_shapes_coding_tool_approval_satisfaction_projection_protocol_response() {
        let response = project_coding_tool_approval_satisfaction_protocol_response(
            CodingToolApprovalSatisfactionProjectionProtocolRequest {
                request: approval_satisfaction_projection_request(),
            },
        )
        .expect("approval satisfaction projection protocol response");

        assert_eq!(
            response["source"],
            "rust_coding_tool_approval_satisfaction_projection_protocol"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "projected");
        assert_eq!(
            response["approval_request"]["approval_id"],
            "approval_alpha"
        );
        assert_eq!(response["latest_decision"]["event_id"], "event_decision");
        assert_eq!(response["lease_state"]["lease_id"], "lease_alpha");
        assert_eq!(
            response["record"]["schema_version"],
            CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_RESULT_SCHEMA_VERSION
        );
    }

    #[test]
    fn rust_approval_satisfaction_projection_requires_state_dir() {
        let mut request = approval_satisfaction_projection_request();
        request.state_dir = None;

        let error = CodingToolApprovalSatisfactionProjectionCore
            .project(&request)
            .expect_err("missing state_dir must fail closed");

        assert_eq!(
            error,
            CodingToolApprovalSatisfactionProjectionError::StateDirRequired
        );
    }

    #[test]
    fn rust_approval_satisfaction_projection_rejects_js_candidate_transport() {
        let mut request = approval_satisfaction_projection_request();
        request.run = json!({ "id": "run_retired", "trace": {} });

        let error = CodingToolApprovalSatisfactionProjectionCore
            .project(&request)
            .expect_err("run candidate transport must stay retired");

        assert_eq!(
            error,
            CodingToolApprovalSatisfactionProjectionError::RetiredCandidateTransport("run")
        );
    }

    #[test]
    fn rust_authority_projects_public_approval_queue_pending_only() {
        let record = ApprovalQueueProjectionCore
            .project(&approval_queue_projection_request(false))
            .expect("approval queue projection");

        assert_eq!(
            record.schema_version,
            APPROVAL_QUEUE_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "projected");
        assert_eq!(record.operation_kind, "approval.queue_projection");
        assert_eq!(record.thread_id, "thread_alpha");
        assert_eq!(record.pending_count, 1);
        assert_eq!(record.resolved_count, 1);
        assert_eq!(record.approvals.len(), 1);
        assert_eq!(record.approvals[0]["approval_id"], "approval_beta");
        assert_eq!(record.approvals[0]["status"], "pending");
        assert_eq!(record.approvals[0]["decision"], Value::Null);
        assert_eq!(
            record.approvals[0]["request_event_id"],
            "event_approval_beta"
        );
        assert_eq!(
            record.approvals[0]["receipt_refs"][0],
            "receipt_request_beta"
        );
        assert!(record.approvals[0].get("approvalId").is_none());
        assert!(record.approvals[0].get("requestEventId").is_none());
    }

    #[test]
    fn rust_authority_projects_public_approval_queue_with_resolved_records() {
        let record = ApprovalQueueProjectionCore
            .project(&approval_queue_projection_request(true))
            .expect("approval queue projection");

        assert_eq!(record.pending_count, 1);
        assert_eq!(record.resolved_count, 1);
        assert_eq!(record.approvals.len(), 2);
        assert_eq!(record.approvals[0]["approval_id"], "approval_alpha");
        assert_eq!(record.approvals[0]["status"], "approved");
        assert_eq!(record.approvals[0]["decision"], "approve");
        assert_eq!(
            record.approvals[0]["decision_event_id"],
            "event_decision_alpha"
        );
        assert_eq!(
            record.approvals[0]["receipt_refs"][1],
            "receipt_decision_alpha"
        );
        assert_eq!(record.approvals[1]["approval_id"], "approval_beta");
        assert_eq!(record.approvals[1]["status"], "pending");
        assert_eq!(
            record.expected_head.as_deref(),
            Some("agentgres://head/queue-before")
        );
    }

    #[test]
    fn rust_approval_queue_projection_requires_state_dir() {
        let mut request = approval_queue_projection_request(false);
        request.state_dir = None;

        let error = ApprovalQueueProjectionCore
            .project(&request)
            .expect_err("approval queue projection without state_dir should fail");

        assert_eq!(error, ApprovalQueueProjectionError::StateDirRequired);
    }

    #[test]
    fn rust_approval_queue_projection_rejects_js_candidate_transport() {
        let mut request = approval_queue_projection_request(false);
        request.run = json!({
            "id": "run_candidate",
            "trace": {
                "approvalRequests": [{
                    "approval_id": "approval_candidate"
                }]
            }
        });

        let error = ApprovalQueueProjectionCore
            .project(&request)
            .expect_err("approval queue JS run candidates should fail");

        assert_eq!(
            error,
            ApprovalQueueProjectionError::RetiredCandidateTransport("run")
        );
    }

    #[test]
    fn rust_core_shapes_public_approval_queue_protocol_response() {
        let response =
            project_approval_queue_protocol_response(ApprovalQueueProjectionProtocolRequest {
                request: approval_queue_projection_request(false),
            })
            .expect("approval queue protocol response");

        assert_eq!(
            response["source"],
            "rust_approval_queue_projection_protocol"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "projected");
        assert_eq!(response["operation_kind"], "approval.queue_projection");
        assert_eq!(response["thread_id"], "thread_alpha");
        assert_eq!(response["pending_count"], 1);
        assert_eq!(response["resolved_count"], 1);
        assert_eq!(response["approvals"][0]["approval_id"], "approval_beta");
        assert_eq!(
            response["record"]["schema_version"],
            APPROVAL_QUEUE_PROJECTION_RESULT_SCHEMA_VERSION
        );
    }

    #[test]
    fn rust_authority_authorizes_approval_decision_with_wallet_network_grant() {
        let record = ApprovalDecisionAuthorityCore
            .authorize(&approval_decision_authority_request("approve"))
            .expect("approval decision authority");

        assert_eq!(
            record.schema_version,
            APPROVAL_DECISION_AUTHORITY_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "authorized");
        assert_eq!(record.operation_kind, "approval.decision.authority");
        assert_eq!(record.decision, "approve");
        assert_eq!(
            record.wallet_network_grant_refs,
            vec!["wallet.network://grant/approval/approval_alpha"]
        );
        assert_eq!(
            record.authority_receipt_refs,
            vec!["receipt://wallet.network/approval/approval_alpha"]
        );
        assert_eq!(record.direct_truth_write_allowed, false);
        assert!(record.authority_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_authority_rejects_approval_decision_without_wallet_network_grant() {
        let mut request = approval_decision_authority_request("approve");
        request.authority_grant_refs = vec!["grant://local-debug-only".to_string()];

        let error = ApprovalDecisionAuthorityCore
            .authorize(&request)
            .expect_err("wallet.network authority is required");

        assert_eq!(
            error,
            ApprovalDecisionAuthorityError::MissingWalletNetworkAuthority
        );
    }

    #[test]
    fn rust_core_shapes_approval_decision_authority_protocol_response() {
        let response = authorize_approval_decision_protocol_response(
            ApprovalDecisionAuthorityProtocolRequest {
                request: approval_decision_authority_request("revoke"),
            },
        )
        .expect("approval decision authority protocol response");

        assert_eq!(
            response["schema_version"],
            APPROVAL_DECISION_AUTHORITY_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            response["source"],
            "rust_approval_decision_authority_protocol"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "authorized");
        assert_eq!(response["operation_kind"], "approval.decision.authority");
        assert_eq!(response["decision"], "revoke");
        assert_eq!(
            response["wallet_network_grant_refs"][0],
            "wallet.network://grant/approval/approval_alpha"
        );
        assert_eq!(
            response["authority_receipt_refs"][0],
            "receipt://wallet.network/approval/approval_alpha"
        );
        assert_eq!(response["direct_truth_write_allowed"], false);
        assert!(response["authority_hash"]
            .as_str()
            .expect("authority hash")
            .starts_with("sha256:"));
    }

    #[test]
    fn rust_authority_plans_coding_tool_approval_block_result_event() {
        let record = CodingToolApprovalBlockCore
            .plan(&approval_block_request())
            .expect("approval block");

        assert_eq!(
            record.schema_version,
            CODING_TOOL_APPROVAL_BLOCK_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "blocked");
        assert_eq!(record.operation_kind, "coding_tool.approval.block");
        assert_eq!(record.reason, "approval_required");
        assert_eq!(record.approval_id.as_deref(), Some("approval_alpha"));
        assert!(record
            .receipt_refs
            .contains(&"receipt_coding_tool_file_apply_patch".to_string()));
        assert!(record
            .receipt_refs
            .contains(&"receipt_invocation".to_string()));
        assert!(record.receipt_refs.contains(&"receipt_request".to_string()));
        assert!(record
            .policy_decision_refs
            .contains(&"policy_invocation".to_string()));
        assert_eq!(
            record.result["schema_version"],
            CODING_TOOL_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.result["status"], "blocked");
        assert_eq!(record.result["approval_required"], true);
        assert_eq!(record.result["approval_satisfied"], false);
        assert_eq!(record.result["rust_authority_block"], true);
        assert_eq!(record.event["event_stream_id"], "thread_1:events");
        assert_eq!(record.event["event_kind"], "tool.blocked");
        assert_eq!(record.event["status"], "blocked");
        assert_eq!(
            record.event["payload_summary"]["approval_id"],
            "approval_alpha"
        );
        assert_eq!(
            record.event["payload_summary"]["rust_authority_block"],
            true
        );
    }

    #[test]
    fn rust_core_shapes_coding_tool_approval_block_protocol_response() {
        let response = plan_coding_tool_approval_block_protocol_response(
            CodingToolApprovalBlockProtocolRequest {
                request: approval_block_request(),
            },
        )
        .expect("approval block protocol response");

        assert_eq!(
            response["source"],
            "rust_coding_tool_approval_block_protocol"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "blocked");
        assert_eq!(response["operation_kind"], "coding_tool.approval.block");
        assert_eq!(response["approval_id"], "approval_alpha");
        assert_eq!(response["result"]["status"], "blocked");
        assert_eq!(response["event"]["event_kind"], "tool.blocked");
        assert_eq!(
            response["record"]["schema_version"],
            CODING_TOOL_APPROVAL_BLOCK_RESULT_SCHEMA_VERSION
        );
    }

    #[test]
    fn rust_authority_plans_approval_request_state_update() {
        let record = ApprovalRequestStateUpdateCore
            .plan(&approval_request_state_update_request())
            .expect("approval request state update");

        assert_eq!(
            record.schema_version,
            APPROVAL_REQUEST_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "approval.required");
        assert_eq!(record.target_kind, "run");
        assert_eq!(record.operator_control["control"], "approval_request");
        assert_eq!(record.operator_control["approval_id"], "approval_alpha");
        assert!(record.operator_control.get("approvalId").is_none());
        assert!(record.operator_control.get("eventId").is_none());
        assert!(record.operator_control.get("receiptRefs").is_none());
        assert!(record.operator_control.get("policyDecisionRefs").is_none());
        assert!(record.operator_control.get("createdAt").is_none());
        assert_eq!(record.run["status"], "blocked");
        assert_eq!(record.run["turnStatus"], "waiting_for_approval");
        assert_eq!(
            record.run["trace"]["approvalRequests"][0]["event_id"],
            "event_approval"
        );
        assert_eq!(
            record.run["operatorControls"][0]["receipt_refs"][0],
            "receipt_approval"
        );
    }

    #[test]
    fn rust_authority_plans_approval_request_agent_state_update() {
        let mut request = approval_request_state_update_request();
        request.target_kind = Some("agent".to_string());
        request.run_id = None;
        let state_dir = PathBuf::from(request.state_dir.as_deref().expect("state_dir"));
        write_state_record(
            &state_dir,
            "agents",
            "agent_alpha",
            json!({
                "id": "agent_alpha",
                "thread_id": "thread_alpha",
                "cwd": "/workspace",
                "updatedAt": "2026-06-06T04:00:00.000Z"
            }),
        );

        let record = ApprovalRequestStateUpdateCore
            .plan(&request)
            .expect("approval request agent state update");

        assert_eq!(record.target_kind, "agent");
        assert!(record.run.is_null());
        assert_eq!(
            record.agent.as_ref().expect("agent record")["updatedAt"],
            "2026-06-06T04:30:00.000Z"
        );
        assert_eq!(record.operation_kind, "approval.required");
    }

    #[test]
    fn rust_authority_plans_approval_request_state_update_from_state_dir_without_run_id() {
        let mut request = approval_request_state_update_request();
        request.run_id = None;

        let record = ApprovalRequestStateUpdateCore
            .plan(&request)
            .expect("approval request state update from state_dir replay");

        assert_eq!(record.target_kind, "run");
        assert_eq!(record.run_id.as_deref(), Some("run_alpha"));
        assert_eq!(record.run["id"], "run_alpha");
        assert_eq!(record.run["status"], "blocked");
    }

    #[test]
    fn rust_approval_request_state_update_rejects_cross_thread_run_id_replay() {
        let mut request = approval_request_state_update_request();
        request.run_id = Some("run_foreign".to_string());
        let state_dir = PathBuf::from(request.state_dir.as_deref().expect("state_dir"));
        write_state_record(
            &state_dir,
            "runs",
            "run_foreign",
            json!({
                "id": "run_foreign",
                "thread_id": "thread_other",
                "createdAt": "2026-06-06T04:05:00.000Z",
                "status": "running",
                "turnStatus": "running",
                "trace": {},
            }),
        );

        let error = ApprovalRequestStateUpdateCore
            .plan(&request)
            .expect_err("cross-thread run replay should fail");

        assert_eq!(
            error,
            ApprovalRequestStateUpdateError::TargetNotFound("run")
        );
    }

    #[test]
    fn rust_approval_request_state_update_requires_state_dir() {
        let mut request = approval_request_state_update_request();
        request.state_dir = None;

        let error = ApprovalRequestStateUpdateCore
            .plan(&request)
            .expect_err("approval request state update without state_dir should fail");

        assert_eq!(error, ApprovalRequestStateUpdateError::StateDirRequired);
    }

    #[test]
    fn rust_approval_request_state_update_rejects_js_candidate_transport() {
        let mut request = approval_request_state_update_request();
        request.run = json!({ "id": "run_retired", "trace": {} });

        let error = ApprovalRequestStateUpdateCore
            .plan(&request)
            .expect_err("approval request JS run candidate should fail");

        assert_eq!(
            error,
            ApprovalRequestStateUpdateError::RetiredCandidateTransport("run")
        );
    }

    #[test]
    fn rust_authority_rejects_invalid_approval_request_state_update_schema() {
        let mut request = approval_request_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = ApprovalRequestStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            ApprovalRequestStateUpdateError::InvalidSchemaVersion {
                expected: APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_core_shapes_approval_request_state_update_protocol_response() {
        let response = plan_approval_request_state_update_protocol_response(
            ApprovalRequestStateUpdateProtocolRequest {
                request: approval_request_state_update_request(),
            },
        )
        .expect("approval request protocol response");

        assert_eq!(
            response["source"],
            "rust_approval_request_state_update_protocol"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "approval.required");
        assert_eq!(
            response["operator_control"]["approval_id"],
            "approval_alpha"
        );
        assert_eq!(
            response["record"]["schema_version"],
            APPROVAL_REQUEST_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
    }

    #[test]
    fn rust_authority_plans_approval_decision_state_update() {
        let record = ApprovalDecisionStateUpdateCore
            .plan(&approval_decision_state_update_request())
            .expect("approval decision state update");

        assert_eq!(
            record.schema_version,
            APPROVAL_DECISION_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "approval.approve");
        assert_eq!(record.target_kind, "run");
        assert_eq!(record.operator_control["control"], "approval_decision");
        assert_eq!(record.operator_control["lease_id"], "lease_alpha");
        assert!(record.operator_control.get("approvalId").is_none());
        assert!(record.operator_control.get("leaseId").is_none());
        assert!(record.operator_control.get("leaseStatus").is_none());
        assert!(record.operator_control.get("eventId").is_none());
        assert!(record.operator_control.get("receiptRefs").is_none());
        assert!(record.operator_control.get("policyDecisionRefs").is_none());
        assert!(record.operator_control.get("createdAt").is_none());
        assert_eq!(record.run["turnStatus"], "waiting_for_approval");
        assert_eq!(
            record.run["trace"]["approvalDecisions"][0]["event_id"],
            "event_decision"
        );
        assert_eq!(
            record.run["operatorControls"][0]["receipt_refs"][0],
            "receipt_decision"
        );
        assert_eq!(
            record.run["operatorControls"][0]["receipt_refs"][1],
            "receipt://wallet.network/approval/approval_alpha"
        );
        assert_eq!(
            record.operator_control["authority_hash"],
            "sha256:approval-authority"
        );
        assert_eq!(
            record.operator_control["authority_grant_refs"][0],
            "wallet.network://grant/approval/approval_alpha"
        );
        assert_eq!(
            record.operator_control["authority_receipt_refs"][0],
            "receipt://wallet.network/approval/approval_alpha"
        );
    }

    #[test]
    fn rust_authority_plans_approval_decision_agent_state_update() {
        let mut request = approval_decision_state_update_request();
        request.target_kind = Some("agent".to_string());
        request.run_id = None;
        let state_dir = PathBuf::from(request.state_dir.as_deref().expect("state_dir"));
        write_state_record(
            &state_dir,
            "agents",
            "agent_alpha",
            json!({
                "id": "agent_alpha",
                "thread_id": "thread_alpha",
                "cwd": "/workspace",
                "updatedAt": "2026-06-06T04:00:00.000Z"
            }),
        );

        let record = ApprovalDecisionStateUpdateCore
            .plan(&request)
            .expect("approval decision agent state update");

        assert_eq!(record.target_kind, "agent");
        assert!(record.run.is_null());
        assert_eq!(
            record.agent.as_ref().expect("agent record")["updatedAt"],
            "2026-06-06T04:35:00.000Z"
        );
        assert_eq!(record.operation_kind, "approval.approve");
    }

    #[test]
    fn rust_approval_decision_state_update_requires_state_dir() {
        let mut request = approval_decision_state_update_request();
        request.state_dir = None;

        let error = ApprovalDecisionStateUpdateCore
            .plan(&request)
            .expect_err("approval decision state update without state_dir should fail");

        assert_eq!(error, ApprovalDecisionStateUpdateError::StateDirRequired);
    }

    #[test]
    fn rust_approval_decision_state_update_rejects_js_candidate_transport() {
        let mut request = approval_decision_state_update_request();
        request.agent = json!({ "id": "agent_retired" });

        let error = ApprovalDecisionStateUpdateCore
            .plan(&request)
            .expect_err("approval decision JS agent candidate should fail");

        assert_eq!(
            error,
            ApprovalDecisionStateUpdateError::RetiredCandidateTransport("agent")
        );
    }

    #[test]
    fn rust_authority_plans_rejected_approval_decision_turn_input_state() {
        let mut request = approval_decision_state_update_request();
        request.decision = "reject".to_string();
        request.status = "rejected".to_string();
        request.lease_status = "denied".to_string();

        let record = ApprovalDecisionStateUpdateCore
            .plan(&request)
            .expect("approval reject state update");

        assert_eq!(record.operation_kind, "approval.reject");
        assert_eq!(record.operator_control["lease_status"], "denied");
        assert!(record.operator_control.get("leaseStatus").is_none());
        assert_eq!(record.run["turnStatus"], "waiting_for_input");
    }

    #[test]
    fn rust_authority_rejects_invalid_approval_decision_state_update_schema() {
        let mut request = approval_decision_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = ApprovalDecisionStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            ApprovalDecisionStateUpdateError::InvalidSchemaVersion {
                expected: APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_authority_rejects_approval_decision_state_update_without_wallet_authority() {
        let mut request = approval_decision_state_update_request();
        request.authority_record = Value::Null;
        request.authority_hash = None;
        request.authority_grant_refs.clear();
        request.authority_receipt_refs.clear();

        let error = ApprovalDecisionStateUpdateCore
            .plan(&request)
            .expect_err("wallet authority is required");

        assert_eq!(
            error,
            ApprovalDecisionStateUpdateError::MissingField("authority_record")
        );
    }

    #[test]
    fn rust_core_shapes_approval_decision_state_update_protocol_response() {
        let response = plan_approval_decision_state_update_protocol_response(
            ApprovalDecisionStateUpdateProtocolRequest {
                request: approval_decision_state_update_request(),
            },
        )
        .expect("approval decision protocol response");

        assert_eq!(
            response["source"],
            "rust_approval_decision_state_update_protocol"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "approval.approve");
        assert_eq!(response["operator_control"]["lease_id"], "lease_alpha");
        assert_eq!(
            response["operator_control"]["authority_hash"],
            "sha256:approval-authority"
        );
        assert_eq!(
            response["record"]["schema_version"],
            APPROVAL_DECISION_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
    }

    #[test]
    fn rust_authority_plans_approval_revoke_state_update() {
        let record = ApprovalRevokeStateUpdateCore
            .plan(&approval_revoke_state_update_request())
            .expect("approval revoke state update");

        assert_eq!(
            record.schema_version,
            APPROVAL_REVOKE_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "approval.revoke");
        assert_eq!(record.target_kind, "run");
        assert_eq!(record.operator_control["control"], "approval_revoke");
        assert_eq!(record.operator_control["lease_status"], "revoked");
        assert!(record.operator_control.get("approvalId").is_none());
        assert!(record.operator_control.get("leaseId").is_none());
        assert!(record.operator_control.get("leaseStatus").is_none());
        assert!(record.operator_control.get("eventId").is_none());
        assert!(record.operator_control.get("receiptRefs").is_none());
        assert!(record.operator_control.get("policyDecisionRefs").is_none());
        assert!(record.operator_control.get("createdAt").is_none());
        assert_eq!(record.run["turnStatus"], "waiting_for_input");
        assert_eq!(
            record.run["trace"]["approvalRevocations"][0]["event_id"],
            "event_revoke"
        );
        assert_eq!(
            record.run["approvalDecisions"][0]["receipt_refs"][0],
            "receipt_revoke"
        );
        assert_eq!(
            record.run["operatorControls"][0]["policy_decision_refs"][0],
            "policy_revoke"
        );
        assert_eq!(
            record.run["operatorControls"][0]["policy_decision_refs"][1],
            "policy_wallet_approval"
        );
        assert_eq!(
            record.operator_control["authority_hash"],
            "sha256:approval-authority-revoke"
        );
        assert_eq!(
            record.operator_control["authority_receipt_refs"][0],
            "receipt://wallet.network/approval/approval_alpha"
        );
    }

    #[test]
    fn rust_authority_plans_approval_revoke_agent_state_update() {
        let mut request = approval_revoke_state_update_request();
        request.target_kind = Some("agent".to_string());
        request.run_id = None;
        let state_dir = PathBuf::from(request.state_dir.as_deref().expect("state_dir"));
        write_state_record(
            &state_dir,
            "agents",
            "agent_alpha",
            json!({
                "id": "agent_alpha",
                "thread_id": "thread_alpha",
                "cwd": "/workspace",
                "updatedAt": "2026-06-06T04:00:00.000Z"
            }),
        );

        let record = ApprovalRevokeStateUpdateCore
            .plan(&request)
            .expect("approval revoke agent state update");

        assert_eq!(record.target_kind, "agent");
        assert!(record.run.is_null());
        assert_eq!(
            record.agent.as_ref().expect("agent record")["updatedAt"],
            "2026-06-06T04:40:00.000Z"
        );
        assert_eq!(record.operation_kind, "approval.revoke");
    }

    #[test]
    fn rust_approval_revoke_state_update_requires_state_dir() {
        let mut request = approval_revoke_state_update_request();
        request.state_dir = None;

        let error = ApprovalRevokeStateUpdateCore
            .plan(&request)
            .expect_err("approval revoke state update without state_dir should fail");

        assert_eq!(error, ApprovalRevokeStateUpdateError::StateDirRequired);
    }

    #[test]
    fn rust_approval_revoke_state_update_rejects_js_candidate_transport() {
        let mut request = approval_revoke_state_update_request();
        request.run = json!({ "id": "run_retired", "trace": {} });

        let error = ApprovalRevokeStateUpdateCore
            .plan(&request)
            .expect_err("approval revoke JS run candidate should fail");

        assert_eq!(
            error,
            ApprovalRevokeStateUpdateError::RetiredCandidateTransport("run")
        );
    }

    #[test]
    fn rust_authority_rejects_invalid_approval_revoke_state_update_schema() {
        let mut request = approval_revoke_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = ApprovalRevokeStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            ApprovalRevokeStateUpdateError::InvalidSchemaVersion {
                expected: APPROVAL_REVOKE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_authority_rejects_approval_revoke_state_update_without_wallet_authority() {
        let mut request = approval_revoke_state_update_request();
        request.authority_record = Value::Null;
        request.authority_hash = None;
        request.authority_grant_refs.clear();
        request.authority_receipt_refs.clear();

        let error = ApprovalRevokeStateUpdateCore
            .plan(&request)
            .expect_err("wallet authority is required");

        assert_eq!(
            error,
            ApprovalRevokeStateUpdateError::MissingField("authority_record")
        );
    }

    #[test]
    fn rust_core_shapes_approval_revoke_state_update_protocol_response() {
        let response = plan_approval_revoke_state_update_protocol_response(
            ApprovalRevokeStateUpdateProtocolRequest {
                request: approval_revoke_state_update_request(),
            },
        )
        .expect("approval revoke protocol response");

        assert_eq!(
            response["source"],
            "rust_approval_revoke_state_update_protocol"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "approval.revoke");
        assert_eq!(response["operator_control"]["lease_status"], "revoked");
        assert_eq!(
            response["operator_control"]["authority_hash"],
            "sha256:approval-authority-revoke"
        );
        assert_eq!(
            response["record"]["schema_version"],
            APPROVAL_REVOKE_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
    }

    #[test]
    fn matches_operation_label() {
        let request = ActionRequest {
            target: ActionTarget::BrowserInteract,
            params: br#"{"url":"https://example.com/a"}"#.to_vec(),
            context: ActionContext {
                agent_id: "agent".to_string(),
                session_id: None,
                window_id: None,
            },
            nonce: 1,
        };
        let context = ApprovalScopeContext::from_action_request(&request)
            .with_operation_label("desktop_agent.resume");
        let decision =
            AuthorityScopeMatcher::evaluate(&authority(vec!["desktop_agent.resume"]), &context);
        assert!(decision.allowed);
    }

    #[test]
    fn rejects_out_of_scope_authority() {
        let context = ApprovalScopeContext::new("browser::interact");
        let decision =
            AuthorityScopeMatcher::evaluate(&authority(vec!["wallet_network.approval"]), &context);
        assert!(!decision.allowed);
        assert_eq!(
            decision.reason.as_deref(),
            Some("approval_grant_out_of_scope:target=browser::interact")
        );
    }

    #[test]
    fn matches_domain_scope_from_params() {
        let request = ActionRequest {
            target: ActionTarget::NetFetch,
            params: br#"{"url":"https://api.example.com/v1"}"#.to_vec(),
            context: ActionContext {
                agent_id: "agent".to_string(),
                session_id: None,
                window_id: None,
            },
            nonce: 1,
        };
        let context = ApprovalScopeContext::from_action_request(&request);
        let decision =
            AuthorityScopeMatcher::evaluate(&authority(vec!["domain:api.example.com"]), &context);
        assert!(decision.allowed);
    }
}
