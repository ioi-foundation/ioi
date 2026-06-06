use ioi_types::app::{ActionRequest, ActionTarget, ApprovalAuthority, ApprovalGrant};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

pub const CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-approval-request.v1";
pub const CODING_TOOL_APPROVAL_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-approval-result.v1";
pub const CODING_TOOL_APPROVAL_MANIFEST_SCHEMA_VERSION: &str =
    "ioi.runtime.coding-tool-approval-manifest.v1";
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
pub enum ApprovalRequestStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalDecisionStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
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
pub struct ApprovalRequestStateUpdateRequest {
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
pub struct ApprovalDecisionStateUpdateRequest {
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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalDecisionStateUpdateRecord {
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

#[derive(Debug, Default, Clone)]
pub struct CodingToolApprovalCore;

#[derive(Debug, Default, Clone)]
pub struct ApprovalRequestStateUpdateCore;

#[derive(Debug, Default, Clone)]
pub struct ApprovalDecisionStateUpdateCore;

impl ApprovalRequestStateUpdateCore {
    pub fn plan(
        &self,
        request: &ApprovalRequestStateUpdateRequest,
    ) -> Result<ApprovalRequestStateUpdateRecord, ApprovalRequestStateUpdateError> {
        request.validate()?;
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let run_id = optional_trimmed(request.run_id.as_deref());
        let source = optional_trimmed(Some(request.source.as_str()))
            .unwrap_or_else(|| "sdk_client".to_string());
        let reason = optional_trimmed(Some(request.reason.as_str()))
            .unwrap_or_else(|| "operator requested approval".to_string());
        let approval_id = optional_trimmed(Some(request.approval_id.as_str())).unwrap();
        let operator_control = json!({
            "control": "approval_request",
            "approvalId": approval_id,
            "status": "waiting_for_approval",
            "source": source,
            "reason": reason,
            "eventId": request.event_id,
            "seq": request.seq,
            "receiptRefs": request.receipt_refs.clone(),
            "policyDecisionRefs": request.policy_decision_refs.clone(),
            "createdAt": request.created_at,
        });
        let mut run = object_value(&request.run)
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

        Ok(ApprovalRequestStateUpdateRecord {
            schema_version: APPROVAL_REQUEST_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_approval_request_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "approval.required".to_string(),
            thread_id,
            run_id,
            updated_at: request.created_at.clone(),
            operator_control,
            run: Value::Object(run),
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
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let run_id = optional_trimmed(request.run_id.as_deref());
        let source = optional_trimmed(Some(request.source.as_str()))
            .unwrap_or_else(|| "sdk_client".to_string());
        let approval_id = optional_trimmed(Some(request.approval_id.as_str())).unwrap();
        let lease_id = optional_trimmed(request.lease_id.as_deref());
        let lease_status = optional_trimmed(Some(request.lease_status.as_str())).unwrap();
        let decision = normalized_approval_decision(Some(request.decision.as_str())).unwrap();
        let status = optional_trimmed(Some(request.status.as_str())).unwrap();
        let reason = optional_trimmed(request.reason.as_deref());
        let operator_control = json!({
            "control": "approval_decision",
            "approvalId": approval_id,
            "leaseId": lease_id,
            "leaseStatus": lease_status,
            "decision": decision,
            "status": status,
            "source": source,
            "reason": reason,
            "eventId": request.event_id,
            "seq": request.seq,
            "receiptRefs": request.receipt_refs.clone(),
            "policyDecisionRefs": request.policy_decision_refs.clone(),
            "createdAt": request.created_at,
        });
        let mut run = object_value(&request.run)
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

        Ok(ApprovalDecisionStateUpdateRecord {
            schema_version: APPROVAL_DECISION_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_approval_decision_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: format!("approval.{decision}"),
            thread_id,
            run_id,
            updated_at: request.created_at.clone(),
            operator_control,
            run: Value::Object(run),
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

impl ApprovalRequestStateUpdateRequest {
    pub fn validate(&self) -> Result<(), ApprovalRequestStateUpdateError> {
        if self.schema_version != APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(ApprovalRequestStateUpdateError::InvalidSchemaVersion {
                expected: APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if !self.run.is_object() {
            return Err(ApprovalRequestStateUpdateError::MissingField("run"));
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
        if !self.run.is_object() {
            return Err(ApprovalDecisionStateUpdateError::MissingField("run"));
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

fn object_value(value: &Value) -> Option<serde_json::Map<String, Value>> {
    value.as_object().cloned()
}

fn append_operator_control(existing: Option<&Value>, control: &Value) -> Value {
    let control_event_id = control.get("eventId").and_then(Value::as_str);
    let mut entries = existing
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let exists = control_event_id.is_some_and(|event_id| {
        entries
            .iter()
            .any(|entry| entry.get("eventId").and_then(Value::as_str) == Some(event_id))
    });
    if !exists {
        entries.push(control.clone());
    }
    Value::Array(entries)
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

fn value_hash(value: &Value) -> Result<String, CodingToolApprovalError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| CodingToolApprovalError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{ActionContext, SignatureSuite};

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
        ApprovalRequestStateUpdateRequest {
            schema_version: APPROVAL_REQUEST_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: Some("thread_alpha".to_string()),
            run_id: Some("run_alpha".to_string()),
            run: json!({
                "id": "run_alpha",
                "agentId": "agent_alpha",
                "status": "running",
                "turnStatus": "running",
                "trace": {},
            }),
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
        ApprovalDecisionStateUpdateRequest {
            schema_version: APPROVAL_DECISION_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: Some("thread_alpha".to_string()),
            run_id: Some("run_alpha".to_string()),
            run: json!({
                "id": "run_alpha",
                "agentId": "agent_alpha",
                "status": "blocked",
                "turnStatus": "waiting_for_approval",
                "trace": {},
            }),
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
        assert_eq!(record.operator_control["control"], "approval_request");
        assert_eq!(record.operator_control["approvalId"], "approval_alpha");
        assert_eq!(record.run["status"], "blocked");
        assert_eq!(record.run["turnStatus"], "waiting_for_approval");
        assert_eq!(
            record.run["trace"]["approvalRequests"][0]["eventId"],
            "event_approval"
        );
        assert_eq!(
            record.run["operatorControls"][0]["receiptRefs"][0],
            "receipt_approval"
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
        assert_eq!(record.operator_control["control"], "approval_decision");
        assert_eq!(record.operator_control["leaseId"], "lease_alpha");
        assert_eq!(record.run["turnStatus"], "waiting_for_approval");
        assert_eq!(
            record.run["trace"]["approvalDecisions"][0]["eventId"],
            "event_decision"
        );
        assert_eq!(
            record.run["operatorControls"][0]["receiptRefs"][0],
            "receipt_decision"
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
        assert_eq!(record.operator_control["leaseStatus"], "denied");
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
