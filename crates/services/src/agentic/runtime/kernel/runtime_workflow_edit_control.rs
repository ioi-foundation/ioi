use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const RUNTIME_WORKFLOW_EDIT_CONTROL_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.workflow-edit-control-request.v1";
pub const RUNTIME_WORKFLOW_EDIT_CONTROL_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.workflow_edit_control.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeWorkflowEditControlRequest {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub event_stream_id: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub proposal_id: Option<String>,
    #[serde(default)]
    pub edit_intent_id: Option<String>,
    #[serde(default)]
    pub approval_id: Option<String>,
    #[serde(default)]
    pub workflow_graph_id: Option<String>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    #[serde(default)]
    pub workflow_path: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub event_seed: Option<String>,
    #[serde(default)]
    pub request: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeWorkflowEditControlCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeWorkflowEditControlCommandError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeWorkflowEditControlCore;

#[derive(Debug, Clone)]
pub struct RuntimeWorkflowEditControlRecord {
    pub operation: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub proposal_id: String,
    pub status: String,
    pub event: Value,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
}

impl RuntimeWorkflowEditControlCore {
    pub fn plan(
        &self,
        request: &RuntimeWorkflowEditControlRequest,
    ) -> Result<RuntimeWorkflowEditControlRecord, RuntimeWorkflowEditControlCommandError> {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_WORKFLOW_EDIT_CONTROL_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeWorkflowEditControlCommandError::new(
                    "runtime_workflow_edit_control_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_WORKFLOW_EDIT_CONTROL_REQUEST_SCHEMA_VERSION}, got {schema_version}"
                    ),
                ));
            }
        }

        let operation_kind = normalized_operation_kind(request)?;
        let operation = operation_for_kind(&operation_kind).to_string();
        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeWorkflowEditControlCommandError::new(
                "runtime_workflow_edit_control_thread_id_required",
                "workflow edit control requires thread_id",
            )
        })?;
        let event_stream_id =
            optional_trimmed(request.event_stream_id.as_deref()).ok_or_else(|| {
                RuntimeWorkflowEditControlCommandError::new(
                    "runtime_workflow_edit_control_event_stream_required",
                    "workflow edit control requires event_stream_id",
                )
            })?;
        let event_seed = optional_trimmed(request.event_seed.as_deref())
            .or_else(|| string_field(&request.request, "event_seed"))
            .or_else(|| string_field(&request.request, "created_at"))
            .unwrap_or_else(|| operation_kind.clone());
        let seed = format!("{thread_id}:{operation_kind}:{event_seed}");
        let event_hash = short_hash(seed);
        let requested_proposal_id = optional_trimmed(request.proposal_id.as_deref())
            .or_else(|| string_field(&request.request, "proposal_id"));
        if operation_kind == "workflow.edit.apply" && requested_proposal_id.is_none() {
            return Err(RuntimeWorkflowEditControlCommandError::new(
                "runtime_workflow_edit_control_proposal_id_required",
                "workflow edit apply requires proposal_id",
            ));
        }
        let proposal_id =
            requested_proposal_id.unwrap_or_else(|| format!("workflow_edit_proposal_{event_hash}"));
        let turn_id = optional_trimmed(request.turn_id.as_deref())
            .or_else(|| string_field(&request.request, "turn_id"));
        let edit_intent_id = optional_trimmed(request.edit_intent_id.as_deref())
            .or_else(|| string_field(&request.request, "edit_intent_id"));
        let approval_id = optional_trimmed(request.approval_id.as_deref())
            .or_else(|| string_field(&request.request, "approval_id"));
        let workflow_graph_id = optional_trimmed(request.workflow_graph_id.as_deref())
            .or_else(|| string_field(&request.request, "workflow_graph_id"));
        let workflow_node_id = optional_trimmed(request.workflow_node_id.as_deref())
            .or_else(|| string_field(&request.request, "workflow_node_id"))
            .unwrap_or_else(|| "runtime.workflow_edit".to_string());
        let workflow_path = optional_trimmed(request.workflow_path.as_deref())
            .or_else(|| string_field(&request.request, "workflow_path"));
        let workspace_root = optional_trimmed(request.workspace_root.as_deref())
            .or_else(|| string_field(&request.request, "workspace_root"));
        let source = optional_trimmed(request.source.as_deref())
            .or_else(|| string_field(&request.request, "source"))
            .unwrap_or_else(|| "agent_studio".to_string());
        let status = optional_trimmed(request.status.as_deref())
            .or_else(|| string_field(&request.request, "status"))
            .unwrap_or_else(|| default_status(&operation_kind).to_string());
        let receipt_refs = workflow_edit_receipt_refs(request, &operation, &event_hash);
        let policy_decision_refs =
            workflow_edit_policy_decision_refs(request, &operation, &event_hash);
        let evidence_refs = workflow_edit_evidence_refs(request, &operation_kind);
        let event_id = string_field(&request.request, "event_id").unwrap_or_else(|| {
            format!("event_workflow_edit_{}_{}", safe_id(&operation), event_hash)
        });
        let turn_or_thread = turn_id.clone().unwrap_or_else(|| thread_id.clone());
        let event = json!({
            "event_id": event_id,
            "event_stream_id": event_stream_id,
            "thread_id": thread_id,
            "turn_id": turn_id.unwrap_or_default(),
            "item_id": format!("{turn_or_thread}:item:workflow_edit:{}:{}", safe_id(&operation), safe_id(&proposal_id)),
            "idempotency_key": string_field(&request.request, "idempotency_key")
                .unwrap_or_else(|| format!("thread:{thread_id}:{operation_kind}:{proposal_id}:{event_hash}")),
            "source": source,
            "source_event_kind": source_event_kind(&operation_kind),
            "event_kind": operation_kind,
            "status": status,
            "actor": "operator",
            "workspace_root": workspace_root.unwrap_or_default(),
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "component_kind": "workflow_edit",
            "payload_schema_version": "ioi.runtime.workflow-edit-control.v1",
            "payload": workflow_edit_payload(
                request,
                &operation,
                &proposal_id,
                edit_intent_id,
                approval_id,
                workflow_path,
            ),
            "receipt_refs": receipt_refs,
            "policy_decision_refs": policy_decision_refs,
            "artifact_refs": string_array_field(&request.request, "artifact_refs"),
            "rollback_refs": string_array_field(&request.request, "rollback_refs"),
            "redaction_profile": "internal",
            "fixture_profile": "local_daemon_agentgres_projection",
            "evidence_refs": evidence_refs,
        });

        Ok(RuntimeWorkflowEditControlRecord {
            operation,
            operation_kind,
            thread_id,
            proposal_id,
            status,
            event,
            receipt_refs,
            policy_decision_refs,
            evidence_refs,
        })
    }
}

fn normalized_operation_kind(
    request: &RuntimeWorkflowEditControlRequest,
) -> Result<String, RuntimeWorkflowEditControlCommandError> {
    let operation_kind = optional_trimmed(request.operation_kind.as_deref()).or_else(|| {
        optional_trimmed(request.operation.as_deref()).map(|operation| match operation.as_str() {
            "workflow_edit_proposal" | "proposal" | "propose" => {
                "workflow.edit_proposed".to_string()
            }
            "workflow_edit_apply" | "apply" => "workflow.edit.apply".to_string(),
            _ => operation,
        })
    });
    match operation_kind.as_deref() {
        Some("workflow.edit_proposed") | Some("workflow.edit.apply") => Ok(operation_kind.unwrap()),
        Some(value) => Err(RuntimeWorkflowEditControlCommandError::new(
            "runtime_workflow_edit_control_operation_kind_unsupported",
            format!("{value} is not yet Rust-owned"),
        )),
        None => Err(RuntimeWorkflowEditControlCommandError::new(
            "runtime_workflow_edit_control_operation_kind_required",
            "workflow edit control requires operation_kind",
        )),
    }
}

fn operation_for_kind(operation_kind: &str) -> &'static str {
    match operation_kind {
        "workflow.edit.apply" => "workflow_edit_apply",
        _ => "workflow_edit_proposal",
    }
}

fn default_status(operation_kind: &str) -> &'static str {
    match operation_kind {
        "workflow.edit.apply" => "applied",
        _ => "pending_approval",
    }
}

fn source_event_kind(operation_kind: &str) -> &'static str {
    match operation_kind {
        "workflow.edit.apply" => "WorkflowEdit.Apply",
        _ => "WorkflowEdit.Proposed",
    }
}

fn workflow_edit_payload(
    request: &RuntimeWorkflowEditControlRequest,
    operation: &str,
    proposal_id: &str,
    edit_intent_id: Option<String>,
    approval_id: Option<String>,
    workflow_path: Option<String>,
) -> Value {
    let workflow_patch = request.request.get("workflow_patch");
    let code_diff = request.request.get("code_diff");
    json!({
        "schema_version": "ioi.runtime.workflow-edit-control.payload.v1",
        "operation": operation,
        "proposal_id": proposal_id,
        "edit_intent_id": edit_intent_id,
        "approval_id": approval_id,
        "workflow_path": workflow_path,
        "target_workflow_node_ids": string_array_field(&request.request, "target_workflow_node_ids"),
        "bounded_targets": request.request.get("bounded_targets").cloned().unwrap_or_else(|| json!([])),
        "workflow_patch_present": workflow_patch.is_some(),
        "workflow_patch_hash": workflow_patch.map(value_hash),
        "code_diff_present": code_diff.is_some(),
        "code_diff_hash": code_diff.map(value_hash),
    })
}

fn workflow_edit_receipt_refs(
    request: &RuntimeWorkflowEditControlRequest,
    operation: &str,
    event_hash: &str,
) -> Vec<String> {
    unique_strings(
        request
            .receipt_refs
            .iter()
            .cloned()
            .chain(string_array_field(&request.request, "receipt_refs"))
            .chain(std::iter::once(format!(
                "receipt_workflow_edit_{}_{event_hash}",
                safe_id(operation)
            )))
            .collect(),
    )
}

fn workflow_edit_policy_decision_refs(
    request: &RuntimeWorkflowEditControlRequest,
    operation: &str,
    event_hash: &str,
) -> Vec<String> {
    unique_strings(
        request
            .policy_decision_refs
            .iter()
            .cloned()
            .chain(string_array_field(&request.request, "policy_decision_refs"))
            .chain(std::iter::once(format!(
                "policy_workflow_edit_{}_{event_hash}",
                safe_id(operation)
            )))
            .collect(),
    )
}

fn workflow_edit_evidence_refs(
    request: &RuntimeWorkflowEditControlRequest,
    operation_kind: &str,
) -> Vec<String> {
    if !request.evidence_refs.is_empty() {
        return request.evidence_refs.clone();
    }
    let operation_ref = match operation_kind {
        "workflow.edit.apply" => "runtime_workflow_edit_apply_control_rust_owned",
        _ => "runtime_workflow_edit_proposal_control_rust_owned",
    };
    vec![
        operation_ref.to_string(),
        "runtime_workflow_edit_control_event_rust_owned".to_string(),
        "agentgres_runtime_thread_event_truth_required".to_string(),
    ]
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    optional_trimmed(value.get(key)?.as_str())
}

fn string_array_field(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| optional_trimmed(value.as_str()))
                .collect()
        })
        .unwrap_or_default()
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}

fn safe_id(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn short_hash(value: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hex::encode(&hasher.finalize()[..8])
}

fn value_hash(value: &Value) -> String {
    short_hash(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request(operation_kind: &str) -> RuntimeWorkflowEditControlRequest {
        RuntimeWorkflowEditControlRequest {
            schema_version: Some(RUNTIME_WORKFLOW_EDIT_CONTROL_REQUEST_SCHEMA_VERSION.to_string()),
            operation_kind: Some(operation_kind.to_string()),
            thread_id: Some("thread_alpha".to_string()),
            event_stream_id: Some("event_stream_thread_alpha".to_string()),
            turn_id: Some("turn_alpha".to_string()),
            proposal_id: Some("proposal_alpha".to_string()),
            workflow_graph_id: Some("graph_alpha".to_string()),
            workflow_node_id: Some("node_alpha".to_string()),
            workflow_path: Some("workflows/demo.json".to_string()),
            request: json!({
                "source": "agent_studio",
                "workflow_patch": { "nodes": [{ "id": "node_alpha" }] },
                "target_workflow_node_ids": ["node_alpha"],
                "receipt_refs": ["receipt_request"],
                "policy_decision_refs": ["policy_request"]
            }),
            ..Default::default()
        }
    }

    #[test]
    fn rust_plans_runtime_workflow_edit_proposal_control_event() {
        let record = RuntimeWorkflowEditControlCore
            .plan(&base_request("workflow.edit_proposed"))
            .expect("workflow edit proposal control");

        assert_eq!(record.operation_kind, "workflow.edit_proposed");
        assert_eq!(record.proposal_id, "proposal_alpha");
        assert_eq!(record.event["event_kind"], "workflow.edit_proposed");
        assert_eq!(record.event["payload"]["workflow_patch_present"], true);
        assert!(record
            .receipt_refs
            .iter()
            .any(|value| value.starts_with("receipt_workflow_edit_workflow_edit_proposal_")));
        assert!(record
            .evidence_refs
            .contains(&"runtime_workflow_edit_proposal_control_rust_owned".to_string()));
        assert!(record
            .evidence_refs
            .contains(&"runtime_workflow_edit_control_event_rust_owned".to_string()));
    }

    #[test]
    fn rust_plans_runtime_workflow_edit_apply_control_event() {
        let record = RuntimeWorkflowEditControlCore
            .plan(&base_request("workflow.edit.apply"))
            .expect("workflow edit apply control");

        assert_eq!(record.operation, "workflow_edit_apply");
        assert_eq!(record.operation_kind, "workflow.edit.apply");
        assert_eq!(record.status, "applied");
        assert_eq!(record.event["source_event_kind"], "WorkflowEdit.Apply");
        assert_eq!(
            record.event["payload"]["proposal_id"],
            Value::String("proposal_alpha".to_string())
        );
        assert!(record
            .evidence_refs
            .contains(&"runtime_workflow_edit_apply_control_rust_owned".to_string()));
    }

    #[test]
    fn rust_rejects_runtime_workflow_edit_apply_without_proposal_id() {
        let mut request = base_request("workflow.edit.apply");
        request.proposal_id = None;
        request
            .request
            .as_object_mut()
            .expect("request object")
            .remove("proposal_id");

        let error = RuntimeWorkflowEditControlCore
            .plan(&request)
            .expect_err("missing apply proposal id");
        assert_eq!(
            error.code(),
            "runtime_workflow_edit_control_proposal_id_required"
        );
    }

    #[test]
    fn rust_rejects_unowned_runtime_workflow_edit_control_kind() {
        let mut request = base_request("workflow.edit.delete");
        let error = RuntimeWorkflowEditControlCore
            .plan(&request)
            .expect_err("unsupported workflow edit operation kind");
        assert_eq!(
            error.code(),
            "runtime_workflow_edit_control_operation_kind_unsupported"
        );

        request.operation_kind = None;
        request.operation = None;
        let error = RuntimeWorkflowEditControlCore
            .plan(&request)
            .expect_err("missing workflow edit operation kind");
        assert_eq!(
            error.code(),
            "runtime_workflow_edit_control_operation_kind_required"
        );
    }
}
