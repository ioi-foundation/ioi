use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
    CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION,
    CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    CODING_TOOL_BUDGET_RECOVERY_STATE_UPDATE_RESULT_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq)]
pub enum CodingToolBudgetRecoveryStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum CodingToolBudgetRecoveryAdmissionRequiredError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
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
pub struct CodingToolBudgetRecoveryAdmissionRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    pub run_id: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub approval_id: Option<String>,
    #[serde(default)]
    pub source_event_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolBudgetRecoveryAdmissionRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    pub run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub evidence_refs: Vec<String>,
    pub details: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CodingToolBudgetRecoveryCommandError {
    code: &'static str,
    message: String,
}

impl CodingToolBudgetRecoveryCommandError {
    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    fn from_debug<E: std::fmt::Debug>(code: &'static str, error: E) -> Self {
        Self {
            code,
            message: format!("{error:?}"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CodingToolBudgetRecoveryStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: CodingToolBudgetRecoveryStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct CodingToolBudgetRecoveryAdmissionRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: CodingToolBudgetRecoveryAdmissionRequiredRequest,
}

pub fn plan_coding_tool_budget_recovery_state_update_response(
    request: CodingToolBudgetRecoveryStateUpdateBridgeRequest,
) -> Result<Value, CodingToolBudgetRecoveryCommandError> {
    let record = CodingToolBudgetRecoveryStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            CodingToolBudgetRecoveryCommandError::from_debug(
                "coding_tool_budget_recovery_state_update_invalid",
                error,
            )
        })?;
    Ok(json!({
        "source": "rust_coding_tool_budget_recovery_state_update_command",
        "backend": runtime_control_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
    }))
}

pub fn plan_coding_tool_budget_recovery_admission_required_response(
    request: CodingToolBudgetRecoveryAdmissionRequiredBridgeRequest,
) -> Result<Value, CodingToolBudgetRecoveryCommandError> {
    let record = CodingToolBudgetRecoveryAdmissionRequiredCore
        .plan(&request.request)
        .map_err(|error| {
            CodingToolBudgetRecoveryCommandError::from_debug(
                "coding_tool_budget_recovery_admission_required_invalid",
                error,
            )
        })?;
    Ok(json!({
        "source": "rust_coding_tool_budget_recovery_admission_required_command",
        "backend": runtime_control_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "status_code": record.status_code,
        "code": record.code.clone(),
        "message": record.message.clone(),
        "rust_core_boundary": record.rust_core_boundary.clone(),
        "operation_kind": record.operation_kind.clone(),
        "details": record.details.clone(),
    }))
}

fn runtime_control_policy_backend(backend: Option<String>) -> String {
    backend.unwrap_or_else(|| "rust_policy".to_string())
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
pub struct CodingToolBudgetRecoveryAdmissionRequiredCore;

impl CodingToolBudgetRecoveryAdmissionRequiredCore {
    pub fn plan(
        &self,
        request: &CodingToolBudgetRecoveryAdmissionRequiredRequest,
    ) -> Result<
        CodingToolBudgetRecoveryAdmissionRequiredRecord,
        CodingToolBudgetRecoveryAdmissionRequiredError,
    > {
        request.validate()?;
        let operation = optional_trimmed(Some(request.operation.as_str())).unwrap();
        let operation_kind = optional_trimmed(Some(request.operation_kind.as_str())).unwrap();
        let run_id = optional_trimmed(Some(request.run_id.as_str())).unwrap();
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let action = optional_trimmed(request.action.as_deref());
        let approval_id = optional_trimmed(request.approval_id.as_deref());
        let source_event_id = optional_trimmed(request.source_event_id.as_deref());
        let source = optional_trimmed(request.source.as_deref());
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                format!("{operation}_js_facade_retired"),
                "rust_daemon_core_coding_tool_budget_recovery_admission_required".to_string(),
                "agentgres_coding_tool_budget_recovery_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let details = json!({
            "rust_core_boundary": "runtime.coding_tool_budget_recovery",
            "operation": operation,
            "operation_kind": operation_kind,
            "run_id": run_id,
            "thread_id": thread_id,
            "action": action,
            "approval_id": approval_id,
            "source_event_id": source_event_id,
            "source": source,
            "evidence_refs": evidence_refs,
        });

        Ok(CodingToolBudgetRecoveryAdmissionRequiredRecord {
            schema_version: CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION
                .to_string(),
            object: "ioi.runtime_coding_tool_budget_recovery_admission_required".to_string(),
            status: "rust_core_required".to_string(),
            status_code: 501,
            code: "runtime_coding_tool_budget_recovery_rust_core_required".to_string(),
            message:
                "Runtime coding-tool budget recovery requires direct Rust daemon-core admission and persistence."
                    .to_string(),
            rust_core_boundary: "runtime.coding_tool_budget_recovery".to_string(),
            operation,
            operation_kind,
            run_id,
            thread_id,
            action,
            approval_id,
            source_event_id,
            source,
            evidence_refs,
            details,
            generated_at: "rust_policy_core".to_string(),
        })
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

impl CodingToolBudgetRecoveryAdmissionRequiredRequest {
    pub fn validate(&self) -> Result<(), CodingToolBudgetRecoveryAdmissionRequiredError> {
        if self.schema_version
            != CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION
        {
            return Err(
                CodingToolBudgetRecoveryAdmissionRequiredError::InvalidSchemaVersion {
                    expected: CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        if optional_trimmed(Some(self.operation.as_str())).is_none() {
            return Err(CodingToolBudgetRecoveryAdmissionRequiredError::MissingField("operation"));
        }
        if optional_trimmed(Some(self.operation_kind.as_str())).is_none() {
            return Err(
                CodingToolBudgetRecoveryAdmissionRequiredError::MissingField("operation_kind"),
            );
        }
        if optional_trimmed(Some(self.run_id.as_str())).is_none() {
            return Err(CodingToolBudgetRecoveryAdmissionRequiredError::MissingField("run_id"));
        }
        Ok(())
    }
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn rust_policy_shapes_coding_tool_budget_recovery_state_update_command_response() {
        let response = plan_coding_tool_budget_recovery_state_update_response(
            CodingToolBudgetRecoveryStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: coding_tool_budget_recovery_state_update_request(),
            },
        )
        .expect("coding tool budget recovery state update command response");

        assert_eq!(
            response["source"],
            "rust_coding_tool_budget_recovery_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "workflow.run.retry_completed");
        assert_eq!(
            response["operator_control"]["approval_id"],
            "approval_budget"
        );
        assert!(response["operator_control"].get("approvalId").is_none());
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("receiptRefs").is_none());
        assert!(response["operator_control"]
            .get("policyDecisionRefs")
            .is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["control"],
            "coding_tool_budget_recovery"
        );
    }

    #[test]
    fn rust_policy_plans_coding_tool_budget_recovery_admission_required() {
        let record = CodingToolBudgetRecoveryAdmissionRequiredCore
            .plan(&CodingToolBudgetRecoveryAdmissionRequiredRequest {
                schema_version:
                    CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION
                        .to_string(),
                operation: "coding_tool_budget_recovery_control".to_string(),
                operation_kind: "workflow.run.coding_tool_budget_recovery".to_string(),
                run_id: "run_alpha".to_string(),
                thread_id: Some("thread_alpha".to_string()),
                action: Some("retry_approved".to_string()),
                approval_id: Some("approval_alpha".to_string()),
                source_event_id: Some("event_budget".to_string()),
                source: Some("agent_studio".to_string()),
                evidence_refs: vec![
                    "coding_tool_budget_recovery_js_facade_retired".to_string(),
                    "rust_daemon_core_budget_recovery_admission_required".to_string(),
                    "agentgres_budget_recovery_state_truth_required".to_string(),
                ],
            })
            .expect("coding-tool budget recovery admission required");

        assert_eq!(
            record.schema_version,
            CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(
            record.code,
            "runtime_coding_tool_budget_recovery_rust_core_required"
        );
        assert_eq!(
            record.rust_core_boundary,
            "runtime.coding_tool_budget_recovery"
        );
        assert_eq!(record.operation, "coding_tool_budget_recovery_control");
        assert_eq!(
            record.operation_kind,
            "workflow.run.coding_tool_budget_recovery"
        );
        assert_eq!(record.details["run_id"], "run_alpha");
        assert_eq!(record.details["thread_id"], "thread_alpha");
        assert_eq!(record.details["approval_id"], "approval_alpha");
        assert!(record.details.get("runId").is_none());
    }

    #[test]
    fn rust_policy_shapes_coding_tool_budget_recovery_admission_required_command_response() {
        let response = plan_coding_tool_budget_recovery_admission_required_response(
            CodingToolBudgetRecoveryAdmissionRequiredBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: CodingToolBudgetRecoveryAdmissionRequiredRequest {
                    schema_version:
                        CODING_TOOL_BUDGET_RECOVERY_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION
                            .to_string(),
                    operation: "coding_tool_budget_recovery_control".to_string(),
                    operation_kind: "workflow.run.coding_tool_budget_recovery".to_string(),
                    run_id: "run_alpha".to_string(),
                    thread_id: Some("thread_alpha".to_string()),
                    action: Some("retry_approved".to_string()),
                    approval_id: Some("approval_alpha".to_string()),
                    source_event_id: Some("event_budget".to_string()),
                    source: Some("agent_studio".to_string()),
                    evidence_refs: vec![
                        "coding_tool_budget_recovery_js_facade_retired".to_string(),
                        "rust_daemon_core_budget_recovery_admission_required".to_string(),
                        "agentgres_budget_recovery_state_truth_required".to_string(),
                    ],
                },
            },
        )
        .expect("coding-tool budget recovery admission-required command response");

        assert_eq!(
            response["source"],
            "rust_coding_tool_budget_recovery_admission_required_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "runtime_coding_tool_budget_recovery_rust_core_required"
        );
        assert_eq!(
            response["details"]["rust_core_boundary"],
            "runtime.coding_tool_budget_recovery"
        );
        assert_eq!(
            response["details"]["operation"],
            "coding_tool_budget_recovery_control"
        );
        assert_eq!(
            response["details"]["operation_kind"],
            "workflow.run.coding_tool_budget_recovery"
        );
        assert_eq!(response["details"]["run_id"], "run_alpha");
        assert_eq!(response["details"]["approval_id"], "approval_alpha");
        assert!(response["details"].get("runId").is_none());
        assert!(response["details"].get("approvalId").is_none());
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
}
