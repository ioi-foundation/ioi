use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
    DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION,
    WORKFLOW_EDIT_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
    WORKFLOW_EDIT_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq)]
pub enum WorkflowEditAdmissionRequiredError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum DiagnosticsRepairAdmissionRequiredError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowEditAdmissionRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    pub thread_id: String,
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
    pub source: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowEditAdmissionRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    pub thread_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edit_intent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_graph_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub evidence_refs: Vec<String>,
    pub details: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticsRepairAdmissionRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub decision_id: Option<String>,
    #[serde(default)]
    pub gate_event_id: Option<String>,
    #[serde(default)]
    pub gate_id: Option<String>,
    #[serde(default)]
    pub snapshot_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticsRepairAdmissionRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub evidence_refs: Vec<String>,
    pub details: Value,
    pub generated_at: String,
}

#[derive(Debug, Default, Clone)]
pub struct WorkflowEditAdmissionRequiredCore;

impl WorkflowEditAdmissionRequiredCore {
    pub fn plan(
        &self,
        request: &WorkflowEditAdmissionRequiredRequest,
    ) -> Result<WorkflowEditAdmissionRequiredRecord, WorkflowEditAdmissionRequiredError> {
        request.validate()?;
        let thread_id = optional_trimmed(Some(request.thread_id.as_str())).unwrap();
        let operation = optional_trimmed(Some(request.operation.as_str())).unwrap();
        let operation_kind = optional_trimmed(Some(request.operation_kind.as_str())).unwrap();
        let turn_id = optional_trimmed(request.turn_id.as_deref());
        let proposal_id = optional_trimmed(request.proposal_id.as_deref());
        let edit_intent_id = optional_trimmed(request.edit_intent_id.as_deref());
        let approval_id = optional_trimmed(request.approval_id.as_deref());
        let workflow_graph_id = optional_trimmed(request.workflow_graph_id.as_deref());
        let workflow_node_id = optional_trimmed(request.workflow_node_id.as_deref());
        let workflow_path = optional_trimmed(request.workflow_path.as_deref());
        let source = optional_trimmed(request.source.as_deref());
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                format!("{operation}_js_facade_retired"),
                "rust_daemon_core_workflow_edit_admission_required".to_string(),
                "agentgres_workflow_edit_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let details = json!({
            "rust_core_boundary": "runtime.workflow_edit",
            "operation": operation,
            "operation_kind": operation_kind,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "proposal_id": proposal_id,
            "edit_intent_id": edit_intent_id,
            "approval_id": approval_id,
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
            "workflow_path": workflow_path,
            "source": source,
            "evidence_refs": evidence_refs,
        });

        Ok(WorkflowEditAdmissionRequiredRecord {
            schema_version: WORKFLOW_EDIT_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_workflow_edit_admission_required".to_string(),
            status: "rust_core_required".to_string(),
            status_code: 501,
            code: "runtime_workflow_edit_rust_core_required".to_string(),
            message:
                "Runtime workflow edit control requires direct Rust daemon-core admission and persistence."
                    .to_string(),
            rust_core_boundary: "runtime.workflow_edit".to_string(),
            operation,
            operation_kind,
            thread_id,
            turn_id,
            proposal_id,
            edit_intent_id,
            approval_id,
            workflow_graph_id,
            workflow_node_id,
            workflow_path,
            source,
            evidence_refs,
            details,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

impl WorkflowEditAdmissionRequiredRequest {
    pub fn validate(&self) -> Result<(), WorkflowEditAdmissionRequiredError> {
        if self.schema_version != WORKFLOW_EDIT_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(WorkflowEditAdmissionRequiredError::InvalidSchemaVersion {
                expected: WORKFLOW_EDIT_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.operation.as_str())).is_none() {
            return Err(WorkflowEditAdmissionRequiredError::MissingField(
                "operation",
            ));
        }
        if optional_trimmed(Some(self.operation_kind.as_str())).is_none() {
            return Err(WorkflowEditAdmissionRequiredError::MissingField(
                "operation_kind",
            ));
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(WorkflowEditAdmissionRequiredError::MissingField(
                "thread_id",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct DiagnosticsRepairAdmissionRequiredCore;

impl DiagnosticsRepairAdmissionRequiredCore {
    pub fn plan(
        &self,
        request: &DiagnosticsRepairAdmissionRequiredRequest,
    ) -> Result<DiagnosticsRepairAdmissionRequiredRecord, DiagnosticsRepairAdmissionRequiredError>
    {
        request.validate()?;
        let operation = optional_trimmed(Some(request.operation.as_str())).unwrap();
        let operation_kind = optional_trimmed(Some(request.operation_kind.as_str())).unwrap();
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let decision_id = optional_trimmed(request.decision_id.as_deref());
        let gate_event_id = optional_trimmed(request.gate_event_id.as_deref());
        let gate_id = optional_trimmed(request.gate_id.as_deref());
        let snapshot_id = optional_trimmed(request.snapshot_id.as_deref());
        let source = optional_trimmed(request.source.as_deref());
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                format!("{operation}_js_facade_retired"),
                "rust_daemon_core_diagnostics_repair_admission_required".to_string(),
                "agentgres_diagnostics_repair_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let details = json!({
            "rust_core_boundary": "runtime.diagnostics_repair",
            "operation": operation,
            "operation_kind": operation_kind,
            "thread_id": thread_id,
            "decision_id": decision_id,
            "gate_event_id": gate_event_id,
            "gate_id": gate_id,
            "snapshot_id": snapshot_id,
            "source": source,
            "evidence_refs": evidence_refs,
        });

        Ok(DiagnosticsRepairAdmissionRequiredRecord {
            schema_version: DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_diagnostics_repair_admission_required".to_string(),
            status: "rust_core_required".to_string(),
            status_code: 501,
            code: "runtime_diagnostics_repair_rust_core_required".to_string(),
            message:
                "Runtime diagnostics repair control requires direct Rust daemon-core admission and persistence."
                    .to_string(),
            rust_core_boundary: "runtime.diagnostics_repair".to_string(),
            operation,
            operation_kind,
            thread_id,
            decision_id,
            gate_event_id,
            gate_id,
            snapshot_id,
            source,
            evidence_refs,
            details,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

impl DiagnosticsRepairAdmissionRequiredRequest {
    pub fn validate(&self) -> Result<(), DiagnosticsRepairAdmissionRequiredError> {
        if self.schema_version != DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(
                DiagnosticsRepairAdmissionRequiredError::InvalidSchemaVersion {
                    expected: DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        if optional_trimmed(Some(self.operation.as_str())).is_none() {
            return Err(DiagnosticsRepairAdmissionRequiredError::MissingField(
                "operation",
            ));
        }
        if optional_trimmed(Some(self.operation_kind.as_str())).is_none() {
            return Err(DiagnosticsRepairAdmissionRequiredError::MissingField(
                "operation_kind",
            ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_policy_plans_workflow_edit_admission_required() {
        let record = WorkflowEditAdmissionRequiredCore
            .plan(&WorkflowEditAdmissionRequiredRequest {
                schema_version: WORKFLOW_EDIT_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION.to_string(),
                operation: "workflow_edit_proposal".to_string(),
                operation_kind: "workflow.edit_proposed".to_string(),
                thread_id: "thread_alpha".to_string(),
                turn_id: Some("turn_alpha".to_string()),
                proposal_id: Some("proposal_alpha".to_string()),
                edit_intent_id: Some("intent_alpha".to_string()),
                approval_id: Some("approval_alpha".to_string()),
                workflow_graph_id: Some("graph_alpha".to_string()),
                workflow_node_id: Some("node_alpha".to_string()),
                workflow_path: Some("workflows/demo.json".to_string()),
                source: Some("agent_studio".to_string()),
                evidence_refs: vec![
                    "workflow_edit_proposal_js_facade_retired".to_string(),
                    "rust_daemon_core_workflow_edit_proposal_required".to_string(),
                    "agentgres_workflow_edit_proposal_truth_required".to_string(),
                ],
            })
            .expect("workflow edit admission required");

        assert_eq!(
            record.schema_version,
            WORKFLOW_EDIT_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(record.code, "runtime_workflow_edit_rust_core_required");
        assert_eq!(record.rust_core_boundary, "runtime.workflow_edit");
        assert_eq!(record.operation, "workflow_edit_proposal");
        assert_eq!(record.operation_kind, "workflow.edit_proposed");
        assert_eq!(record.details["thread_id"], "thread_alpha");
        assert_eq!(record.details["proposal_id"], "proposal_alpha");
        assert!(record.details.get("threadId").is_none());
        assert!(record.details.get("proposalId").is_none());
    }

    #[test]
    fn rust_policy_plans_diagnostics_repair_admission_required() {
        let record = DiagnosticsRepairAdmissionRequiredCore
            .plan(&DiagnosticsRepairAdmissionRequiredRequest {
                schema_version: DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION
                    .to_string(),
                operation: "diagnostics_repair_decision_execution".to_string(),
                operation_kind: "diagnostics.repair_decision.execute".to_string(),
                thread_id: Some("thread_alpha".to_string()),
                decision_id: Some("decision_alpha".to_string()),
                gate_event_id: Some("event_gate".to_string()),
                gate_id: Some("gate_alpha".to_string()),
                snapshot_id: Some("snapshot_alpha".to_string()),
                source: Some("agent_studio".to_string()),
                evidence_refs: vec![
                    "diagnostics_repair_decision_execution_js_facade_retired".to_string(),
                    "rust_daemon_core_diagnostics_repair_admission_required".to_string(),
                    "agentgres_diagnostics_repair_state_truth_required".to_string(),
                ],
            })
            .expect("diagnostics repair admission required");

        assert_eq!(
            record.schema_version,
            DIAGNOSTICS_REPAIR_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(record.code, "runtime_diagnostics_repair_rust_core_required");
        assert_eq!(record.rust_core_boundary, "runtime.diagnostics_repair");
        assert_eq!(record.operation, "diagnostics_repair_decision_execution");
        assert_eq!(record.operation_kind, "diagnostics.repair_decision.execute");
        assert_eq!(record.details["thread_id"], "thread_alpha");
        assert_eq!(record.details["decision_id"], "decision_alpha");
        assert_eq!(record.details["gate_event_id"], "event_gate");
        assert_eq!(record.details["gate_id"], "gate_alpha");
        assert_eq!(record.details["snapshot_id"], "snapshot_alpha");
        assert!(record.details.get("threadId").is_none());
        assert!(record.details.get("decisionId").is_none());
        assert!(record.details.get("gateEventId").is_none());
    }
}
