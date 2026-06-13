use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{
    DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    OPERATOR_INTERRUPT_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    OPERATOR_STEER_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
    OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq)]
pub enum DiagnosticsOperatorOverrideStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    RetiredApprovalVerdictTransport(Vec<String>),
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
pub enum OperatorTurnControlAdmissionRequiredError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    UnsupportedOperationKind(String),
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
    pub operator_override_request: Value,
    #[serde(default)]
    pub decision: Value,
    #[serde(default)]
    pub repair_policy: Value,
    #[serde(default)]
    pub snapshot_id: Option<String>,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
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
pub struct OperatorTurnControlAdmissionRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub requested_action: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorTurnControlAdmissionRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    pub details: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OperatorControlCommandError {
    code: &'static str,
    message: String,
}

impl OperatorControlCommandError {
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
pub struct DiagnosticsOperatorOverrideStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: DiagnosticsOperatorOverrideStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct OperatorTurnControlAdmissionRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: OperatorTurnControlAdmissionRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub struct OperatorInterruptStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: OperatorInterruptStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct OperatorSteerStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: OperatorSteerStateUpdateRequest,
}

pub fn plan_diagnostics_operator_override_state_update_response(
    request: DiagnosticsOperatorOverrideStateUpdateBridgeRequest,
) -> Result<Value, OperatorControlCommandError> {
    let record = DiagnosticsOperatorOverrideStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            OperatorControlCommandError::from_debug(
                "diagnostics_operator_override_state_update_invalid",
                error,
            )
        })?;
    Ok(json!({
        "source": "rust_diagnostics_operator_override_state_update_command",
        "backend": runtime_control_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
    }))
}

pub fn plan_operator_turn_control_admission_required_response(
    request: OperatorTurnControlAdmissionRequiredBridgeRequest,
) -> Result<Value, OperatorControlCommandError> {
    let record = OperatorTurnControlAdmissionRequiredCore
        .plan(&request.request)
        .map_err(|error| {
            OperatorControlCommandError::from_debug(
                "operator_turn_control_admission_required_invalid",
                error,
            )
        })?;
    Ok(json!({
        "source": "rust_operator_turn_control_admission_required_command",
        "backend": runtime_control_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "status_code": record.status_code,
        "code": record.code.clone(),
        "message": record.message.clone(),
        "rust_core_boundary": record.rust_core_boundary.clone(),
        "operation": record.operation.clone(),
        "operation_kind": record.operation_kind.clone(),
        "details": record.details.clone(),
    }))
}

pub fn plan_operator_interrupt_state_update_response(
    request: OperatorInterruptStateUpdateBridgeRequest,
) -> Result<Value, OperatorControlCommandError> {
    let record = OperatorInterruptStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            OperatorControlCommandError::from_debug(
                "operator_interrupt_state_update_invalid",
                error,
            )
        })?;
    Ok(json!({
        "source": "rust_operator_interrupt_state_update_command",
        "backend": runtime_control_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "stop_condition": record.stop_condition.clone(),
        "run": record.run.clone(),
    }))
}

pub fn plan_operator_steer_state_update_response(
    request: OperatorSteerStateUpdateBridgeRequest,
) -> Result<Value, OperatorControlCommandError> {
    let record = OperatorSteerStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            OperatorControlCommandError::from_debug("operator_steer_state_update_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_operator_steer_state_update_command",
        "backend": runtime_control_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
    }))
}

fn runtime_control_policy_backend(backend: Option<String>) -> String {
    backend.unwrap_or_else(|| "rust_policy".to_string())
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
        let approval = diagnostics_operator_override_approval_for_request(request)?;
        let snapshot_id = optional_trimmed(request.snapshot_id.as_deref());
        let operator_control = json!({
            "control": "diagnostics_operator_override",
            "source": source,
            "decision_id": decision_id,
            "gate_event_id": gate_event_id,
            "approval_required": approval.required,
            "approval_satisfied": approval.satisfied,
            "approval_source": approval.source,
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
                    Value::Bool(approval.required),
                );
                gate.insert(
                    "approval_required".to_string(),
                    Value::Bool(approval.required),
                );
                gate.insert(
                    "approvalSatisfied".to_string(),
                    Value::Bool(approval.satisfied),
                );
                gate.insert(
                    "approval_satisfied".to_string(),
                    Value::Bool(approval.satisfied),
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiagnosticsOperatorOverrideApproval {
    required: bool,
    satisfied: bool,
    source: String,
}

fn diagnostics_operator_override_approval_for_request(
    request: &DiagnosticsOperatorOverrideStateUpdateRequest,
) -> Result<DiagnosticsOperatorOverrideApproval, DiagnosticsOperatorOverrideStateUpdateError> {
    reject_retired_operator_override_approval_transport(request)?;
    let operator_request = object_value(&request.operator_override_request).unwrap_or_default();
    let decision = object_value(&request.decision).unwrap_or_default();
    let repair_policy = object_value(&request.repair_policy).unwrap_or_default();
    let required = first_json_bool([
        operator_request.get("operator_override_requires_approval"),
        decision.get("requires_approval"),
        repair_policy.get("operator_override_requires_approval"),
    ])
    .unwrap_or(true);
    let approval_text = first_json_string([
        operator_request.get("operator_override_approval"),
        operator_request.get("approval"),
        operator_request.get("approval_decision"),
        operator_request.get("policy_decision"),
        operator_request.get("decision"),
        operator_request.get("status"),
    ])
    .map(|value| value.to_ascii_lowercase());
    let approved_text = matches!(
        approval_text.as_deref(),
        Some(
            "approve"
                | "approved"
                | "allow"
                | "allowed"
                | "accept"
                | "accepted"
                | "confirm"
                | "confirmed"
                | "override"
        )
    );
    let approved_boolean = [
        operator_request.get("operator_override_approved"),
        operator_request.get("override_approved"),
        operator_request.get("confirm"),
        operator_request.get("confirmed"),
        operator_request.get("approval_granted"),
        operator_request.get("approved"),
    ]
    .into_iter()
    .flatten()
    .any(|value| json_bool(value) == Some(true));
    let satisfied = !required || approved_boolean || approved_text;
    let source = if !required {
        "workflow_policy".to_string()
    } else if approved_boolean {
        "boolean_confirmation".to_string()
    } else if approved_text {
        approval_text.unwrap_or_else(|| "approval".to_string())
    } else {
        "missing".to_string()
    };
    Ok(DiagnosticsOperatorOverrideApproval {
        required,
        satisfied,
        source,
    })
}

fn reject_retired_operator_override_approval_transport(
    request: &DiagnosticsOperatorOverrideStateUpdateRequest,
) -> Result<(), DiagnosticsOperatorOverrideStateUpdateError> {
    let mut retired = Vec::new();
    let top_level_fields = [
        "approval_required",
        "approval_satisfied",
        "approval_source",
        "approvalRequired",
        "approvalSatisfied",
        "approvalSource",
    ];
    for field in top_level_fields {
        if request.extra.contains_key(field) {
            retired.push(field.to_string());
        }
    }
    if let Some(operator_request) = object_value_ref(&request.operator_override_request) {
        for field in top_level_fields {
            if operator_request.contains_key(field) {
                retired.push(format!("operator_override_request.{field}"));
            }
        }
        for field in [
            "operatorOverrideRequiresApproval",
            "operatorOverrideApproval",
            "approvalDecision",
            "policyDecision",
            "operatorOverrideApproved",
            "overrideApproved",
            "approvalGranted",
        ] {
            if operator_request.contains_key(field) {
                retired.push(format!("operator_override_request.{field}"));
            }
        }
    }
    if let Some(decision) = object_value_ref(&request.decision) {
        if decision.contains_key("requiresApproval") {
            retired.push("decision.requiresApproval".to_string());
        }
    }
    if let Some(repair_policy) = object_value_ref(&request.repair_policy) {
        if repair_policy.contains_key("operatorOverrideRequiresApproval") {
            retired.push("repair_policy.operatorOverrideRequiresApproval".to_string());
        }
    }
    if retired.is_empty() {
        Ok(())
    } else {
        Err(DiagnosticsOperatorOverrideStateUpdateError::RetiredApprovalVerdictTransport(retired))
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
pub struct OperatorTurnControlAdmissionRequiredCore;

impl OperatorTurnControlAdmissionRequiredCore {
    pub fn plan(
        &self,
        request: &OperatorTurnControlAdmissionRequiredRequest,
    ) -> Result<OperatorTurnControlAdmissionRequiredRecord, OperatorTurnControlAdmissionRequiredError>
    {
        request.validate()?;
        let operation = optional_trimmed(Some(request.operation.as_str())).unwrap();
        let operation_kind = optional_trimmed(Some(request.operation_kind.as_str())).unwrap();
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let turn_id = optional_trimmed(request.turn_id.as_deref());
        let requested_action = optional_trimmed(request.requested_action.as_deref());
        let evidence_refs = if request.evidence_refs.is_empty() {
            default_operator_turn_control_evidence_refs(operation.as_str())
        } else {
            request.evidence_refs.clone()
        };
        let details = json!({
            "rust_core_boundary": "runtime.operator_turn_control",
            "operation": operation,
            "operation_kind": operation_kind,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "requested_action": requested_action,
            "evidence_refs": evidence_refs,
        });

        Ok(OperatorTurnControlAdmissionRequiredRecord {
            schema_version: OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION
                .to_string(),
            object: "ioi.runtime_operator_turn_control_admission_required".to_string(),
            status: "rust_core_required".to_string(),
            status_code: 501,
            code: "runtime_operator_turn_control_rust_core_required".to_string(),
            message: "Operator turn control requires direct Rust daemon-core state admission and persistence.".to_string(),
            rust_core_boundary: "runtime.operator_turn_control".to_string(),
            operation,
            operation_kind,
            details,
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

impl OperatorTurnControlAdmissionRequiredRequest {
    pub fn validate(&self) -> Result<(), OperatorTurnControlAdmissionRequiredError> {
        if self.schema_version != OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(
                OperatorTurnControlAdmissionRequiredError::InvalidSchemaVersion {
                    expected: OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        if optional_trimmed(Some(self.operation.as_str())).is_none() {
            return Err(OperatorTurnControlAdmissionRequiredError::MissingField(
                "operation",
            ));
        }
        let operation_kind = optional_trimmed(Some(self.operation_kind.as_str())).ok_or(
            OperatorTurnControlAdmissionRequiredError::MissingField("operation_kind"),
        )?;
        if operation_kind != "turn.interrupt" && operation_kind != "turn.steer" {
            return Err(
                OperatorTurnControlAdmissionRequiredError::UnsupportedOperationKind(operation_kind),
            );
        }
        if optional_trimmed(self.thread_id.as_deref()).is_none() {
            return Err(OperatorTurnControlAdmissionRequiredError::MissingField(
                "thread_id",
            ));
        }
        if optional_trimmed(self.turn_id.as_deref()).is_none() {
            return Err(OperatorTurnControlAdmissionRequiredError::MissingField(
                "turn_id",
            ));
        }
        Ok(())
    }
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn operator_control_source(value: Option<&str>) -> String {
    optional_trimmed(value).unwrap_or_else(|| "operator".to_string())
}

fn object_value(value: &Value) -> Option<serde_json::Map<String, Value>> {
    value.as_object().cloned()
}

fn object_value_ref(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

fn first_json_bool<'a>(values: impl IntoIterator<Item = Option<&'a Value>>) -> Option<bool> {
    values.into_iter().flatten().find_map(json_bool)
}

fn json_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "approved" | "approve" => Some(true),
            "false" | "0" | "no" | "denied" | "deny" => Some(false),
            _ => None,
        },
        Value::Number(value) => value.as_i64().map(|value| value != 0),
        _ => None,
    }
}

fn first_json_string<'a>(values: impl IntoIterator<Item = Option<&'a Value>>) -> Option<String> {
    values
        .into_iter()
        .flatten()
        .find_map(|value| optional_trimmed(value.as_str()))
}

fn append_operator_control(existing: Option<&Value>, control: &Value) -> Value {
    let mut controls = existing
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    controls.push(control.clone());
    Value::Array(controls)
}

fn default_operator_turn_control_evidence_refs(operation: &str) -> Vec<String> {
    match operation {
        "operator_interrupt" => vec![
            "operator_interrupt_js_facade_retired".to_string(),
            "rust_daemon_core_operator_interrupt_required".to_string(),
            "agentgres_operator_interrupt_state_truth_required".to_string(),
        ],
        "operator_steer" => vec![
            "operator_steer_js_facade_retired".to_string(),
            "rust_daemon_core_operator_steer_required".to_string(),
            "agentgres_operator_steer_state_truth_required".to_string(),
        ],
        _ => vec!["rust_daemon_core_operator_turn_control_required".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            operator_override_request: json!({
                "operator_override_approval": "override"
            }),
            decision: json!({
                "requires_approval": true
            }),
            repair_policy: json!({
                "operator_override_requires_approval": true
            }),
            snapshot_id: Some("snapshot_alpha".to_string()),
            extra: Map::new(),
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

    fn operator_turn_control_admission_required_request(
    ) -> OperatorTurnControlAdmissionRequiredRequest {
        OperatorTurnControlAdmissionRequiredRequest {
            schema_version: OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION
                .to_string(),
            operation: "operator_interrupt".to_string(),
            operation_kind: "turn.interrupt".to_string(),
            thread_id: Some("thread_budget".to_string()),
            turn_id: Some("turn_budget".to_string()),
            requested_action: Some("cancel".to_string()),
            evidence_refs: vec![],
        }
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
        assert_eq!(
            record.run["trace"]["operatorControls"][0]["approval_source"],
            "override"
        );
        assert_eq!(
            record.run["diagnosticsBlockingGate"]["approval_satisfied"],
            true
        );
    }

    #[test]
    fn rust_policy_derives_diagnostics_operator_override_approval_from_request_context() {
        let mut request = diagnostics_operator_override_state_update_request();
        request.operator_override_request = json!({
            "operator_override_requires_approval": false
        });
        request.decision = Value::Null;
        request.repair_policy = Value::Null;
        let record = DiagnosticsOperatorOverrideStateUpdateCore
            .plan(&request)
            .expect("diagnostics operator override approval derivation");

        assert_eq!(record.operator_control["approval_required"], false);
        assert_eq!(record.operator_control["approval_satisfied"], true);
        assert_eq!(
            record.operator_control["approval_source"],
            "workflow_policy"
        );
    }

    #[test]
    fn rust_policy_rejects_diagnostics_operator_override_js_verdict_transport() {
        let mut request = diagnostics_operator_override_state_update_request();
        request
            .extra
            .insert("approval_satisfied".to_string(), Value::Bool(true));
        request.operator_override_request = json!({
            "approvalRequired": true
        });
        let error = DiagnosticsOperatorOverrideStateUpdateCore
            .plan(&request)
            .expect_err("retired diagnostics operator override verdict transport");

        assert_eq!(
            error,
            DiagnosticsOperatorOverrideStateUpdateError::RetiredApprovalVerdictTransport(vec![
                "approval_satisfied".to_string(),
                "operator_override_request.approvalRequired".to_string(),
            ])
        );
    }

    #[test]
    fn rust_policy_shapes_diagnostics_operator_override_state_update_command_response() {
        let response = plan_diagnostics_operator_override_state_update_response(
            DiagnosticsOperatorOverrideStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: diagnostics_operator_override_state_update_request(),
            },
        )
        .expect("diagnostics operator override state update command response");

        assert_eq!(
            response["source"],
            "rust_diagnostics_operator_override_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(
            response["operation_kind"],
            "diagnostics.operator_override.event"
        );
        assert_eq!(
            response["operator_control"]["control"],
            "diagnostics_operator_override"
        );
        assert_eq!(
            response["operator_control"]["decision_id"],
            "decision_override"
        );
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
            assert!(response["operator_control"].get(field).is_none());
        }
        assert_eq!(response["run"]["status"], "completed");
        assert_eq!(
            response["run"]["diagnosticsBlockingGate"]["status"],
            "overridden"
        );
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["event_id"],
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
    fn rust_policy_shapes_operator_interrupt_state_update_command_response() {
        let response = plan_operator_interrupt_state_update_response(
            OperatorInterruptStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: operator_interrupt_state_update_request(),
            },
        )
        .expect("operator interrupt state update command response");

        assert_eq!(
            response["source"],
            "rust_operator_interrupt_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "turn.interrupt");
        assert_eq!(response["operator_control"]["control"], "interrupt");
        assert_eq!(response["operator_control"]["event_id"], "event_interrupt");
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["event_id"],
            "event_interrupt"
        );
        assert_eq!(response["run"]["status"], "canceled");
        assert_eq!(response["run"]["turnStatus"], "interrupted");
        assert_eq!(
            response["run"]["trace"]["qualityLedger"]["failureOntologyLabels"][1],
            "operator_interrupt"
        );
    }

    #[test]
    fn rust_policy_plans_operator_turn_control_admission_required() {
        let record = OperatorTurnControlAdmissionRequiredCore
            .plan(&operator_turn_control_admission_required_request())
            .expect("operator turn control admission-required record");

        assert_eq!(
            record.schema_version,
            OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(
            record.code,
            "runtime_operator_turn_control_rust_core_required"
        );
        assert_eq!(record.operation_kind, "turn.interrupt");
        assert_eq!(
            record.details["rust_core_boundary"],
            "runtime.operator_turn_control"
        );
        assert_eq!(record.details["thread_id"], "thread_budget");
        assert_eq!(record.details["turn_id"], "turn_budget");
        assert_eq!(record.details["requested_action"], "cancel");
        assert!(record.details["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "operator_interrupt_js_facade_retired"));
        for field in [
            "rustCoreBoundary",
            "operationKind",
            "threadId",
            "turnId",
            "requestedAction",
            "evidenceRefs",
        ] {
            assert!(record.details.get(field).is_none());
        }
    }

    #[test]
    fn rust_policy_shapes_operator_turn_control_admission_required_command_response() {
        let response = plan_operator_turn_control_admission_required_response(
            OperatorTurnControlAdmissionRequiredBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: operator_turn_control_admission_required_request(),
            },
        )
        .expect("operator turn control admission-required command response");

        assert_eq!(
            response["source"],
            "rust_operator_turn_control_admission_required_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "runtime_operator_turn_control_rust_core_required"
        );
        assert_eq!(response["operation_kind"], "turn.interrupt");
        assert_eq!(
            response["details"]["rust_core_boundary"],
            "runtime.operator_turn_control"
        );
        assert_eq!(response["details"]["thread_id"], "thread_budget");
        assert_eq!(response["details"]["turn_id"], "turn_budget");
        assert_eq!(response["details"]["requested_action"], "cancel");
        for field in [
            "rustCoreBoundary",
            "operationKind",
            "threadId",
            "turnId",
            "requestedAction",
            "evidenceRefs",
        ] {
            assert!(response["details"].get(field).is_none());
        }
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
    fn rust_policy_shapes_operator_steer_state_update_command_response() {
        let response =
            plan_operator_steer_state_update_response(OperatorSteerStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: operator_steer_state_update_request(),
            })
            .expect("operator steer state update command response");

        assert_eq!(
            response["source"],
            "rust_operator_steer_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "turn.steer");
        assert_eq!(response["operator_control"]["control"], "steer");
        assert_eq!(
            response["operator_control"]["guidance"],
            "focus on the failing bridge assertion"
        );
        assert_eq!(response["operator_control"]["event_id"], "event_steer");
        assert!(response["operator_control"].get("eventId").is_none());
        assert!(response["operator_control"].get("createdAt").is_none());
        assert_eq!(response["run"]["status"], "running");
        assert_eq!(
            response["run"]["trace"]["operatorControls"][0]["event_id"],
            "event_steer"
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
    fn rust_policy_rejects_invalid_operator_turn_control_admission_required_schema() {
        let mut request = operator_turn_control_admission_required_request();
        request.schema_version = "legacy.schema".to_string();

        let error = OperatorTurnControlAdmissionRequiredCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            OperatorTurnControlAdmissionRequiredError::InvalidSchemaVersion {
                expected: OPERATOR_TURN_CONTROL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }
}
