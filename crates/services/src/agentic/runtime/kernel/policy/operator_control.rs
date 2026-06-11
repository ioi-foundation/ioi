use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    DIAGNOSTICS_OPERATOR_OVERRIDE_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    OPERATOR_INTERRUPT_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    OPERATOR_STEER_STATE_UPDATE_RESULT_SCHEMA_VERSION,
};

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

fn append_operator_control(existing: Option<&Value>, control: &Value) -> Value {
    let mut controls = existing
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    controls.push(control.clone());
    Value::Array(controls)
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
}
