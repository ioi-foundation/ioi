use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

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
    MissingWalletNetworkAuthority,
    MissingAuthorityReceipt,
    UnsatisfiedApprovalRequired,
    HashFailed(String),
    RetiredApprovalVerdictTransport(Vec<String>),
    RetiredAuthorityTransport(Vec<String>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum OperatorInterruptStateUpdateError {
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
pub enum OperatorSteerStateUpdateError {
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
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
    #[serde(default)]
    pub authority_context: Value,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DiagnosticsOperatorOverrideAuthorityRecord {
    schema_version: String,
    object: String,
    status: String,
    operation_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
    decision_id: String,
    approval_required: bool,
    approval_satisfied: bool,
    approval_source: String,
    wallet_network_grant_refs: Vec<String>,
    authority_receipt_refs: Vec<String>,
    policy_decision_refs: Vec<String>,
    direct_truth_write_allowed: bool,
    authority_hash: String,
    projection_source: String,
    generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorInterruptStateUpdateRequest {
    pub schema_version: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub event_stream_id: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    pub event_id: String,
    #[serde(default)]
    pub seq: Option<u64>,
    pub created_at: String,
    pub source: String,
    pub reason: String,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
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
    pub state_dir: Option<String>,
    #[serde(default)]
    pub event_stream_id: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    pub event_id: String,
    #[serde(default)]
    pub seq: Option<u64>,
    pub created_at: String,
    pub source: String,
    pub guidance: String,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
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
        let authority = diagnostics_operator_override_authority_for_request(
            request,
            &approval,
            thread_id.clone(),
            run_id.clone(),
            decision_id.clone(),
        )?;
        let authority_value = serde_json::to_value(&authority).unwrap_or(Value::Null);
        let snapshot_id = optional_trimmed(request.snapshot_id.as_deref());
        let operator_control = json!({
            "control": "diagnostics_operator_override",
            "source": source,
            "decision_id": decision_id,
            "gate_event_id": gate_event_id,
            "approval_required": approval.required,
            "approval_satisfied": approval.satisfied,
            "approval_source": approval.source,
            "authority": authority_value,
            "authority_hash": authority.authority_hash,
            "wallet_network_grant_refs": authority.wallet_network_grant_refs,
            "authority_receipt_refs": authority.authority_receipt_refs,
            "policy_decision_refs": authority.policy_decision_refs,
            "direct_truth_write_allowed": authority.direct_truth_write_allowed,
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
                    "authority_hash".to_string(),
                    Value::String(authority.authority_hash.clone()),
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

fn diagnostics_operator_override_authority_for_request(
    request: &DiagnosticsOperatorOverrideStateUpdateRequest,
    approval: &DiagnosticsOperatorOverrideApproval,
    thread_id: Option<String>,
    run_id: Option<String>,
    decision_id: String,
) -> Result<DiagnosticsOperatorOverrideAuthorityRecord, DiagnosticsOperatorOverrideStateUpdateError>
{
    reject_retired_operator_override_authority_transport(request)?;
    if approval.required && !approval.satisfied {
        return Err(DiagnosticsOperatorOverrideStateUpdateError::UnsatisfiedApprovalRequired);
    }
    let operator_authority_grant_refs =
        array_strings(&request.operator_override_request, "authority_grant_refs");
    let operator_authority_receipt_refs =
        array_strings(&request.operator_override_request, "authority_receipt_refs");
    let operator_policy_decision_refs =
        array_strings(&request.operator_override_request, "policy_decision_refs");
    let decision_policy_decision_refs = array_strings(&request.decision, "policy_decision_refs");
    let repair_policy_decision_refs = array_strings(&request.repair_policy, "policy_decision_refs");
    let wallet_network_grant_refs = unique_trimmed_values(
        request
            .authority_grant_refs
            .iter()
            .chain(operator_authority_grant_refs.iter())
            .filter(|grant_ref| is_wallet_network_grant_ref(grant_ref))
            .cloned()
            .collect::<Vec<_>>()
            .as_slice(),
    );
    let authority_receipt_refs = unique_trimmed_values(
        request
            .authority_receipt_refs
            .iter()
            .chain(operator_authority_receipt_refs.iter())
            .cloned()
            .collect::<Vec<_>>()
            .as_slice(),
    );
    if approval.required && wallet_network_grant_refs.is_empty() {
        return Err(DiagnosticsOperatorOverrideStateUpdateError::MissingWalletNetworkAuthority);
    }
    if approval.required && authority_receipt_refs.is_empty() {
        return Err(DiagnosticsOperatorOverrideStateUpdateError::MissingAuthorityReceipt);
    }
    let policy_decision_refs = unique_trimmed_values(
        request
            .policy_decision_refs
            .iter()
            .chain(operator_policy_decision_refs.iter())
            .chain(decision_policy_decision_refs.iter())
            .chain(repair_policy_decision_refs.iter())
            .cloned()
            .collect::<Vec<_>>()
            .as_slice(),
    );
    let mut record = DiagnosticsOperatorOverrideAuthorityRecord {
        schema_version: "ioi.runtime.diagnostics-operator-override-authority.v1".to_string(),
        object: "ioi.runtime_diagnostics_operator_override_authority".to_string(),
        status: "authorized".to_string(),
        operation_kind: "diagnostics.operator_override.authority".to_string(),
        thread_id,
        run_id,
        decision_id,
        approval_required: approval.required,
        approval_satisfied: approval.satisfied,
        approval_source: approval.source.clone(),
        wallet_network_grant_refs,
        authority_receipt_refs,
        policy_decision_refs,
        direct_truth_write_allowed: false,
        authority_hash: String::new(),
        projection_source: if approval.required {
            "rust_daemon_core_wallet_network_diagnostics_operator_override_authority".to_string()
        } else {
            "rust_daemon_core_workflow_policy_diagnostics_operator_override_authority".to_string()
        },
        generated_at: "rust_policy_core".to_string(),
    };
    record.authority_hash = diagnostics_operator_override_authority_hash(&record)?;
    Ok(record)
}

fn diagnostics_operator_override_authority_hash(
    record: &DiagnosticsOperatorOverrideAuthorityRecord,
) -> Result<String, DiagnosticsOperatorOverrideStateUpdateError> {
    let mut canonical = record.clone();
    canonical.authority_hash.clear();
    let bytes = serde_json::to_vec(&canonical).map_err(|error| {
        DiagnosticsOperatorOverrideStateUpdateError::HashFailed(error.to_string())
    })?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
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

fn reject_retired_operator_override_authority_transport(
    request: &DiagnosticsOperatorOverrideStateUpdateRequest,
) -> Result<(), DiagnosticsOperatorOverrideStateUpdateError> {
    let mut retired = Vec::new();
    for field in [
        "authority",
        "authority_hash",
        "walletNetworkGrantRefs",
        "authorityGrantRefs",
        "authorityReceiptRefs",
        "policyDecisionRefs",
        "authorityHash",
    ] {
        if request.extra.contains_key(field) {
            retired.push(field.to_string());
        }
    }
    for (container_name, value) in [
        (
            "operator_override_request",
            &request.operator_override_request,
        ),
        ("decision", &request.decision),
        ("repair_policy", &request.repair_policy),
        ("authority_context", &request.authority_context),
    ] {
        if let Some(container) = object_value_ref(value) {
            for field in [
                "walletNetworkGrantRefs",
                "authorityGrantRefs",
                "authorityReceiptRefs",
                "policyDecisionRefs",
                "authorityHash",
            ] {
                if container.contains_key(field) {
                    retired.push(format!("{container_name}.{field}"));
                }
            }
        }
    }
    if retired.is_empty() {
        Ok(())
    } else {
        Err(DiagnosticsOperatorOverrideStateUpdateError::RetiredAuthorityTransport(retired))
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
        let seq = super::latest_runtime_event_seq_from_state_dir(
            request.state_dir.as_deref(),
            thread_id.as_deref(),
            request.event_stream_id.as_deref(),
        )
        .map_err(OperatorInterruptStateUpdateError::ReplayReadFailed)?
            + 1;
        let operator_control = json!({
            "control": "interrupt",
            "source": source,
            "reason": reason,
            "event_id": request.event_id,
            "seq": seq,
            "created_at": request.created_at,
        });
        let stop_condition = json!({
            "reason": "operator_interrupt",
            "evidenceSufficient": true,
            "rationale": format!("Operator interrupt accepted from {source}: {reason}"),
        });
        let mut run = operator_turn_control_run_from_state_dir(
            request.state_dir.as_deref(),
            run_id.as_deref(),
            turn_id.as_deref(),
            thread_id.as_deref(),
            "operator interrupt",
        )
        .map_err(OperatorInterruptStateUpdateError::ReplayReadFailed)?;
        let run_id = Some(
            optional_json_string(&Value::Object(run.clone()), &["id", "run_id"])
                .ok_or(OperatorInterruptStateUpdateError::MissingField("run.id"))?,
        );
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
        let seq = super::latest_runtime_event_seq_from_state_dir(
            request.state_dir.as_deref(),
            thread_id.as_deref(),
            request.event_stream_id.as_deref(),
        )
        .map_err(OperatorSteerStateUpdateError::ReplayReadFailed)?
            + 1;
        let operator_control = json!({
            "control": "steer",
            "source": source,
            "guidance": guidance,
            "event_id": request.event_id,
            "seq": seq,
            "created_at": request.created_at,
        });
        let mut run = operator_turn_control_run_from_state_dir(
            request.state_dir.as_deref(),
            run_id.as_deref(),
            turn_id.as_deref(),
            thread_id.as_deref(),
            "operator steer",
        )
        .map_err(OperatorSteerStateUpdateError::ReplayReadFailed)?;
        let run_id = Some(
            optional_json_string(&Value::Object(run.clone()), &["id", "run_id"])
                .ok_or(OperatorSteerStateUpdateError::MissingField("run.id"))?,
        );
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
        if let Some(field) = retired_operator_turn_control_candidate_field(&self.extra) {
            return Err(OperatorInterruptStateUpdateError::RetiredField(field));
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(OperatorInterruptStateUpdateError::MissingField("event_id"));
        }
        if self.seq.is_some() {
            return Err(OperatorInterruptStateUpdateError::RetiredField("seq"));
        }
        if optional_trimmed(self.state_dir.as_deref()).is_none() {
            return Err(OperatorInterruptStateUpdateError::StateDirRequired);
        }
        if optional_trimmed(self.run_id.as_deref()).is_none()
            && optional_trimmed(self.turn_id.as_deref()).is_none()
        {
            return Err(OperatorInterruptStateUpdateError::MissingField("run_id"));
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
        if let Some(field) = retired_operator_turn_control_candidate_field(&self.extra) {
            return Err(OperatorSteerStateUpdateError::RetiredField(field));
        }
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(OperatorSteerStateUpdateError::MissingField("event_id"));
        }
        if self.seq.is_some() {
            return Err(OperatorSteerStateUpdateError::RetiredField("seq"));
        }
        if optional_trimmed(self.state_dir.as_deref()).is_none() {
            return Err(OperatorSteerStateUpdateError::StateDirRequired);
        }
        if optional_trimmed(self.run_id.as_deref()).is_none()
            && optional_trimmed(self.turn_id.as_deref()).is_none()
        {
            return Err(OperatorSteerStateUpdateError::MissingField("run_id"));
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

fn operator_turn_control_run_from_state_dir(
    state_dir: Option<&str>,
    run_id: Option<&str>,
    turn_id: Option<&str>,
    thread_id: Option<&str>,
    operation: &str,
) -> Result<Map<String, Value>, String> {
    let state_dir = optional_trimmed(state_dir)
        .ok_or_else(|| format!("runtime {operation} requires Agentgres state_dir replay"))?;
    let run_id = optional_trimmed(run_id);
    let turn_id = optional_trimmed(turn_id);
    let thread_id = optional_trimmed(thread_id);
    let runs_dir = Path::new(&state_dir).join("runs");
    let mut run_records = operator_turn_control_run_records_from_state_dir(&runs_dir, operation)?;
    run_records.sort_by(|left, right| {
        optional_json_string(&Value::Object(left.clone()), &["id", "run_id"]).cmp(
            &optional_json_string(&Value::Object(right.clone()), &["id", "run_id"]),
        )
    });
    run_records
        .into_iter()
        .find(|record| {
            operator_turn_control_run_matches(
                record,
                run_id.as_deref(),
                turn_id.as_deref(),
                thread_id.as_deref(),
            )
        })
        .ok_or_else(|| {
            format!("runtime {operation} could not replay target run from Agentgres state_dir")
        })
}

fn operator_turn_control_run_records_from_state_dir(
    runs_dir: &Path,
    operation: &str,
) -> Result<Vec<Map<String, Value>>, String> {
    if !runs_dir.exists() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(runs_dir).map_err(|error| {
        format!(
            "runtime {operation} could not read Agentgres runs directory {}: {error}",
            runs_dir.display()
        )
    })?;
    let mut paths = Vec::<PathBuf>::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "runtime {operation} could not inspect Agentgres runs directory {}: {error}",
                runs_dir.display()
            )
        })?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|value| value.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut records = Vec::new();
    for path in paths.into_iter().take(1000) {
        let contents = fs::read_to_string(&path).map_err(|error| {
            format!(
                "runtime {operation} could not read Agentgres run record {}: {error}",
                path.display()
            )
        })?;
        let value: Value = serde_json::from_str(&contents).map_err(|error| {
            format!(
                "runtime {operation} found invalid Agentgres run record {}: {error}",
                path.display()
            )
        })?;
        if let Some(record) = value.as_object().cloned() {
            records.push(record);
        }
    }
    Ok(records)
}

fn operator_turn_control_run_matches(
    record: &Map<String, Value>,
    run_id: Option<&str>,
    turn_id: Option<&str>,
    thread_id: Option<&str>,
) -> bool {
    let record_value = Value::Object(record.clone());
    let record_run_id = optional_json_string(&record_value, &["id", "run_id"]);
    let record_turn_id = optional_json_string(&record_value, &["turn_id", "runtime_turn_id"]);
    let record_thread_id = optional_json_string(&record_value, &["thread_id"]);
    let run_matches = run_id.is_some_and(|expected| record_run_id.as_deref() == Some(expected));
    let turn_matches = turn_id.is_some_and(|expected| {
        record_turn_id.as_deref() == Some(expected)
            || record_run_id.as_deref().map(turn_id_for_run).as_deref() == Some(expected)
    });
    let thread_matches = match thread_id {
        Some(expected) => match record_thread_id.as_deref() {
            Some(actual) => actual == expected,
            None => true,
        },
        None => true,
    };
    thread_matches && (run_matches || turn_matches)
}

fn retired_operator_turn_control_candidate_field(
    extra: &Map<String, Value>,
) -> Option<&'static str> {
    for field in ["run", "runs", "agent", "candidate_run", "candidateRun"] {
        if extra.contains_key(field) {
            return Some(field);
        }
    }
    None
}

fn optional_json_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .and_then(|value| optional_trimmed(Some(value)))
    })
}

fn turn_id_for_run(run_id: &str) -> String {
    run_id
        .strip_prefix("run_")
        .map(|suffix| format!("turn_{suffix}"))
        .unwrap_or_else(|| format!("turn_{run_id}"))
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

fn array_strings(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| optional_trimmed(value.as_str()))
                .collect()
        })
        .unwrap_or_default()
}

fn unique_trimmed_values(values: &[String]) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values
        .iter()
        .filter_map(|value| optional_trimmed(Some(value)))
    {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}

fn is_wallet_network_grant_ref(grant_ref: &str) -> bool {
    let normalized = grant_ref.trim().to_ascii_lowercase();
    normalized.starts_with("wallet.network://grant/")
        || normalized.starts_with("grant://wallet.network/")
        || normalized.starts_with("wallet-network://grant/")
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
            authority_grant_refs: vec![
                "wallet.network://grant/diagnostics/operator-override".to_string()
            ],
            authority_receipt_refs: vec![
                "receipt://wallet.network/diagnostics/operator-override".to_string()
            ],
            policy_decision_refs: vec!["policy_diagnostics_operator_override".to_string()],
            authority_context: Value::Null,
            snapshot_id: Some("snapshot_alpha".to_string()),
            extra: Map::new(),
        }
    }

    fn operator_interrupt_state_update_request() -> OperatorInterruptStateUpdateRequest {
        let state_dir = temp_operator_control_state_dir("interrupt");
        write_operator_control_run_record(
            &state_dir,
            json!({
                "id": "run_budget",
                "agentId": "agent_budget",
                "thread_id": "thread_budget",
                "status": "running",
                "turnStatus": "running",
                "trace": {
                    "qualityLedger": {
                        "failureOntologyLabels": ["existing_label"]
                    }
                },
                "operatorControls": []
            }),
        );
        OperatorInterruptStateUpdateRequest {
            schema_version: OPERATOR_INTERRUPT_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: Some("thread_budget".to_string()),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            event_stream_id: Some("thread_budget:events".to_string()),
            turn_id: Some("turn_budget".to_string()),
            run_id: None,
            event_id: "event_interrupt".to_string(),
            seq: None,
            created_at: "2026-06-06T04:25:00.000Z".to_string(),
            source: "runtime_auto".to_string(),
            reason: "operator_stop".to_string(),
            extra: Map::new(),
        }
    }

    fn operator_steer_state_update_request() -> OperatorSteerStateUpdateRequest {
        let state_dir = temp_operator_control_state_dir("steer");
        write_operator_control_run_record(
            &state_dir,
            json!({
                "id": "run_budget",
                "agentId": "agent_budget",
                "thread_id": "thread_budget",
                "status": "running",
                "turnStatus": "running",
                "trace": {},
                "operatorControls": []
            }),
        );
        OperatorSteerStateUpdateRequest {
            schema_version: OPERATOR_STEER_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: Some("thread_budget".to_string()),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            event_stream_id: Some("thread_budget:events".to_string()),
            turn_id: Some("turn_budget".to_string()),
            run_id: None,
            event_id: "event_steer".to_string(),
            seq: None,
            created_at: "2026-06-06T04:35:00.000Z".to_string(),
            source: "react_flow".to_string(),
            guidance: "focus on the failing bridge assertion".to_string(),
            extra: Map::new(),
        }
    }

    fn temp_operator_control_state_dir(label: &str) -> PathBuf {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let state_dir = std::env::temp_dir().join(format!(
            "ioi_runtime_operator_control_{label}_{}_{}",
            std::process::id(),
            suffix
        ));
        let _ = fs::remove_dir_all(&state_dir);
        fs::create_dir_all(state_dir.join("runs")).expect("runs dir");
        state_dir
    }

    fn write_operator_control_run_record(state_dir: &Path, run: Value) {
        let run_id = run.get("id").and_then(Value::as_str).expect("run id");
        let path = state_dir.join("runs").join(format!("{run_id}.json"));
        fs::write(
            path,
            serde_json::to_string_pretty(&run).expect("serialize run"),
        )
        .expect("write run record");
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
        assert_eq!(
            record.operator_control["authority"]["wallet_network_grant_refs"][0],
            "wallet.network://grant/diagnostics/operator-override"
        );
        assert_eq!(
            record.operator_control["authority"]["authority_receipt_refs"][0],
            "receipt://wallet.network/diagnostics/operator-override"
        );
        assert_eq!(record.operator_control["direct_truth_write_allowed"], false);
        assert!(record.operator_control["authority_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
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
        assert_eq!(
            record.operator_control["authority"]["projection_source"],
            "rust_daemon_core_workflow_policy_diagnostics_operator_override_authority"
        );
    }

    #[test]
    fn rust_policy_requires_wallet_authority_for_diagnostics_operator_override() {
        let mut request = diagnostics_operator_override_state_update_request();
        request.authority_grant_refs = vec!["grant://local-debug".to_string()];
        let error = DiagnosticsOperatorOverrideStateUpdateCore
            .plan(&request)
            .expect_err("wallet.network authority is required");

        assert_eq!(
            error,
            DiagnosticsOperatorOverrideStateUpdateError::MissingWalletNetworkAuthority
        );

        let mut request = diagnostics_operator_override_state_update_request();
        request.authority_receipt_refs.clear();
        let error = DiagnosticsOperatorOverrideStateUpdateCore
            .plan(&request)
            .expect_err("wallet.network authority receipt is required");

        assert_eq!(
            error,
            DiagnosticsOperatorOverrideStateUpdateError::MissingAuthorityReceipt
        );
    }

    #[test]
    fn rust_policy_rejects_unsatisfied_diagnostics_operator_override_approval() {
        let mut request = diagnostics_operator_override_state_update_request();
        request.operator_override_request = json!({});
        let error = DiagnosticsOperatorOverrideStateUpdateCore
            .plan(&request)
            .expect_err("unsatisfied operator override approval");

        assert_eq!(
            error,
            DiagnosticsOperatorOverrideStateUpdateError::UnsatisfiedApprovalRequired
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
    fn rust_policy_rejects_diagnostics_operator_override_authority_alias_transport() {
        let mut request = diagnostics_operator_override_state_update_request();
        request.extra.insert(
            "authorityHash".to_string(),
            Value::String("sha256:js".to_string()),
        );
        request.operator_override_request = json!({
            "walletNetworkGrantRefs": ["wallet.network://grant/js"]
        });
        let error = DiagnosticsOperatorOverrideStateUpdateCore
            .plan(&request)
            .expect_err("retired diagnostics operator override authority transport");

        assert_eq!(
            error,
            DiagnosticsOperatorOverrideStateUpdateError::RetiredAuthorityTransport(vec![
                "authorityHash".to_string(),
                "operator_override_request.walletNetworkGrantRefs".to_string(),
            ])
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
    fn rust_policy_replays_operator_interrupt_run_from_state_dir() {
        let request = operator_interrupt_state_update_request();
        let state_dir = request.state_dir.clone().expect("state_dir");
        let record = OperatorInterruptStateUpdateCore
            .plan(&request)
            .expect("operator interrupt state-dir run replay");

        assert_eq!(record.run_id.as_deref(), Some("run_budget"));
        assert_eq!(record.run["id"], "run_budget");
        assert!(state_dir.contains("ioi_runtime_operator_control_interrupt"));
    }

    #[test]
    fn rust_policy_rejects_operator_interrupt_run_candidate_transport() {
        let mut request = operator_interrupt_state_update_request();
        request
            .extra
            .insert("run".to_string(), json!({"id": "run_js_candidate"}));

        let error = OperatorInterruptStateUpdateCore
            .plan(&request)
            .expect_err("retired JS run candidate transport");

        assert_eq!(
            error,
            OperatorInterruptStateUpdateError::RetiredField("run")
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
    fn rust_policy_replays_operator_steer_run_from_state_dir() {
        let request = operator_steer_state_update_request();
        let state_dir = request.state_dir.clone().expect("state_dir");
        let record = OperatorSteerStateUpdateCore
            .plan(&request)
            .expect("operator steer state-dir run replay");

        assert_eq!(record.run_id.as_deref(), Some("run_budget"));
        assert_eq!(record.run["id"], "run_budget");
        assert!(state_dir.contains("ioi_runtime_operator_control_steer"));
    }

    #[test]
    fn rust_policy_rejects_operator_steer_run_candidate_transport() {
        let mut request = operator_steer_state_update_request();
        request
            .extra
            .insert("run".to_string(), json!({"id": "run_js_candidate"}));

        let error = OperatorSteerStateUpdateCore
            .plan(&request)
            .expect_err("retired JS run candidate transport");

        assert_eq!(error, OperatorSteerStateUpdateError::RetiredField("run"));
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
