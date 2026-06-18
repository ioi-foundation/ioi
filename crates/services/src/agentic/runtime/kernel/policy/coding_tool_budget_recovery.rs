use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use super::{
    CODING_TOOL_BUDGET_RECOVERY_CONTROL_REQUEST_SCHEMA_VERSION,
    CODING_TOOL_BUDGET_RECOVERY_CONTROL_RESULT_SCHEMA_VERSION,
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
pub enum CodingToolBudgetRecoveryControlError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    UnsupportedAction(String),
    MissingWalletNetworkAuthority,
    MissingAuthorityReceipt,
    RetiredControlTransport(Vec<String>),
    HashFailed(String),
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
pub struct CodingToolBudgetRecoveryControlRequest {
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
    pub run: Value,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub seq: Option<u64>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
    #[serde(default)]
    pub authority_context: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodingToolBudgetRecoveryControlRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
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
    pub updated_at: String,
    pub operator_control: Value,
    pub run: Value,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub wallet_network_grant_refs: Vec<String>,
    pub authority_receipt_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_hash: Option<String>,
    pub evidence_refs: Vec<String>,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct CodingToolBudgetRecoveryAuthorityRecord {
    schema_version: String,
    object: String,
    status: String,
    operation_kind: String,
    thread_id: Option<String>,
    run_id: String,
    approval_id: String,
    action: String,
    source: Option<String>,
    source_event_id: Option<String>,
    wallet_network_grant_refs: Vec<String>,
    authority_receipt_refs: Vec<String>,
    policy_decision_refs: Vec<String>,
    direct_truth_write_allowed: bool,
    authority_hash: String,
    projection_source: String,
    generated_at: String,
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
pub struct CodingToolBudgetRecoveryControlCore;

impl CodingToolBudgetRecoveryControlCore {
    pub fn plan(
        &self,
        request: &CodingToolBudgetRecoveryControlRequest,
    ) -> Result<CodingToolBudgetRecoveryControlRecord, CodingToolBudgetRecoveryControlError> {
        request.validate()?;
        let operation = optional_trimmed(Some(request.operation.as_str())).unwrap();
        let run_id = optional_trimmed(Some(request.run_id.as_str())).unwrap();
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let action = normalized_budget_recovery_control_action(request.action.as_deref());
        let operation_kind = budget_recovery_control_operation_kind(&action);
        let approval_id = optional_trimmed(request.approval_id.as_deref()).ok_or(
            CodingToolBudgetRecoveryControlError::MissingField("approval_id"),
        )?;
        let source_event_id = optional_trimmed(request.source_event_id.as_deref());
        let source = optional_trimmed(request.source.as_deref());
        let event_id = optional_trimmed(request.event_id.as_deref()).ok_or(
            CodingToolBudgetRecoveryControlError::MissingField("event_id"),
        )?;
        let seq = request
            .seq
            .filter(|seq| *seq > 0)
            .ok_or(CodingToolBudgetRecoveryControlError::MissingField("seq"))?;
        let created_at = optional_trimmed(request.created_at.as_deref()).ok_or(
            CodingToolBudgetRecoveryControlError::MissingField("created_at"),
        )?;
        let reason = optional_trimmed(request.reason.as_deref())
            .unwrap_or_else(|| budget_recovery_control_reason(&action));
        let authority = budget_recovery_control_authority(
            request,
            &action,
            thread_id.clone(),
            &run_id,
            &approval_id,
            source.clone(),
            source_event_id.clone(),
        )?;
        let authority_value = authority
            .as_ref()
            .map(|record| serde_json::to_value(record).unwrap_or(Value::Null));
        let wallet_network_grant_refs = authority
            .as_ref()
            .map(|record| record.wallet_network_grant_refs.clone())
            .unwrap_or_default();
        let authority_receipt_refs = authority
            .as_ref()
            .map(|record| record.authority_receipt_refs.clone())
            .unwrap_or_default();
        let authority_hash = authority
            .as_ref()
            .map(|record| record.authority_hash.clone());
        let policy_decision_refs = unique_trimmed(&request.policy_decision_refs);
        let receipt_refs = unique_trimmed_values(
            request
                .receipt_refs
                .iter()
                .cloned()
                .chain(authority_receipt_refs.iter().cloned())
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let operator_status = budget_recovery_control_status(&action);
        let operator_control = json!({
            "control": "coding_tool_budget_recovery",
            "action": action.clone(),
            "approval_id": approval_id.clone(),
            "status": operator_status.clone(),
            "approval_required": true,
            "approval_satisfied": action == "approve_override",
            "source": source.clone(),
            "reason": reason.clone(),
            "source_event_id": source_event_id.clone(),
            "event_id": event_id.clone(),
            "seq": seq,
            "receipt_refs": receipt_refs.clone(),
            "policy_decision_refs": policy_decision_refs.clone(),
            "authority": authority_value.clone(),
            "authority_hash": authority_hash.clone(),
            "wallet_network_grant_refs": wallet_network_grant_refs.clone(),
            "authority_receipt_refs": authority_receipt_refs.clone(),
            "direct_truth_write_allowed": false,
            "created_at": created_at.clone(),
        });
        let mut run = object_value(&request.run)
            .ok_or(CodingToolBudgetRecoveryControlError::MissingField("run"))?;
        run.insert("updatedAt".to_string(), Value::String(created_at.clone()));
        if action == "request_approval" {
            run.insert(
                "turnStatus".to_string(),
                Value::String("waiting_for_approval".to_string()),
            );
            let prior_status = run
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if matches!(prior_status.as_str(), "queued" | "running") {
                run.insert("status".to_string(), Value::String("blocked".to_string()));
            }
        }
        let mut trace = run.get("trace").and_then(object_value).unwrap_or_default();
        trace.insert(
            "operatorControls".to_string(),
            append_operator_control(trace.get("operatorControls"), &operator_control),
        );
        trace.insert(
            "budgetRecoveryControls".to_string(),
            append_operator_control(trace.get("budgetRecoveryControls"), &operator_control),
        );
        if action == "request_approval" {
            trace.insert(
                "approvalRequests".to_string(),
                append_operator_control(trace.get("approvalRequests"), &operator_control),
            );
        } else {
            trace.insert(
                "approvalDecisions".to_string(),
                append_operator_control(trace.get("approvalDecisions"), &operator_control),
            );
        }
        run.insert("trace".to_string(), Value::Object(trace));
        run.insert(
            "operatorControls".to_string(),
            append_operator_control(run.get("operatorControls"), &operator_control),
        );
        run.insert(
            "budgetRecoveryControls".to_string(),
            append_operator_control(run.get("budgetRecoveryControls"), &operator_control),
        );
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "coding_tool_budget_recovery_control_rust_owned".to_string(),
                "rust_daemon_core_budget_recovery_control".to_string(),
                "rust_agentgres_runtime_run_state_commit".to_string(),
            ]
        } else {
            unique_trimmed(&request.evidence_refs)
        };

        Ok(CodingToolBudgetRecoveryControlRecord {
            schema_version: CODING_TOOL_BUDGET_RECOVERY_CONTROL_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_coding_tool_budget_recovery_control".to_string(),
            status: "planned".to_string(),
            operation,
            operation_kind,
            run_id,
            thread_id,
            action: Some(action),
            approval_id: Some(approval_id),
            source_event_id,
            source,
            updated_at: created_at,
            operator_control,
            run: Value::Object(run),
            receipt_refs,
            policy_decision_refs,
            wallet_network_grant_refs,
            authority_receipt_refs,
            authority: authority_value,
            authority_hash,
            evidence_refs,
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

impl CodingToolBudgetRecoveryControlRequest {
    pub fn validate(&self) -> Result<(), CodingToolBudgetRecoveryControlError> {
        if self.schema_version != CODING_TOOL_BUDGET_RECOVERY_CONTROL_REQUEST_SCHEMA_VERSION {
            return Err(CodingToolBudgetRecoveryControlError::InvalidSchemaVersion {
                expected: CODING_TOOL_BUDGET_RECOVERY_CONTROL_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        reject_retired_budget_recovery_control_transport(self)?;
        if optional_trimmed(Some(self.operation.as_str())).is_none() {
            return Err(CodingToolBudgetRecoveryControlError::MissingField(
                "operation",
            ));
        }
        if optional_trimmed(Some(self.operation_kind.as_str())).is_none() {
            return Err(CodingToolBudgetRecoveryControlError::MissingField(
                "operation_kind",
            ));
        }
        if optional_trimmed(Some(self.run_id.as_str())).is_none() {
            return Err(CodingToolBudgetRecoveryControlError::MissingField("run_id"));
        }
        let action = normalized_budget_recovery_control_action(self.action.as_deref());
        if !matches!(action.as_str(), "request_approval" | "approve_override") {
            return Err(CodingToolBudgetRecoveryControlError::UnsupportedAction(
                action,
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

fn normalized_budget_recovery_control_action(value: Option<&str>) -> String {
    optional_trimmed(value)
        .unwrap_or_else(|| "request_approval".to_string())
        .to_lowercase()
        .replace('-', "_")
}

fn budget_recovery_control_operation_kind(action: &str) -> String {
    format!("workflow.run.coding_tool_budget_recovery.{action}")
}

fn budget_recovery_control_status(action: &str) -> String {
    match action {
        "approve_override" => "override_approved",
        _ => "waiting_for_approval",
    }
    .to_string()
}

fn budget_recovery_control_reason(action: &str) -> String {
    match action {
        "approve_override" => "Operator approved coding-tool budget recovery override.",
        _ => "Coding-tool budget recovery requires operator approval.",
    }
    .to_string()
}

fn budget_recovery_control_authority(
    request: &CodingToolBudgetRecoveryControlRequest,
    action: &str,
    thread_id: Option<String>,
    run_id: &str,
    approval_id: &str,
    source: Option<String>,
    source_event_id: Option<String>,
) -> Result<Option<CodingToolBudgetRecoveryAuthorityRecord>, CodingToolBudgetRecoveryControlError> {
    if action != "approve_override" {
        return Ok(None);
    }
    let wallet_network_grant_refs = unique_trimmed_values(
        request
            .authority_grant_refs
            .iter()
            .filter(|grant_ref| is_wallet_network_grant_ref(grant_ref))
            .cloned()
            .collect::<Vec<_>>()
            .as_slice(),
    );
    if wallet_network_grant_refs.is_empty() {
        return Err(CodingToolBudgetRecoveryControlError::MissingWalletNetworkAuthority);
    }
    let authority_receipt_refs = unique_trimmed(&request.authority_receipt_refs);
    if authority_receipt_refs.is_empty() {
        return Err(CodingToolBudgetRecoveryControlError::MissingAuthorityReceipt);
    }
    let policy_decision_refs = unique_trimmed(&request.policy_decision_refs);
    let mut record = CodingToolBudgetRecoveryAuthorityRecord {
        schema_version: "ioi.runtime.coding-tool-budget-recovery-authority.v1".to_string(),
        object: "ioi.runtime_coding_tool_budget_recovery_authority".to_string(),
        status: "authorized".to_string(),
        operation_kind: budget_recovery_control_operation_kind(action),
        thread_id,
        run_id: run_id.to_string(),
        approval_id: approval_id.to_string(),
        action: action.to_string(),
        source,
        source_event_id,
        wallet_network_grant_refs,
        authority_receipt_refs,
        policy_decision_refs,
        direct_truth_write_allowed: false,
        authority_hash: String::new(),
        projection_source: "rust_daemon_core_wallet_network_coding_tool_budget_recovery_authority"
            .to_string(),
        generated_at: "rust_policy_core".to_string(),
    };
    record.authority_hash = budget_recovery_control_authority_hash(&record)?;
    Ok(Some(record))
}

fn budget_recovery_control_authority_hash(
    record: &CodingToolBudgetRecoveryAuthorityRecord,
) -> Result<String, CodingToolBudgetRecoveryControlError> {
    let mut canonical = record.clone();
    canonical.authority_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| CodingToolBudgetRecoveryControlError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn reject_retired_budget_recovery_control_transport(
    request: &CodingToolBudgetRecoveryControlRequest,
) -> Result<(), CodingToolBudgetRecoveryControlError> {
    let retired: Vec<String> = request
        .extra
        .keys()
        .filter(|key| {
            matches!(
                key.as_str(),
                "threadId"
                    | "runId"
                    | "operationKind"
                    | "approvalId"
                    | "sourceEventId"
                    | "eventId"
                    | "createdAt"
                    | "recoveryAction"
                    | "receiptRefs"
                    | "policyDecisionRefs"
                    | "authority"
                    | "authorityHash"
                    | "authorityGrantRefs"
                    | "authorityReceiptRefs"
                    | "walletNetworkGrantRefs"
            )
        })
        .cloned()
        .collect();
    if retired.is_empty() {
        Ok(())
    } else {
        Err(CodingToolBudgetRecoveryControlError::RetiredControlTransport(retired))
    }
}

fn unique_trimmed(values: &[String]) -> Vec<String> {
    unique_trimmed_values(values)
}

fn unique_trimmed_values(values: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        if let Some(trimmed) = optional_trimmed(Some(value.as_str())) {
            if !out.contains(&trimmed) {
                out.push(trimmed);
            }
        }
    }
    out
}

fn is_wallet_network_grant_ref(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("wallet.network://")
        || trimmed.starts_with("wallet-network://")
        || trimmed.starts_with("wallet_network://")
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

    fn coding_tool_budget_recovery_control_request(
        action: &str,
    ) -> CodingToolBudgetRecoveryControlRequest {
        CodingToolBudgetRecoveryControlRequest {
            schema_version: CODING_TOOL_BUDGET_RECOVERY_CONTROL_REQUEST_SCHEMA_VERSION.to_string(),
            operation: "coding_tool_budget_recovery_control".to_string(),
            operation_kind: "workflow.run.coding_tool_budget_recovery".to_string(),
            run_id: "run_alpha".to_string(),
            thread_id: Some("thread_alpha".to_string()),
            action: Some(action.to_string()),
            approval_id: Some("approval_alpha".to_string()),
            source_event_id: Some("event_budget".to_string()),
            source: Some("hypervisor_session".to_string()),
            run: json!({
                "id": "run_alpha",
                "agentId": "agent_alpha",
                "status": "running",
                "trace": {},
            }),
            event_id: Some(format!("event_budget_{action}")),
            seq: Some(17),
            created_at: Some("2026-06-12T10:40:00.000Z".to_string()),
            reason: Some("budget recovery needs approval".to_string()),
            receipt_refs: vec!["receipt_budget_control".to_string()],
            policy_decision_refs: vec!["policy_budget_control".to_string()],
            authority_grant_refs: vec![
                "wallet.network://grant/coding-tool-budget-recovery".to_string()
            ],
            authority_receipt_refs: vec![
                "receipt://wallet.network/coding-tool-budget-recovery".to_string()
            ],
            authority_context: Value::Null,
            evidence_refs: vec![],
            extra: BTreeMap::new(),
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
    fn rust_policy_plans_coding_tool_budget_recovery_request_approval_control() {
        let record = CodingToolBudgetRecoveryControlCore
            .plan(&coding_tool_budget_recovery_control_request(
                "request_approval",
            ))
            .expect("coding-tool budget recovery request approval control");

        assert_eq!(
            record.schema_version,
            CODING_TOOL_BUDGET_RECOVERY_CONTROL_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation, "coding_tool_budget_recovery_control");
        assert_eq!(
            record.operation_kind,
            "workflow.run.coding_tool_budget_recovery.request_approval"
        );
        assert_eq!(
            record.operator_control["control"],
            "coding_tool_budget_recovery"
        );
        assert_eq!(record.operator_control["action"], "request_approval");
        assert_eq!(record.operator_control["approval_required"], true);
        assert_eq!(record.operator_control["approval_satisfied"], false);
        assert_eq!(record.run["status"], "blocked");
        assert_eq!(record.run["turnStatus"], "waiting_for_approval");
        assert_eq!(
            record.run["trace"]["approvalRequests"][0]["approval_id"],
            "approval_alpha"
        );
        assert!(record.operator_control.get("approvalId").is_none());
        assert!(record.operator_control.get("sourceEventId").is_none());
        assert!(record.operator_control.get("authorityHash").is_none());
    }

    #[test]
    fn rust_policy_rejects_coding_tool_budget_recovery_override_without_wallet_authority() {
        let mut request = coding_tool_budget_recovery_control_request("approve_override");
        request.authority_grant_refs = vec!["grant://local-debug".to_string()];

        let error = CodingToolBudgetRecoveryControlCore
            .plan(&request)
            .expect_err("override authority must require wallet.network");

        assert_eq!(
            error,
            CodingToolBudgetRecoveryControlError::MissingWalletNetworkAuthority
        );
    }

    #[test]
    fn rust_policy_rejects_coding_tool_budget_recovery_control_alias_transport() {
        let mut request = coding_tool_budget_recovery_control_request("request_approval");
        request.extra.insert(
            "approvalId".to_string(),
            Value::String("approval_js".to_string()),
        );

        let error = CodingToolBudgetRecoveryControlCore
            .plan(&request)
            .expect_err("retired alias transport must fail");

        assert_eq!(
            error,
            CodingToolBudgetRecoveryControlError::RetiredControlTransport(vec![
                "approvalId".to_string()
            ])
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
}
