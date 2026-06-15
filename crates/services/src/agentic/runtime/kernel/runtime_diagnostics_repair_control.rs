use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-repair-control-request.v1";
pub const RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics_repair_control.v1";
pub const RUNTIME_DIAGNOSTICS_REPAIR_RETRY_RUN_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-repair-retry-run-request.v1";
pub const RUNTIME_DIAGNOSTICS_REPAIR_RETRY_RUN_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics_repair_retry_run.v1";
pub const RUNTIME_DIAGNOSTICS_REPAIR_RETRY_RESULT_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics-repair-retry-result-projection-request.v1";
pub const RUNTIME_DIAGNOSTICS_REPAIR_RETRY_RESULT_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.diagnostics_repair_retry_result_projection.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeDiagnosticsRepairControlRequest {
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
    pub decision_id: Option<String>,
    #[serde(default)]
    pub gate_event_id: Option<String>,
    #[serde(default)]
    pub gate_id: Option<String>,
    #[serde(default)]
    pub snapshot_id: Option<String>,
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
pub struct RuntimeDiagnosticsRepairControlCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeDiagnosticsRepairControlCommandError {
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
pub struct RuntimeDiagnosticsRepairControlCore;

#[derive(Debug, Clone)]
pub struct RuntimeDiagnosticsRepairControlRecord {
    pub operation: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub decision_id: String,
    pub status: String,
    pub event: Value,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeDiagnosticsRepairRetryRunRequest {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub decision_id: Option<String>,
    #[serde(default)]
    pub gate_event_id: Option<String>,
    #[serde(default)]
    pub snapshot_id: Option<String>,
    #[serde(default)]
    pub target_run_id: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub request: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeDiagnosticsRepairRetryRunCore;

#[derive(Debug, Clone)]
pub struct RuntimeDiagnosticsRepairRetryRunRecord {
    pub operation: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub agent_id: String,
    pub decision_id: String,
    pub run_request: Value,
    pub retry_event_request: Value,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeDiagnosticsRepairRetryResultProjectionRequest {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub event: Value,
    #[serde(default)]
    pub run: Value,
    #[serde(default)]
    pub turn: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeDiagnosticsRepairRetryResultProjectionCore;

#[derive(Debug, Clone)]
pub struct RuntimeDiagnosticsRepairRetryResultProjectionRecord {
    pub operation: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub status: String,
    pub turn_id: Option<String>,
    pub request_id: Option<String>,
    pub repair_turn: Value,
    pub event: Value,
    pub repair_retry_event: Value,
    pub receipt_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub summary: String,
    pub evidence_refs: Vec<String>,
}

impl RuntimeDiagnosticsRepairControlCore {
    pub fn plan(
        &self,
        request: &RuntimeDiagnosticsRepairControlRequest,
    ) -> Result<RuntimeDiagnosticsRepairControlRecord, RuntimeDiagnosticsRepairControlCommandError>
    {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeDiagnosticsRepairControlCommandError::new(
                    "runtime_diagnostics_repair_control_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_REQUEST_SCHEMA_VERSION}, got {schema_version}"
                    ),
                ));
            }
        }

        let operation_kind = normalized_operation_kind(request)?;
        let operation = operation_for_kind(&operation_kind).to_string();
        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeDiagnosticsRepairControlCommandError::new(
                "runtime_diagnostics_repair_control_thread_id_required",
                "diagnostics repair control requires thread_id",
            )
        })?;
        let event_stream_id =
            optional_trimmed(request.event_stream_id.as_deref()).ok_or_else(|| {
                RuntimeDiagnosticsRepairControlCommandError::new(
                    "runtime_diagnostics_repair_control_event_stream_required",
                    "diagnostics repair control requires event_stream_id",
                )
            })?;
        let decision_id = optional_trimmed(request.decision_id.as_deref())
            .or_else(|| string_field(&request.request, "decision_id"))
            .ok_or_else(|| {
                RuntimeDiagnosticsRepairControlCommandError::new(
                    "runtime_diagnostics_repair_control_decision_id_required",
                    "diagnostics repair control requires decision_id",
                )
            })?;
        let event_seed = optional_trimmed(request.event_seed.as_deref())
            .or_else(|| string_field(&request.request, "event_seed"))
            .or_else(|| string_field(&request.request, "created_at"))
            .unwrap_or_else(|| decision_id.clone());
        let seed = format!("{thread_id}:{operation_kind}:{decision_id}:{event_seed}");
        let event_hash = short_hash(seed);
        let turn_id = optional_trimmed(request.turn_id.as_deref())
            .or_else(|| string_field(&request.request, "turn_id"));
        let gate_event_id = optional_trimmed(request.gate_event_id.as_deref())
            .or_else(|| string_field(&request.request, "gate_event_id"));
        let gate_id = optional_trimmed(request.gate_id.as_deref())
            .or_else(|| string_field(&request.request, "gate_id"));
        let snapshot_id = optional_trimmed(request.snapshot_id.as_deref())
            .or_else(|| string_field(&request.request, "snapshot_id"));
        let workspace_root = optional_trimmed(request.workspace_root.as_deref())
            .or_else(|| string_field(&request.request, "workspace_root"));
        let source = optional_trimmed(request.source.as_deref())
            .or_else(|| string_field(&request.request, "source"))
            .unwrap_or_else(|| "agent_studio".to_string());
        let status = optional_trimmed(request.status.as_deref())
            .or_else(|| string_field(&request.request, "status"))
            .unwrap_or_else(|| default_status(&operation_kind).to_string());
        let receipt_refs = diagnostics_repair_receipt_refs(request, &operation, &event_hash);
        let policy_decision_refs =
            diagnostics_repair_policy_decision_refs(request, &operation, &event_hash);
        let evidence_refs = diagnostics_repair_evidence_refs(request, &operation_kind);
        let operator_override_authority = diagnostics_operator_override_event_authority(
            request,
            &operation_kind,
            &thread_id,
            &decision_id,
        )?;
        let event_id = string_field(&request.request, "event_id").unwrap_or_else(|| {
            format!(
                "event_diagnostics_repair_{}_{}",
                safe_id(&operation),
                event_hash
            )
        });
        let turn_or_thread = turn_id.clone().unwrap_or_else(|| thread_id.clone());
        let event = json!({
            "event_id": event_id,
            "event_stream_id": event_stream_id,
            "thread_id": thread_id,
            "turn_id": turn_id.unwrap_or_default(),
            "item_id": format!("{turn_or_thread}:item:diagnostics_repair:{}:{}", safe_id(&operation), safe_id(&decision_id)),
            "idempotency_key": string_field(&request.request, "idempotency_key")
                .unwrap_or_else(|| format!("thread:{thread_id}:{operation_kind}:{decision_id}:{event_hash}")),
            "source": source,
            "source_event_kind": source_event_kind(&operation_kind),
            "event_kind": operation_kind,
            "status": status,
            "actor": "operator",
            "workspace_root": workspace_root.unwrap_or_default(),
            "component_kind": "diagnostics_repair",
            "payload_schema_version": "ioi.runtime.diagnostics-repair-control.v1",
            "payload": diagnostics_repair_payload(
                request,
                &operation,
                &decision_id,
                gate_event_id,
                gate_id,
                snapshot_id,
                operator_override_authority,
            ),
            "receipt_refs": receipt_refs,
            "policy_decision_refs": policy_decision_refs,
            "artifact_refs": string_array_field(&request.request, "artifact_refs"),
            "rollback_refs": string_array_field(&request.request, "rollback_refs"),
            "redaction_profile": "internal",
            "fixture_profile": "local_daemon_agentgres_projection",
            "evidence_refs": evidence_refs,
        });

        Ok(RuntimeDiagnosticsRepairControlRecord {
            operation,
            operation_kind,
            thread_id,
            decision_id,
            status,
            event,
            receipt_refs,
            policy_decision_refs,
            evidence_refs,
        })
    }
}

impl RuntimeDiagnosticsRepairRetryRunCore {
    pub fn plan(
        &self,
        request: &RuntimeDiagnosticsRepairRetryRunRequest,
    ) -> Result<RuntimeDiagnosticsRepairRetryRunRecord, RuntimeDiagnosticsRepairControlCommandError>
    {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_DIAGNOSTICS_REPAIR_RETRY_RUN_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeDiagnosticsRepairControlCommandError::new(
                    "runtime_diagnostics_repair_retry_run_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_DIAGNOSTICS_REPAIR_RETRY_RUN_REQUEST_SCHEMA_VERSION}, got {schema_version}"
                    ),
                ));
            }
        }

        let operation = optional_trimmed(request.operation.as_deref())
            .unwrap_or_else(|| "diagnostics_repair_retry_run_create".to_string());
        if operation != "diagnostics_repair_retry_run_create" {
            return Err(RuntimeDiagnosticsRepairControlCommandError::new(
                "runtime_diagnostics_repair_retry_run_operation_unsupported",
                format!("{operation} is not a diagnostics repair retry run operation"),
            ));
        }
        let operation_kind = optional_trimmed(request.operation_kind.as_deref())
            .unwrap_or_else(|| "diagnostics.repair_retry.run_create".to_string());
        if operation_kind != "diagnostics.repair_retry.run_create" {
            return Err(RuntimeDiagnosticsRepairControlCommandError::new(
                "runtime_diagnostics_repair_retry_run_operation_kind_unsupported",
                format!("{operation_kind} is not a diagnostics repair retry run operation kind"),
            ));
        }
        reject_retired_retry_run_request_transport(&request.request)?;

        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeDiagnosticsRepairControlCommandError::new(
                "runtime_diagnostics_repair_retry_run_thread_id_required",
                "diagnostics repair retry run planning requires thread_id",
            )
        })?;
        let agent_id = optional_trimmed(request.agent_id.as_deref()).ok_or_else(|| {
            RuntimeDiagnosticsRepairControlCommandError::new(
                "runtime_diagnostics_repair_retry_run_agent_id_required",
                "diagnostics repair retry run planning requires agent_id",
            )
        })?;
        let decision_id = optional_trimmed(request.decision_id.as_deref())
            .or_else(|| string_field(&request.request, "decision_id"))
            .ok_or_else(|| {
                RuntimeDiagnosticsRepairControlCommandError::new(
                    "runtime_diagnostics_repair_retry_run_decision_id_required",
                    "diagnostics repair retry run planning requires decision_id",
                )
            })?;
        let gate_event_id = optional_trimmed(request.gate_event_id.as_deref())
            .or_else(|| string_field(&request.request, "gate_event_id"));
        let snapshot_id = optional_trimmed(request.snapshot_id.as_deref())
            .or_else(|| string_field(&request.request, "snapshot_id"));
        let target_run_id = optional_trimmed(request.target_run_id.as_deref())
            .or_else(|| string_field(&request.request, "target_run_id"));
        let prompt = optional_trimmed(request.prompt.as_deref())
            .or_else(|| string_field(&request.request, "prompt"))
            .unwrap_or_else(|| format!("Retry diagnostics repair for {decision_id}."));
        let summary = string_field(&request.request, "summary")
            .unwrap_or_else(|| "Diagnostics repair retry turn created.".to_string());
        let receipt_refs = unique_strings(
            request
                .receipt_refs
                .iter()
                .cloned()
                .chain(string_array_field(&request.request, "receipt_refs"))
                .collect(),
        );
        let policy_decision_refs = unique_strings(
            request
                .policy_decision_refs
                .iter()
                .cloned()
                .chain(string_array_field(&request.request, "policy_decision_refs"))
                .collect(),
        );
        let evidence_refs = diagnostics_repair_retry_run_evidence_refs(request);

        let mut options = object_field(&request.request, "options").unwrap_or_default();
        options.insert(
            "diagnostics_repair".to_string(),
            json!({
                "action": "repair_retry",
                "decision_id": decision_id,
                "gate_event_id": gate_event_id,
                "snapshot_id": snapshot_id,
            }),
        );
        let diagnostics_feedback = json!({
            "mode": "repair_retry",
            "decision_id": decision_id,
            "gate_event_id": gate_event_id,
            "snapshot_id": snapshot_id,
        });
        let run_request = json!({
            "mode": "send",
            "prompt": prompt,
            "options": Value::Object(options),
            "diagnostics_feedback": diagnostics_feedback,
        });
        let retry_event_request = json!({
            "decision_id": decision_id,
            "gate_event_id": gate_event_id,
            "snapshot_id": snapshot_id,
            "action": "repair_retry",
            "target_run_id": target_run_id,
            "summary": summary,
            "receipt_refs": receipt_refs,
            "policy_decision_refs": policy_decision_refs,
        });

        Ok(RuntimeDiagnosticsRepairRetryRunRecord {
            operation,
            operation_kind,
            thread_id,
            agent_id,
            decision_id,
            run_request,
            retry_event_request,
            receipt_refs,
            policy_decision_refs,
            evidence_refs,
        })
    }
}

impl RuntimeDiagnosticsRepairRetryResultProjectionCore {
    pub fn project(
        &self,
        request: &RuntimeDiagnosticsRepairRetryResultProjectionRequest,
    ) -> Result<
        RuntimeDiagnosticsRepairRetryResultProjectionRecord,
        RuntimeDiagnosticsRepairControlCommandError,
    > {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version
                != RUNTIME_DIAGNOSTICS_REPAIR_RETRY_RESULT_PROJECTION_REQUEST_SCHEMA_VERSION
            {
                return Err(RuntimeDiagnosticsRepairControlCommandError::new(
                    "runtime_diagnostics_repair_retry_result_projection_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_DIAGNOSTICS_REPAIR_RETRY_RESULT_PROJECTION_REQUEST_SCHEMA_VERSION}, got {schema_version}"
                    ),
                ));
            }
        }
        let operation = optional_trimmed(request.operation.as_deref())
            .unwrap_or_else(|| "project_runtime_diagnostics_repair_retry_result".to_string());
        if operation != "project_runtime_diagnostics_repair_retry_result" {
            return Err(RuntimeDiagnosticsRepairControlCommandError::new(
                "runtime_diagnostics_repair_retry_result_projection_operation_unsupported",
                format!("{operation} is not a diagnostics repair retry result projection"),
            ));
        }
        let operation_kind = optional_trimmed(request.operation_kind.as_deref())
            .unwrap_or_else(|| "runtime.diagnostics_repair_retry.result".to_string());
        if operation_kind != "runtime.diagnostics_repair_retry.result" {
            return Err(RuntimeDiagnosticsRepairControlCommandError::new(
                "runtime_diagnostics_repair_retry_result_projection_operation_kind_unsupported",
                format!("{operation_kind} is not a diagnostics repair retry result operation kind"),
            ));
        }
        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeDiagnosticsRepairControlCommandError::new(
                "runtime_diagnostics_repair_retry_result_projection_thread_id_required",
                "diagnostics repair retry result projection requires thread_id",
            )
        })?;
        let event = request.event.as_object().ok_or_else(|| {
            RuntimeDiagnosticsRepairControlCommandError::new(
                "runtime_diagnostics_repair_retry_result_projection_event_required",
                "diagnostics repair retry result projection requires the admitted retry event",
            )
        })?;
        if string_field(&request.event, "event_kind").as_deref()
            != Some("diagnostics.repair_retry.created")
        {
            return Err(RuntimeDiagnosticsRepairControlCommandError::new(
                "runtime_diagnostics_repair_retry_result_projection_event_kind_invalid",
                "diagnostics repair retry result projection requires a Rust-admitted retry-created event",
            ));
        }
        if let Some(event_thread_id) = string_field(&request.event, "thread_id") {
            if event_thread_id != thread_id {
                return Err(RuntimeDiagnosticsRepairControlCommandError::new(
                    "runtime_diagnostics_repair_retry_result_projection_thread_mismatch",
                    "diagnostics repair retry result event thread_id does not match request thread_id",
                ));
            }
        }
        let payload = event
            .get("payload_summary")
            .or_else(|| event.get("payload"))
            .cloned()
            .unwrap_or(Value::Null);
        reject_retired_retry_result_projection_transport(&payload)?;
        let turn_id = string_field(&request.turn, "turn_id")
            .or_else(|| string_field(&payload, "retry_turn_id"))
            .or_else(|| string_field(&request.run, "turn_id"));
        let request_id = string_field(&request.turn, "request_id")
            .or_else(|| string_field(&request.run, "id"))
            .or_else(|| string_field(&payload, "retry_request_id"));
        let summary = string_field(&payload, "summary")
            .unwrap_or_else(|| "Diagnostics repair retry turn created.".to_string());
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_diagnostics_repair_retry_result_projection_rust_owned".to_string(),
                "runtime_diagnostics_repair_retry_event_replay_required".to_string(),
                "runtime_diagnostics_repair_js_result_helper_retired".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };

        Ok(RuntimeDiagnosticsRepairRetryResultProjectionRecord {
            operation,
            operation_kind,
            thread_id,
            status: string_field(&request.event, "status").unwrap_or_else(|| "created".to_string()),
            turn_id,
            request_id,
            repair_turn: if request.turn.is_object() {
                request.turn.clone()
            } else {
                Value::Null
            },
            event: request.event.clone(),
            repair_retry_event: request.event.clone(),
            receipt_refs: string_array_field(&request.event, "receipt_refs"),
            artifact_refs: string_array_field(&request.event, "artifact_refs"),
            policy_decision_refs: string_array_field(&request.event, "policy_decision_refs"),
            rollback_refs: string_array_field(&request.event, "rollback_refs"),
            summary,
            evidence_refs,
        })
    }
}

fn normalized_operation_kind(
    request: &RuntimeDiagnosticsRepairControlRequest,
) -> Result<String, RuntimeDiagnosticsRepairControlCommandError> {
    let operation_kind = optional_trimmed(request.operation_kind.as_deref()).or_else(|| {
        optional_trimmed(request.operation.as_deref()).map(|operation| match operation.as_str() {
            "diagnostics_repair_decision_execution" | "decision_execution" | "execute" => {
                "diagnostics.repair_decision.execute".to_string()
            }
            "diagnostics_repair_decision_event_append" | "decision_event" | "event_append" => {
                "diagnostics.repair_decision.executed".to_string()
            }
            "diagnostics_repair_retry_event_append"
            | "diagnostics_repair_retry_turn_creation"
            | "repair_retry"
            | "retry_event"
            | "retry_created" => "diagnostics.repair_retry.created".to_string(),
            "diagnostics_operator_override_event_append"
            | "operator_override"
            | "operator_override_event"
            | "override_event" => "diagnostics.operator_override.event".to_string(),
            _ => operation,
        })
    });
    match operation_kind.as_deref() {
        Some("diagnostics.repair_decision.execute")
        | Some("diagnostics.repair_decision.executed")
        | Some("diagnostics.repair_retry.created")
        | Some("diagnostics.operator_override.event") => Ok(operation_kind.unwrap()),
        Some(value) => Err(RuntimeDiagnosticsRepairControlCommandError::new(
            "runtime_diagnostics_repair_control_operation_kind_unsupported",
            format!("{value} is not yet Rust-owned"),
        )),
        None => Err(RuntimeDiagnosticsRepairControlCommandError::new(
            "runtime_diagnostics_repair_control_operation_kind_required",
            "diagnostics repair control requires operation_kind",
        )),
    }
}

fn operation_for_kind(operation_kind: &str) -> &'static str {
    match operation_kind {
        "diagnostics.repair_decision.executed" => "diagnostics_repair_decision_event_append",
        "diagnostics.repair_retry.created" => "diagnostics_repair_retry_event_append",
        "diagnostics.operator_override.event" => "diagnostics_operator_override_event_append",
        _ => "diagnostics_repair_decision_execution",
    }
}

fn default_status(operation_kind: &str) -> &'static str {
    match operation_kind {
        "diagnostics.repair_decision.executed" => "executed",
        "diagnostics.repair_retry.created" => "created",
        "diagnostics.operator_override.event" => "overridden",
        _ => "accepted",
    }
}

fn source_event_kind(operation_kind: &str) -> &'static str {
    match operation_kind {
        "diagnostics.repair_decision.executed" => "DiagnosticsRepair.DecisionExecuted",
        "diagnostics.repair_retry.created" => "DiagnosticsRepair.RetryCreated",
        "diagnostics.operator_override.event" => "DiagnosticsRepair.OperatorOverride",
        _ => "DiagnosticsRepair.DecisionExecute",
    }
}

fn diagnostics_repair_payload(
    request: &RuntimeDiagnosticsRepairControlRequest,
    operation: &str,
    decision_id: &str,
    gate_event_id: Option<String>,
    gate_id: Option<String>,
    snapshot_id: Option<String>,
    operator_override_authority: Value,
) -> Value {
    json!({
        "schema_version": "ioi.runtime.diagnostics-repair-control.payload.v1",
        "operation": operation,
        "decision_id": decision_id,
        "gate_event_id": gate_event_id,
        "gate_id": gate_id,
        "snapshot_id": snapshot_id,
        "action": string_field(&request.request, "action"),
        "repair_action": string_field(&request.request, "repair_action"),
        "approval_id": string_field(&request.request, "approval_id"),
        "diagnostic_refs": string_array_field(&request.request, "diagnostic_refs"),
        "target_paths": string_array_field(&request.request, "target_paths"),
        "retry_turn_id": string_field(&request.request, "retry_turn_id"),
        "retry_request_id": string_field(&request.request, "retry_request_id"),
        "retry_run_id": string_field(&request.request, "retry_run_id"),
        "target_run_id": string_field(&request.request, "target_run_id"),
        "summary": string_field(&request.request, "summary"),
        "authority": operator_override_authority.clone(),
        "authority_hash": string_field(&operator_override_authority, "authority_hash"),
        "wallet_network_grant_refs": string_array_field(&operator_override_authority, "wallet_network_grant_refs"),
        "authority_receipt_refs": string_array_field(&operator_override_authority, "authority_receipt_refs"),
        "direct_truth_write_allowed": operator_override_authority
            .get("direct_truth_write_allowed")
            .and_then(Value::as_bool),
    })
}

fn diagnostics_operator_override_event_authority(
    request: &RuntimeDiagnosticsRepairControlRequest,
    operation_kind: &str,
    thread_id: &str,
    decision_id: &str,
) -> Result<Value, RuntimeDiagnosticsRepairControlCommandError> {
    if operation_kind != "diagnostics.operator_override.event" {
        return Ok(Value::Null);
    }
    reject_retired_operator_override_authority_transport(&request.request)?;
    let wallet_network_grant_refs = unique_strings(
        string_array_field(&request.request, "authority_grant_refs")
            .into_iter()
            .filter(|grant_ref| is_wallet_network_grant_ref(grant_ref))
            .collect(),
    );
    if wallet_network_grant_refs.is_empty() {
        return Err(RuntimeDiagnosticsRepairControlCommandError::new(
            "runtime_diagnostics_operator_override_wallet_authority_required",
            "diagnostics operator override events require wallet.network authority grants",
        ));
    }
    let authority_receipt_refs = unique_strings(string_array_field(
        &request.request,
        "authority_receipt_refs",
    ));
    if authority_receipt_refs.is_empty() {
        return Err(RuntimeDiagnosticsRepairControlCommandError::new(
            "runtime_diagnostics_operator_override_authority_receipt_required",
            "diagnostics operator override events require wallet.network authority receipts",
        ));
    }
    let policy_decision_refs = unique_strings(
        request
            .policy_decision_refs
            .iter()
            .cloned()
            .chain(string_array_field(&request.request, "policy_decision_refs"))
            .collect(),
    );
    let mut authority = json!({
        "schema_version": "ioi.runtime.diagnostics-operator-override-authority.v1",
        "object": "ioi.runtime_diagnostics_operator_override_authority",
        "status": "authorized",
        "operation_kind": "diagnostics.operator_override.authority",
        "thread_id": thread_id,
        "decision_id": decision_id,
        "approval_id": string_field(&request.request, "approval_id"),
        "wallet_network_grant_refs": wallet_network_grant_refs,
        "authority_receipt_refs": authority_receipt_refs,
        "policy_decision_refs": policy_decision_refs,
        "direct_truth_write_allowed": false,
        "authority_hash": "",
        "projection_source": "rust_daemon_core_wallet_network_diagnostics_operator_override_authority",
        "generated_at": "rust_policy_core",
    });
    let authority_hash = diagnostics_operator_override_authority_hash(&authority)?;
    if let Some(object) = authority.as_object_mut() {
        object.insert("authority_hash".to_string(), Value::String(authority_hash));
    }
    Ok(authority)
}

fn reject_retired_operator_override_authority_transport(
    request: &Value,
) -> Result<(), RuntimeDiagnosticsRepairControlCommandError> {
    let Some(request) = request.as_object() else {
        return Ok(());
    };
    let retired: Vec<String> = [
        "walletNetworkGrantRefs",
        "authorityGrantRefs",
        "authorityReceiptRefs",
        "policyDecisionRefs",
        "authorityHash",
    ]
    .into_iter()
    .filter(|field| request.contains_key(*field))
    .map(str::to_string)
    .collect();
    if retired.is_empty() {
        Ok(())
    } else {
        Err(RuntimeDiagnosticsRepairControlCommandError::new(
            "runtime_diagnostics_operator_override_authority_transport_retired",
            format!("retired diagnostics operator override authority transport: {retired:?}"),
        ))
    }
}

fn diagnostics_operator_override_authority_hash(
    authority: &Value,
) -> Result<String, RuntimeDiagnosticsRepairControlCommandError> {
    let bytes = serde_json::to_vec(authority).map_err(|error| {
        RuntimeDiagnosticsRepairControlCommandError::new(
            "runtime_diagnostics_operator_override_authority_hash_failed",
            error.to_string(),
        )
    })?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn diagnostics_repair_receipt_refs(
    request: &RuntimeDiagnosticsRepairControlRequest,
    operation: &str,
    event_hash: &str,
) -> Vec<String> {
    unique_strings(
        request
            .receipt_refs
            .iter()
            .cloned()
            .chain(string_array_field(&request.request, "receipt_refs"))
            .chain(string_array_field(
                &request.request,
                "authority_receipt_refs",
            ))
            .chain(std::iter::once(format!(
                "receipt_diagnostics_repair_{}_{event_hash}",
                safe_id(operation)
            )))
            .collect(),
    )
}

fn diagnostics_repair_policy_decision_refs(
    request: &RuntimeDiagnosticsRepairControlRequest,
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
                "policy_diagnostics_repair_{}_{event_hash}",
                safe_id(operation)
            )))
            .collect(),
    )
}

fn diagnostics_repair_evidence_refs(
    request: &RuntimeDiagnosticsRepairControlRequest,
    operation_kind: &str,
) -> Vec<String> {
    if !request.evidence_refs.is_empty() {
        return request.evidence_refs.clone();
    }
    let operation_ref = match operation_kind {
        "diagnostics.repair_decision.executed" => {
            "runtime_diagnostics_repair_decision_event_rust_owned"
        }
        "diagnostics.repair_retry.created" => "runtime_diagnostics_repair_retry_event_rust_owned",
        "diagnostics.operator_override.event" => {
            "runtime_diagnostics_operator_override_event_rust_owned"
        }
        _ => "runtime_diagnostics_repair_decision_execution_rust_owned",
    };
    vec![
        operation_ref.to_string(),
        "runtime_diagnostics_repair_control_event_rust_owned".to_string(),
        "agentgres_runtime_thread_event_truth_required".to_string(),
    ]
}

fn diagnostics_repair_retry_run_evidence_refs(
    request: &RuntimeDiagnosticsRepairRetryRunRequest,
) -> Vec<String> {
    if !request.evidence_refs.is_empty() {
        return request.evidence_refs.clone();
    }
    vec![
        "runtime_diagnostics_repair_retry_run_request_rust_owned".to_string(),
        "diagnostics_repair_retry_run_create_rust_owned".to_string(),
        "runtime_run_create_js_facade_retired".to_string(),
    ]
}

fn object_field(value: &Value, key: &str) -> Option<Map<String, Value>> {
    value.get(key)?.as_object().cloned()
}

fn reject_retired_retry_run_request_transport(
    request: &Value,
) -> Result<(), RuntimeDiagnosticsRepairControlCommandError> {
    let Some(request) = request.as_object() else {
        return Ok(());
    };
    let retired: Vec<String> = [
        "repair_prompt",
        "repairPrompt",
        "targetRunId",
        "gateEventId",
        "snapshotId",
        "decisionId",
        "receiptRefs",
        "policyDecisionRefs",
        "idempotencyKey",
        "repairRetryIdempotencyKey",
        "retryRunId",
        "retryTurnId",
    ]
    .into_iter()
    .filter(|field| request.contains_key(*field))
    .map(str::to_string)
    .collect();
    if retired.is_empty() {
        Ok(())
    } else {
        Err(RuntimeDiagnosticsRepairControlCommandError::new(
            "runtime_diagnostics_repair_retry_run_transport_retired",
            format!("retired diagnostics repair retry run transport: {retired:?}"),
        ))
    }
}

fn reject_retired_retry_result_projection_transport(
    payload: &Value,
) -> Result<(), RuntimeDiagnosticsRepairControlCommandError> {
    let Some(payload) = payload.as_object() else {
        return Ok(());
    };
    let retired: Vec<String> = [
        "retryTurnId",
        "retryRequestId",
        "retryRunId",
        "turnId",
        "requestId",
        "receiptRefs",
        "artifactRefs",
        "policyDecisionRefs",
        "rollbackRefs",
    ]
    .into_iter()
    .filter(|field| payload.contains_key(*field))
    .map(str::to_string)
    .collect();
    if retired.is_empty() {
        Ok(())
    } else {
        Err(RuntimeDiagnosticsRepairControlCommandError::new(
            "runtime_diagnostics_repair_retry_result_projection_transport_retired",
            format!("retired diagnostics repair retry result projection transport: {retired:?}"),
        ))
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

fn is_wallet_network_grant_ref(grant_ref: &str) -> bool {
    let normalized = grant_ref.trim().to_ascii_lowercase();
    normalized.starts_with("wallet.network://grant/")
        || normalized.starts_with("grant://wallet.network/")
        || normalized.starts_with("wallet-network://grant/")
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

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request(operation_kind: &str) -> RuntimeDiagnosticsRepairControlRequest {
        RuntimeDiagnosticsRepairControlRequest {
            schema_version: Some(
                RUNTIME_DIAGNOSTICS_REPAIR_CONTROL_REQUEST_SCHEMA_VERSION.to_string(),
            ),
            operation_kind: Some(operation_kind.to_string()),
            thread_id: Some("thread_alpha".to_string()),
            event_stream_id: Some("event_stream_thread_alpha".to_string()),
            turn_id: Some("turn_alpha".to_string()),
            decision_id: Some("decision_alpha".to_string()),
            gate_event_id: Some("event_gate_alpha".to_string()),
            gate_id: Some("gate_alpha".to_string()),
            snapshot_id: Some("snapshot_alpha".to_string()),
            workspace_root: Some("/workspace".to_string()),
            request: json!({
                "source": "agent_studio",
                "action": "restore_apply",
                "diagnostic_refs": ["diagnostic_alpha"],
                "target_paths": ["src/main.rs"],
                "receipt_refs": ["receipt_request"],
                "policy_decision_refs": ["policy_request"]
            }),
            ..Default::default()
        }
    }

    fn retry_run_request() -> RuntimeDiagnosticsRepairRetryRunRequest {
        RuntimeDiagnosticsRepairRetryRunRequest {
            schema_version: Some(
                RUNTIME_DIAGNOSTICS_REPAIR_RETRY_RUN_REQUEST_SCHEMA_VERSION.to_string(),
            ),
            operation: Some("diagnostics_repair_retry_run_create".to_string()),
            operation_kind: Some("diagnostics.repair_retry.run_create".to_string()),
            thread_id: Some("thread_alpha".to_string()),
            agent_id: Some("agent_alpha".to_string()),
            decision_id: Some("decision_retry".to_string()),
            gate_event_id: Some("event_gate_alpha".to_string()),
            snapshot_id: Some("snapshot_alpha".to_string()),
            target_run_id: Some("run_blocked".to_string()),
            request: json!({
                "prompt": "Retry the diagnostics repair.",
                "summary": "Retry queued.",
                "options": {
                    "model": { "id": "route.local" }
                },
                "receipt_refs": ["receipt_retry_request"],
                "policy_decision_refs": ["policy_retry_request"]
            }),
            receipt_refs: vec!["receipt_retry_outer".to_string()],
            policy_decision_refs: vec!["policy_retry_outer".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn rust_plans_runtime_diagnostics_repair_decision_execution_control_event() {
        let record = RuntimeDiagnosticsRepairControlCore
            .plan(&base_request("diagnostics.repair_decision.execute"))
            .expect("diagnostics repair decision execution control");

        assert_eq!(record.operation, "diagnostics_repair_decision_execution");
        assert_eq!(record.operation_kind, "diagnostics.repair_decision.execute");
        assert_eq!(record.decision_id, "decision_alpha");
        assert_eq!(record.status, "accepted");
        assert_eq!(
            record.event["payload"]["decision_id"],
            Value::String("decision_alpha".to_string())
        );
        assert!(record.receipt_refs.iter().any(|value| value
            .starts_with("receipt_diagnostics_repair_diagnostics_repair_decision_execution_")));
        assert!(record
            .evidence_refs
            .contains(&"runtime_diagnostics_repair_decision_execution_rust_owned".to_string()));
        assert!(record
            .evidence_refs
            .contains(&"runtime_diagnostics_repair_control_event_rust_owned".to_string()));
    }

    #[test]
    fn rust_plans_runtime_diagnostics_repair_decision_executed_control_event() {
        let record = RuntimeDiagnosticsRepairControlCore
            .plan(&base_request("diagnostics.repair_decision.executed"))
            .expect("diagnostics repair decision executed event control");

        assert_eq!(record.operation, "diagnostics_repair_decision_event_append");
        assert_eq!(
            record.operation_kind,
            "diagnostics.repair_decision.executed"
        );
        assert_eq!(record.status, "executed");
        assert_eq!(
            record.event["source_event_kind"],
            "DiagnosticsRepair.DecisionExecuted"
        );
        assert!(record
            .evidence_refs
            .contains(&"runtime_diagnostics_repair_decision_event_rust_owned".to_string()));
    }

    #[test]
    fn rust_plans_runtime_diagnostics_repair_retry_created_control_event() {
        let mut request = base_request("diagnostics.repair_retry.created");
        request.request = json!({
            "action": "repair_retry",
            "retry_turn_id": "turn_retry",
            "retry_request_id": "run_retry",
            "retry_run_id": "run_retry",
            "target_run_id": "run_blocked",
            "summary": "Diagnostics repair retry turn created.",
        });
        let record = RuntimeDiagnosticsRepairControlCore
            .plan(&request)
            .expect("diagnostics repair retry created event control");

        assert_eq!(record.operation, "diagnostics_repair_retry_event_append");
        assert_eq!(record.operation_kind, "diagnostics.repair_retry.created");
        assert_eq!(record.status, "created");
        assert_eq!(
            record.event["source_event_kind"],
            "DiagnosticsRepair.RetryCreated"
        );
        assert_eq!(
            record.event["payload"]["retry_run_id"],
            Value::String("run_retry".to_string())
        );
        assert!(record
            .evidence_refs
            .contains(&"runtime_diagnostics_repair_retry_event_rust_owned".to_string()));
    }

    #[test]
    fn rust_plans_runtime_diagnostics_repair_retry_run_create_request() {
        let record = RuntimeDiagnosticsRepairRetryRunCore
            .plan(&retry_run_request())
            .expect("diagnostics repair retry run plan");

        assert_eq!(record.operation, "diagnostics_repair_retry_run_create");
        assert_eq!(record.operation_kind, "diagnostics.repair_retry.run_create");
        assert_eq!(record.thread_id, "thread_alpha");
        assert_eq!(record.agent_id, "agent_alpha");
        assert_eq!(record.decision_id, "decision_retry");
        assert_eq!(record.run_request["mode"], "send");
        assert_eq!(
            record.run_request["prompt"],
            Value::String("Retry the diagnostics repair.".to_string())
        );
        assert_eq!(
            record.run_request["options"]["diagnostics_repair"]["action"],
            "repair_retry"
        );
        assert_eq!(
            record.run_request["options"]["diagnostics_repair"]["decision_id"],
            "decision_retry"
        );
        assert_eq!(
            record.run_request["diagnostics_feedback"]["snapshot_id"],
            "snapshot_alpha"
        );
        assert_eq!(
            record.retry_event_request["target_run_id"],
            Value::String("run_blocked".to_string())
        );
        assert_eq!(record.retry_event_request["summary"], "Retry queued.");
        assert!(record
            .receipt_refs
            .contains(&"receipt_retry_outer".to_string()));
        assert!(record
            .receipt_refs
            .contains(&"receipt_retry_request".to_string()));
        assert!(record
            .evidence_refs
            .contains(&"runtime_diagnostics_repair_retry_run_request_rust_owned".to_string()));
    }

    #[test]
    fn rust_projects_runtime_diagnostics_repair_retry_result() {
        let request = RuntimeDiagnosticsRepairRetryResultProjectionRequest {
            schema_version: Some(
                RUNTIME_DIAGNOSTICS_REPAIR_RETRY_RESULT_PROJECTION_REQUEST_SCHEMA_VERSION
                    .to_string(),
            ),
            operation: Some("project_runtime_diagnostics_repair_retry_result".to_string()),
            operation_kind: Some("runtime.diagnostics_repair_retry.result".to_string()),
            thread_id: Some("thread_alpha".to_string()),
            event: json!({
                "event_id": "event_retry",
                "thread_id": "thread_alpha",
                "event_kind": "diagnostics.repair_retry.created",
                "status": "created",
                "payload": {
                    "retry_turn_id": "turn_retry",
                    "retry_request_id": "run_retry",
                    "summary": "Retry queued."
                },
                "receipt_refs": ["receipt_retry_event"],
                "artifact_refs": ["artifact_retry"],
                "policy_decision_refs": ["policy_retry"],
                "rollback_refs": ["snapshot_retry"]
            }),
            run: json!({ "id": "run_retry", "turn_id": "turn_retry" }),
            ..Default::default()
        };

        let record = RuntimeDiagnosticsRepairRetryResultProjectionCore
            .project(&request)
            .expect("diagnostics repair retry result projection");
        assert_eq!(
            record.operation,
            "project_runtime_diagnostics_repair_retry_result"
        );
        assert_eq!(
            record.operation_kind,
            "runtime.diagnostics_repair_retry.result"
        );
        assert_eq!(record.thread_id, "thread_alpha");
        assert_eq!(record.turn_id.as_deref(), Some("turn_retry"));
        assert_eq!(record.request_id.as_deref(), Some("run_retry"));
        assert_eq!(record.summary, "Retry queued.");
        assert!(record
            .receipt_refs
            .contains(&"receipt_retry_event".to_string()));
        assert!(record.evidence_refs.contains(
            &"runtime_diagnostics_repair_retry_result_projection_rust_owned".to_string()
        ));
    }

    #[test]
    fn rust_rejects_runtime_diagnostics_repair_retry_result_alias_transport() {
        let request = RuntimeDiagnosticsRepairRetryResultProjectionRequest {
            operation: Some("project_runtime_diagnostics_repair_retry_result".to_string()),
            operation_kind: Some("runtime.diagnostics_repair_retry.result".to_string()),
            thread_id: Some("thread_alpha".to_string()),
            event: json!({
                "thread_id": "thread_alpha",
                "event_kind": "diagnostics.repair_retry.created",
                "payload": {
                    "retryTurnId": "turn_legacy"
                }
            }),
            ..Default::default()
        };

        let error = RuntimeDiagnosticsRepairRetryResultProjectionCore
            .project(&request)
            .expect_err("retired retry result transport is rejected");
        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_retry_result_projection_transport_retired"
        );
    }

    #[test]
    fn rust_plans_runtime_diagnostics_operator_override_control_event() {
        let mut request = base_request("diagnostics.operator_override.event");
        request.request = json!({
            "action": "operator_override",
            "approval_id": "approval_override",
            "authority_grant_refs": ["wallet.network://grant/diagnostics/operator-override"],
            "authority_receipt_refs": ["receipt://wallet.network/diagnostics/operator-override"],
            "receipt_refs": ["receipt_request"],
            "policy_decision_refs": ["policy_request"]
        });
        let record = RuntimeDiagnosticsRepairControlCore
            .plan(&request)
            .expect("diagnostics operator override event control");

        assert_eq!(
            record.operation,
            "diagnostics_operator_override_event_append"
        );
        assert_eq!(record.operation_kind, "diagnostics.operator_override.event");
        assert_eq!(record.status, "overridden");
        assert_eq!(
            record.event["source_event_kind"],
            "DiagnosticsRepair.OperatorOverride"
        );
        assert_eq!(
            record.event["payload"]["approval_id"],
            Value::String("approval_override".to_string())
        );
        assert_eq!(
            record.event["payload"]["authority"]["wallet_network_grant_refs"][0],
            "wallet.network://grant/diagnostics/operator-override"
        );
        assert_eq!(
            record.event["payload"]["authority"]["authority_receipt_refs"][0],
            "receipt://wallet.network/diagnostics/operator-override"
        );
        assert_eq!(
            record.event["payload"]["direct_truth_write_allowed"],
            Value::Bool(false)
        );
        assert!(record.event["payload"]["authority_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert!(record
            .receipt_refs
            .contains(&"receipt://wallet.network/diagnostics/operator-override".to_string()));
        assert!(record
            .evidence_refs
            .contains(&"runtime_diagnostics_operator_override_event_rust_owned".to_string()));
    }

    #[test]
    fn rust_rejects_runtime_diagnostics_operator_override_control_without_wallet_authority() {
        let mut request = base_request("diagnostics.operator_override.event");
        request.request = json!({
            "action": "operator_override",
            "approval_id": "approval_override",
            "authority_grant_refs": ["grant://local-debug"],
            "authority_receipt_refs": ["receipt://wallet.network/diagnostics/operator-override"],
        });

        let error = RuntimeDiagnosticsRepairControlCore
            .plan(&request)
            .expect_err("operator override event requires wallet.network grant");
        assert_eq!(
            error.code(),
            "runtime_diagnostics_operator_override_wallet_authority_required"
        );

        request.request = json!({
            "action": "operator_override",
            "approval_id": "approval_override",
            "authority_grant_refs": ["wallet.network://grant/diagnostics/operator-override"],
        });
        let error = RuntimeDiagnosticsRepairControlCore
            .plan(&request)
            .expect_err("operator override event requires authority receipt");
        assert_eq!(
            error.code(),
            "runtime_diagnostics_operator_override_authority_receipt_required"
        );
    }

    #[test]
    fn rust_rejects_runtime_diagnostics_repair_retry_run_retired_transport() {
        let mut request = retry_run_request();
        request.request = json!({
            "repair_prompt": "legacy retry prompt",
            "targetRunId": "run_legacy"
        });

        let error = RuntimeDiagnosticsRepairRetryRunCore
            .plan(&request)
            .expect_err("retired retry run transport is rejected");
        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_retry_run_transport_retired"
        );
    }

    #[test]
    fn rust_rejects_runtime_diagnostics_operator_override_authority_alias_transport() {
        let mut request = base_request("diagnostics.operator_override.event");
        request.request = json!({
            "action": "operator_override",
            "walletNetworkGrantRefs": ["wallet.network://grant/diagnostics/operator-override"],
            "authorityReceiptRefs": ["receipt://wallet.network/diagnostics/operator-override"],
        });

        let error = RuntimeDiagnosticsRepairControlCore
            .plan(&request)
            .expect_err("retired operator override authority transport");
        assert_eq!(
            error.code(),
            "runtime_diagnostics_operator_override_authority_transport_retired"
        );
    }

    #[test]
    fn rust_rejects_runtime_diagnostics_repair_control_without_decision_id() {
        let mut request = base_request("diagnostics.repair_decision.execute");
        request.decision_id = None;

        let error = RuntimeDiagnosticsRepairControlCore
            .plan(&request)
            .expect_err("missing diagnostics repair decision id");
        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_control_decision_id_required"
        );
    }

    #[test]
    fn rust_rejects_unowned_runtime_diagnostics_repair_control_kind() {
        let mut request = base_request("diagnostics.repair_projection.resolve");
        let error = RuntimeDiagnosticsRepairControlCore
            .plan(&request)
            .expect_err("unsupported diagnostics repair operation kind");
        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_control_operation_kind_unsupported"
        );

        request.operation_kind = None;
        request.operation = None;
        let error = RuntimeDiagnosticsRepairControlCore
            .plan(&request)
            .expect_err("missing diagnostics repair operation kind");
        assert_eq!(
            error.code(),
            "runtime_diagnostics_repair_control_operation_kind_required"
        );
    }
}
