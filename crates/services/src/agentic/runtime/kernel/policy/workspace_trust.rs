use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::{
    WORKSPACE_TRUST_CONTROL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    WORKSPACE_TRUST_CONTROL_STATE_UPDATE_RESULT_SCHEMA_VERSION,
};

pub const WORKSPACE_TRUST_WARNING_SCHEMA_VERSION: &str = "ioi.runtime.workspace-trust-warning.v1";
pub const WORKSPACE_TRUST_ACKNOWLEDGEMENT_SCHEMA_VERSION: &str =
    "ioi.runtime.workspace-trust-acknowledgement.v1";

#[derive(Debug, Clone, PartialEq)]
pub enum WorkspaceTrustControlStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    UnsupportedOperationKind(String),
    WarningEventNotFound(String),
    MismatchedField {
        field: &'static str,
        expected: String,
        actual: String,
    },
    HashFailed(String),
}

#[derive(Debug, Clone)]
pub struct WorkspaceTrustControlCommandError {
    code: &'static str,
    message: String,
}

impl WorkspaceTrustControlCommandError {
    fn from_debug(code: &'static str, error: WorkspaceTrustControlStateUpdateError) -> Self {
        Self {
            code,
            message: format!("{error:?}"),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceTrustControlStateUpdateRequest {
    pub schema_version: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub event_stream_id: String,
    #[serde(default)]
    pub agent: Value,
    #[serde(default)]
    pub controls: Value,
    #[serde(default)]
    pub warning_id: Option<String>,
    #[serde(default)]
    pub source_event_id: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub requested_by: Option<String>,
    #[serde(default)]
    pub workflow_graph_id: Option<String>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub seq: Option<u64>,
    pub created_at: String,
    #[serde(default)]
    pub events: Vec<Value>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
    #[serde(default)]
    pub wallet_authority_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
    #[serde(default)]
    pub ctee_receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceTrustControlStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub event_stream_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_event_id: Option<String>,
    pub created_at: String,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub wallet_authority_refs: Vec<String>,
    pub authority_receipt_refs: Vec<String>,
    pub ctee_receipt_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_trust_warning: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_trust_acknowledgement: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<Value>,
    pub generated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct WorkspaceTrustControlStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: WorkspaceTrustControlStateUpdateRequest,
}

pub fn plan_workspace_trust_control_state_update_response(
    request: WorkspaceTrustControlStateUpdateBridgeRequest,
) -> Result<Value, WorkspaceTrustControlCommandError> {
    let record = WorkspaceTrustControlStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            WorkspaceTrustControlCommandError::from_debug(
                "workspace_trust_control_state_update_invalid",
                error,
            )
        })?;
    Ok(json!({
        "source": "rust_workspace_trust_control_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "thread_id": record.thread_id.clone(),
        "event_stream_id": record.event_stream_id.clone(),
        "event_id": record.event_id.clone(),
        "warning_id": record.warning_id.clone(),
        "source_event_id": record.source_event_id.clone(),
        "created_at": record.created_at.clone(),
        "receipt_refs": record.receipt_refs.clone(),
        "policy_decision_refs": record.policy_decision_refs.clone(),
        "wallet_authority_refs": record.wallet_authority_refs.clone(),
        "authority_receipt_refs": record.authority_receipt_refs.clone(),
        "ctee_receipt_refs": record.ctee_receipt_refs.clone(),
        "workspace_trust_warning": record.workspace_trust_warning.clone(),
        "workspace_trust_acknowledgement": record.workspace_trust_acknowledgement.clone(),
        "event": record.event.clone(),
    }))
}

#[derive(Debug, Default, Clone)]
pub struct WorkspaceTrustControlStateUpdateCore;

impl WorkspaceTrustControlStateUpdateCore {
    pub fn plan(
        &self,
        request: &WorkspaceTrustControlStateUpdateRequest,
    ) -> Result<WorkspaceTrustControlStateUpdateRecord, WorkspaceTrustControlStateUpdateError> {
        request.validate()?;
        match request.operation_kind.as_str() {
            "workspace_trust.warning" => self.plan_warning(request),
            "workspace_trust.acknowledge" => self.plan_acknowledgement(request),
            other => Err(
                WorkspaceTrustControlStateUpdateError::UnsupportedOperationKind(other.to_string()),
            ),
        }
    }

    fn plan_warning(
        &self,
        request: &WorkspaceTrustControlStateUpdateRequest,
    ) -> Result<WorkspaceTrustControlStateUpdateRecord, WorkspaceTrustControlStateUpdateError> {
        let controls = request.controls.as_object().ok_or(
            WorkspaceTrustControlStateUpdateError::MissingField("controls"),
        )?;
        let mode = optional_map_string(controls, "mode").ok_or(
            WorkspaceTrustControlStateUpdateError::MissingField("controls.mode"),
        )?;
        if mode != "review" && mode != "yolo" {
            return Ok(not_required_record(request));
        }

        let agent = request
            .agent
            .as_object()
            .ok_or(WorkspaceTrustControlStateUpdateError::MissingField("agent"))?;
        let agent_id = optional_map_string(agent, "id").ok_or(
            WorkspaceTrustControlStateUpdateError::MissingField("agent.id"),
        )?;
        let workspace_root = optional_map_string(agent, "cwd")
            .or_else(|| optional_map_string(agent, "workspace_root"))
            .unwrap_or_else(|| "unknown".to_string());
        let approval_mode = optional_map_string(controls, "approval_mode")
            .unwrap_or_else(|| approval_mode_for_mode(&mode).to_string());
        let workflow_node_id = request
            .workflow_node_id
            .as_deref()
            .and_then(optional_trimmed)
            .unwrap_or("runtime.workspace-trust")
            .to_string();
        let workflow_graph_id = request
            .workflow_graph_id
            .as_deref()
            .and_then(optional_trimmed);
        let warning_id = request
            .warning_id
            .as_deref()
            .and_then(optional_trimmed)
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "workspace_trust_{}",
                    short_hash(
                        &format!(
                            "{}:{}:{}:{}:{}",
                            request.thread_id,
                            mode,
                            approval_mode,
                            workspace_root,
                            workflow_node_id
                        ),
                        16,
                    )
                )
            });
        let event_id = request
            .event_id
            .as_deref()
            .and_then(optional_trimmed)
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "evt_workspace_trust_warning_{}",
                    short_hash(
                        &format!(
                            "{}:{}:{}",
                            request.event_stream_id, warning_id, request.created_at
                        ),
                        16,
                    )
                )
            });
        let severity = if mode == "yolo" { "high" } else { "notice" };
        let warning_reasons = if mode == "yolo" {
            vec!["thread_yolo_mode_never_prompts".to_string()]
        } else {
            vec!["thread_review_mode_requires_visible_review".to_string()]
        };
        let summary = if mode == "yolo" {
            "YOLO mode can run without further prompts.".to_string()
        } else {
            "Review mode requires visible workspace-trust acknowledgement.".to_string()
        };
        let receipt_refs = workspace_trust_receipt_refs(request, "warning", &warning_id);
        let policy_decision_refs =
            workspace_trust_policy_refs(request, "warning", &warning_id, &mode);
        let wallet_authority_refs = unique_string_vec(request.wallet_authority_refs.clone());
        let authority_receipt_refs = unique_string_vec(request.authority_receipt_refs.clone());
        let ctee_receipt_refs = unique_string_vec(request.ctee_receipt_refs.clone());
        let warning = json!({
            "schema_version": WORKSPACE_TRUST_WARNING_SCHEMA_VERSION,
            "object": "ioi.workspace_trust_warning",
            "warning_id": warning_id.clone(),
            "generated_at": request.created_at.clone(),
            "status": "warning",
            "severity": severity,
            "summary": summary.clone(),
            "message": summary.clone(),
            "mode": mode.clone(),
            "thread_mode": mode.clone(),
            "approval_mode": approval_mode.clone(),
            "trust_profile": "local_private",
            "daemon_trust_source": "rust_workspace_trust_control",
            "canvas_local_trust_state_accepted": false,
            "ui_override_ignored": false,
            "ignored_ui_fields": [],
            "requested_by": request.requested_by.as_deref().and_then(optional_trimmed).unwrap_or("operator"),
            "control_surface": request.source.as_deref().and_then(optional_trimmed).unwrap_or("runtime_thread_control"),
            "agent_id": agent_id,
            "thread_id": request.thread_id.clone(),
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id.clone(),
            "source_mode_event_id": request.source_event_id.clone(),
            "workspace_root": workspace_root.clone(),
            "workspace_root_hash": format!("sha256:{}", sha256_hex(workspace_root.as_bytes())),
            "warning_reasons": warning_reasons.clone(),
            "read_only": true,
            "mutation_executed": false,
            "receipt_refs": receipt_refs.clone(),
            "policy_decision_refs": policy_decision_refs.clone(),
            "wallet_authority_refs": wallet_authority_refs.clone(),
            "authority_receipt_refs": authority_receipt_refs.clone(),
            "ctee_receipt_refs": ctee_receipt_refs.clone(),
            "evidence_refs": [
                "rust_workspace_trust_warning",
                "daemon_owned_workspace_trust",
                "runtime_thread_event_agentgres_admission"
            ],
        });
        let event = json!({
            "event_id": event_id.clone(),
            "event_stream_id": request.event_stream_id.clone(),
            "thread_id": request.thread_id.clone(),
            "turn_id": "",
            "item_id": format!("{}:workspace-trust-warning:{}", request.thread_id, warning_id),
            "idempotency_key": format!("{}:workspace-trust-warning:{}", request.thread_id, warning_id),
            "source": request.source.as_deref().and_then(optional_trimmed).unwrap_or("runtime_thread_control"),
            "source_event_kind": "WorkspaceTrust.Warning",
            "event_kind": "workspace.trust_warning",
            "status": "warning",
            "actor": "policy",
            "created_at": request.created_at.clone(),
            "workspace_root": workspace_root.clone(),
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id.clone(),
            "component_kind": "workspace_trust",
            "payload_schema_version": WORKSPACE_TRUST_WARNING_SCHEMA_VERSION,
            "payload_summary": warning.clone(),
            "receipt_refs": receipt_refs.clone(),
            "policy_decision_refs": policy_decision_refs.clone(),
            "artifact_refs": [],
            "rollback_refs": [],
            "redaction_profile": "internal",
            "fixture_profile": optional_map_string(agent, "fixtureProfile").unwrap_or_else(|| "runtime".to_string()),
        });

        Ok(WorkspaceTrustControlStateUpdateRecord {
            schema_version: WORKSPACE_TRUST_CONTROL_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_workspace_trust_control_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: request.operation_kind.clone(),
            thread_id: request.thread_id.clone(),
            event_stream_id: request.event_stream_id.clone(),
            event_id: Some(event_id),
            warning_id: Some(warning_id),
            source_event_id: request.source_event_id.clone(),
            created_at: request.created_at.clone(),
            receipt_refs,
            policy_decision_refs,
            wallet_authority_refs,
            authority_receipt_refs,
            ctee_receipt_refs,
            workspace_trust_warning: Some(warning),
            workspace_trust_acknowledgement: None,
            event: Some(event),
            generated_at: "rust_policy_core".to_string(),
        })
    }

    fn plan_acknowledgement(
        &self,
        request: &WorkspaceTrustControlStateUpdateRequest,
    ) -> Result<WorkspaceTrustControlStateUpdateRecord, WorkspaceTrustControlStateUpdateError> {
        let warning_id = request
            .warning_id
            .as_deref()
            .and_then(optional_trimmed)
            .ok_or(WorkspaceTrustControlStateUpdateError::MissingField(
                "warning_id",
            ))?
            .to_string();
        let warning_event = matching_warning_event(request, &warning_id)?;
        let warning_event_id = event_string(&warning_event, "event_id")
            .ok_or(WorkspaceTrustControlStateUpdateError::MissingField(
                "warning_event.event_id",
            ))?
            .to_string();
        if let Some(requested_source_event_id) = request
            .source_event_id
            .as_deref()
            .and_then(optional_trimmed)
        {
            if requested_source_event_id != warning_event_id {
                return Err(WorkspaceTrustControlStateUpdateError::MismatchedField {
                    field: "source_event_id",
                    expected: warning_event_id.clone(),
                    actual: requested_source_event_id.to_string(),
                });
            }
        }
        let payload = warning_event
            .get("payload_summary")
            .and_then(Value::as_object)
            .ok_or(WorkspaceTrustControlStateUpdateError::MissingField(
                "warning_event.payload_summary",
            ))?;
        let workflow_node_id = request
            .workflow_node_id
            .as_deref()
            .and_then(optional_trimmed)
            .or_else(|| event_string(&warning_event, "workflow_node_id"))
            .unwrap_or("runtime.workspace-trust")
            .to_string();
        let workflow_graph_id = request
            .workflow_graph_id
            .as_deref()
            .and_then(optional_trimmed)
            .or_else(|| event_string(&warning_event, "workflow_graph_id"));
        let event_id = request
            .event_id
            .as_deref()
            .and_then(optional_trimmed)
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "evt_workspace_trust_ack_{}",
                    short_hash(
                        &format!(
                            "{}:{}:{}",
                            request.event_stream_id, warning_id, request.created_at
                        ),
                        16,
                    )
                )
            });
        let actor = request
            .actor
            .as_deref()
            .and_then(optional_trimmed)
            .or_else(|| request.requested_by.as_deref().and_then(optional_trimmed))
            .unwrap_or("operator")
            .to_string();
        let receipt_refs = workspace_trust_receipt_refs(request, "ack", &warning_id);
        let policy_decision_refs = workspace_trust_policy_refs(request, "ack", &warning_id, &actor);
        let wallet_authority_refs = unique_string_vec(request.wallet_authority_refs.clone());
        let authority_receipt_refs = unique_string_vec(request.authority_receipt_refs.clone());
        let ctee_receipt_refs = unique_string_vec(request.ctee_receipt_refs.clone());
        let acknowledgement = json!({
            "schema_version": WORKSPACE_TRUST_ACKNOWLEDGEMENT_SCHEMA_VERSION,
            "object": "ioi.workspace_trust_acknowledgement",
            "warning_id": warning_id.clone(),
            "source_event_id": warning_event_id.clone(),
            "status": "acknowledged",
            "acknowledged_at": request.created_at.clone(),
            "acknowledged_by": actor.clone(),
            "reason": request.reason.as_deref().and_then(optional_trimmed).unwrap_or("Workspace trust warning acknowledged."),
            "thread_id": request.thread_id.clone(),
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id.clone(),
            "source_receipt_refs": string_array_from_map(&warning_event, "receipt_refs"),
            "source_policy_decision_refs": string_array_from_map(&warning_event, "policy_decision_refs"),
            "mode": optional_map_string(payload, "mode"),
            "approval_mode": optional_map_string(payload, "approval_mode"),
            "severity": optional_map_string(payload, "severity"),
            "receipt_refs": receipt_refs.clone(),
            "policy_decision_refs": policy_decision_refs.clone(),
            "wallet_authority_refs": wallet_authority_refs.clone(),
            "authority_receipt_refs": authority_receipt_refs.clone(),
            "ctee_receipt_refs": ctee_receipt_refs.clone(),
            "evidence_refs": [
                "rust_workspace_trust_acknowledgement",
                "runtime_thread_event_replay_warning_source",
                "runtime_thread_event_agentgres_admission"
            ],
        });
        let event = json!({
            "event_id": event_id.clone(),
            "event_stream_id": request.event_stream_id.clone(),
            "thread_id": request.thread_id.clone(),
            "turn_id": "",
            "item_id": format!("{}:workspace-trust-acknowledgement:{}", request.thread_id, warning_id),
            "idempotency_key": format!("{}:workspace-trust-acknowledgement:{}", request.thread_id, warning_id),
            "source": request.source.as_deref().and_then(optional_trimmed).unwrap_or("runtime_thread_control"),
            "source_event_kind": "WorkspaceTrust.Acknowledged",
            "event_kind": "workspace.trust_acknowledged",
            "status": "completed",
            "actor": actor.clone(),
            "created_at": request.created_at.clone(),
            "workspace_root": event_string(&warning_event, "workspace_root"),
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id.clone(),
            "component_kind": "workspace_trust",
            "payload_schema_version": WORKSPACE_TRUST_ACKNOWLEDGEMENT_SCHEMA_VERSION,
            "payload_summary": acknowledgement.clone(),
            "receipt_refs": receipt_refs.clone(),
            "policy_decision_refs": policy_decision_refs.clone(),
            "artifact_refs": [],
            "rollback_refs": [],
            "redaction_profile": "internal",
            "fixture_profile": event_string(&warning_event, "fixture_profile").unwrap_or("runtime"),
        });

        Ok(WorkspaceTrustControlStateUpdateRecord {
            schema_version: WORKSPACE_TRUST_CONTROL_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_workspace_trust_control_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: request.operation_kind.clone(),
            thread_id: request.thread_id.clone(),
            event_stream_id: request.event_stream_id.clone(),
            event_id: Some(event_id),
            warning_id: Some(warning_id),
            source_event_id: Some(warning_event_id),
            created_at: request.created_at.clone(),
            receipt_refs,
            policy_decision_refs,
            wallet_authority_refs,
            authority_receipt_refs,
            ctee_receipt_refs,
            workspace_trust_warning: None,
            workspace_trust_acknowledgement: Some(acknowledgement),
            event: Some(event),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

impl WorkspaceTrustControlStateUpdateRequest {
    pub fn validate(&self) -> Result<(), WorkspaceTrustControlStateUpdateError> {
        if self.schema_version != WORKSPACE_TRUST_CONTROL_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(
                WorkspaceTrustControlStateUpdateError::InvalidSchemaVersion {
                    expected: WORKSPACE_TRUST_CONTROL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        require_non_empty("operation_kind", &self.operation_kind)?;
        require_non_empty("thread_id", &self.thread_id)?;
        require_non_empty("event_stream_id", &self.event_stream_id)?;
        require_non_empty("created_at", &self.created_at)?;
        if !self.agent.is_object() {
            return Err(WorkspaceTrustControlStateUpdateError::MissingField("agent"));
        }
        match self.operation_kind.as_str() {
            "workspace_trust.warning" => {
                if !self.controls.is_object() {
                    return Err(WorkspaceTrustControlStateUpdateError::MissingField(
                        "controls",
                    ));
                }
            }
            "workspace_trust.acknowledge" => {
                if self
                    .warning_id
                    .as_deref()
                    .and_then(optional_trimmed)
                    .is_none()
                {
                    return Err(WorkspaceTrustControlStateUpdateError::MissingField(
                        "warning_id",
                    ));
                }
            }
            other => {
                return Err(
                    WorkspaceTrustControlStateUpdateError::UnsupportedOperationKind(
                        other.to_string(),
                    ),
                )
            }
        }
        Ok(())
    }
}

fn not_required_record(
    request: &WorkspaceTrustControlStateUpdateRequest,
) -> WorkspaceTrustControlStateUpdateRecord {
    WorkspaceTrustControlStateUpdateRecord {
        schema_version: WORKSPACE_TRUST_CONTROL_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
        object: "ioi.runtime_workspace_trust_control_state_update".to_string(),
        status: "not_required".to_string(),
        operation_kind: request.operation_kind.clone(),
        thread_id: request.thread_id.clone(),
        event_stream_id: request.event_stream_id.clone(),
        event_id: None,
        warning_id: None,
        source_event_id: request.source_event_id.clone(),
        created_at: request.created_at.clone(),
        receipt_refs: vec![],
        policy_decision_refs: vec![],
        wallet_authority_refs: unique_string_vec(request.wallet_authority_refs.clone()),
        authority_receipt_refs: unique_string_vec(request.authority_receipt_refs.clone()),
        ctee_receipt_refs: unique_string_vec(request.ctee_receipt_refs.clone()),
        workspace_trust_warning: None,
        workspace_trust_acknowledgement: None,
        event: None,
        generated_at: "rust_policy_core".to_string(),
    }
}

fn matching_warning_event(
    request: &WorkspaceTrustControlStateUpdateRequest,
    warning_id: &str,
) -> Result<Map<String, Value>, WorkspaceTrustControlStateUpdateError> {
    let requested_source_event_id = request
        .source_event_id
        .as_deref()
        .and_then(optional_trimmed);
    for event in request.events.iter().filter_map(Value::as_object) {
        let Some(payload) = event.get("payload_summary").and_then(Value::as_object) else {
            continue;
        };
        if optional_map_string(payload, "warning_id").as_deref() != Some(warning_id) {
            continue;
        }
        if event_string(event, "event_kind").as_deref() != Some("workspace.trust_warning") {
            continue;
        }
        if let Some(source_event_id) = requested_source_event_id {
            if event_string(event, "event_id").as_deref() != Some(source_event_id) {
                continue;
            }
        }
        return Ok(event.clone());
    }
    Err(WorkspaceTrustControlStateUpdateError::WarningEventNotFound(
        warning_id.to_string(),
    ))
}

fn workspace_trust_receipt_refs(
    request: &WorkspaceTrustControlStateUpdateRequest,
    kind: &str,
    warning_id: &str,
) -> Vec<String> {
    let refs = unique_string_vec(
        request
            .receipt_refs
            .iter()
            .chain(request.authority_receipt_refs.iter())
            .chain(request.ctee_receipt_refs.iter())
            .cloned()
            .collect(),
    );
    if refs.is_empty() {
        vec![format!(
            "receipt_workspace_trust_{}_{}",
            kind,
            short_hash(
                &format!(
                    "{}:{}:{}",
                    request.thread_id, warning_id, request.created_at
                ),
                16
            )
        )]
    } else {
        refs
    }
}

fn workspace_trust_policy_refs(
    request: &WorkspaceTrustControlStateUpdateRequest,
    kind: &str,
    warning_id: &str,
    discriminator: &str,
) -> Vec<String> {
    let refs = unique_string_vec(request.policy_decision_refs.clone());
    if refs.is_empty() {
        vec![format!(
            "policy_workspace_trust_{}_{}",
            kind,
            short_hash(
                &format!("{}:{}:{}", warning_id, discriminator, request.created_at),
                16
            )
        )]
    } else {
        refs
    }
}

fn approval_mode_for_mode(mode: &str) -> &'static str {
    if mode == "yolo" {
        "never_prompt"
    } else {
        "human_required"
    }
}

fn require_non_empty(
    field: &'static str,
    value: &str,
) -> Result<(), WorkspaceTrustControlStateUpdateError> {
    if optional_trimmed(value).is_none() {
        Err(WorkspaceTrustControlStateUpdateError::MissingField(field))
    } else {
        Ok(())
    }
}

fn optional_map_string(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(Value::as_str)
        .and_then(optional_trimmed)
        .map(str::to_string)
}

fn event_string<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key)
        .and_then(Value::as_str)
        .and_then(optional_trimmed)
}

fn optional_trimmed(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn string_array_from_map(map: &Map<String, Value>, key: &str) -> Vec<String> {
    map.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            unique_string_vec(
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect(),
            )
        })
        .unwrap_or_default()
}

fn unique_string_vec(values: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if !trimmed.is_empty() && !unique.iter().any(|existing| existing == trimmed) {
            unique.push(trimmed.to_string());
        }
    }
    unique
}

fn short_hash(input: &str, len: usize) -> String {
    sha256_hex(input.as_bytes()).chars().take(len).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warning_request(mode: &str) -> WorkspaceTrustControlStateUpdateRequest {
        WorkspaceTrustControlStateUpdateRequest {
            schema_version: WORKSPACE_TRUST_CONTROL_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            operation_kind: "workspace_trust.warning".to_string(),
            thread_id: "thread_1".to_string(),
            event_stream_id: "stream_thread_1".to_string(),
            agent: json!({
                "id": "agent_1",
                "cwd": "/workspace",
                "fixtureProfile": "fixture.test"
            }),
            controls: json!({
                "mode": mode,
                "approval_mode": if mode == "yolo" { "never_prompt" } else { "human_required" }
            }),
            warning_id: None,
            source_event_id: Some("evt_thread_mode".to_string()),
            reason: None,
            source: Some("react_flow".to_string()),
            actor: None,
            requested_by: Some("operator_1".to_string()),
            workflow_graph_id: Some("workflow_1".to_string()),
            workflow_node_id: Some("runtime.thread-mode.yolo.workspace-trust".to_string()),
            event_id: None,
            seq: Some(4),
            created_at: "2026-06-06T05:00:01.000Z".to_string(),
            events: vec![],
            receipt_refs: vec![],
            policy_decision_refs: vec![],
            wallet_authority_refs: vec!["wallet.network://grant/workspace-trust".to_string()],
            authority_receipt_refs: vec!["receipt://wallet.network/workspace-trust".to_string()],
            ctee_receipt_refs: vec!["receipt://ctee/private-workspace/workspace-trust".to_string()],
        }
    }

    #[test]
    fn rust_policy_plans_workspace_trust_warning_event() {
        let record = WorkspaceTrustControlStateUpdateCore
            .plan(&warning_request("yolo"))
            .expect("workspace trust warning");

        assert_eq!(
            record.schema_version,
            WORKSPACE_TRUST_CONTROL_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "workspace_trust.warning");
        assert_eq!(
            record.workspace_trust_warning.as_ref().unwrap()["schema_version"],
            WORKSPACE_TRUST_WARNING_SCHEMA_VERSION
        );
        assert_eq!(
            record.workspace_trust_warning.as_ref().unwrap()["mode"],
            "yolo"
        );
        assert_eq!(
            record.event.as_ref().unwrap()["event_kind"],
            "workspace.trust_warning"
        );
        assert_eq!(
            record.event.as_ref().unwrap()["source_event_kind"],
            "WorkspaceTrust.Warning"
        );
        assert_eq!(
            record.event.as_ref().unwrap()["payload_summary"]["warning_id"],
            record.warning_id.clone().unwrap()
        );
        assert!(record
            .receipt_refs
            .contains(&"receipt://wallet.network/workspace-trust".to_string()));
        assert!(record
            .receipt_refs
            .contains(&"receipt://ctee/private-workspace/workspace-trust".to_string()));
        assert!(record
            .event
            .as_ref()
            .unwrap()
            .get("workflowNodeId")
            .is_none());
    }

    #[test]
    fn rust_policy_skips_workspace_trust_warning_when_mode_is_not_risky() {
        let record = WorkspaceTrustControlStateUpdateCore
            .plan(&warning_request("agent"))
            .expect("workspace trust warning not required");

        assert_eq!(record.status, "not_required");
        assert!(record.event.is_none());
        assert!(record.workspace_trust_warning.is_none());
    }

    #[test]
    fn rust_policy_plans_workspace_trust_acknowledgement_event_from_replay() {
        let warning = WorkspaceTrustControlStateUpdateCore
            .plan(&warning_request("yolo"))
            .expect("workspace trust warning");
        let warning_event = warning.event.clone().unwrap();
        let warning_id = warning.warning_id.clone().unwrap();
        let request = WorkspaceTrustControlStateUpdateRequest {
            schema_version: WORKSPACE_TRUST_CONTROL_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            operation_kind: "workspace_trust.acknowledge".to_string(),
            thread_id: "thread_1".to_string(),
            event_stream_id: "stream_thread_1".to_string(),
            agent: json!({ "id": "agent_1", "cwd": "/workspace" }),
            controls: Value::Null,
            warning_id: Some(warning_id.clone()),
            source_event_id: warning.event_id.clone(),
            reason: Some("operator reviewed the warning".to_string()),
            source: Some("react_flow".to_string()),
            actor: Some("operator_1".to_string()),
            requested_by: None,
            workflow_graph_id: Some("workflow_1".to_string()),
            workflow_node_id: Some("runtime.thread-mode.yolo.workspace-trust".to_string()),
            event_id: None,
            seq: Some(5),
            created_at: "2026-06-06T05:00:02.000Z".to_string(),
            events: vec![warning_event],
            receipt_refs: vec![],
            policy_decision_refs: vec![],
            wallet_authority_refs: vec![],
            authority_receipt_refs: vec![],
            ctee_receipt_refs: vec![],
        };

        let record = WorkspaceTrustControlStateUpdateCore
            .plan(&request)
            .expect("workspace trust acknowledgement");

        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "workspace_trust.acknowledge");
        assert_eq!(record.warning_id, Some(warning_id.clone()));
        assert_eq!(
            record.workspace_trust_acknowledgement.as_ref().unwrap()["warning_id"],
            warning_id
        );
        assert_eq!(
            record.event.as_ref().unwrap()["event_kind"],
            "workspace.trust_acknowledged"
        );
        assert_eq!(
            record.event.as_ref().unwrap()["payload_schema_version"],
            WORKSPACE_TRUST_ACKNOWLEDGEMENT_SCHEMA_VERSION
        );
        assert!(record.receipt_refs[0].starts_with("receipt_workspace_trust_ack_"));
    }

    #[test]
    fn rust_policy_rejects_workspace_trust_acknowledgement_without_warning_replay() {
        let mut request = warning_request("yolo");
        request.operation_kind = "workspace_trust.acknowledge".to_string();
        request.warning_id = Some("workspace_trust_missing".to_string());
        request.controls = Value::Null;

        let error = WorkspaceTrustControlStateUpdateCore
            .plan(&request)
            .expect_err("warning replay required");

        assert_eq!(
            error,
            WorkspaceTrustControlStateUpdateError::WarningEventNotFound(
                "workspace_trust_missing".to_string()
            )
        );
    }

    #[test]
    fn rust_policy_shapes_workspace_trust_command_response() {
        let response = plan_workspace_trust_control_state_update_response(
            WorkspaceTrustControlStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: warning_request("review"),
            },
        )
        .expect("workspace trust response");

        assert_eq!(
            response["source"],
            "rust_workspace_trust_control_state_update_command"
        );
        assert_eq!(response["operation_kind"], "workspace_trust.warning");
        assert_eq!(response["event"]["event_kind"], "workspace.trust_warning");
        assert_eq!(response["workspace_trust_warning"]["mode"], "review");
    }
}
