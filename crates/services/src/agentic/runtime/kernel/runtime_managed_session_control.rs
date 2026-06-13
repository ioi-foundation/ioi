use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const RUNTIME_MANAGED_SESSION_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.managed-session-projection-request.v1";
pub const RUNTIME_MANAGED_SESSION_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.managed_session_projection.v1";
pub const RUNTIME_MANAGED_SESSION_CONTROL_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.managed-session-control-request.v1";
pub const RUNTIME_MANAGED_SESSION_CONTROL_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.managed_session_control.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeManagedSessionProjectionRequest {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub projection_kind: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub projection: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeManagedSessionControlRequest {
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
    pub managed_session_id: Option<String>,
    #[serde(default)]
    pub control_state: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub event_seed: Option<String>,
    #[serde(default)]
    pub managed_session: Value,
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
pub struct RuntimeManagedSessionCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeManagedSessionCommandError {
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
pub struct RuntimeManagedSessionProjectionCore;

#[derive(Debug, Clone, Default)]
pub struct RuntimeManagedSessionControlCore;

#[derive(Debug, Clone)]
pub struct RuntimeManagedSessionProjectionRecord {
    pub operation: String,
    pub operation_kind: String,
    pub projection_kind: String,
    pub thread_id: String,
    pub source: String,
    pub projection: Value,
    pub record_count: usize,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RuntimeManagedSessionControlRecord {
    pub operation: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub managed_session_id: String,
    pub control_state: String,
    pub event: Value,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
}

pub fn project_runtime_managed_session_projection_response(
    request: RuntimeManagedSessionProjectionRequest,
) -> Result<Value, RuntimeManagedSessionCommandError> {
    let record = RuntimeManagedSessionProjectionCore.project(&request)?;
    Ok(json!({
        "source": "rust_runtime_managed_session_projection_command",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

pub fn plan_runtime_managed_session_control_response(
    request: RuntimeManagedSessionControlRequest,
) -> Result<Value, RuntimeManagedSessionCommandError> {
    let record = RuntimeManagedSessionControlCore.plan(&request)?;
    Ok(json!({
        "source": "rust_runtime_managed_session_control_command",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RuntimeManagedSessionProjectionCore {
    pub fn project(
        &self,
        request: &RuntimeManagedSessionProjectionRequest,
    ) -> Result<RuntimeManagedSessionProjectionRecord, RuntimeManagedSessionCommandError> {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_MANAGED_SESSION_PROJECTION_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeManagedSessionCommandError::new(
                    "runtime_managed_session_projection_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_MANAGED_SESSION_PROJECTION_REQUEST_SCHEMA_VERSION}, got {schema_version}"
                    ),
                ));
            }
        }

        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeManagedSessionCommandError::new(
                "runtime_managed_session_projection_thread_id_required",
                "managed session projection requires thread_id",
            )
        })?;
        let projection_kind = normalized_projection_kind(request)?;
        let sessions = projected_sessions(&request.projection, &thread_id);
        let projection = match projection_kind.as_str() {
            "inspect" | "list" => Value::Array(sessions.clone()),
            "summary" => managed_session_summary(&sessions),
            _ => {
                return Err(RuntimeManagedSessionCommandError::new(
                    "runtime_managed_session_projection_kind_unsupported",
                    format!("unsupported managed session projection kind {projection_kind}"),
                ));
            }
        };
        let record_count = match &projection {
            Value::Array(values) => values.len(),
            Value::Object(map) => map
                .get("session_count")
                .and_then(Value::as_u64)
                .unwrap_or_default() as usize,
            _ => 0,
        };
        let operation = optional_trimmed(request.operation.as_deref())
            .unwrap_or_else(|| "managed_session_inspection".to_string());
        let operation_kind = optional_trimmed(request.operation_kind.as_deref())
            .unwrap_or_else(|| "managed_session.inspect".to_string());
        if operation_kind != "managed_session.inspect" {
            return Err(RuntimeManagedSessionCommandError::new(
                "runtime_managed_session_projection_operation_kind_unsupported",
                format!("{operation_kind} is not a managed session inspection operation"),
            ));
        }
        let source = optional_trimmed(request.source.as_deref())
            .unwrap_or_else(|| "runtime.managed_session_projection.rust_command".to_string());
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_managed_session_projection_rust_owned".to_string(),
                "agentgres_managed_session_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let receipt_refs = vec![format!(
            "receipt_runtime_managed_session_projection_{projection_kind}"
        )];

        Ok(RuntimeManagedSessionProjectionRecord {
            operation,
            operation_kind,
            projection_kind,
            thread_id,
            source,
            projection,
            record_count,
            evidence_refs,
            receipt_refs,
        })
    }
}

impl RuntimeManagedSessionControlCore {
    pub fn plan(
        &self,
        request: &RuntimeManagedSessionControlRequest,
    ) -> Result<RuntimeManagedSessionControlRecord, RuntimeManagedSessionCommandError> {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_MANAGED_SESSION_CONTROL_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeManagedSessionCommandError::new(
                    "runtime_managed_session_control_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_MANAGED_SESSION_CONTROL_REQUEST_SCHEMA_VERSION}, got {schema_version}"
                    ),
                ));
            }
        }

        let operation_kind = optional_trimmed(request.operation_kind.as_deref())
            .unwrap_or_else(|| "managed_session.control".to_string());
        if operation_kind != "managed_session.control" {
            return Err(RuntimeManagedSessionCommandError::new(
                "runtime_managed_session_control_operation_kind_unsupported",
                format!("{operation_kind} is not a managed session control operation"),
            ));
        }
        let operation = optional_trimmed(request.operation.as_deref())
            .unwrap_or_else(|| "managed_session_control".to_string());
        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeManagedSessionCommandError::new(
                "runtime_managed_session_control_thread_id_required",
                "managed session control requires thread_id",
            )
        })?;
        let event_stream_id =
            optional_trimmed(request.event_stream_id.as_deref()).ok_or_else(|| {
                RuntimeManagedSessionCommandError::new(
                    "runtime_managed_session_control_event_stream_required",
                    "managed session control requires event_stream_id",
                )
            })?;
        let managed_session_id = optional_trimmed(request.managed_session_id.as_deref())
            .or_else(|| string_field(&request.request, "managed_session_id"))
            .or_else(|| string_field(&request.managed_session, "managed_session_id"))
            .ok_or_else(|| {
                RuntimeManagedSessionCommandError::new(
                    "runtime_managed_session_control_id_required",
                    "managed session control requires managed_session_id",
                )
            })?;
        let requested_control_state = optional_trimmed(request.control_state.as_deref())
            .or_else(|| string_field(&request.request, "control_state"))
            .ok_or_else(|| {
                RuntimeManagedSessionCommandError::new(
                    "runtime_managed_session_control_state_required",
                    "managed session control requires control_state",
                )
            })?;
        let control_state = normalized_control_state(Some(requested_control_state.as_str()))?;
        let previous_control_state = string_field(&request.managed_session, "control_state")
            .and_then(|value| normalized_control_state(Some(value.as_str())).ok())
            .unwrap_or_else(|| "observe".to_string());
        let reason = optional_trimmed(request.reason.as_deref())
            .or_else(|| string_field(&request.request, "reason"));
        let event_seed = optional_trimmed(request.event_seed.as_deref())
            .or_else(|| string_field(&request.request, "event_seed"))
            .or_else(|| string_field(&request.request, "created_at"))
            .or_else(|| string_field(&request.managed_session, "updated_at"))
            .unwrap_or_else(|| control_state.clone());
        let event_hash = short_hash(format!(
            "{thread_id}:{managed_session_id}:{control_state}:{event_seed}"
        ));
        let receipt_refs = managed_session_receipt_refs(request, &event_hash);
        let policy_decision_refs = managed_session_policy_decision_refs(request, &event_hash);
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_managed_session_control_rust_owned".to_string(),
                "runtime_managed_session_control_event_rust_owned".to_string(),
                "agentgres_managed_session_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let source =
            string_field(&request.request, "source").unwrap_or_else(|| "agent_studio".to_string());
        let turn_id = string_field(&request.request, "turn_id");
        let turn_or_thread = turn_id.clone().unwrap_or_else(|| thread_id.clone());
        let event = json!({
            "event_id": string_field(&request.request, "event_id")
                .unwrap_or_else(|| format!("event_managed_session_control_{event_hash}")),
            "event_stream_id": event_stream_id,
            "thread_id": thread_id,
            "turn_id": turn_id.unwrap_or_default(),
            "item_id": format!("{turn_or_thread}:item:managed_session:{}:{event_hash}", safe_id(&managed_session_id)),
            "idempotency_key": string_field(&request.request, "idempotency_key")
                .unwrap_or_else(|| format!("thread:{thread_id}:managed_session.control:{managed_session_id}:{event_hash}")),
            "source": source,
            "source_event_kind": "OperatorControl.ManagedSessionControl",
            "event_kind": "managed_session.controlled",
            "status": control_state,
            "actor": "operator",
            "workspace_root": string_field(&request.request, "workspace_root").unwrap_or_default(),
            "component_kind": "managed_session_control",
            "payload_schema_version": "ioi.runtime.managed-session-control.v1",
            "payload": {
                "operation": operation,
                "managed_session_id": managed_session_id,
                "control_state": control_state,
                "previous_control_state": previous_control_state,
                "reason": reason,
                "requested_by": string_field(&request.request, "requested_by").unwrap_or_else(|| "operator".to_string()),
                "available_control_states": ["observe", "take_over", "return_agent"],
                "receipt_refs": receipt_refs,
                "policy_decision_refs": policy_decision_refs,
            },
            "receipt_refs": receipt_refs,
            "policy_decision_refs": policy_decision_refs,
            "artifact_refs": string_array_field(&request.request, "artifact_refs"),
            "rollback_refs": [],
            "redaction_profile": "internal",
            "fixture_profile": string_field(&request.request, "fixture_profile")
                .unwrap_or_else(|| "local_daemon_agentgres_projection".to_string()),
            "evidence_refs": evidence_refs,
        });

        Ok(RuntimeManagedSessionControlRecord {
            operation,
            operation_kind,
            thread_id,
            managed_session_id,
            control_state,
            event,
            receipt_refs,
            policy_decision_refs,
            evidence_refs,
        })
    }
}

impl RuntimeManagedSessionProjectionRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_MANAGED_SESSION_PROJECTION_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_managed_session_projection",
            "status": "projected",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "projection_kind": self.projection_kind,
            "thread_id": self.thread_id,
            "source": self.source,
            "projection": self.projection,
            "record_count": self.record_count,
            "evidence_refs": self.evidence_refs,
            "receipt_refs": self.receipt_refs,
        })
    }
}

impl RuntimeManagedSessionControlRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_MANAGED_SESSION_CONTROL_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_managed_session_control",
            "status": "planned",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "thread_id": self.thread_id,
            "managed_session_id": self.managed_session_id,
            "control_state": self.control_state,
            "event": self.event,
            "receipt_refs": self.receipt_refs,
            "policy_decision_refs": self.policy_decision_refs,
            "evidence_refs": self.evidence_refs,
        })
    }
}

fn normalized_projection_kind(
    request: &RuntimeManagedSessionProjectionRequest,
) -> Result<String, RuntimeManagedSessionCommandError> {
    if let Some(value) = optional_trimmed_lower(request.projection_kind.as_deref()) {
        return Ok(value);
    }
    match optional_trimmed(request.operation_kind.as_deref()).as_deref() {
        Some("managed_session.inspect") | None => Ok("list".to_string()),
        Some(value) => value
            .split('.')
            .next_back()
            .map(str::to_string)
            .ok_or_else(|| {
                RuntimeManagedSessionCommandError::new(
                    "runtime_managed_session_projection_kind_required",
                    "managed session projection kind is required",
                )
            }),
    }
}

fn projected_sessions(projection: &Value, thread_id: &str) -> Vec<Value> {
    let mut sessions: Vec<Value> = managed_session_candidates(projection)
        .into_iter()
        .filter(|record| matches_thread(record, thread_id))
        .filter_map(|record| projected_session_record(&record, thread_id))
        .collect();
    sessions.sort_by(|left, right| updated_at(right).cmp(&updated_at(left)));
    sessions
}

fn managed_session_candidates(projection: &Value) -> Vec<Value> {
    if let Some(values) = projection.as_array() {
        return values.clone();
    }
    for field in ["sessions", "managed_sessions", "records"] {
        if let Some(values) = projection.get(field).and_then(Value::as_array) {
            return values.clone();
        }
    }
    Vec::new()
}

fn projected_session_record(record: &Value, thread_id: &str) -> Option<Value> {
    let managed_session_id =
        string_field(record, "managed_session_id").or_else(|| string_field(record, "id"))?;
    let status = string_field(record, "status").unwrap_or_else(|| "unknown".to_string());
    let control_state = string_field(record, "control_state")
        .and_then(|value| normalized_control_state(Some(value.as_str())).ok())
        .unwrap_or_else(|| "observe".to_string());
    Some(json!({
        "schema_version": "ioi.runtime.managed-session-card.v1",
        "managed_session_id": managed_session_id,
        "thread_id": string_field(record, "thread_id").unwrap_or_else(|| thread_id.to_string()),
        "kind": string_field(record, "kind").unwrap_or_else(|| "managed_session".to_string()),
        "surface_label": string_field(record, "surface_label"),
        "status": status,
        "control_state": control_state,
        "available_control_states": ["observe", "take_over", "return_agent"],
        "waiting_for_user": bool_field(record, "waiting_for_user").unwrap_or(false),
        "waiting_reason": string_field(record, "waiting_reason"),
        "replay_ready": bool_field(record, "replay_ready").unwrap_or(false),
        "detail": string_field(record, "detail"),
        "detail_visibility": string_field(record, "detail_visibility").unwrap_or_else(|| "summary".to_string()),
        "sanitized_preview_ref": string_field(record, "sanitized_preview_ref"),
        "updated_at": string_field(record, "updated_at"),
        "receipt_refs": string_array_field(record, "receipt_refs"),
        "policy_decision_refs": string_array_field(record, "policy_decision_refs"),
    }))
}

fn managed_session_summary(sessions: &[Value]) -> Value {
    let waiting_session_ids: Vec<Value> = sessions
        .iter()
        .filter(|record| bool_field(record, "waiting_for_user").unwrap_or(false))
        .filter_map(|record| string_field(record, "managed_session_id"))
        .map(Value::String)
        .collect();
    let replayable_session_ids: Vec<Value> = sessions
        .iter()
        .filter(|record| bool_field(record, "replay_ready").unwrap_or(false))
        .filter_map(|record| string_field(record, "managed_session_id"))
        .map(Value::String)
        .collect();
    json!({
        "session_count": sessions.len(),
        "waiting_session_ids": waiting_session_ids,
        "replayable_session_ids": replayable_session_ids,
        "sessions": sessions,
    })
}

fn matches_thread(record: &Value, thread_id: &str) -> bool {
    string_field(record, "thread_id")
        .or_else(|| string_field(record, "parent_thread_id"))
        .map(|value| value == thread_id)
        .unwrap_or(true)
}

fn normalized_control_state(
    value: Option<&str>,
) -> Result<String, RuntimeManagedSessionCommandError> {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("observe")
        .to_ascii_lowercase()
        .replace('-', "_")
        .as_str()
    {
        "observe" => Ok("observe".to_string()),
        "take_over" => Ok("take_over".to_string()),
        "return_agent" => Ok("return_agent".to_string()),
        other => Err(RuntimeManagedSessionCommandError::new(
            "runtime_managed_session_control_state_unsupported",
            format!("unsupported managed session control state {other}"),
        )),
    }
}

fn managed_session_receipt_refs(
    request: &RuntimeManagedSessionControlRequest,
    event_hash: &str,
) -> Vec<String> {
    unique_strings(
        request
            .receipt_refs
            .clone()
            .into_iter()
            .chain(string_array_field(&request.request, "receipt_refs"))
            .chain(std::iter::once(format!(
                "receipt_managed_session_control_{event_hash}"
            )))
            .collect(),
    )
}

fn managed_session_policy_decision_refs(
    request: &RuntimeManagedSessionControlRequest,
    event_hash: &str,
) -> Vec<String> {
    unique_strings(
        request
            .policy_decision_refs
            .clone()
            .into_iter()
            .chain(string_array_field(&request.request, "policy_decision_refs"))
            .chain(std::iter::once(format!(
                "policy_managed_session_control_allow_{event_hash}"
            )))
            .collect(),
    )
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn string_array_field(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .collect()
}

fn bool_field(value: &Value, field: &str) -> Option<bool> {
    value.get(field).and_then(Value::as_bool)
}

fn updated_at(value: &Value) -> String {
    string_field(value, "updated_at").unwrap_or_default()
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn optional_trimmed_lower(value: Option<&str>) -> Option<String> {
    optional_trimmed(value).map(|value| value.to_ascii_lowercase().replace('-', "_"))
}

fn safe_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn short_hash(value: String) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(digest)[..12].to_string()
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values {
        if !value.is_empty() && !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projection_request() -> RuntimeManagedSessionProjectionRequest {
        RuntimeManagedSessionProjectionRequest {
            schema_version: Some(
                RUNTIME_MANAGED_SESSION_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            ),
            operation: Some("managed_session_inspection".to_string()),
            operation_kind: Some("managed_session.inspect".to_string()),
            projection_kind: Some("list".to_string()),
            thread_id: Some("thread_1".to_string()),
            source: Some("runtime.managed_session_state".to_string()),
            projection: json!({
                "sessions": [{
                    "id": "sandbox_browser:1",
                    "thread_id": "thread_1",
                    "kind": "sandbox_browser",
                    "status": "waiting_for_user",
                    "control_state": "observe",
                    "waiting_for_user": true,
                    "replay_ready": true,
                    "updated_at": "2026-06-12T12:00:00.000Z",
                    "receipt_refs": ["receipt_session"]
                }, {
                    "id": "sandbox_browser:2",
                    "thread_id": "thread_other"
                }],
            }),
            evidence_refs: vec![],
        }
    }

    fn control_request() -> RuntimeManagedSessionControlRequest {
        RuntimeManagedSessionControlRequest {
            schema_version: Some(
                RUNTIME_MANAGED_SESSION_CONTROL_REQUEST_SCHEMA_VERSION.to_string(),
            ),
            operation: Some("managed_session_control".to_string()),
            operation_kind: Some("managed_session.control".to_string()),
            thread_id: Some("thread_1".to_string()),
            event_stream_id: Some("thread_1:events".to_string()),
            managed_session_id: Some("sandbox_browser:1".to_string()),
            control_state: Some("take_over".to_string()),
            reason: Some("operator takeover".to_string()),
            event_seed: Some("2026-06-12T12:00:00.000Z".to_string()),
            managed_session: json!({
                "managed_session_id": "sandbox_browser:1",
                "thread_id": "thread_1",
                "control_state": "observe",
                "updated_at": "2026-06-12T11:59:00.000Z",
            }),
            request: json!({
                "source": "agent_studio",
                "workspace_root": "/workspace/project",
                "receipt_refs": ["receipt_request"],
                "policy_decision_refs": ["policy_request"],
            }),
            receipt_refs: vec![],
            policy_decision_refs: vec![],
            evidence_refs: vec![],
        }
    }

    #[test]
    fn rust_projects_managed_session_inspection() {
        let record = RuntimeManagedSessionProjectionCore
            .project(&projection_request())
            .expect("projection should be planned");

        assert_eq!(record.operation_kind, "managed_session.inspect");
        assert_eq!(record.record_count, 1);
        let sessions = record.projection.as_array().expect("sessions array");
        assert_eq!(sessions[0]["managed_session_id"], "sandbox_browser:1");
        assert_eq!(sessions[0]["control_state"], "observe");
        assert!(record
            .evidence_refs
            .contains(&"runtime_managed_session_projection_rust_owned".to_string()));
    }

    #[test]
    fn rust_shapes_managed_session_projection_command_response() {
        let response = project_runtime_managed_session_projection_response(projection_request())
            .expect("response should shape");

        assert_eq!(
            response["source"],
            "rust_runtime_managed_session_projection_command"
        );
        assert_eq!(
            response["record"]["operation_kind"],
            "managed_session.inspect"
        );
        assert_eq!(response["record"]["record_count"], 1);
    }

    #[test]
    fn rust_plans_managed_session_control_event() {
        let record = RuntimeManagedSessionControlCore
            .plan(&control_request())
            .expect("control should plan");

        assert_eq!(record.operation_kind, "managed_session.control");
        assert_eq!(record.control_state, "take_over");
        assert_eq!(record.event["event_kind"], "managed_session.controlled");
        assert_eq!(
            record.event["source_event_kind"],
            "OperatorControl.ManagedSessionControl"
        );
        assert_eq!(
            record.event["payload"]["managed_session_id"],
            "sandbox_browser:1"
        );
        assert_eq!(record.event["payload"]["control_state"], "take_over");
        assert_eq!(record.event["payload"]["previous_control_state"], "observe");
        assert_eq!(record.event["receipt_refs"][0], "receipt_request");
        assert!(record
            .evidence_refs
            .contains(&"runtime_managed_session_control_rust_owned".to_string()));
    }

    #[test]
    fn rust_shapes_managed_session_control_command_response() {
        let response = plan_runtime_managed_session_control_response(control_request())
            .expect("response should shape");

        assert_eq!(
            response["source"],
            "rust_runtime_managed_session_control_command"
        );
        assert_eq!(
            response["record"]["operation_kind"],
            "managed_session.control"
        );
        assert_eq!(
            response["record"]["event"]["component_kind"],
            "managed_session_control"
        );
    }

    #[test]
    fn rust_rejects_unowned_managed_session_control_state() {
        let mut request = control_request();
        request.control_state = Some("plaintext_takeover".to_string());
        let error = RuntimeManagedSessionControlCore
            .plan(&request)
            .expect_err("unsupported control state should fail");
        assert_eq!(
            error.code(),
            "runtime_managed_session_control_state_unsupported"
        );
    }

    #[test]
    fn rust_rejects_retired_managed_session_control_action_alias() {
        let mut request = control_request();
        request.control_state = None;
        request.request = json!({
            "action": "take_over",
            "source": "agent_studio",
            "workspace_root": "/workspace/project",
        });
        let error = RuntimeManagedSessionControlCore
            .plan(&request)
            .expect_err("retired action alias should not satisfy control_state");
        assert_eq!(
            error.code(),
            "runtime_managed_session_control_state_required"
        );
    }

    #[test]
    fn rust_rejects_invalid_managed_session_projection_schema() {
        let mut request = projection_request();
        request.schema_version = Some("legacy.managed-session-projection".to_string());
        let error = RuntimeManagedSessionProjectionCore
            .project(&request)
            .expect_err("invalid schema should fail");
        assert_eq!(
            error.code(),
            "runtime_managed_session_projection_schema_version_invalid"
        );
    }
}
