use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const RUNTIME_WORKSPACE_CHANGE_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.workspace-change-projection-request.v1";
pub const RUNTIME_WORKSPACE_CHANGE_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.workspace_change_projection.v1";
pub const RUNTIME_WORKSPACE_CHANGE_CONTROL_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.workspace-change-control-request.v1";
pub const RUNTIME_WORKSPACE_CHANGE_CONTROL_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.workspace_change_control.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeWorkspaceChangeProjectionRequest {
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
pub struct RuntimeWorkspaceChangeControlRequest {
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
    pub workspace_change_id: Option<String>,
    #[serde(default)]
    pub control_state: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub event_seed: Option<String>,
    #[serde(default)]
    pub workspace_change: Value,
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
pub struct RuntimeWorkspaceChangeCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeWorkspaceChangeCommandError {
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
pub struct RuntimeWorkspaceChangeProjectionCore;

#[derive(Debug, Clone, Default)]
pub struct RuntimeWorkspaceChangeControlCore;

#[derive(Debug, Clone)]
pub struct RuntimeWorkspaceChangeProjectionRecord {
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
pub struct RuntimeWorkspaceChangeControlRecord {
    pub operation: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub workspace_change_id: String,
    pub control_state: String,
    pub event: Value,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
}

pub fn project_runtime_workspace_change_projection_response(
    request: RuntimeWorkspaceChangeProjectionRequest,
) -> Result<Value, RuntimeWorkspaceChangeCommandError> {
    let record = RuntimeWorkspaceChangeProjectionCore.project(&request)?;
    Ok(json!({
        "source": "rust_runtime_workspace_change_projection_command",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

pub fn plan_runtime_workspace_change_control_response(
    request: RuntimeWorkspaceChangeControlRequest,
) -> Result<Value, RuntimeWorkspaceChangeCommandError> {
    let record = RuntimeWorkspaceChangeControlCore.plan(&request)?;
    Ok(json!({
        "source": "rust_runtime_workspace_change_control_command",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RuntimeWorkspaceChangeProjectionCore {
    pub fn project(
        &self,
        request: &RuntimeWorkspaceChangeProjectionRequest,
    ) -> Result<RuntimeWorkspaceChangeProjectionRecord, RuntimeWorkspaceChangeCommandError> {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_WORKSPACE_CHANGE_PROJECTION_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeWorkspaceChangeCommandError::new(
                    "runtime_workspace_change_projection_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_WORKSPACE_CHANGE_PROJECTION_REQUEST_SCHEMA_VERSION}, got {schema_version}"
                    ),
                ));
            }
        }

        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeWorkspaceChangeCommandError::new(
                "runtime_workspace_change_projection_thread_id_required",
                "workspace change projection requires thread_id",
            )
        })?;
        let projection_kind = normalized_projection_kind(request)?;
        let changes = projected_workspace_changes(&request.projection, &thread_id);
        let projection = match projection_kind.as_str() {
            "inspect" | "list" => Value::Array(changes.clone()),
            "summary" => workspace_change_summary(&changes),
            _ => {
                return Err(RuntimeWorkspaceChangeCommandError::new(
                    "runtime_workspace_change_projection_kind_unsupported",
                    format!("unsupported workspace change projection kind {projection_kind}"),
                ));
            }
        };
        let record_count = match &projection {
            Value::Array(values) => values.len(),
            Value::Object(map) => map
                .get("change_count")
                .and_then(Value::as_u64)
                .unwrap_or_default() as usize,
            _ => 0,
        };
        let operation = optional_trimmed(request.operation.as_deref())
            .unwrap_or_else(|| "workspace_change_inspection".to_string());
        let operation_kind = optional_trimmed(request.operation_kind.as_deref())
            .unwrap_or_else(|| "workspace_change.inspect".to_string());
        if operation_kind != "workspace_change.inspect" {
            return Err(RuntimeWorkspaceChangeCommandError::new(
                "runtime_workspace_change_projection_operation_kind_unsupported",
                format!("{operation_kind} is not a workspace change inspection operation"),
            ));
        }
        let source = optional_trimmed(request.source.as_deref())
            .unwrap_or_else(|| "runtime.workspace_change_projection.rust_command".to_string());
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_workspace_change_projection_rust_owned".to_string(),
                "agentgres_workspace_change_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let receipt_refs = vec![format!(
            "receipt_runtime_workspace_change_projection_{projection_kind}"
        )];

        Ok(RuntimeWorkspaceChangeProjectionRecord {
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

impl RuntimeWorkspaceChangeControlCore {
    pub fn plan(
        &self,
        request: &RuntimeWorkspaceChangeControlRequest,
    ) -> Result<RuntimeWorkspaceChangeControlRecord, RuntimeWorkspaceChangeCommandError> {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_WORKSPACE_CHANGE_CONTROL_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeWorkspaceChangeCommandError::new(
                    "runtime_workspace_change_control_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_WORKSPACE_CHANGE_CONTROL_REQUEST_SCHEMA_VERSION}, got {schema_version}"
                    ),
                ));
            }
        }

        let operation_kind = optional_trimmed(request.operation_kind.as_deref())
            .unwrap_or_else(|| "workspace_change.control".to_string());
        if operation_kind != "workspace_change.control" {
            return Err(RuntimeWorkspaceChangeCommandError::new(
                "runtime_workspace_change_control_operation_kind_unsupported",
                format!("{operation_kind} is not a workspace change control operation"),
            ));
        }
        let operation = optional_trimmed(request.operation.as_deref())
            .unwrap_or_else(|| "workspace_change_control".to_string());
        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeWorkspaceChangeCommandError::new(
                "runtime_workspace_change_control_thread_id_required",
                "workspace change control requires thread_id",
            )
        })?;
        let event_stream_id =
            optional_trimmed(request.event_stream_id.as_deref()).ok_or_else(|| {
                RuntimeWorkspaceChangeCommandError::new(
                    "runtime_workspace_change_control_event_stream_required",
                    "workspace change control requires event_stream_id",
                )
            })?;
        let workspace_change_id = optional_trimmed(request.workspace_change_id.as_deref())
            .or_else(|| string_field(&request.request, "workspace_change_id"))
            .or_else(|| string_field(&request.workspace_change, "workspace_change_id"))
            .or_else(|| string_field(&request.workspace_change, "change_id"))
            .ok_or_else(|| {
                RuntimeWorkspaceChangeCommandError::new(
                    "runtime_workspace_change_control_id_required",
                    "workspace change control requires workspace_change_id",
                )
            })?;
        let requested_control_state = optional_trimmed(request.control_state.as_deref())
            .or_else(|| string_field(&request.request, "control_state"))
            .ok_or_else(|| {
                RuntimeWorkspaceChangeCommandError::new(
                    "runtime_workspace_change_control_state_required",
                    "workspace change control requires control_state",
                )
            })?;
        let control_state = normalized_control_state(Some(requested_control_state.as_str()))?;
        let previous_lifecycle = string_field(&request.workspace_change, "lifecycle")
            .or_else(|| string_field(&request.workspace_change, "review_state"))
            .unwrap_or_else(|| "unknown".to_string());
        ensure_control_transition_allowed(&control_state, &previous_lifecycle)?;
        let reason = optional_trimmed(request.reason.as_deref())
            .or_else(|| string_field(&request.request, "reason"));
        let event_seed = optional_trimmed(request.event_seed.as_deref())
            .or_else(|| string_field(&request.request, "event_seed"))
            .or_else(|| string_field(&request.request, "created_at"))
            .or_else(|| string_field(&request.workspace_change, "updated_at"))
            .or_else(|| string_field(&request.workspace_change, "receipt_ref"))
            .unwrap_or_else(|| control_state.clone());
        let event_hash = short_hash(format!(
            "{thread_id}:{workspace_change_id}:{control_state}:{event_seed}"
        ));
        let receipt_refs = workspace_change_receipt_refs(request, &event_hash);
        let policy_decision_refs = workspace_change_policy_decision_refs(request, &event_hash);
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_workspace_change_control_rust_owned".to_string(),
                "runtime_workspace_change_control_event_rust_owned".to_string(),
                "agentgres_workspace_change_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let source =
            string_field(&request.request, "source").unwrap_or_else(|| "agent_studio".to_string());
        let turn_id = string_field(&request.request, "turn_id");
        let turn_or_thread = turn_id.clone().unwrap_or_else(|| thread_id.clone());
        let next_lifecycle = lifecycle_after_control(&control_state);
        let event = json!({
            "event_id": string_field(&request.request, "event_id")
                .unwrap_or_else(|| format!("event_workspace_change_control_{event_hash}")),
            "event_stream_id": event_stream_id,
            "thread_id": thread_id,
            "turn_id": turn_id.unwrap_or_default(),
            "item_id": format!("{turn_or_thread}:item:workspace_change:{}:{event_hash}", safe_id(&workspace_change_id)),
            "idempotency_key": string_field(&request.request, "idempotency_key")
                .unwrap_or_else(|| format!("thread:{thread_id}:workspace_change.control:{workspace_change_id}:{event_hash}")),
            "source": source,
            "source_event_kind": "OperatorControl.WorkspaceChangeControl",
            "event_kind": "workspace_change.controlled",
            "status": next_lifecycle,
            "actor": "operator",
            "workspace_root": string_field(&request.request, "workspace_root").unwrap_or_default(),
            "component_kind": "workspace_change_control",
            "payload_schema_version": "ioi.runtime.workspace-change-control.v1",
            "payload": {
                "operation": operation,
                "workspace_change_id": workspace_change_id,
                "control_state": control_state,
                "previous_lifecycle": previous_lifecycle,
                "next_lifecycle": next_lifecycle,
                "reason": reason,
                "requested_by": string_field(&request.request, "requested_by").unwrap_or_else(|| "operator".to_string()),
                "available_control_states": ["accept", "reject", "rollback"],
                "path": string_field(&request.workspace_change, "path"),
                "tool_name": string_field(&request.workspace_change, "tool_name"),
                "expected_head_ref": string_field(&request.request, "expected_head_ref"),
                "state_root_ref": string_field(&request.request, "state_root_ref"),
                "receipt_refs": receipt_refs,
                "policy_decision_refs": policy_decision_refs,
            },
            "receipt_refs": receipt_refs,
            "policy_decision_refs": policy_decision_refs,
            "artifact_refs": string_array_field(&request.request, "artifact_refs"),
            "rollback_refs": string_array_field(&request.request, "rollback_refs"),
            "redaction_profile": "internal",
            "fixture_profile": string_field(&request.request, "fixture_profile")
                .unwrap_or_else(|| "local_daemon_agentgres_projection".to_string()),
            "evidence_refs": evidence_refs,
        });

        Ok(RuntimeWorkspaceChangeControlRecord {
            operation,
            operation_kind,
            thread_id,
            workspace_change_id,
            control_state,
            event,
            receipt_refs,
            policy_decision_refs,
            evidence_refs,
        })
    }
}

impl RuntimeWorkspaceChangeProjectionRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_WORKSPACE_CHANGE_PROJECTION_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_workspace_change_projection",
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

impl RuntimeWorkspaceChangeControlRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_WORKSPACE_CHANGE_CONTROL_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_workspace_change_control",
            "status": "planned",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "thread_id": self.thread_id,
            "workspace_change_id": self.workspace_change_id,
            "control_state": self.control_state,
            "event": self.event,
            "receipt_refs": self.receipt_refs,
            "policy_decision_refs": self.policy_decision_refs,
            "evidence_refs": self.evidence_refs,
        })
    }
}

fn normalized_projection_kind(
    request: &RuntimeWorkspaceChangeProjectionRequest,
) -> Result<String, RuntimeWorkspaceChangeCommandError> {
    if let Some(value) = optional_trimmed_lower(request.projection_kind.as_deref()) {
        return Ok(value);
    }
    match optional_trimmed(request.operation_kind.as_deref()).as_deref() {
        Some("workspace_change.inspect") | None => Ok("list".to_string()),
        Some(value) => value
            .split('.')
            .next_back()
            .map(str::to_string)
            .ok_or_else(|| {
                RuntimeWorkspaceChangeCommandError::new(
                    "runtime_workspace_change_projection_kind_required",
                    "workspace change projection kind is required",
                )
            }),
    }
}

fn projected_workspace_changes(projection: &Value, thread_id: &str) -> Vec<Value> {
    let mut changes: Vec<Value> = workspace_change_candidates(projection)
        .into_iter()
        .filter(|record| matches_thread(record, thread_id))
        .filter_map(|record| projected_workspace_change_record(&record, thread_id))
        .collect();
    changes.sort_by(|left, right| {
        updated_at(right)
            .cmp(&updated_at(left))
            .then_with(|| workspace_change_id(left).cmp(&workspace_change_id(right)))
    });
    changes
}

fn workspace_change_candidates(projection: &Value) -> Vec<Value> {
    if let Some(values) = projection.as_array() {
        return values.clone();
    }
    for field in ["changes", "workspace_changes", "records"] {
        if let Some(values) = projection.get(field).and_then(Value::as_array) {
            return values.clone();
        }
    }
    Vec::new()
}

fn projected_workspace_change_record(record: &Value, thread_id: &str) -> Option<Value> {
    let workspace_change_id = workspace_change_id(record)?;
    let lifecycle = string_field(record, "lifecycle")
        .or_else(|| string_field(record, "status"))
        .unwrap_or_else(|| "unknown".to_string());
    let review_state = review_state_for_lifecycle(&lifecycle);
    Some(json!({
        "schema_version": "ioi.runtime.workspace-change-card.v1",
        "workspace_change_id": workspace_change_id,
        "thread_id": string_field(record, "thread_id").unwrap_or_else(|| thread_id.to_string()),
        "tool_name": string_field(record, "tool_name"),
        "path": string_field(record, "path"),
        "lifecycle": lifecycle,
        "review_state": review_state,
        "control_state": review_state,
        "available_control_states": available_control_states(&review_state),
        "edit_count": number_field(record, "edit_count").unwrap_or_default(),
        "hunk_count": array_field(record, "hunks").len(),
        "hunks": projected_hunks(record),
        "before_hash": string_field(record, "before_hash"),
        "after_hash": string_field(record, "after_hash"),
        "authority_ref": string_field(record, "authority_ref"),
        "receipt_ref": string_field(record, "receipt_ref"),
        "evidence_ref": string_field(record, "evidence_ref"),
        "updated_at": string_field(record, "updated_at"),
        "state_root_ref": string_field(record, "state_root_ref"),
        "expected_head_ref": string_field(record, "expected_head_ref"),
        "receipt_refs": string_array_field(record, "receipt_refs"),
        "policy_decision_refs": string_array_field(record, "policy_decision_refs"),
    }))
}

fn projected_hunks(record: &Value) -> Vec<Value> {
    array_field(record, "hunks")
        .into_iter()
        .map(|hunk| {
            json!({
                "hunk_index": number_field(&hunk, "hunk_index").unwrap_or_default(),
                "kind": string_field(&hunk, "kind"),
                "line_start": number_field(&hunk, "line_start"),
                "line_end": number_field(&hunk, "line_end"),
                "search_hash": string_field(&hunk, "search_hash"),
                "replace_hash": string_field(&hunk, "replace_hash"),
                "content_hash": string_field(&hunk, "content_hash"),
                "search_len": number_field(&hunk, "search_len").unwrap_or_default(),
                "replace_len": number_field(&hunk, "replace_len").unwrap_or_default(),
            })
        })
        .collect()
}

fn workspace_change_summary(changes: &[Value]) -> Value {
    let pending_change_ids: Vec<Value> = changes
        .iter()
        .filter(|record| {
            matches!(
                string_field(record, "review_state").as_deref(),
                Some("pending_review")
            )
        })
        .filter_map(|record| string_field(record, "workspace_change_id"))
        .map(Value::String)
        .collect();
    let rollback_change_ids: Vec<Value> = changes
        .iter()
        .filter(|record| {
            string_array_field(record, "available_control_states")
                .iter()
                .any(|state| state == "rollback")
        })
        .filter_map(|record| string_field(record, "workspace_change_id"))
        .map(Value::String)
        .collect();
    json!({
        "change_count": changes.len(),
        "pending_change_ids": pending_change_ids,
        "rollback_change_ids": rollback_change_ids,
        "changes": changes,
    })
}

fn review_state_for_lifecycle(lifecycle: &str) -> String {
    match lifecycle.trim().to_ascii_lowercase().as_str() {
        "proposed" | "awaiting_approval" => "pending_review".to_string(),
        "applied" => "applied".to_string(),
        "rejected" => "rejected".to_string(),
        "rolled_back" => "rolled_back".to_string(),
        "failed" => "failed".to_string(),
        _ => "unknown".to_string(),
    }
}

fn available_control_states(review_state: &str) -> Vec<Value> {
    match review_state {
        "pending_review" => vec![
            Value::String("accept".to_string()),
            Value::String("reject".to_string()),
        ],
        "applied" => vec![Value::String("rollback".to_string())],
        _ => Vec::new(),
    }
}

fn normalized_control_state(
    value: Option<&str>,
) -> Result<String, RuntimeWorkspaceChangeCommandError> {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("")
        .to_ascii_lowercase()
        .replace('-', "_")
        .as_str()
    {
        "accept" => Ok("accept".to_string()),
        "reject" => Ok("reject".to_string()),
        "rollback" => Ok("rollback".to_string()),
        other => Err(RuntimeWorkspaceChangeCommandError::new(
            "runtime_workspace_change_control_state_unsupported",
            format!("unsupported workspace change control state {other}"),
        )),
    }
}

fn ensure_control_transition_allowed(
    control_state: &str,
    previous_lifecycle: &str,
) -> Result<(), RuntimeWorkspaceChangeCommandError> {
    match (control_state, previous_lifecycle) {
        ("accept", "proposed" | "awaiting_approval" | "unknown") => Ok(()),
        ("reject", "proposed" | "awaiting_approval" | "unknown") => Ok(()),
        ("rollback", "applied" | "unknown") => Ok(()),
        _ => Err(RuntimeWorkspaceChangeCommandError::new(
            "runtime_workspace_change_control_transition_unsupported",
            format!(
                "workspace change in lifecycle {previous_lifecycle} cannot be controlled with {control_state}"
            ),
        )),
    }
}

fn lifecycle_after_control(control_state: &str) -> String {
    match control_state {
        "accept" => "applied".to_string(),
        "reject" => "rejected".to_string(),
        "rollback" => "rolled_back".to_string(),
        _ => "unknown".to_string(),
    }
}

fn workspace_change_receipt_refs(
    request: &RuntimeWorkspaceChangeControlRequest,
    event_hash: &str,
) -> Vec<String> {
    unique_strings(
        request
            .receipt_refs
            .clone()
            .into_iter()
            .chain(string_array_field(&request.request, "receipt_refs"))
            .chain(string_field(&request.workspace_change, "receipt_ref"))
            .chain(std::iter::once(format!(
                "receipt_workspace_change_control_{event_hash}"
            )))
            .collect(),
    )
}

fn workspace_change_policy_decision_refs(
    request: &RuntimeWorkspaceChangeControlRequest,
    event_hash: &str,
) -> Vec<String> {
    unique_strings(
        request
            .policy_decision_refs
            .clone()
            .into_iter()
            .chain(string_array_field(&request.request, "policy_decision_refs"))
            .chain(std::iter::once(format!(
                "policy_workspace_change_control_allow_{event_hash}"
            )))
            .collect(),
    )
}

fn matches_thread(record: &Value, thread_id: &str) -> bool {
    string_field(record, "thread_id")
        .or_else(|| string_field(record, "parent_thread_id"))
        .map(|value| value == thread_id)
        .unwrap_or(true)
}

fn workspace_change_id(record: &Value) -> Option<String> {
    string_field(record, "workspace_change_id")
        .or_else(|| string_field(record, "change_id"))
        .or_else(|| string_field(record, "id"))
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

fn array_field(value: &Value, field: &str) -> Vec<Value> {
    value
        .get(field)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn number_field(value: &Value, field: &str) -> Option<u64> {
    value.get(field).and_then(Value::as_u64)
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

    fn projection_request() -> RuntimeWorkspaceChangeProjectionRequest {
        RuntimeWorkspaceChangeProjectionRequest {
            schema_version: Some(
                RUNTIME_WORKSPACE_CHANGE_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            ),
            operation: Some("workspace_change_inspection".to_string()),
            operation_kind: Some("workspace_change.inspect".to_string()),
            projection_kind: Some("list".to_string()),
            thread_id: Some("thread_1".to_string()),
            source: Some("runtime.workspace_change_state".to_string()),
            projection: json!({
                "changes": [{
                    "change_id": "workspace_change:file:1",
                    "thread_id": "thread_1",
                    "tool_name": "file__edit",
                    "path": "src/lib.rs",
                    "lifecycle": "proposed",
                    "edit_count": 1,
                    "hunks": [{
                        "hunk_index": 0,
                        "kind": "replace",
                        "line_start": 10,
                        "line_end": 12,
                        "search_hash": "hash_search",
                        "replace_hash": "hash_replace"
                    }],
                    "receipt_ref": "receipt_workspace_change_proposed",
                    "updated_at": "2026-06-12T12:00:00.000Z"
                }, {
                    "change_id": "workspace_change:file:other",
                    "thread_id": "thread_other",
                    "lifecycle": "proposed"
                }],
            }),
            evidence_refs: vec![],
        }
    }

    fn control_request() -> RuntimeWorkspaceChangeControlRequest {
        RuntimeWorkspaceChangeControlRequest {
            schema_version: Some(
                RUNTIME_WORKSPACE_CHANGE_CONTROL_REQUEST_SCHEMA_VERSION.to_string(),
            ),
            operation: Some("workspace_change_control".to_string()),
            operation_kind: Some("workspace_change.control".to_string()),
            thread_id: Some("thread_1".to_string()),
            event_stream_id: Some("thread_1:events".to_string()),
            workspace_change_id: Some("workspace_change:file:1".to_string()),
            control_state: Some("accept".to_string()),
            reason: Some("operator accepted".to_string()),
            event_seed: Some("2026-06-12T12:00:00.000Z".to_string()),
            workspace_change: json!({
                "change_id": "workspace_change:file:1",
                "thread_id": "thread_1",
                "tool_name": "file__edit",
                "path": "src/lib.rs",
                "lifecycle": "proposed",
                "receipt_ref": "receipt_workspace_change_proposed",
                "updated_at": "2026-06-12T11:59:00.000Z",
            }),
            request: json!({
                "source": "agent_studio",
                "workspace_root": "/workspace/project",
                "expected_head_ref": "head_before",
                "state_root_ref": "state_after",
                "receipt_refs": ["receipt_request"],
                "policy_decision_refs": ["policy_request"],
            }),
            receipt_refs: vec![],
            policy_decision_refs: vec![],
            evidence_refs: vec![],
        }
    }

    #[test]
    fn rust_projects_workspace_change_inspection() {
        let record = RuntimeWorkspaceChangeProjectionCore
            .project(&projection_request())
            .expect("projection should be planned");

        assert_eq!(record.operation_kind, "workspace_change.inspect");
        assert_eq!(record.record_count, 1);
        let changes = record.projection.as_array().expect("changes array");
        assert_eq!(changes[0]["workspace_change_id"], "workspace_change:file:1");
        assert_eq!(changes[0]["review_state"], "pending_review");
        assert_eq!(changes[0]["available_control_states"][0], "accept");
        assert!(record
            .evidence_refs
            .contains(&"runtime_workspace_change_projection_rust_owned".to_string()));
    }

    #[test]
    fn rust_shapes_workspace_change_projection_command_response() {
        let response = project_runtime_workspace_change_projection_response(projection_request())
            .expect("response should shape");

        assert_eq!(
            response["source"],
            "rust_runtime_workspace_change_projection_command"
        );
        assert_eq!(
            response["record"]["operation_kind"],
            "workspace_change.inspect"
        );
        assert_eq!(response["record"]["record_count"], 1);
    }

    #[test]
    fn rust_plans_workspace_change_control_event() {
        let record = RuntimeWorkspaceChangeControlCore
            .plan(&control_request())
            .expect("control should plan");

        assert_eq!(record.operation_kind, "workspace_change.control");
        assert_eq!(record.control_state, "accept");
        assert_eq!(record.event["event_kind"], "workspace_change.controlled");
        assert_eq!(
            record.event["source_event_kind"],
            "OperatorControl.WorkspaceChangeControl"
        );
        assert_eq!(
            record.event["payload"]["workspace_change_id"],
            "workspace_change:file:1"
        );
        assert_eq!(record.event["payload"]["control_state"], "accept");
        assert_eq!(record.event["payload"]["previous_lifecycle"], "proposed");
        assert_eq!(record.event["payload"]["next_lifecycle"], "applied");
        assert_eq!(record.event["payload"]["expected_head_ref"], "head_before");
        assert_eq!(record.event["payload"]["state_root_ref"], "state_after");
        assert_eq!(
            record.event["payload"]["receipt_refs"][0],
            "receipt_request"
        );
        assert!(record
            .evidence_refs
            .contains(&"runtime_workspace_change_control_rust_owned".to_string()));
    }

    #[test]
    fn rust_shapes_workspace_change_control_command_response() {
        let response = plan_runtime_workspace_change_control_response(control_request())
            .expect("response should shape");

        assert_eq!(
            response["source"],
            "rust_runtime_workspace_change_control_command"
        );
        assert_eq!(
            response["record"]["operation_kind"],
            "workspace_change.control"
        );
        assert_eq!(
            response["record"]["event"]["component_kind"],
            "workspace_change_control"
        );
    }

    #[test]
    fn rust_rejects_unowned_workspace_change_control_state() {
        let mut request = control_request();
        request.control_state = Some("apply".to_string());
        let error = RuntimeWorkspaceChangeControlCore
            .plan(&request)
            .expect_err("unsupported control state should fail");
        assert_eq!(
            error.code(),
            "runtime_workspace_change_control_state_unsupported"
        );
    }

    #[test]
    fn rust_rejects_retired_workspace_change_control_action_alias() {
        let mut request = control_request();
        request.control_state = None;
        request.request = json!({
            "action": "accept",
            "source": "agent_studio",
            "workspace_root": "/workspace/project",
        });
        let error = RuntimeWorkspaceChangeControlCore
            .plan(&request)
            .expect_err("retired action alias should not satisfy control_state");
        assert_eq!(
            error.code(),
            "runtime_workspace_change_control_state_required"
        );
    }

    #[test]
    fn rust_rejects_invalid_workspace_change_projection_schema() {
        let mut request = projection_request();
        request.schema_version = Some("legacy.workspace-change-projection".to_string());
        let error = RuntimeWorkspaceChangeProjectionCore
            .project(&request)
            .expect_err("invalid schema should fail");
        assert_eq!(
            error.code(),
            "runtime_workspace_change_projection_schema_version_invalid"
        );
    }

    #[test]
    fn rust_rejects_invalid_workspace_change_transition() {
        let mut request = control_request();
        request.control_state = Some("rollback".to_string());
        let error = RuntimeWorkspaceChangeControlCore
            .plan(&request)
            .expect_err("pending change cannot roll back");
        assert_eq!(
            error.code(),
            "runtime_workspace_change_control_transition_unsupported"
        );
    }
}
