use serde::Deserialize;
use serde_json::{json, Map, Value};

use super::policy::{
    MemoryManagerStatusProjectionCore, MemoryManagerStatusProjectionRequest,
    MemoryManagerValidationProjectionCore, MemoryManagerValidationProjectionRequest,
};

pub const RUNTIME_MEMORY_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-projection-request.v1";
pub const RUNTIME_MEMORY_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-projection.v1";
const MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-manager-status-projection-request.v1";
const MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-manager-validation-projection-request.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeMemoryProjectionBridgeRequest {
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub projection_kind: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    #[serde(default)]
    pub validation_schema_version: Option<String>,
    #[serde(default)]
    pub projection: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeMemoryProjectionCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeMemoryProjectionCommandError {
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
pub struct RuntimeMemoryProjectionCore;

#[derive(Debug, Clone)]
pub struct RuntimeMemoryProjectionRecord {
    pub operation: String,
    pub operation_kind: String,
    pub projection_kind: String,
    pub agent_id: Option<String>,
    pub thread_id: Option<String>,
    pub workspace_root: Option<String>,
    pub source: String,
    pub projection: Value,
    pub record_count: usize,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
}

pub fn project_runtime_memory_projection_response(
    request: RuntimeMemoryProjectionBridgeRequest,
) -> Result<Value, RuntimeMemoryProjectionCommandError> {
    let record = RuntimeMemoryProjectionCore::default().project(&request)?;
    Ok(json!({
        "source": "rust_runtime_memory_projection_command",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RuntimeMemoryProjectionCore {
    pub fn project(
        &self,
        request: &RuntimeMemoryProjectionBridgeRequest,
    ) -> Result<RuntimeMemoryProjectionRecord, RuntimeMemoryProjectionCommandError> {
        let projection_kind = normalized_projection_kind(request)?;
        let operation_kind = request
            .operation_kind
            .clone()
            .unwrap_or_else(|| format!("runtime.memory_projection.{projection_kind}"));
        let operation = request
            .operation
            .clone()
            .unwrap_or_else(|| "runtime_memory_projection".to_string());
        let source = optional_trimmed(request.source.as_deref())
            .unwrap_or_else(|| "rust_runtime_memory_projection_command".to_string());
        let projection = projection_for_kind(&projection_kind, request)?;
        let record_count = record_count_for_projection(&projection_kind, &projection);
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_memory_public_projection_rust_owned".to_string(),
                "agentgres_thread_memory_projection_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };

        Ok(RuntimeMemoryProjectionRecord {
            operation,
            operation_kind,
            projection_kind: projection_kind.clone(),
            agent_id: optional_trimmed(request.agent_id.as_deref()),
            thread_id: optional_trimmed(request.thread_id.as_deref()),
            workspace_root: optional_trimmed(request.workspace_root.as_deref()),
            source,
            projection,
            record_count,
            evidence_refs,
            receipt_refs: vec![format!(
                "receipt_runtime_memory_projection_{projection_kind}"
            )],
        })
    }
}

impl RuntimeMemoryProjectionRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_MEMORY_PROJECTION_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_memory_projection",
            "status": "projected",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "projection_kind": self.projection_kind,
            "agent_id": self.agent_id,
            "thread_id": self.thread_id,
            "workspace_root": self.workspace_root,
            "source": self.source,
            "projection": self.projection,
            "record_count": self.record_count,
            "evidence_refs": self.evidence_refs,
            "receipt_refs": self.receipt_refs,
        })
    }
}

fn projection_for_kind(
    projection_kind: &str,
    request: &RuntimeMemoryProjectionBridgeRequest,
) -> Result<Value, RuntimeMemoryProjectionCommandError> {
    match projection_kind {
        "records" => Ok(memory_projection_value(request)),
        "policy" => Ok(memory_projection_object(request, "policy")),
        "path" | "paths" => Ok(memory_projection_object(request, "paths")),
        "status" => {
            let record = MemoryManagerStatusProjectionCore
                .project(&MemoryManagerStatusProjectionRequest {
                    schema_version: MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    status_schema_version: request.status_schema_version.clone(),
                    validation_schema_version: request.validation_schema_version.clone(),
                    projection: memory_projection_value(request),
                })
                .map_err(|error| {
                    RuntimeMemoryProjectionCommandError::new(
                        "runtime_memory_projection_status_invalid",
                        format!("{error:?}"),
                    )
                })?;
            let mut value =
                serde_json::to_value(record).unwrap_or_else(|_| Value::Object(Map::new()));
            insert_context_fields(&mut value, request);
            Ok(value)
        }
        "validation" => {
            let record = MemoryManagerValidationProjectionCore
                .project(&MemoryManagerValidationProjectionRequest {
                    schema_version: MEMORY_MANAGER_VALIDATION_PROJECTION_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    validation_schema_version: request.validation_schema_version.clone(),
                    projection: memory_projection_value(request),
                })
                .map_err(|error| {
                    RuntimeMemoryProjectionCommandError::new(
                        "runtime_memory_projection_validation_invalid",
                        format!("{error:?}"),
                    )
                })?;
            let mut value =
                serde_json::to_value(record).unwrap_or_else(|_| Value::Object(Map::new()));
            insert_context_fields(&mut value, request);
            Ok(value)
        }
        _ => Err(RuntimeMemoryProjectionCommandError::new(
            "runtime_memory_projection_kind_invalid",
            format!("unsupported runtime memory projection kind {projection_kind}"),
        )),
    }
}

fn normalized_projection_kind(
    request: &RuntimeMemoryProjectionBridgeRequest,
) -> Result<String, RuntimeMemoryProjectionCommandError> {
    if let Some(value) = optional_trimmed_lower(request.projection_kind.as_deref()) {
        return Ok(value);
    }
    let operation_kind = optional_trimmed(request.operation_kind.as_deref()).unwrap_or_default();
    if let Some(last) = operation_kind.split('.').next_back() {
        if !last.is_empty() {
            return Ok(last.to_string());
        }
    }
    Err(RuntimeMemoryProjectionCommandError::new(
        "runtime_memory_projection_kind_required",
        "runtime memory projection kind is required",
    ))
}

fn memory_projection_value(request: &RuntimeMemoryProjectionBridgeRequest) -> Value {
    let mut value = object_value(&request.projection);
    insert_context_fields(&mut value, request);
    value
}

fn memory_projection_object(request: &RuntimeMemoryProjectionBridgeRequest, key: &str) -> Value {
    let mut value = request
        .projection
        .get(key)
        .cloned()
        .filter(Value::is_object)
        .unwrap_or_else(|| Value::Object(Map::new()));
    insert_context_fields(&mut value, request);
    value
}

fn insert_context_fields(value: &mut Value, request: &RuntimeMemoryProjectionBridgeRequest) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    if let Some(thread_id) = optional_trimmed(request.thread_id.as_deref()) {
        object
            .entry("thread_id")
            .or_insert_with(|| Value::String(thread_id));
    }
    if let Some(agent_id) = optional_trimmed(request.agent_id.as_deref()) {
        object
            .entry("agent_id")
            .or_insert_with(|| Value::String(agent_id));
    }
    if let Some(workspace_root) = optional_trimmed(request.workspace_root.as_deref()) {
        object
            .entry("workspace")
            .or_insert_with(|| Value::String(workspace_root));
    }
}

fn object_value(value: &Value) -> Value {
    value
        .as_object()
        .cloned()
        .map(Value::Object)
        .unwrap_or_else(|| Value::Object(Map::new()))
}

fn record_count_for_projection(projection_kind: &str, projection: &Value) -> usize {
    if projection_kind == "records" {
        if let Some(total_matches) = projection.get("total_matches").and_then(Value::as_u64) {
            return total_matches as usize;
        }
        return projection
            .get("records")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
    }
    if let Some(record_count) = projection.get("record_count").and_then(Value::as_u64) {
        return record_count as usize;
    }
    match projection {
        Value::Array(items) => items.len(),
        Value::Null => 0,
        Value::Object(object) if object.is_empty() => 0,
        _ => 1,
    }
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn optional_trimmed_lower(value: Option<&str>) -> Option<String> {
    optional_trimmed(value).map(|value| value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request(projection_kind: &str) -> RuntimeMemoryProjectionBridgeRequest {
        RuntimeMemoryProjectionBridgeRequest {
            operation: Some("runtime_memory_projection".to_string()),
            operation_kind: Some(format!("runtime.memory_projection.{projection_kind}")),
            projection_kind: Some(projection_kind.to_string()),
            thread_id: Some("thread_one".to_string()),
            agent_id: Some("agent_one".to_string()),
            workspace_root: Some("/workspace/project".to_string()),
            projection: json!({
                "schema_version": "ioi.agent-runtime.memory.v1",
                "object": "ioi.agent_memory_projection",
                "thread_id": "thread_one",
                "agent_id": "agent_one",
                "workspace": "/workspace/project",
                "policy": {
                    "id": "memory_policy_thread_one",
                    "disabled": false,
                    "injection_enabled": true,
                    "read_only": false,
                    "write_requires_approval": true,
                    "subagent_inheritance": "explicit"
                },
                "paths": {
                    "records_path": "/state/memory-records",
                    "policies_path": "/state/memory-policies",
                    "effective_policy_id": "memory_policy_thread_one"
                },
                "filters": {"query": "deploy"},
                "records": [{
                    "id": "memory_one",
                    "fact": "Deployment requires Rust-owned memory projection.",
                    "scope": "thread",
                    "memory_key": "project",
                    "fact_hash": "abc123"
                }],
                "total_matches": 1
            }),
            ..Default::default()
        }
    }

    #[test]
    fn rust_projects_runtime_memory_route_family_shapes() {
        let core = RuntimeMemoryProjectionCore;

        let records = core.project(&base_request("records")).expect("records");
        assert_eq!(records.projection_kind, "records");
        assert_eq!(records.record_count, 1);
        assert_eq!(records.projection["records"][0]["id"], "memory_one");

        let policy = core.project(&base_request("policy")).expect("policy");
        assert_eq!(policy.projection["id"], "memory_policy_thread_one");
        assert_eq!(policy.projection["thread_id"], "thread_one");
        assert_eq!(policy.record_count, 1);

        let path = core.project(&base_request("path")).expect("path");
        assert_eq!(path.projection["records_path"], "/state/memory-records");
        assert_eq!(path.projection["workspace"], "/workspace/project");

        let status = core.project(&base_request("status")).expect("status");
        assert_eq!(
            status.projection["object"],
            "ioi.runtime_memory_manager_status"
        );
        assert_eq!(status.projection["status"], "ready");
        assert_eq!(status.projection["thread_id"], "thread_one");
        assert_eq!(status.projection["record_count"], 1);

        let validation = core
            .project(&base_request("validation"))
            .expect("validation");
        assert_eq!(
            validation.projection["object"],
            "ioi.runtime_memory_manager_validation"
        );
        assert_eq!(validation.projection["ok"], true);
        assert_eq!(validation.projection["agent_id"], "agent_one");
    }

    #[test]
    fn rust_shapes_runtime_memory_projection_command_response() {
        let response = project_runtime_memory_projection_response(base_request("records"))
            .expect("runtime memory projection response");

        assert_eq!(response["source"], "rust_runtime_memory_projection_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(
            response["record"]["schema_version"],
            RUNTIME_MEMORY_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(response["record"]["projection_kind"], "records");
        assert_eq!(response["record"]["projection"]["total_matches"], 1);
        assert_eq!(
            response["record"]["receipt_refs"][0],
            "receipt_runtime_memory_projection_records"
        );
    }
}
