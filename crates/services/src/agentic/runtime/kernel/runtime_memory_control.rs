use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-control-request.v1";
pub const RUNTIME_MEMORY_CONTROL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.memory_control.v1";
const AGENT_MEMORY_SCHEMA_VERSION: &str = "ioi.agent-runtime.memory.v1";
const AGENT_MEMORY_POLICY_SCHEMA_VERSION: &str = "ioi.agent-runtime.memory-policy.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeMemoryControlRequest {
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
    pub memory_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub target_type: Option<String>,
    #[serde(default)]
    pub target_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub now: Option<String>,
    #[serde(default)]
    pub request: Value,
    #[serde(default)]
    pub current_record: Value,
    #[serde(default)]
    pub current_policy: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeMemoryControlCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeMemoryControlCommandError {
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
pub struct RuntimeMemoryControlCore;

#[derive(Debug, Clone)]
pub struct RuntimeMemoryControlRecord {
    pub operation: String,
    pub operation_kind: String,
    pub memory_state_kind: String,
    pub state_id: String,
    pub thread_id: Option<String>,
    pub agent_id: Option<String>,
    pub workspace_root: Option<String>,
    pub payload: Value,
    pub receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
}

pub fn plan_runtime_memory_control_response(
    request: RuntimeMemoryControlRequest,
) -> Result<Value, RuntimeMemoryControlCommandError> {
    let record = RuntimeMemoryControlCore::default().plan(&request)?;
    Ok(json!({
        "source": "rust_runtime_memory_control_command",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RuntimeMemoryControlCore {
    pub fn plan(
        &self,
        request: &RuntimeMemoryControlRequest,
    ) -> Result<RuntimeMemoryControlRecord, RuntimeMemoryControlCommandError> {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeMemoryControlCommandError::new(
                    "runtime_memory_control_schema_version_invalid",
                    format!("expected {RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION}, got {schema_version}"),
                ));
            }
        }
        let operation_kind = normalized_operation_kind(request)?;
        let operation = operation_for_kind(&operation_kind).to_string();
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let agent_id = optional_trimmed(request.agent_id.as_deref());
        let workspace_root = optional_trimmed(request.workspace_root.as_deref());
        if thread_id.is_none()
            && agent_id.is_none()
            && !matches!(operation_kind.as_str(), "memory.edit" | "memory.delete")
        {
            return Err(RuntimeMemoryControlCommandError::new(
                "runtime_memory_control_identity_required",
                "memory control requires thread_id or agent_id",
            ));
        }
        let now = optional_trimmed(request.now.as_deref())
            .or_else(|| string_field(&request.request, "created_at"))
            .or_else(|| string_field(&request.request, "updated_at"))
            .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string());
        let seed = format!(
            "{}:{}:{}:{}:{}",
            operation_kind,
            thread_id.clone().unwrap_or_default(),
            agent_id.clone().unwrap_or_default(),
            string_field(&request.request, "text")
                .or_else(|| string_field(&request.request, "fact"))
                .unwrap_or_default(),
            now
        );
        let generated_memory_id = format!("memory_{}", short_hash(&seed));
        let memory_state_kind = if is_event_operation(&operation_kind) {
            "event".to_string()
        } else if operation_kind == "memory.policy" {
            "policy".to_string()
        } else {
            "record".to_string()
        };
        let state_id = if is_event_operation(&operation_kind) {
            string_field(&request.request, "event_id").unwrap_or_else(|| {
                format!(
                    "event_memory_{}_{}",
                    safe_id(operation_for_kind(&operation_kind)),
                    short_hash(&seed)
                )
            })
        } else if operation_kind == "memory.policy" {
            policy_id(request, thread_id.as_deref(), agent_id.as_deref())
        } else {
            optional_trimmed(request.memory_id.as_deref())
                .or_else(|| string_field(&request.current_record, "id"))
                .unwrap_or(generated_memory_id)
        };
        if matches!(operation_kind.as_str(), "memory.edit" | "memory.delete")
            && optional_trimmed(request.memory_id.as_deref()).is_none()
            && string_field(&request.current_record, "id").is_none()
        {
            return Err(RuntimeMemoryControlCommandError::new(
                "runtime_memory_control_memory_id_required",
                "memory edit/delete requires memory_id",
            ));
        }
        let receipt_refs = memory_receipt_refs(request, &operation, &state_id);
        let evidence_refs = memory_evidence_refs(request, &operation_kind);
        let payload = if is_event_operation(&operation_kind) {
            event_payload(
                request,
                &operation_kind,
                &state_id,
                thread_id.as_deref(),
                agent_id.as_deref(),
                workspace_root.as_deref(),
                &now,
                &receipt_refs,
                &evidence_refs,
            )
        } else if operation_kind == "memory.policy" {
            policy_payload(
                request,
                &state_id,
                thread_id.as_deref(),
                agent_id.as_deref(),
                workspace_root.as_deref(),
                &now,
                &receipt_refs,
                &evidence_refs,
            )
        } else {
            record_payload(
                request,
                &operation_kind,
                &state_id,
                thread_id.as_deref(),
                agent_id.as_deref(),
                workspace_root.as_deref(),
                &now,
                &receipt_refs,
                &evidence_refs,
            )
        };
        Ok(RuntimeMemoryControlRecord {
            operation,
            operation_kind,
            memory_state_kind,
            state_id,
            thread_id,
            agent_id,
            workspace_root,
            payload,
            receipt_refs,
            evidence_refs,
        })
    }
}

impl RuntimeMemoryControlRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_MEMORY_CONTROL_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_memory_control",
            "status": "planned",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "memory_state_kind": self.memory_state_kind,
            "state_id": self.state_id,
            "thread_id": self.thread_id,
            "agent_id": self.agent_id,
            "workspace_root": self.workspace_root,
            "payload": self.payload,
            "receipt_refs": self.receipt_refs,
            "evidence_refs": self.evidence_refs,
        })
    }
}

fn record_payload(
    request: &RuntimeMemoryControlRequest,
    operation_kind: &str,
    state_id: &str,
    thread_id: Option<&str>,
    agent_id: Option<&str>,
    workspace_root: Option<&str>,
    now: &str,
    receipt_refs: &[String],
    evidence_refs: &[String],
) -> Value {
    let current = object_map(&request.current_record);
    let fact = string_field(&request.request, "fact")
        .or_else(|| string_field(&request.request, "text"))
        .or_else(|| current.and_then(|map| string_entry(map, "fact")))
        .unwrap_or_default();
    let created_at = current
        .and_then(|map| string_entry(map, "created_at"))
        .unwrap_or_else(|| now.to_string());
    let mut record = current.cloned().unwrap_or_default();
    record.insert(
        "schema_version".to_string(),
        json!(AGENT_MEMORY_SCHEMA_VERSION),
    );
    record.insert("object".to_string(), json!("ioi.agent_memory_record"));
    record.insert("id".to_string(), json!(state_id));
    record.insert("agent_id".to_string(), json!(agent_id));
    record.insert("thread_id".to_string(), json!(thread_id));
    record.insert("workspace".to_string(), json!(workspace_root));
    record.insert("fact".to_string(), json!(fact));
    record.insert(
        "memory_key".to_string(),
        json!(string_field(&request.request, "memory_key")
            .or_else(|| current.and_then(|map| string_entry(map, "memory_key")))),
    );
    record.insert(
        "scope".to_string(),
        json!(string_field(&request.request, "scope")
            .or_else(|| current.and_then(|map| string_entry(map, "scope")))
            .unwrap_or_else(|| if thread_id.is_some() {
                "thread"
            } else {
                "agent"
            }
            .to_string())),
    );
    record.insert(
        "source".to_string(),
        json!(string_field(&request.request, "source")
            .or_else(|| optional_trimmed(request.source.as_deref()))
            .unwrap_or_else(|| "memory_control".to_string())),
    );
    record.insert(
        "workflow_graph_id".to_string(),
        json!(string_field(&request.request, "workflow_graph_id")
            .or_else(|| current.and_then(|map| string_entry(map, "workflow_graph_id")))),
    );
    record.insert(
        "workflow_node_id".to_string(),
        json!(string_field(&request.request, "workflow_node_id")
            .or_else(|| current.and_then(|map| string_entry(map, "workflow_node_id")))
            .unwrap_or_else(|| format!("runtime.memory.{}", operation_for_kind(operation_kind)))),
    );
    record.insert("created_at".to_string(), json!(created_at));
    record.insert("updated_at".to_string(), json!(now));
    record.insert("receipt_refs".to_string(), json!(receipt_refs));
    record.insert("evidence_refs".to_string(), json!(evidence_refs));
    if operation_kind == "memory.delete" {
        record.insert("status".to_string(), json!("deleted"));
        record.insert("deleted_at".to_string(), json!(now));
        record.insert(
            "deletion_reason".to_string(),
            json!(string_field(&request.request, "reason")
                .unwrap_or_else(|| "operator_delete".to_string())),
        );
    } else {
        record.insert("status".to_string(), json!("active"));
    }
    Value::Object(record)
}

fn policy_payload(
    request: &RuntimeMemoryControlRequest,
    state_id: &str,
    thread_id: Option<&str>,
    agent_id: Option<&str>,
    workspace_root: Option<&str>,
    now: &str,
    receipt_refs: &[String],
    evidence_refs: &[String],
) -> Value {
    let current = object_map(&request.current_policy);
    let requested_policy = object_map(request.request.get("policy").unwrap_or(&request.request));
    let target_type = optional_trimmed(request.target_type.as_deref())
        .or_else(|| current.and_then(|map| string_entry(map, "target_type")))
        .unwrap_or_else(|| {
            if thread_id.is_some() {
                "thread"
            } else {
                "agent"
            }
            .to_string()
        });
    let target_id = optional_trimmed(request.target_id.as_deref())
        .or_else(|| current.and_then(|map| string_entry(map, "target_id")))
        .unwrap_or_else(|| thread_id.or(agent_id).unwrap_or("runtime").to_string());
    let created_at = current
        .and_then(|map| string_entry(map, "created_at"))
        .unwrap_or_else(|| now.to_string());
    let mut policy = current.cloned().unwrap_or_default();
    policy.insert(
        "schema_version".to_string(),
        json!(AGENT_MEMORY_POLICY_SCHEMA_VERSION),
    );
    policy.insert("object".to_string(), json!("ioi.agent_memory_policy"));
    policy.insert("id".to_string(), json!(state_id));
    policy.insert("target_type".to_string(), json!(target_type));
    policy.insert("target_id".to_string(), json!(target_id));
    policy.insert("agent_id".to_string(), json!(agent_id));
    policy.insert("thread_id".to_string(), json!(thread_id));
    policy.insert("workspace".to_string(), json!(workspace_root));
    policy.insert(
        "source".to_string(),
        json!(string_field(&request.request, "source")
            .or_else(|| optional_trimmed(request.source.as_deref()))
            .unwrap_or_else(|| "memory_policy_api".to_string())),
    );
    for key in [
        "disabled",
        "injection_enabled",
        "read_only",
        "write_requires_approval",
        "retention",
        "redaction",
        "subagent_inheritance",
        "scope",
    ] {
        if let Some(value) = requested_policy.and_then(|map| map.get(key)) {
            policy.insert(key.to_string(), value.clone());
        }
    }
    policy.insert("created_at".to_string(), json!(created_at));
    policy.insert("updated_at".to_string(), json!(now));
    policy.insert("receipt_refs".to_string(), json!(receipt_refs));
    policy.insert("evidence_refs".to_string(), json!(evidence_refs));
    Value::Object(policy)
}

fn event_payload(
    request: &RuntimeMemoryControlRequest,
    operation_kind: &str,
    event_id: &str,
    thread_id: Option<&str>,
    agent_id: Option<&str>,
    workspace_root: Option<&str>,
    now: &str,
    receipt_refs: &[String],
    evidence_refs: &[String],
) -> Value {
    let operation = operation_for_kind(operation_kind);
    let control_kind = string_field(&request.request, "control_kind")
        .unwrap_or_else(|| format!("memory_{operation}"));
    let event_kind =
        string_field(&request.request, "event_kind").unwrap_or_else(|| operation_kind.to_string());
    let event_stream_id = string_field(&request.request, "event_stream_id")
        .unwrap_or_else(|| format!("{}:events", thread_id.unwrap_or("runtime")));
    let turn_id = string_field(&request.request, "turn_id");
    let item_id = string_field(&request.request, "item_id").or_else(|| {
        turn_id
            .as_ref()
            .map(|turn| format!("{turn}:item:memory:{operation}"))
    });
    let idempotency_key = string_field(&request.request, "idempotency_key").unwrap_or_else(|| {
        format!(
            "thread:{}:{}:{}",
            thread_id.unwrap_or("runtime"),
            operation_kind,
            short_hash(format!("{event_stream_id}:{event_id}:{now}"))
        )
    });
    let mut event_payload = object_map(request.request.get("payload").unwrap_or(&Value::Null))
        .cloned()
        .unwrap_or_default();
    event_payload.insert("operation".to_string(), json!(operation));
    event_payload.insert("control_kind".to_string(), json!(control_kind.clone()));
    event_payload.insert("thread_id".to_string(), json!(thread_id));
    event_payload.insert("agent_id".to_string(), json!(agent_id));
    event_payload.insert("workspace_root".to_string(), json!(workspace_root));
    event_payload.insert(
        "status".to_string(),
        json!(string_field(&request.request, "status")),
    );
    event_payload.insert("receipt_refs".to_string(), json!(receipt_refs));
    event_payload.insert("evidence_refs".to_string(), json!(evidence_refs));

    json!({
        "event_id": event_id,
        "event_stream_id": event_stream_id,
        "thread_id": thread_id,
        "agent_id": agent_id,
        "workspace_root": workspace_root,
        "turn_id": turn_id,
        "item_id": item_id,
        "idempotency_key": idempotency_key,
        "source": string_field(&request.request, "source")
            .or_else(|| optional_trimmed(request.source.as_deref()))
            .unwrap_or_else(|| "agent_studio".to_string()),
        "source_event_kind": string_field(&request.request, "source_event_kind")
            .unwrap_or_else(|| format!("OperatorControl.Memory{}", title_case(operation))),
        "event_kind": event_kind,
        "status": string_field(&request.request, "status").unwrap_or_else(|| "completed".to_string()),
        "component_kind": string_field(&request.request, "component_kind")
            .unwrap_or_else(|| "memory_manager".to_string()),
        "workflow_node_id": string_field(&request.request, "workflow_node_id")
            .unwrap_or_else(|| format!("runtime.memory-manager.{operation}")),
        "payload_schema_version": string_field(&request.request, "payload_schema_version")
            .unwrap_or_else(|| format!("ioi.runtime.memory-{operation}.v1")),
        "payload": Value::Object(event_payload),
        "receipt_refs": receipt_refs,
        "policy_decision_refs": string_array_field(&request.request, "policy_decision_refs"),
        "policy_decision_kind": string_field(&request.request, "policy_decision_kind")
            .unwrap_or_else(|| "read".to_string()),
        "evidence_refs": evidence_refs,
    })
}

fn normalized_operation_kind(
    request: &RuntimeMemoryControlRequest,
) -> Result<String, RuntimeMemoryControlCommandError> {
    let operation_kind = optional_trimmed(request.operation_kind.as_deref()).unwrap_or_else(|| {
        let operation =
            optional_trimmed(request.operation.as_deref()).unwrap_or_else(|| "write".to_string());
        match operation.as_str() {
            "write" => "memory.write".to_string(),
            "edit" => "memory.edit".to_string(),
            "delete" => "memory.delete".to_string(),
            "policy" | "policy_update" => "memory.policy".to_string(),
            "status" => "memory.status".to_string(),
            "validate" | "validation" => "memory.validate".to_string(),
            other => format!("memory.{other}"),
        }
    });
    if !matches!(
        operation_kind.as_str(),
        "memory.write"
            | "memory.edit"
            | "memory.delete"
            | "memory.policy"
            | "memory.status"
            | "memory.validate"
    ) {
        return Err(RuntimeMemoryControlCommandError::new(
            "runtime_memory_control_operation_kind_unsupported",
            format!("{operation_kind} is not yet Rust-owned"),
        ));
    }
    Ok(operation_kind)
}

fn operation_for_kind(operation_kind: &str) -> &str {
    match operation_kind {
        "memory.policy" => "policy",
        "memory.edit" => "edit",
        "memory.delete" => "delete",
        "memory.status" => "status",
        "memory.validate" => "validate",
        _ => "write",
    }
}

fn is_event_operation(operation_kind: &str) -> bool {
    matches!(operation_kind, "memory.status" | "memory.validate")
}

fn policy_id(
    request: &RuntimeMemoryControlRequest,
    thread_id: Option<&str>,
    agent_id: Option<&str>,
) -> String {
    if let Some(policy_id) = string_field(&request.current_policy, "id") {
        return policy_id;
    }
    let target_type = optional_trimmed(request.target_type.as_deref()).unwrap_or_else(|| {
        if thread_id.is_some() {
            "thread"
        } else {
            "agent"
        }
        .to_string()
    });
    let target_id = optional_trimmed(request.target_id.as_deref())
        .unwrap_or_else(|| thread_id.or(agent_id).unwrap_or("runtime").to_string());
    format!(
        "memory_policy_{}_{}",
        safe_id(&target_type),
        safe_id(&target_id)
    )
}

fn memory_receipt_refs(
    request: &RuntimeMemoryControlRequest,
    operation: &str,
    state_id: &str,
) -> Vec<String> {
    unique_strings(
        request
            .receipt_refs
            .iter()
            .cloned()
            .chain(string_array_field(&request.request, "receipt_refs"))
            .chain(std::iter::once(format!(
                "receipt_memory_{}_{}",
                safe_id(operation),
                short_hash(state_id)
            )))
            .collect(),
    )
}

fn memory_evidence_refs(
    request: &RuntimeMemoryControlRequest,
    operation_kind: &str,
) -> Vec<String> {
    if !request.evidence_refs.is_empty() {
        return request.evidence_refs.clone();
    }
    vec![
        "runtime_memory_control_rust_owned".to_string(),
        match operation_kind {
            "memory.policy" => "runtime_memory_policy_control_rust_owned",
            "memory.edit" => "runtime_memory_edit_control_rust_owned",
            "memory.delete" => "runtime_memory_delete_control_rust_owned",
            "memory.status" => "runtime_memory_status_control_rust_owned",
            "memory.validate" => "runtime_memory_validation_control_rust_owned",
            _ => "runtime_memory_write_control_rust_owned",
        }
        .to_string(),
        if is_event_operation(operation_kind) {
            "runtime_memory_control_event_rust_owned".to_string()
        } else {
            "runtime_memory_state_store_js_mutation_retired".to_string()
        },
        if is_event_operation(operation_kind) {
            "agentgres_runtime_thread_event_truth_required".to_string()
        } else {
            "agentgres_thread_memory_state_truth_required".to_string()
        },
    ]
}

fn title_case(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

fn object_map(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|text| optional_trimmed(Some(text)))
}

fn string_entry(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(Value::as_str)
        .and_then(|text| optional_trimmed(Some(text)))
}

fn string_array_field(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|text| optional_trimmed(Some(text)))
                .collect()
        })
        .unwrap_or_default()
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
}

fn safe_id(value: &str) -> String {
    let mut output = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
            output.push(ch);
        } else {
            output.push('_');
        }
    }
    let trimmed = output.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "memory".to_string()
    } else {
        trimmed
    }
}

fn short_hash(value: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hex::encode(hasher.finalize())[..16].to_string()
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut output = Vec::new();
    for value in values {
        if value.trim().is_empty() || output.contains(&value) {
            continue;
        }
        output.push(value);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_control_request() -> RuntimeMemoryControlRequest {
        RuntimeMemoryControlRequest {
            schema_version: Some(RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION.to_string()),
            operation: Some("write".to_string()),
            operation_kind: Some("memory.write".to_string()),
            thread_id: Some("thread_1".to_string()),
            agent_id: Some("agent_1".to_string()),
            workspace_root: Some("/workspace".to_string()),
            now: Some("2026-06-12T10:00:00.000Z".to_string()),
            request: json!({
                "text": "Remember deployment window",
                "memory_key": "deploy.window",
                "source": "operator_remember"
            }),
            ..Default::default()
        }
    }

    #[test]
    fn rust_plans_runtime_memory_write_control() {
        let record = RuntimeMemoryControlCore
            .plan(&memory_control_request())
            .expect("memory write planned");

        assert_eq!(record.operation_kind, "memory.write");
        assert_eq!(record.memory_state_kind, "record");
        assert!(record.state_id.starts_with("memory_"));
        assert_eq!(
            record.payload["schema_version"],
            AGENT_MEMORY_SCHEMA_VERSION
        );
        assert_eq!(record.payload["object"], "ioi.agent_memory_record");
        assert_eq!(record.payload["thread_id"], "thread_1");
        assert_eq!(record.payload["agent_id"], "agent_1");
        assert_eq!(record.payload["fact"], "Remember deployment window");
        assert_eq!(record.payload["memory_key"], "deploy.window");
        assert!(record.receipt_refs[0].starts_with("receipt_memory_write_"));
        assert!(record
            .evidence_refs
            .contains(&"runtime_memory_write_control_rust_owned".to_string()));
    }

    #[test]
    fn rust_plans_runtime_memory_policy_control() {
        let mut request = memory_control_request();
        request.operation = Some("policy".to_string());
        request.operation_kind = Some("memory.policy".to_string());
        request.request = json!({
            "policy": {
                "read_only": true,
                "write_requires_approval": true
            }
        });

        let record = RuntimeMemoryControlCore
            .plan(&request)
            .expect("memory policy planned");

        assert_eq!(record.memory_state_kind, "policy");
        assert_eq!(record.state_id, "memory_policy_thread_thread_1");
        assert_eq!(
            record.payload["schema_version"],
            AGENT_MEMORY_POLICY_SCHEMA_VERSION
        );
        assert_eq!(record.payload["target_type"], "thread");
        assert_eq!(record.payload["target_id"], "thread_1");
        assert_eq!(record.payload["read_only"], true);
        assert_eq!(record.payload["write_requires_approval"], true);
        assert!(record
            .evidence_refs
            .contains(&"runtime_memory_policy_control_rust_owned".to_string()));
    }

    #[test]
    fn rust_plans_runtime_memory_status_control_event() {
        let mut request = memory_control_request();
        request.operation = Some("status".to_string());
        request.operation_kind = Some("memory.status".to_string());
        request.request = json!({
            "event_stream_id": "thread_1:events",
            "turn_id": "turn_latest",
            "control_kind": "memory_status",
            "source_event_kind": "OperatorControl.MemoryStatus",
            "event_kind": "memory.status",
            "component_kind": "memory_manager",
            "workflow_node_id": "runtime.memory-manager.status",
            "payload_schema_version": "ioi.runtime.memory-status.v1",
            "payload": {
                "status": "ready",
                "record_count": 1
            }
        });

        let record = RuntimeMemoryControlCore
            .plan(&request)
            .expect("memory status event planned");

        assert_eq!(record.operation_kind, "memory.status");
        assert_eq!(record.memory_state_kind, "event");
        assert!(record.state_id.starts_with("event_memory_status_"));
        assert_eq!(record.payload["event_stream_id"], "thread_1:events");
        assert_eq!(record.payload["thread_id"], "thread_1");
        assert_eq!(record.payload["event_kind"], "memory.status");
        assert_eq!(record.payload["payload"]["control_kind"], "memory_status");
        assert_eq!(record.payload["payload"]["record_count"], 1);
        assert!(record
            .evidence_refs
            .contains(&"runtime_memory_status_control_rust_owned".to_string()));
        assert!(record
            .evidence_refs
            .contains(&"runtime_memory_control_event_rust_owned".to_string()));
    }

    #[test]
    fn rust_plans_runtime_memory_validation_control_event() {
        let mut request = memory_control_request();
        request.operation = Some("validate".to_string());
        request.operation_kind = Some("memory.validate".to_string());
        request.request = json!({
            "event_stream_id": "thread_1:events",
            "control_kind": "memory_validate",
            "event_kind": "memory.validate",
            "payload": {
                "ok": true,
                "record_count": 1
            }
        });

        let record = RuntimeMemoryControlCore
            .plan(&request)
            .expect("memory validation event planned");

        assert_eq!(record.operation, "validate");
        assert_eq!(record.operation_kind, "memory.validate");
        assert_eq!(record.memory_state_kind, "event");
        assert_eq!(record.payload["event_kind"], "memory.validate");
        assert_eq!(
            record.payload["source_event_kind"],
            "OperatorControl.MemoryValidate"
        );
        assert_eq!(record.payload["payload"]["control_kind"], "memory_validate");
        assert_eq!(record.payload["payload"]["ok"], true);
        assert!(record
            .evidence_refs
            .contains(&"runtime_memory_validation_control_rust_owned".to_string()));
    }

    #[test]
    fn rust_rejects_unowned_runtime_memory_control_kind() {
        let mut request = memory_control_request();
        request.operation_kind = Some("memory.audit".to_string());

        let error = RuntimeMemoryControlCore
            .plan(&request)
            .expect_err("memory audit is not part of this cut");

        assert_eq!(
            error.code(),
            "runtime_memory_control_operation_kind_unsupported"
        );
    }
}
