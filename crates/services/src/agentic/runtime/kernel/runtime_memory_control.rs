use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

pub const RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.memory-control-request.v1";
pub const RUNTIME_MEMORY_CONTROL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.memory_control.v1";
const AGENT_MEMORY_SCHEMA_VERSION: &str = "ioi.agent-runtime.memory.v1";
const AGENT_MEMORY_POLICY_SCHEMA_VERSION: &str = "ioi.agent-runtime.memory-policy.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeMemoryControlApiRequest {
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
    pub state_dir: Option<String>,
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
pub struct RuntimeMemoryControlApiError {
    code: &'static str,
    message: String,
}

impl RuntimeMemoryControlApiError {
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
    request: RuntimeMemoryControlApiRequest,
) -> Result<Value, RuntimeMemoryControlApiError> {
    let record = RuntimeMemoryControlCore::default().plan(&request)?;
    Ok(json!({
        "source": "rust_runtime_memory_control_api",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RuntimeMemoryControlCore {
    pub fn plan(
        &self,
        request: &RuntimeMemoryControlApiRequest,
    ) -> Result<RuntimeMemoryControlRecord, RuntimeMemoryControlApiError> {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeMemoryControlApiError::new(
                    "runtime_memory_control_schema_version_invalid",
                    format!("expected {RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION}, got {schema_version}"),
                ));
            }
        }
        let operation_kind = normalized_operation_kind(request)?;
        reject_control_candidate_transport(request)?;
        let operation = operation_for_kind(&operation_kind).to_string();
        let requested_memory_id = optional_trimmed(request.memory_id.as_deref());
        let current_record = if matches!(operation_kind.as_str(), "memory.edit" | "memory.delete") {
            let memory_id = requested_memory_id.as_deref().ok_or_else(|| {
                RuntimeMemoryControlApiError::new(
                    "runtime_memory_control_memory_id_required",
                    "memory edit/delete requires memory_id",
                )
            })?;
            memory_control_record_from_state_dir(request.state_dir.as_deref(), memory_id)?
        } else {
            Value::Null
        };
        let thread_id = optional_trimmed(request.thread_id.as_deref())
            .or_else(|| string_field(&current_record, "thread_id"));
        let agent_id = optional_trimmed(request.agent_id.as_deref())
            .or_else(|| string_field(&current_record, "agent_id"));
        let workspace_root = optional_trimmed(request.workspace_root.as_deref())
            .or_else(|| string_field(&current_record, "workspace"));
        if thread_id.is_none()
            && agent_id.is_none()
            && !matches!(operation_kind.as_str(), "memory.edit" | "memory.delete")
        {
            return Err(RuntimeMemoryControlApiError::new(
                "runtime_memory_control_identity_required",
                "memory control requires thread_id or agent_id",
            ));
        }
        let current_policy = if operation_kind == "memory.policy" {
            memory_control_policy_from_state_dir(
                request.state_dir.as_deref(),
                request,
                thread_id.as_deref(),
                agent_id.as_deref(),
                workspace_root.as_deref(),
            )?
        } else {
            Value::Null
        };
        let mut effective_request = request.clone();
        effective_request.current_record = current_record;
        effective_request.current_policy = current_policy;
        effective_request.thread_id = thread_id.clone();
        effective_request.agent_id = agent_id.clone();
        effective_request.workspace_root = workspace_root.clone();
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
            policy_id(
                &effective_request,
                thread_id.as_deref(),
                agent_id.as_deref(),
            )
        } else {
            requested_memory_id
                .or_else(|| string_field(&effective_request.current_record, "id"))
                .unwrap_or(generated_memory_id)
        };
        let receipt_refs = memory_receipt_refs(&effective_request, &operation, &state_id);
        let evidence_refs = memory_evidence_refs(&effective_request, &operation_kind);
        let payload = if is_event_operation(&operation_kind) {
            event_payload(
                &effective_request,
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
                &effective_request,
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
                &effective_request,
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

fn reject_control_candidate_transport(
    request: &RuntimeMemoryControlApiRequest,
) -> Result<(), RuntimeMemoryControlApiError> {
    if has_candidate_transport(&request.current_record) {
        return Err(RuntimeMemoryControlApiError::new(
            "runtime_memory_control_current_record_transport_retired",
            "runtime memory control rejects JS-supplied current records; provide state_dir for Agentgres memory replay",
        ));
    }
    if has_candidate_transport(&request.current_policy) {
        return Err(RuntimeMemoryControlApiError::new(
            "runtime_memory_control_current_policy_transport_retired",
            "runtime memory control rejects JS-supplied current policies; provide state_dir for Agentgres memory replay",
        ));
    }
    Ok(())
}

fn has_candidate_transport(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Object(object) => !object.is_empty(),
        Value::Array(items) => !items.is_empty(),
        _ => true,
    }
}

fn memory_control_record_from_state_dir(
    state_dir: Option<&str>,
    memory_id: &str,
) -> Result<Value, RuntimeMemoryControlApiError> {
    let state_root = memory_control_state_root(state_dir)?;
    load_memory_state_dir_records(state_root.join("memory-records"), "memory records")?
        .into_iter()
        .filter(canonical_memory_record)
        .find(|record| string_field(record, "id").as_deref() == Some(memory_id))
        .ok_or_else(|| {
            RuntimeMemoryControlApiError::new(
                "runtime_memory_control_record_required",
                format!("memory control requires admitted memory record {memory_id} in state_dir"),
            )
        })
}

fn memory_control_policy_from_state_dir(
    state_dir: Option<&str>,
    request: &RuntimeMemoryControlApiRequest,
    thread_id: Option<&str>,
    agent_id: Option<&str>,
    workspace_root: Option<&str>,
) -> Result<Value, RuntimeMemoryControlApiError> {
    let state_root = memory_control_state_root(state_dir)?;
    let policies =
        load_memory_state_dir_records(state_root.join("memory-policies"), "memory policies")?
            .into_iter()
            .filter(canonical_memory_policy)
            .collect::<Vec<_>>();
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
    let target_policy_id = memory_policy_id(&target_type, &target_id);
    if let Some(policy) = policies
        .iter()
        .find(|policy| string_field(policy, "id").as_deref() == Some(target_policy_id.as_str()))
    {
        return Ok(policy.clone());
    }
    let mut policy = default_memory_policy(thread_id, agent_id, workspace_root);
    if let Some(object) = policy.as_object_mut() {
        object.insert("target_type".to_string(), json!(target_type));
        object.insert("target_id".to_string(), json!(target_id));
        object.insert("id".to_string(), json!(target_policy_id));
    }
    Ok(policy)
}

fn memory_control_state_root(
    state_dir: Option<&str>,
) -> Result<PathBuf, RuntimeMemoryControlApiError> {
    optional_trimmed(state_dir)
        .map(PathBuf::from)
        .ok_or_else(|| {
            RuntimeMemoryControlApiError::new(
                "runtime_memory_control_state_dir_required",
                "runtime memory control requires runtime state_dir for Agentgres memory replay",
            )
        })
}

fn load_memory_state_dir_records(
    dir: PathBuf,
    label: &str,
) -> Result<Vec<Value>, RuntimeMemoryControlApiError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(&dir).map_err(|error| {
        RuntimeMemoryControlApiError::new(
            "runtime_memory_control_replay_read_failed",
            format!("runtime memory control could not read Agentgres {label}: {error}"),
        )
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            RuntimeMemoryControlApiError::new(
                "runtime_memory_control_replay_read_failed",
                format!(
                    "runtime memory control could not inspect Agentgres {label} entry: {error}"
                ),
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
            RuntimeMemoryControlApiError::new(
                "runtime_memory_control_replay_read_failed",
                format!(
                    "runtime memory control could not read Agentgres {label} record {}: {error}",
                    path.display()
                ),
            )
        })?;
        let record = serde_json::from_str(&contents).map_err(|error| {
            RuntimeMemoryControlApiError::new(
                "runtime_memory_control_replay_record_invalid",
                format!(
                    "runtime memory control found invalid Agentgres {label} record {}: {error}",
                    path.display()
                ),
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

fn canonical_memory_record(record: &Value) -> bool {
    record.as_object().is_some()
        && string_field(record, "schema_version").as_deref() == Some(AGENT_MEMORY_SCHEMA_VERSION)
        && string_field(record, "object").as_deref() == Some("ioi.agent_memory_record")
        && string_field(record, "id").is_some()
}

fn canonical_memory_policy(record: &Value) -> bool {
    record.as_object().is_some()
        && string_field(record, "schema_version").as_deref()
            == Some(AGENT_MEMORY_POLICY_SCHEMA_VERSION)
        && string_field(record, "object").as_deref() == Some("ioi.agent_memory_policy")
        && string_field(record, "id").is_some()
}

fn default_memory_policy(
    thread_id: Option<&str>,
    agent_id: Option<&str>,
    workspace_root: Option<&str>,
) -> Value {
    let target_id = thread_id.or(agent_id).unwrap_or("runtime");
    json!({
        "schema_version": AGENT_MEMORY_POLICY_SCHEMA_VERSION,
        "object": "ioi.agent_memory_policy",
        "id": memory_policy_id("thread", target_id),
        "target_type": "thread",
        "target_id": target_id,
        "agent_id": agent_id,
        "thread_id": thread_id,
        "workspace": workspace_root,
        "disabled": false,
        "injection_enabled": true,
        "read_only": false,
        "write_requires_approval": false,
        "retention": "persistent",
        "redaction": "none",
        "subagent_inheritance": "explicit",
        "scope": "thread",
        "source": "rust_runtime_memory_control_default_policy",
        "evidence_refs": [
            "runtime_memory_control_state_dir_replay",
            "agentgres_thread_memory_state_truth_required"
        ],
    })
}

fn record_payload(
    request: &RuntimeMemoryControlApiRequest,
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
    request: &RuntimeMemoryControlApiRequest,
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
    request: &RuntimeMemoryControlApiRequest,
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
            .unwrap_or_else(|| "hypervisor_session".to_string()),
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
    request: &RuntimeMemoryControlApiRequest,
) -> Result<String, RuntimeMemoryControlApiError> {
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
        return Err(RuntimeMemoryControlApiError::new(
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
    request: &RuntimeMemoryControlApiRequest,
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
    memory_policy_id(&target_type, &target_id)
}

fn memory_policy_id(target_type: &str, target_id: &str) -> String {
    // MUST match runtime_memory_projection::policy_id (the reader): raw target_type +
    // safe_file_id(target_id). The previous safe_id() form trimmed leading/trailing `_` and fell
    // back to "memory" on empty, so a target_id with leading/trailing special chars was WRITTEN
    // under one id but LOOKED UP under another by the projection — silently losing the policy
    // update. (Identical for normal thread_<uuid>/agent_<uuid> ids, so this is byte-compatible.)
    format!("memory_policy_{target_type}_{}", safe_file_id(target_id))
}

/// Mirror runtime_memory_projection::safe_file_id (NO trim, NO empty-fallback) so the policy id
/// written here matches the id the projection computes when reading the persisted policy back.
fn safe_file_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn memory_receipt_refs(
    request: &RuntimeMemoryControlApiRequest,
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
    request: &RuntimeMemoryControlApiRequest,
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
    use std::{
        env,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_state_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is available")
            .as_nanos();
        let dir = env::temp_dir().join(format!(
            "ioi-runtime-memory-control-{label}-{nanos}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp state dir");
        dir
    }

    fn write_state_record(state_dir: &Path, dir: &str, id: &str, record: Value) {
        let target_dir = state_dir.join(dir);
        fs::create_dir_all(&target_dir).expect("create memory state dir");
        fs::write(
            target_dir.join(format!("{id}.json")),
            serde_json::to_vec_pretty(&record).expect("serialize memory state record"),
        )
        .expect("write memory state record");
    }

    fn seed_memory_state(state_dir: &Path) {
        write_state_record(
            state_dir,
            "memory-records",
            "memory_1",
            json!({
                "schema_version": AGENT_MEMORY_SCHEMA_VERSION,
                "object": "ioi.agent_memory_record",
                "id": "memory_1",
                "thread_id": "thread_1",
                "agent_id": "agent_1",
                "workspace": "/workspace",
                "fact": "Remember deployment window",
                "scope": "thread",
                "memory_key": "deploy.window",
                "source": "operator_remember",
                "created_at": "2026-06-11T10:00:00.000Z",
                "status": "active",
                "receipt_refs": ["receipt_memory_write_seed"]
            }),
        );
        write_state_record(
            state_dir,
            "memory-policies",
            "memory_policy_thread_thread_1",
            json!({
                "schema_version": AGENT_MEMORY_POLICY_SCHEMA_VERSION,
                "object": "ioi.agent_memory_policy",
                "id": "memory_policy_thread_thread_1",
                "target_type": "thread",
                "target_id": "thread_1",
                "thread_id": "thread_1",
                "agent_id": "agent_1",
                "workspace": "/workspace",
                "read_only": false,
                "write_requires_approval": false,
                "retention": "persistent",
                "created_at": "2026-06-11T10:00:00.000Z",
                "receipt_refs": ["receipt_memory_policy_seed"]
            }),
        );
    }

    fn memory_control_request(state_dir: &Path) -> RuntimeMemoryControlApiRequest {
        RuntimeMemoryControlApiRequest {
            schema_version: Some(RUNTIME_MEMORY_CONTROL_REQUEST_SCHEMA_VERSION.to_string()),
            operation: Some("write".to_string()),
            operation_kind: Some("memory.write".to_string()),
            thread_id: Some("thread_1".to_string()),
            agent_id: Some("agent_1".to_string()),
            workspace_root: Some("/workspace".to_string()),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
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
        let state_dir = temp_state_dir("write");
        let record = RuntimeMemoryControlCore
            .plan(&memory_control_request(&state_dir))
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
        let state_dir = temp_state_dir("policy");
        seed_memory_state(&state_dir);
        let mut request = memory_control_request(&state_dir);
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
        assert_eq!(record.payload["created_at"], "2026-06-11T10:00:00.000Z");
        assert!(record
            .evidence_refs
            .contains(&"runtime_memory_policy_control_rust_owned".to_string()));
    }

    #[test]
    fn memory_policy_id_matches_projection_reader_formula() {
        // The projection reads policies by `memory_policy_{target_type}_{safe_file_id(target_id)}`.
        // Normal ids are byte-identical to the old safe_id form.
        assert_eq!(memory_policy_id("thread", "thread_1"), "memory_policy_thread_thread_1");
        assert_eq!(memory_policy_id("agent", "agent_42"), "memory_policy_agent_agent_42");
        // A leading special char: safe_file_id keeps the underscore (no trim) so the written id
        // matches the projection's lookup id — the previous safe_id form trimmed it and lost the
        // policy on read.
        assert_eq!(memory_policy_id("thread", "@weird"), "memory_policy_thread__weird");
        assert_eq!(memory_policy_id("agent", "a/b c"), "memory_policy_agent_a_b_c");
    }

    #[test]
    fn rust_plans_runtime_memory_status_control_event() {
        let state_dir = temp_state_dir("status");
        let mut request = memory_control_request(&state_dir);
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
        let state_dir = temp_state_dir("validation");
        let mut request = memory_control_request(&state_dir);
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
        let state_dir = temp_state_dir("unsupported");
        let mut request = memory_control_request(&state_dir);
        request.operation_kind = Some("memory.audit".to_string());

        let error = RuntimeMemoryControlCore
            .plan(&request)
            .expect_err("memory audit is not part of this cut");

        assert_eq!(
            error.code(),
            "runtime_memory_control_operation_kind_unsupported"
        );
    }

    #[test]
    fn rust_replays_current_record_for_memory_edit_control() {
        let state_dir = temp_state_dir("edit-replay");
        seed_memory_state(&state_dir);
        let mut request = memory_control_request(&state_dir);
        request.operation = Some("edit".to_string());
        request.operation_kind = Some("memory.edit".to_string());
        request.thread_id = None;
        request.agent_id = None;
        request.workspace_root = None;
        request.memory_id = Some("memory_1".to_string());
        request.request = json!({ "text": "Edited deployment window" });

        let record = RuntimeMemoryControlCore
            .plan(&request)
            .expect("memory edit planned from replayed current record");

        assert_eq!(record.operation_kind, "memory.edit");
        assert_eq!(record.state_id, "memory_1");
        assert_eq!(record.thread_id.as_deref(), Some("thread_1"));
        assert_eq!(record.agent_id.as_deref(), Some("agent_1"));
        assert_eq!(record.workspace_root.as_deref(), Some("/workspace"));
        assert_eq!(record.payload["fact"], "Edited deployment window");
        assert_eq!(record.payload["memory_key"], "deploy.window");
        assert_eq!(record.payload["created_at"], "2026-06-11T10:00:00.000Z");
        assert_eq!(record.payload["status"], "active");
    }

    #[test]
    fn rust_requires_state_dir_for_memory_edit_control() {
        let state_dir = temp_state_dir("edit-missing-state-dir");
        let mut request = memory_control_request(&state_dir);
        request.operation = Some("edit".to_string());
        request.operation_kind = Some("memory.edit".to_string());
        request.memory_id = Some("memory_1".to_string());
        request.state_dir = None;

        let error = RuntimeMemoryControlCore
            .plan(&request)
            .expect_err("missing state_dir should fail");

        assert_eq!(error.code(), "runtime_memory_control_state_dir_required");
    }

    #[test]
    fn rust_requires_replayed_record_for_memory_edit_control() {
        let state_dir = temp_state_dir("edit-missing-record");
        let mut request = memory_control_request(&state_dir);
        request.operation = Some("edit".to_string());
        request.operation_kind = Some("memory.edit".to_string());
        request.memory_id = Some("memory_missing".to_string());

        let error = RuntimeMemoryControlCore
            .plan(&request)
            .expect_err("missing replayed record should fail");

        assert_eq!(error.code(), "runtime_memory_control_record_required");
    }

    #[test]
    fn rust_rejects_memory_control_current_record_transport() {
        let state_dir = temp_state_dir("current-record-transport");
        let mut request = memory_control_request(&state_dir);
        request.operation = Some("edit".to_string());
        request.operation_kind = Some("memory.edit".to_string());
        request.memory_id = Some("memory_1".to_string());
        request.current_record = json!({ "id": "memory_1" });

        let error = RuntimeMemoryControlCore
            .plan(&request)
            .expect_err("current record transport should fail");

        assert_eq!(
            error.code(),
            "runtime_memory_control_current_record_transport_retired"
        );
    }

    #[test]
    fn rust_rejects_memory_control_current_policy_transport() {
        let state_dir = temp_state_dir("current-policy-transport");
        let mut request = memory_control_request(&state_dir);
        request.operation = Some("policy".to_string());
        request.operation_kind = Some("memory.policy".to_string());
        request.current_policy = json!({ "id": "memory_policy_thread_thread_1" });

        let error = RuntimeMemoryControlCore
            .plan(&request)
            .expect_err("current policy transport should fail");

        assert_eq!(
            error.code(),
            "runtime_memory_control_current_policy_transport_retired"
        );
    }
}
