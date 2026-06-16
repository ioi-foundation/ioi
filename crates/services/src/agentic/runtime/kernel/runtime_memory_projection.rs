use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

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
const AGENT_MEMORY_SCHEMA_VERSION: &str = "ioi.agent-runtime.memory.v1";
const AGENT_MEMORY_POLICY_SCHEMA_VERSION: &str = "ioi.agent-runtime.memory-policy.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeMemoryProjectionApiRequest {
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
    pub state_dir: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub status_schema_version: Option<String>,
    #[serde(default)]
    pub validation_schema_version: Option<String>,
    #[serde(default)]
    pub filters: Value,
    #[serde(default)]
    pub projection: Value,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeMemoryProjectionApiError {
    code: &'static str,
    message: String,
}

impl RuntimeMemoryProjectionApiError {
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
    request: RuntimeMemoryProjectionApiRequest,
) -> Result<Value, RuntimeMemoryProjectionApiError> {
    let record = RuntimeMemoryProjectionCore::default().project(&request)?;
    Ok(json!({
        "source": "rust_runtime_memory_projection_api",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RuntimeMemoryProjectionCore {
    pub fn project(
        &self,
        request: &RuntimeMemoryProjectionApiRequest,
    ) -> Result<RuntimeMemoryProjectionRecord, RuntimeMemoryProjectionApiError> {
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
            .unwrap_or_else(|| "rust_runtime_memory_projection_api".to_string());
        reject_projection_candidate_transport(request)?;
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
    request: &RuntimeMemoryProjectionApiRequest,
) -> Result<Value, RuntimeMemoryProjectionApiError> {
    let memory_projection = memory_projection_from_state_dir(request)?;
    match projection_kind {
        "records" => Ok(memory_projection),
        "policy" => Ok(memory_projection
            .get("policy")
            .cloned()
            .filter(Value::is_object)
            .unwrap_or_else(|| Value::Object(Map::new()))),
        "path" | "paths" => Ok(memory_projection
            .get("paths")
            .cloned()
            .filter(Value::is_object)
            .unwrap_or_else(|| Value::Object(Map::new()))),
        "status" => {
            let record = MemoryManagerStatusProjectionCore
                .project(&MemoryManagerStatusProjectionRequest {
                    schema_version: MEMORY_MANAGER_STATUS_PROJECTION_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    status_schema_version: request.status_schema_version.clone(),
                    validation_schema_version: request.validation_schema_version.clone(),
                    projection: memory_projection,
                })
                .map_err(|error| {
                    RuntimeMemoryProjectionApiError::new(
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
                    projection: memory_projection,
                })
                .map_err(|error| {
                    RuntimeMemoryProjectionApiError::new(
                        "runtime_memory_projection_validation_invalid",
                        format!("{error:?}"),
                    )
                })?;
            let mut value =
                serde_json::to_value(record).unwrap_or_else(|_| Value::Object(Map::new()));
            insert_context_fields(&mut value, request);
            Ok(value)
        }
        _ => Err(RuntimeMemoryProjectionApiError::new(
            "runtime_memory_projection_kind_invalid",
            format!("unsupported runtime memory projection kind {projection_kind}"),
        )),
    }
}

fn reject_projection_candidate_transport(
    request: &RuntimeMemoryProjectionApiRequest,
) -> Result<(), RuntimeMemoryProjectionApiError> {
    let has_candidate_projection = match &request.projection {
        Value::Null => false,
        Value::Object(object) => !object.is_empty(),
        Value::Array(items) => !items.is_empty(),
        _ => true,
    };
    if has_candidate_projection {
        return Err(RuntimeMemoryProjectionApiError::new(
            "runtime_memory_projection_candidate_transport_retired",
            "runtime memory projection rejects JS-supplied projection candidates; provide state_dir for Agentgres replay",
        ));
    }
    Ok(())
}

fn normalized_projection_kind(
    request: &RuntimeMemoryProjectionApiRequest,
) -> Result<String, RuntimeMemoryProjectionApiError> {
    if let Some(value) = optional_trimmed_lower(request.projection_kind.as_deref()) {
        return Ok(value);
    }
    let operation_kind = optional_trimmed(request.operation_kind.as_deref()).unwrap_or_default();
    if let Some(last) = operation_kind.split('.').next_back() {
        if !last.is_empty() {
            return Ok(last.to_string());
        }
    }
    Err(RuntimeMemoryProjectionApiError::new(
        "runtime_memory_projection_kind_required",
        "runtime memory projection kind is required",
    ))
}

fn memory_projection_from_state_dir(
    request: &RuntimeMemoryProjectionApiRequest,
) -> Result<Value, RuntimeMemoryProjectionApiError> {
    let state_dir = optional_trimmed(request.state_dir.as_deref()).ok_or_else(|| {
        RuntimeMemoryProjectionApiError::new(
            "runtime_memory_projection_state_dir_required",
            "runtime memory projection requires runtime state_dir for Agentgres memory replay",
        )
    })?;
    let state_root = Path::new(&state_dir);
    let thread_id = optional_trimmed(request.thread_id.as_deref());
    let agent_id = optional_trimmed(request.agent_id.as_deref());
    let workspace_root = optional_trimmed(request.workspace_root.as_deref());
    let filters = MemoryProjectionFilters::from_value(&request.filters);
    let mut records = load_memory_records(state_root)?
        .into_iter()
        .filter(|record| canonical_memory_record(record))
        .filter(|record| memory_record_is_active(record))
        .filter(|record| {
            memory_record_matches_context(record, &thread_id, &agent_id, &workspace_root)
        })
        .filter(|record| filters.matches_record(record))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| memory_record_sort_key(left).cmp(&memory_record_sort_key(right)));
    if let Some(limit) = filters.limit {
        records.truncate(limit);
    }
    if filters.redaction.as_deref() == Some("redacted") {
        records = records.into_iter().map(redact_memory_record).collect();
    }

    let policies = load_memory_policies(state_root)?;
    let policy = effective_memory_policy(
        &policies,
        thread_id.as_deref(),
        agent_id.as_deref(),
        workspace_root.as_deref(),
    );
    let paths = memory_path_projection(
        state_root,
        thread_id.as_deref(),
        agent_id.as_deref(),
        workspace_root.as_deref(),
    );
    let total_matches = records.len();

    Ok(json!({
        "schema_version": AGENT_MEMORY_SCHEMA_VERSION,
        "object": "ioi.agent_memory_projection",
        "thread_id": thread_id,
        "agent_id": agent_id,
        "workspace": workspace_root,
        "policy": policy,
        "paths": paths,
        "filters": filters.to_value(),
        "records": records,
        "total_matches": total_matches,
        "state_dir_replay_required": true,
        "evidence_refs": [
            "runtime_memory_projection_state_dir_replay",
            "agentgres_thread_memory_projection_truth_required"
        ],
    }))
}

fn insert_context_fields(value: &mut Value, request: &RuntimeMemoryProjectionApiRequest) {
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

#[derive(Debug, Clone, Default)]
struct MemoryProjectionFilters {
    scope: Option<String>,
    memory_key: Option<String>,
    query: Option<String>,
    limit: Option<usize>,
    redaction: Option<String>,
}

impl MemoryProjectionFilters {
    fn from_value(value: &Value) -> Self {
        let object = value.as_object();
        let limit = object
            .and_then(|object| object.get("limit"))
            .and_then(numeric_json_value)
            .filter(|limit| *limit > 0)
            .map(|limit| limit.min(200) as usize);
        Self {
            scope: optional_json_string(object, "scope"),
            memory_key: optional_json_string(object, "memory_key"),
            query: optional_json_string(object, "query").map(|value| value.to_ascii_lowercase()),
            limit,
            redaction: optional_json_string(object, "redaction")
                .filter(|value| value == "redacted")
                .or_else(|| Some("none".to_string())),
        }
    }

    fn matches_record(&self, record: &Value) -> bool {
        if self
            .scope
            .as_deref()
            .is_some_and(|scope| memory_json_string(record, "scope").as_deref() != Some(scope))
        {
            return false;
        }
        if self.memory_key.as_deref().is_some_and(|memory_key| {
            memory_json_string(record, "memory_key").as_deref() != Some(memory_key)
        }) {
            return false;
        }
        if let Some(query) = self.query.as_deref() {
            return memory_record_search_text(record).contains(query);
        }
        true
    }

    fn to_value(&self) -> Value {
        json!({
            "scope": self.scope,
            "memory_key": self.memory_key,
            "query": self.query,
            "limit": self.limit,
            "redaction": self.redaction.as_deref().unwrap_or("none"),
        })
    }
}

fn load_memory_records(state_root: &Path) -> Result<Vec<Value>, RuntimeMemoryProjectionApiError> {
    load_memory_state_dir_records(state_root.join("memory-records"), "memory records")
}

fn load_memory_policies(state_root: &Path) -> Result<Vec<Value>, RuntimeMemoryProjectionApiError> {
    load_memory_state_dir_records(state_root.join("memory-policies"), "memory policies").map(
        |records| {
            records
                .into_iter()
                .filter(canonical_memory_policy)
                .collect()
        },
    )
}

fn load_memory_state_dir_records(
    dir: PathBuf,
    label: &str,
) -> Result<Vec<Value>, RuntimeMemoryProjectionApiError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(&dir).map_err(|error| {
        RuntimeMemoryProjectionApiError::new(
            "runtime_memory_projection_replay_read_failed",
            format!("runtime memory projection could not read Agentgres {label}: {error}"),
        )
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            RuntimeMemoryProjectionApiError::new(
                "runtime_memory_projection_replay_read_failed",
                format!(
                    "runtime memory projection could not inspect Agentgres {label} entry: {error}"
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
            RuntimeMemoryProjectionApiError::new(
                "runtime_memory_projection_replay_read_failed",
                format!(
                    "runtime memory projection could not read Agentgres {label} record {}: {error}",
                    path.display()
                ),
            )
        })?;
        let record = serde_json::from_str(&contents).map_err(|error| {
            RuntimeMemoryProjectionApiError::new(
                "runtime_memory_projection_replay_record_invalid",
                format!(
                    "runtime memory projection found invalid Agentgres {label} record {}: {error}",
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
        && memory_json_string(record, "schema_version").as_deref()
            == Some(AGENT_MEMORY_SCHEMA_VERSION)
        && memory_json_string(record, "object").as_deref() == Some("ioi.agent_memory_record")
        && memory_json_string(record, "id").is_some()
}

fn canonical_memory_policy(record: &Value) -> bool {
    record.as_object().is_some()
        && memory_json_string(record, "schema_version").as_deref()
            == Some(AGENT_MEMORY_POLICY_SCHEMA_VERSION)
        && memory_json_string(record, "object").as_deref() == Some("ioi.agent_memory_policy")
        && memory_json_string(record, "id").is_some()
}

fn memory_record_is_active(record: &Value) -> bool {
    memory_json_string(record, "status").as_deref() != Some("deleted")
        && memory_json_string(record, "deleted_at").is_none()
}

fn memory_record_matches_context(
    record: &Value,
    thread_id: &Option<String>,
    agent_id: &Option<String>,
    workspace_root: &Option<String>,
) -> bool {
    if memory_json_string(record, "scope").as_deref() == Some("global") {
        return true;
    }
    if thread_id.as_deref().is_some_and(|thread_id| {
        memory_json_string(record, "thread_id").as_deref() == Some(thread_id)
    }) {
        return true;
    }
    if agent_id.as_deref().is_some_and(|agent_id| {
        memory_json_string(record, "agent_id").as_deref() == Some(agent_id)
            && memory_json_string(record, "scope").as_deref() != Some("thread")
    }) {
        return true;
    }
    if workspace_root.as_deref().is_some_and(|workspace_root| {
        memory_json_string(record, "workspace").as_deref() == Some(workspace_root)
            && memory_json_string(record, "scope").as_deref() == Some("workspace")
    }) {
        return true;
    }
    thread_id.is_none() && agent_id.is_none() && workspace_root.is_none()
}

fn effective_memory_policy(
    policies: &[Value],
    thread_id: Option<&str>,
    agent_id: Option<&str>,
    workspace_root: Option<&str>,
) -> Value {
    let target_id = thread_id.or(agent_id).unwrap_or("runtime");
    let mut policy = default_memory_policy(thread_id, agent_id, workspace_root);
    let mut policy_refs = Vec::new();
    if let Some(agent_id) = agent_id {
        let id = policy_id("agent", agent_id);
        if let Some(agent_policy) = policies
            .iter()
            .find(|policy| memory_json_string(policy, "id").as_deref() == Some(id.as_str()))
        {
            merge_policy_fields(&mut policy, agent_policy);
            policy_refs.push(id);
        }
    }
    if let Some(thread_id) = thread_id {
        let id = policy_id("thread", thread_id);
        if let Some(thread_policy) = policies
            .iter()
            .find(|policy| memory_json_string(policy, "id").as_deref() == Some(id.as_str()))
        {
            merge_policy_fields(&mut policy, thread_policy);
            policy_refs.push(id);
        }
    }
    if let Some(object) = policy.as_object_mut() {
        object.insert("id".to_string(), json!(policy_id("thread", target_id)));
        object.insert("target_type".to_string(), json!("thread"));
        object.insert("target_id".to_string(), json!(target_id));
        object.insert("agent_id".to_string(), json!(agent_id));
        object.insert("thread_id".to_string(), json!(thread_id));
        object.insert("workspace".to_string(), json!(workspace_root));
        object.insert("effective".to_string(), json!(true));
        object.insert("policy_refs".to_string(), json!(policy_refs));
    }
    policy
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
        "id": policy_id("thread", target_id),
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
        "source": "rust_runtime_memory_projection_default",
        "effective": true,
        "policy_refs": [],
        "evidence_refs": [
            "runtime_memory_projection_state_dir_replay",
            "agentgres_thread_memory_projection_truth_required"
        ],
    })
}

fn merge_policy_fields(target: &mut Value, source: &Value) {
    let Some(target) = target.as_object_mut() else {
        return;
    };
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
        if let Some(value) = source.get(key) {
            target.insert(key.to_string(), value.clone());
        }
    }
}

fn memory_path_projection(
    state_root: &Path,
    thread_id: Option<&str>,
    agent_id: Option<&str>,
    workspace_root: Option<&str>,
) -> Value {
    let target_id = thread_id.or(agent_id).unwrap_or("runtime");
    json!({
        "schema_version": AGENT_MEMORY_SCHEMA_VERSION,
        "object": "ioi.agent_memory_path_projection",
        "thread_id": thread_id,
        "agent_id": agent_id,
        "workspace": workspace_root,
        "records_path": state_root.join("memory-records").to_string_lossy(),
        "policies_path": state_root.join("memory-policies").to_string_lossy(),
        "effective_policy_id": policy_id("thread", target_id),
        "state_dir_replay_required": true,
    })
}

fn redact_memory_record(mut record: Value) -> Value {
    let fact = memory_json_string(&record, "fact").unwrap_or_default();
    if let Some(object) = record.as_object_mut() {
        object.insert("fact".to_string(), json!("[REDACTED]"));
        object.insert("fact_hash".to_string(), json!(stable_memory_hash(&fact)));
        object.insert("redaction".to_string(), json!("redacted"));
    }
    record
}

fn memory_record_sort_key(record: &Value) -> String {
    format!(
        "{}\n{}",
        memory_json_string(record, "created_at").unwrap_or_default(),
        memory_json_string(record, "id").unwrap_or_default()
    )
}

fn memory_record_search_text(record: &Value) -> String {
    [
        "fact",
        "id",
        "scope",
        "memory_key",
        "workflow_graph_id",
        "workflow_node_id",
        "workflow_node_type",
        "source",
    ]
    .iter()
    .filter_map(|key| memory_json_string(record, key))
    .map(|value| value.to_ascii_lowercase())
    .collect::<Vec<_>>()
    .join("\n")
}

fn optional_json_string(object: Option<&Map<String, Value>>, key: &str) -> Option<String> {
    object
        .and_then(|object| object.get(key))
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
                .or_else(|| value.as_i64().map(|number| number.to_string()))
                .or_else(|| value.as_u64().map(|number| number.to_string()))
        })
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn numeric_json_value(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()))
        .or_else(|| {
            value
                .as_f64()
                .filter(|number| *number > 0.0)
                .map(|number| number as u64)
        })
}

fn memory_json_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
                .or_else(|| value.as_i64().map(|number| number.to_string()))
                .or_else(|| value.as_u64().map(|number| number.to_string()))
        })
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn policy_id(target_type: &str, target_id: &str) -> String {
    format!("memory_policy_{target_type}_{}", safe_file_id(target_id))
}

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

fn stable_memory_hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
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
    use std::fs;

    fn base_request(projection_kind: &str, state_dir: &Path) -> RuntimeMemoryProjectionApiRequest {
        RuntimeMemoryProjectionApiRequest {
            operation: Some("runtime_memory_projection".to_string()),
            operation_kind: Some(format!("runtime.memory_projection.{projection_kind}")),
            projection_kind: Some(projection_kind.to_string()),
            thread_id: Some("thread_one".to_string()),
            agent_id: Some("agent_one".to_string()),
            workspace_root: Some("/workspace/project".to_string()),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            filters: json!({"query": "deployment"}),
            ..Default::default()
        }
    }

    fn seed_memory_state(state_dir: &Path) {
        let record_dir = state_dir.join("memory-records");
        let policy_dir = state_dir.join("memory-policies");
        fs::create_dir_all(&record_dir).expect("record dir");
        fs::create_dir_all(&policy_dir).expect("policy dir");
        fs::write(
            record_dir.join("memory_one.json"),
            serde_json::to_string_pretty(&json!({
                "schema_version": AGENT_MEMORY_SCHEMA_VERSION,
                "object": "ioi.agent_memory_record",
                "id": "memory_one",
                "thread_id": "thread_one",
                "agent_id": "agent_one",
                "workspace": "/workspace/project",
                "fact": "Deployment requires Rust-owned memory projection.",
                "scope": "thread",
                "memory_key": "project",
                "status": "active",
                "source": "memory_control",
                "created_at": "2026-06-14T00:00:00.000Z",
                "receipt_refs": ["receipt_memory_one"],
                "evidence_refs": ["runtime_memory_control_rust_owned"]
            }))
            .expect("record json"),
        )
        .expect("write record");
        fs::write(
            record_dir.join("memory_deleted.json"),
            serde_json::to_string_pretty(&json!({
                "schema_version": AGENT_MEMORY_SCHEMA_VERSION,
                "object": "ioi.agent_memory_record",
                "id": "memory_deleted",
                "thread_id": "thread_one",
                "agent_id": "agent_one",
                "workspace": "/workspace/project",
                "fact": "Deleted deployment note.",
                "scope": "thread",
                "status": "deleted",
                "deleted_at": "2026-06-14T00:00:00.000Z",
                "receipt_refs": ["receipt_memory_deleted"]
            }))
            .expect("record json"),
        )
        .expect("write deleted record");
        fs::write(
            record_dir.join("memory_js_authored.json"),
            serde_json::to_string_pretty(&json!({
                "schemaVersion": AGENT_MEMORY_SCHEMA_VERSION,
                "object": "ioi.agent_memory_record",
                "id": "memory_js_authored",
                "threadId": "thread_one",
                "agentId": "agent_one",
                "fact": "Retired JS candidate must not project."
            }))
            .expect("record json"),
        )
        .expect("write retired record");
        fs::write(
            policy_dir.join("memory_policy_thread_thread_one.json"),
            serde_json::to_string_pretty(&json!({
                "schema_version": AGENT_MEMORY_POLICY_SCHEMA_VERSION,
                "object": "ioi.agent_memory_policy",
                "id": "memory_policy_thread_thread_one",
                "target_type": "thread",
                "target_id": "thread_one",
                "thread_id": "thread_one",
                "agent_id": "agent_one",
                "workspace": "/workspace/project",
                "write_requires_approval": true,
                "receipt_refs": ["receipt_policy_thread_one"],
                "evidence_refs": ["runtime_memory_control_rust_owned"]
            }))
            .expect("policy json"),
        )
        .expect("write policy");
    }

    #[test]
    fn rust_projects_runtime_memory_route_family_shapes() {
        let temp = tempfile::tempdir().expect("tempdir");
        seed_memory_state(temp.path());
        let core = RuntimeMemoryProjectionCore;

        let records = core
            .project(&base_request("records", temp.path()))
            .expect("records");
        assert_eq!(records.projection_kind, "records");
        assert_eq!(records.record_count, 1);
        assert_eq!(records.projection["records"][0]["id"], "memory_one");
        assert_eq!(
            records.projection["records"][0]["fact"],
            "Deployment requires Rust-owned memory projection."
        );
        assert_eq!(records.projection["filters"]["query"], "deployment");
        assert_eq!(records.projection["state_dir_replay_required"], true);

        let policy = core
            .project(&base_request("policy", temp.path()))
            .expect("policy");
        assert_eq!(policy.projection["id"], "memory_policy_thread_thread_one");
        assert_eq!(policy.projection["thread_id"], "thread_one");
        assert_eq!(policy.projection["write_requires_approval"], true);
        assert_eq!(policy.record_count, 1);

        let path = core
            .project(&base_request("path", temp.path()))
            .expect("path");
        assert!(path.projection["records_path"]
            .as_str()
            .expect("records path")
            .ends_with("memory-records"));
        assert_eq!(path.projection["workspace"], "/workspace/project");

        let status = core
            .project(&base_request("status", temp.path()))
            .expect("status");
        assert_eq!(
            status.projection["object"],
            "ioi.runtime_memory_manager_status"
        );
        assert_eq!(status.projection["status"], "ready");
        assert_eq!(status.projection["thread_id"], "thread_one");
        assert_eq!(status.projection["record_count"], 1);

        let validation = core
            .project(&base_request("validation", temp.path()))
            .expect("validation");
        assert_eq!(
            validation.projection["object"],
            "ioi.runtime_memory_manager_validation"
        );
        assert_eq!(validation.projection["ok"], true);
        assert_eq!(validation.projection["agent_id"], "agent_one");
    }

    #[test]
    fn rust_shapes_runtime_memory_projection_api_response() {
        let temp = tempfile::tempdir().expect("tempdir");
        seed_memory_state(temp.path());
        let response =
            project_runtime_memory_projection_response(base_request("records", temp.path()))
                .expect("runtime memory projection response");

        assert_eq!(response["source"], "rust_runtime_memory_projection_api");
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

    #[test]
    fn rust_rejects_runtime_memory_projection_candidate_transport() {
        let temp = tempfile::tempdir().expect("tempdir");
        seed_memory_state(temp.path());
        let mut request = base_request("records", temp.path());
        request.projection = json!({"records": [{"id": "memory_js_candidate"}]});

        let error = RuntimeMemoryProjectionCore
            .project(&request)
            .expect_err("candidate projection rejected");
        assert_eq!(
            error.code(),
            "runtime_memory_projection_candidate_transport_retired"
        );
    }

    #[test]
    fn rust_requires_state_dir_for_runtime_memory_projection() {
        let mut request = base_request("records", Path::new("/runtime-state"));
        request.state_dir = None;

        let error = RuntimeMemoryProjectionCore
            .project(&request)
            .expect_err("missing state_dir rejected");
        assert_eq!(error.code(), "runtime_memory_projection_state_dir_required");
    }
}
