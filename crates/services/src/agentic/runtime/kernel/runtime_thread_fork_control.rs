use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const RUNTIME_THREAD_FORK_CONTROL_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-fork-control-request.v1";
pub const RUNTIME_THREAD_FORK_CONTROL_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.thread_fork_control.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeThreadForkControlRequest {
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
    pub state_dir: Option<String>,
    #[serde(default)]
    pub source_thread: Value,
    #[serde(default)]
    pub source_agent: Value,
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
pub struct RuntimeThreadForkCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeThreadForkCommandError {
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
pub struct RuntimeThreadForkControlCore;

#[derive(Debug, Clone)]
pub struct RuntimeThreadForkControlRecord {
    pub operation: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub forked_thread_id: String,
    pub agent_id: String,
    pub event: Value,
    pub agent: Value,
    pub thread: Value,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
}

impl RuntimeThreadForkControlCore {
    pub fn plan(
        &self,
        request: &RuntimeThreadForkControlRequest,
    ) -> Result<RuntimeThreadForkControlRecord, RuntimeThreadForkCommandError> {
        if let Some(schema_version) = optional_trimmed(request.schema_version.as_deref()) {
            if schema_version != RUNTIME_THREAD_FORK_CONTROL_REQUEST_SCHEMA_VERSION {
                return Err(RuntimeThreadForkCommandError::new(
                    "runtime_thread_fork_control_schema_version_invalid",
                    format!(
                        "expected {RUNTIME_THREAD_FORK_CONTROL_REQUEST_SCHEMA_VERSION}, got {schema_version}"
                    ),
                ));
            }
        }

        let operation_kind = optional_trimmed(request.operation_kind.as_deref())
            .unwrap_or_else(|| "thread.fork".to_string());
        if operation_kind != "thread.fork" {
            return Err(RuntimeThreadForkCommandError::new(
                "runtime_thread_fork_control_operation_kind_unsupported",
                format!("{operation_kind} is not a thread fork operation"),
            ));
        }
        let operation =
            optional_trimmed(request.operation.as_deref()).unwrap_or_else(|| "thread_fork".into());
        let thread_id = optional_trimmed(request.thread_id.as_deref()).ok_or_else(|| {
            RuntimeThreadForkCommandError::new(
                "runtime_thread_fork_control_thread_id_required",
                "thread fork requires thread_id",
            )
        })?;
        let event_stream_id =
            optional_trimmed(request.event_stream_id.as_deref()).ok_or_else(|| {
                RuntimeThreadForkCommandError::new(
                    "runtime_thread_fork_control_event_stream_required",
                    "thread fork requires event_stream_id",
                )
            })?;
        reject_retired_candidate_transport(request)?;
        let source_agent =
            thread_fork_agent_from_state_dir(request.state_dir.as_deref(), &thread_id)?;
        let source_agent_value = Value::Object(source_agent.clone());
        let source_agent_id = string_field(&source_agent_value, "id").ok_or_else(|| {
            RuntimeThreadForkCommandError::new(
                "runtime_thread_fork_control_source_agent_id_required",
                "thread fork requires source agent id",
            )
        })?;
        let source_cwd = string_field(&request.request, "workspace_root")
            .or_else(|| string_field(&source_agent_value, "cwd"))
            .ok_or_else(|| {
                RuntimeThreadForkCommandError::new(
                    "runtime_thread_fork_control_workspace_required",
                    "thread fork requires workspace_root or source agent cwd",
                )
            })?;
        let source_runtime =
            string_field(&source_agent_value, "runtime").unwrap_or_else(|| "local".to_string());
        let idempotency_key = string_field(&request.request, "idempotency_key")
            .unwrap_or_else(|| format!("thread:{thread_id}:fork"));
        let created_at = string_field(&request.request, "created_at")
            .or_else(|| string_field(&source_agent_value, "updatedAt"))
            .or_else(|| string_field(&source_agent_value, "createdAt"))
            .unwrap_or_else(|| "rust_policy_core".to_string());
        let fork_hash = short_hash(format!(
            "{thread_id}:{source_agent_id}:{idempotency_key}:{created_at}"
        ));
        let agent_id = format!("agent_fork_{fork_hash}");
        let forked_thread_id = format!("thread_fork_{fork_hash}");
        let receipt_refs = thread_fork_receipt_refs(request, &fork_hash);
        let policy_decision_refs = thread_fork_policy_decision_refs(request, &fork_hash);
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_thread_fork_control_rust_owned".to_string(),
                "runtime_thread_fork_event_rust_owned".to_string(),
                "agentgres_thread_fork_state_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };

        let mut agent = source_agent;
        agent.insert("id".to_string(), Value::String(agent_id.clone()));
        agent.insert("status".to_string(), Value::String("active".to_string()));
        agent.insert("runtime".to_string(), Value::String(source_runtime));
        agent.insert("cwd".to_string(), Value::String(source_cwd.clone()));
        agent.insert("createdAt".to_string(), Value::String(created_at.clone()));
        agent.insert("updatedAt".to_string(), Value::String(created_at.clone()));
        agent.insert(
            "parentThreadId".to_string(),
            Value::String(thread_id.clone()),
        );
        agent.insert(
            "forkedFromThreadId".to_string(),
            Value::String(thread_id.clone()),
        );
        agent.insert(
            "forkedFromAgentId".to_string(),
            Value::String(source_agent_id.clone()),
        );
        if !agent.contains_key("runtimeControls") {
            agent.insert("runtimeControls".to_string(), json!({}));
        }
        let mut options =
            object_map(agent.get("options").unwrap_or(&Value::Null)).unwrap_or_else(Map::new);
        options.insert(
            "forked_from_thread_id".to_string(),
            Value::String(thread_id.clone()),
        );
        options.insert(
            "forked_from_agent_id".to_string(),
            Value::String(source_agent_id.clone()),
        );
        agent.insert("options".to_string(), Value::Object(options));

        let thread = json!({
            "schema_version": "ioi.runtime.thread.v1",
            "thread_id": forked_thread_id,
            "agent_id": agent_id,
            "event_stream_id": format!("{forked_thread_id}:events"),
            "status": "active",
            "created_at": created_at,
            "updated_at": created_at,
            "parent_thread_id": thread_id,
            "source_agent_id": source_agent_id,
        });
        let event = json!({
            "event_id": string_field(&request.request, "event_id")
                .unwrap_or_else(|| format!("event_thread_fork_{fork_hash}")),
            "event_stream_id": event_stream_id,
            "thread_id": thread_id,
            "turn_id": string_field(&request.request, "turn_id").unwrap_or_default(),
            "item_id": format!("{thread_id}:item:thread_fork:{fork_hash}"),
            "idempotency_key": idempotency_key,
            "source": string_field(&request.request, "source").unwrap_or_else(|| "hypervisor_session".to_string()),
            "source_event_kind": "OperatorControl.ThreadFork",
            "event_kind": "thread.forked",
            "status": "planned",
            "actor": "operator",
            "workspace_root": source_cwd,
            "component_kind": "thread_fork_control",
            "payload_schema_version": "ioi.runtime.thread-fork-control.v1",
            "payload": {
                "operation": operation,
                "source_thread_id": thread_id,
                "source_agent_id": source_agent_id,
                "forked_thread_id": forked_thread_id,
                "forked_agent_id": agent_id,
                "reason": string_field(&request.request, "reason"),
                "requested_by": string_field(&request.request, "requested_by").unwrap_or_else(|| "operator".to_string()),
                "workflow_graph_id": string_field(&request.request, "workflow_graph_id"),
                "workflow_node_id": string_field(&request.request, "workflow_node_id"),
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

        Ok(RuntimeThreadForkControlRecord {
            operation,
            operation_kind,
            thread_id,
            forked_thread_id,
            agent_id,
            event,
            agent: Value::Object(agent),
            thread,
            receipt_refs,
            policy_decision_refs,
            evidence_refs,
        })
    }
}

fn reject_retired_candidate_transport(
    request: &RuntimeThreadForkControlRequest,
) -> Result<(), RuntimeThreadForkCommandError> {
    if !request.source_agent.is_null() || !request.source_thread.is_null() {
        return Err(RuntimeThreadForkCommandError::new(
            "runtime_thread_fork_control_candidate_transport_retired",
            "thread fork source_agent/source_thread candidate transport is retired; provide state_dir for Agentgres replay",
        ));
    }
    if object_map(&request.request).is_some_and(|body| {
        body.contains_key("source_agent")
            || body.contains_key("sourceAgent")
            || body.contains_key("source_thread")
            || body.contains_key("sourceThread")
    }) {
        return Err(RuntimeThreadForkCommandError::new(
            "runtime_thread_fork_control_candidate_transport_retired",
            "thread fork request candidate transport is retired; provide state_dir for Agentgres replay",
        ));
    }
    Ok(())
}

fn thread_fork_agent_from_state_dir(
    state_dir: Option<&str>,
    thread_id: &str,
) -> Result<Map<String, Value>, RuntimeThreadForkCommandError> {
    let state_root = optional_trimmed(state_dir).ok_or_else(|| {
        RuntimeThreadForkCommandError::new(
            "runtime_thread_fork_control_state_dir_required",
            "thread fork requires Agentgres state_dir replay",
        )
    })?;
    let agents_dir = PathBuf::from(state_root).join("agents");
    let mut candidate_ids = vec![agent_id_for_thread(thread_id), thread_id.to_string()];
    candidate_ids.dedup();

    for candidate_id in &candidate_ids {
        let path = agents_dir.join(format!("{}.json", safe_component(candidate_id)));
        if path.exists() {
            let record = read_thread_fork_agent_record(&path)?;
            if thread_fork_agent_matches_thread(&record, thread_id) {
                return Ok(record);
            }
        }
    }

    if agents_dir.exists() {
        let entries = fs::read_dir(&agents_dir).map_err(|error| {
            RuntimeThreadForkCommandError::new(
                "runtime_thread_fork_control_state_dir_read_failed",
                format!("could not inspect Agentgres agents directory: {error}"),
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                RuntimeThreadForkCommandError::new(
                    "runtime_thread_fork_control_state_dir_read_failed",
                    format!("could not inspect Agentgres agent entry: {error}"),
                )
            })?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let record = read_thread_fork_agent_record(&path)?;
            if thread_fork_agent_matches_thread(&record, thread_id) {
                return Ok(record);
            }
        }
    }

    Err(RuntimeThreadForkCommandError::new(
        "runtime_thread_fork_control_agent_replay_required",
        format!("thread fork requires replayed Agentgres source agent for {thread_id}"),
    ))
}

fn read_thread_fork_agent_record(
    path: &Path,
) -> Result<Map<String, Value>, RuntimeThreadForkCommandError> {
    let body = fs::read_to_string(path).map_err(|error| {
        RuntimeThreadForkCommandError::new(
            "runtime_thread_fork_control_state_dir_read_failed",
            format!(
                "could not read Agentgres agent record {}: {error}",
                path.display()
            ),
        )
    })?;
    let value: Value = serde_json::from_str(&body).map_err(|error| {
        RuntimeThreadForkCommandError::new(
            "runtime_thread_fork_control_state_dir_record_invalid",
            format!("invalid Agentgres agent record {}: {error}", path.display()),
        )
    })?;
    object_map(&value).ok_or_else(|| {
        RuntimeThreadForkCommandError::new(
            "runtime_thread_fork_control_state_dir_record_invalid",
            format!("Agentgres agent record {} is not an object", path.display()),
        )
    })
}

fn thread_fork_agent_matches_thread(agent: &Map<String, Value>, thread_id: &str) -> bool {
    let value = Value::Object(agent.clone());
    let expected_agent_id = agent_id_for_thread(thread_id);
    string_field(&value, "id").as_deref() == Some(expected_agent_id.as_str())
        || string_field(&value, "thread_id").as_deref() == Some(thread_id)
        || json_path_string(&value, &["thread", "thread_id"]).as_deref() == Some(thread_id)
}

fn agent_id_for_thread(thread_id: &str) -> String {
    thread_id
        .strip_prefix("thread_")
        .map(|suffix| format!("agent_{suffix}"))
        .unwrap_or_else(|| thread_id.to_string())
}

fn thread_fork_receipt_refs(
    request: &RuntimeThreadForkControlRequest,
    fork_hash: &str,
) -> Vec<String> {
    unique_strings(
        request
            .receipt_refs
            .clone()
            .into_iter()
            .chain(string_array_field(&request.request, "receipt_refs"))
            .chain(std::iter::once(format!(
                "receipt_thread_fork_control_{fork_hash}"
            )))
            .collect(),
    )
}

fn thread_fork_policy_decision_refs(
    request: &RuntimeThreadForkControlRequest,
    fork_hash: &str,
) -> Vec<String> {
    unique_strings(
        request
            .policy_decision_refs
            .clone()
            .into_iter()
            .chain(string_array_field(&request.request, "policy_decision_refs"))
            .chain(std::iter::once(format!(
                "policy_thread_fork_control_allow_{fork_hash}"
            )))
            .collect(),
    )
}

fn object_map(value: &Value) -> Option<Map<String, Value>> {
    value.as_object().cloned()
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn json_path_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current
        .as_str()
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

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn short_hash(value: String) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(digest)[..12].to_string()
}

fn safe_component(value: &str) -> String {
    let safe = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if safe.is_empty() {
        "runtime".to_string()
    } else {
        safe
    }
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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_thread_fork_state_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let state_dir = std::env::temp_dir().join(format!(
            "ioi_runtime_thread_fork_{label}_{}_{}",
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(state_dir.join("agents")).expect("create temp agents dir");
        state_dir
    }

    fn seed_source_agent(state_dir: &Path) {
        fs::write(
            state_dir.join("agents").join("agent_source.json"),
            serde_json::to_vec_pretty(&json!({
                "id": "agent_source",
                "status": "active",
                "runtime": "local",
                "cwd": "/workspace/source",
                "createdAt": "2026-06-12T11:00:00.000Z",
                "updatedAt": "2026-06-12T11:59:00.000Z",
                "runtimeControls": {
                    "mode": "agent",
                    "model": { "selected_model": "model.local" }
                },
                "modelId": "model.local"
            }))
            .expect("serialize source agent"),
        )
        .expect("seed source agent");
    }

    fn control_request() -> RuntimeThreadForkControlRequest {
        let state_dir = temp_thread_fork_state_dir("control");
        seed_source_agent(&state_dir);
        RuntimeThreadForkControlRequest {
            schema_version: Some(RUNTIME_THREAD_FORK_CONTROL_REQUEST_SCHEMA_VERSION.to_string()),
            operation: Some("thread_fork".to_string()),
            operation_kind: Some("thread.fork".to_string()),
            thread_id: Some("thread_source".to_string()),
            event_stream_id: Some("thread_source:events".to_string()),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            source_thread: Value::Null,
            source_agent: Value::Null,
            request: json!({
                "idempotency_key": "fork-key",
                "source": "hypervisor_session",
                "requested_by": "operator",
                "reason": "branch investigation",
                "workflow_graph_id": "graph",
                "workflow_node_id": "node.fork",
                "created_at": "2026-06-12T12:00:00.000Z",
                "receipt_refs": ["receipt_request"],
                "policy_decision_refs": ["policy_request"]
            }),
            receipt_refs: vec![],
            policy_decision_refs: vec![],
            evidence_refs: vec![],
        }
    }

    #[test]
    fn rust_plans_thread_fork_agent_thread_and_event() {
        let record = RuntimeThreadForkControlCore
            .plan(&control_request())
            .expect("fork should plan");

        assert_eq!(record.operation_kind, "thread.fork");
        assert_eq!(record.thread_id, "thread_source");
        assert_eq!(record.event["event_kind"], "thread.forked");
        assert_eq!(
            record.event["source_event_kind"],
            "OperatorControl.ThreadFork"
        );
        assert_eq!(record.event["payload"]["source_thread_id"], "thread_source");
        assert_eq!(
            record.event["payload"]["forked_thread_id"],
            record.forked_thread_id
        );
        assert_eq!(record.agent["id"], record.agent_id);
        assert_eq!(record.agent["forkedFromThreadId"], "thread_source");
        assert_eq!(record.thread["thread_id"], record.forked_thread_id);
        assert_eq!(record.thread["agent_id"], record.agent_id);
        assert_eq!(record.event["receipt_refs"][0], "receipt_request");
        assert!(record
            .evidence_refs
            .contains(&"runtime_thread_fork_control_rust_owned".to_string()));
    }

    #[test]
    fn rust_ignores_retired_thread_fork_idempotency_alias() {
        let mut request = control_request();
        request.request = json!({
            "idempotencyKey": "retired-key",
            "created_at": "2026-06-12T12:00:00.000Z"
        });
        let record = RuntimeThreadForkControlCore
            .plan(&request)
            .expect("optional retired idempotency alias should be ignored");
        assert_ne!(record.event["idempotency_key"], "retired-key");
    }

    #[test]
    fn rust_rejects_invalid_thread_fork_schema() {
        let mut request = control_request();
        request.schema_version = Some("legacy.thread-fork".to_string());
        let error = RuntimeThreadForkControlCore
            .plan(&request)
            .expect_err("schema mismatch should fail");
        assert_eq!(
            error.code(),
            "runtime_thread_fork_control_schema_version_invalid"
        );
    }

    #[test]
    fn rust_rejects_thread_fork_candidate_transport() {
        let mut request = control_request();
        request.source_thread = json!({ "thread_id": "thread_source" });
        let error = RuntimeThreadForkControlCore
            .plan(&request)
            .expect_err("source candidate transport should fail");
        assert_eq!(
            error.code(),
            "runtime_thread_fork_control_candidate_transport_retired"
        );
    }

    #[test]
    fn rust_requires_state_dir_for_thread_fork_replay() {
        let mut request = control_request();
        request.state_dir = None;
        let error = RuntimeThreadForkControlCore
            .plan(&request)
            .expect_err("state_dir should be required");
        assert_eq!(
            error.code(),
            "runtime_thread_fork_control_state_dir_required"
        );
    }

    #[test]
    fn rust_requires_replayed_source_agent_for_thread_fork() {
        let mut request = control_request();
        let state_dir = temp_thread_fork_state_dir("missing-agent");
        request.state_dir = Some(state_dir.to_string_lossy().to_string());
        let error = RuntimeThreadForkControlCore
            .plan(&request)
            .expect_err("source agent replay should be required");
        assert_eq!(
            error.code(),
            "runtime_thread_fork_control_agent_replay_required"
        );
    }
}
