use serde::Deserialize;
use serde_json::{json, Value};

pub const RUNTIME_LIFECYCLE_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.lifecycle-projection-request.v1";
pub const RUNTIME_LIFECYCLE_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.lifecycle-projection.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeLifecycleProjectionBridgeRequest {
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
    pub turn_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub artifact_ref: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub agents: Vec<Value>,
    #[serde(default)]
    pub agent: Option<Value>,
    #[serde(default)]
    pub threads: Vec<Value>,
    #[serde(default)]
    pub thread: Option<Value>,
    #[serde(default)]
    pub runs: Vec<Value>,
    #[serde(default)]
    pub run: Option<Value>,
    #[serde(default)]
    pub turns: Vec<Value>,
    #[serde(default)]
    pub turn: Option<Value>,
    #[serde(default)]
    pub events: Vec<Value>,
    #[serde(default)]
    pub replay: Vec<Value>,
    #[serde(default)]
    pub usage: Option<Value>,
    #[serde(default)]
    pub conversation: Vec<Value>,
    #[serde(default)]
    pub trace: Option<Value>,
    #[serde(default)]
    pub computer_use_trace: Option<Value>,
    #[serde(default)]
    pub computer_use_trajectory: Option<Value>,
    #[serde(default)]
    pub scorecard: Option<Value>,
    #[serde(default)]
    pub artifacts: Vec<Value>,
    #[serde(default)]
    pub artifact: Option<Value>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLifecycleProjectionCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeLifecycleProjectionCommandError {
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
pub struct RuntimeLifecycleProjectionCore;

#[derive(Debug, Clone)]
pub struct RuntimeLifecycleProjectionRecord {
    pub operation: String,
    pub operation_kind: String,
    pub projection_kind: String,
    pub agent_id: Option<String>,
    pub thread_id: Option<String>,
    pub turn_id: Option<String>,
    pub run_id: Option<String>,
    pub artifact_ref: Option<String>,
    pub workspace_root: Option<String>,
    pub source: String,
    pub projection: Value,
    pub record_count: usize,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
}

pub fn project_runtime_lifecycle_response(
    request: RuntimeLifecycleProjectionBridgeRequest,
) -> Result<Value, RuntimeLifecycleProjectionCommandError> {
    let record = RuntimeLifecycleProjectionCore::default().project(request)?;
    Ok(json!({
        "source": "rust_runtime_lifecycle_projection_command",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RuntimeLifecycleProjectionCore {
    pub fn project(
        &self,
        request: RuntimeLifecycleProjectionBridgeRequest,
    ) -> Result<RuntimeLifecycleProjectionRecord, RuntimeLifecycleProjectionCommandError> {
        let projection_kind = normalized_projection_kind(&request)?;
        let operation_kind = request
            .operation_kind
            .clone()
            .unwrap_or_else(|| format!("runtime.lifecycle_projection.{projection_kind}"));
        let operation = request
            .operation
            .clone()
            .unwrap_or_else(|| "runtime_lifecycle_projection".to_string());
        let source = optional_trimmed(request.source.as_deref())
            .unwrap_or_else(|| "rust_runtime_lifecycle_projection_command".to_string());
        let projection = projection_for_kind(&projection_kind, &request)?;
        let record_count = match &projection {
            Value::Array(items) => items.len(),
            Value::Null => 0,
            _ => 1,
        };
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_lifecycle_rust_projection".to_string(),
                "agentgres_runtime_lifecycle_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };

        Ok(RuntimeLifecycleProjectionRecord {
            operation,
            operation_kind,
            projection_kind: projection_kind.clone(),
            agent_id: optional_trimmed(request.agent_id.as_deref()),
            thread_id: optional_trimmed(request.thread_id.as_deref()),
            turn_id: optional_trimmed(request.turn_id.as_deref()),
            run_id: optional_trimmed(request.run_id.as_deref()),
            artifact_ref: optional_trimmed(request.artifact_ref.as_deref()),
            workspace_root: optional_trimmed(request.workspace_root.as_deref()),
            source,
            projection,
            record_count,
            evidence_refs,
            receipt_refs: vec![format!(
                "receipt_runtime_lifecycle_projection_{projection_kind}"
            )],
        })
    }
}

impl RuntimeLifecycleProjectionRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": RUNTIME_LIFECYCLE_PROJECTION_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_lifecycle_projection",
            "status": "projected",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "projection_kind": self.projection_kind,
            "agent_id": self.agent_id,
            "thread_id": self.thread_id,
            "turn_id": self.turn_id,
            "run_id": self.run_id,
            "artifact_ref": self.artifact_ref,
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
    request: &RuntimeLifecycleProjectionBridgeRequest,
) -> Result<Value, RuntimeLifecycleProjectionCommandError> {
    match projection_kind {
        "agents" => Ok(Value::Array(sort_records(request.agents.clone()))),
        "agent" => Ok(request
            .agent
            .clone()
            .or_else(|| {
                find_by_id(
                    &request.agents,
                    &["id", "agent_id"],
                    request.agent_id.as_deref(),
                )
            })
            .unwrap_or(Value::Null)),
        "threads" => Ok(Value::Array(sort_records(request.threads.clone()))),
        "thread" => Ok(request
            .thread
            .clone()
            .or_else(|| {
                find_by_id(
                    &request.threads,
                    &["thread_id", "id"],
                    request.thread_id.as_deref(),
                )
            })
            .unwrap_or(Value::Null)),
        "thread_usage" => Ok(request.usage.clone().unwrap_or(Value::Null)),
        "thread_turns" => Ok(Value::Array(sort_records(request.turns.clone()))),
        "thread_turn" => Ok(request
            .turn
            .clone()
            .or_else(|| {
                find_by_id(
                    &request.turns,
                    &["turn_id", "id"],
                    request.turn_id.as_deref(),
                )
            })
            .unwrap_or(Value::Null)),
        "thread_events" => Ok(Value::Array(sort_event_records(request.events.clone()))),
        "runs" => Ok(Value::Array(sort_records(request.runs.clone()))),
        "agent_runs" => Ok(Value::Array(sort_records(filter_runs_for_agent(
            request.runs.clone(),
            request.agent_id.as_deref(),
        )))),
        "run" | "run_wait" => Ok(request
            .run
            .clone()
            .or_else(|| find_by_id(&request.runs, &["id", "run_id"], request.run_id.as_deref()))
            .unwrap_or(Value::Null)),
        "run_conversation" => Ok(Value::Array(request.conversation.clone())),
        "run_usage" => Ok(request.usage.clone().unwrap_or(Value::Null)),
        "run_events" => Ok(Value::Array(sort_event_records(request.events.clone()))),
        "run_replay" => {
            let replay = if request.replay.is_empty() {
                request.events.clone()
            } else {
                request.replay.clone()
            };
            Ok(Value::Array(sort_event_records(replay)))
        }
        "run_trace" => Ok(request
            .trace
            .clone()
            .or_else(|| {
                request
                    .run
                    .as_ref()
                    .and_then(|run| value_field(run, "trace"))
            })
            .unwrap_or(Value::Null)),
        "run_computer_use_trace" => Ok(request
            .computer_use_trace
            .clone()
            .or_else(|| nested_value(request.trace.as_ref(), &["computerUse", "trace"]))
            .or_else(|| nested_value(request.trace.as_ref(), &["computer_use", "trace"]))
            .or_else(|| value_field_from_option(request.trace.as_ref(), "computer_use_trace"))
            .unwrap_or(Value::Null)),
        "run_computer_use_trajectory" => Ok(request
            .computer_use_trajectory
            .clone()
            .or_else(|| nested_value(request.trace.as_ref(), &["computerUse", "trajectory"]))
            .or_else(|| nested_value(request.trace.as_ref(), &["computer_use", "trajectory"]))
            .or_else(|| value_field_from_option(request.trace.as_ref(), "computer_use_trajectory"))
            .unwrap_or(Value::Null)),
        "run_scorecard" => Ok(request
            .scorecard
            .clone()
            .or_else(|| value_field_from_option(request.trace.as_ref(), "scorecard"))
            .unwrap_or(Value::Null)),
        "run_artifacts" => Ok(Value::Array(request.artifacts.clone())),
        "run_artifact" => Ok(request
            .artifact
            .clone()
            .or_else(|| find_run_artifact(&request.artifacts, request.artifact_ref.as_deref()))
            .unwrap_or(Value::Null)),
        _ => Err(RuntimeLifecycleProjectionCommandError::new(
            "runtime_lifecycle_projection_kind_invalid",
            format!("unsupported runtime lifecycle projection kind {projection_kind}"),
        )),
    }
}

fn normalized_projection_kind(
    request: &RuntimeLifecycleProjectionBridgeRequest,
) -> Result<String, RuntimeLifecycleProjectionCommandError> {
    if let Some(value) = optional_trimmed_lower(request.projection_kind.as_deref()) {
        return Ok(value);
    }
    let operation_kind = optional_trimmed(request.operation_kind.as_deref()).unwrap_or_default();
    if let Some(last) = operation_kind.split('.').next_back() {
        if !last.is_empty() {
            return Ok(last.to_string());
        }
    }
    Err(RuntimeLifecycleProjectionCommandError::new(
        "runtime_lifecycle_projection_kind_required",
        "runtime lifecycle projection kind is required",
    ))
}

fn sort_records(mut records: Vec<Value>) -> Vec<Value> {
    records.sort_by(|left, right| {
        record_sort_key(left)
            .unwrap_or_default()
            .cmp(&record_sort_key(right).unwrap_or_default())
    });
    records
}

fn sort_event_records(mut records: Vec<Value>) -> Vec<Value> {
    records.sort_by(|left, right| {
        let left_seq = left.get("seq").and_then(Value::as_i64).unwrap_or(0);
        let right_seq = right.get("seq").and_then(Value::as_i64).unwrap_or(0);
        left_seq.cmp(&right_seq).then_with(|| {
            record_sort_key(left)
                .unwrap_or_default()
                .cmp(&record_sort_key(right).unwrap_or_default())
        })
    });
    records
}

fn filter_runs_for_agent(records: Vec<Value>, agent_id: Option<&str>) -> Vec<Value> {
    let Some(agent_id) = optional_trimmed(agent_id) else {
        return records;
    };
    records
        .into_iter()
        .filter(|record| {
            value_string(record, "agentId")
                .or_else(|| value_string(record, "agent_id"))
                .as_deref()
                == Some(agent_id.as_str())
        })
        .collect()
}

fn find_by_id(records: &[Value], keys: &[&str], id: Option<&str>) -> Option<Value> {
    let id = optional_trimmed(id)?;
    records.iter().find_map(|record| {
        if keys
            .iter()
            .any(|key| value_string(record, key).as_deref() == Some(id.as_str()))
        {
            Some(record.clone())
        } else {
            None
        }
    })
}

fn find_run_artifact(records: &[Value], artifact_ref: Option<&str>) -> Option<Value> {
    let artifact_ref = optional_trimmed(artifact_ref)?;
    let normalized = artifact_ref
        .strip_prefix("artifact:")
        .unwrap_or(&artifact_ref);
    records.iter().find_map(|record| {
        let candidates = [
            value_string(record, "id"),
            value_string(record, "name"),
            value_string(record, "artifactRef"),
            value_string(record, "artifact_ref"),
        ];
        if candidates
            .iter()
            .flatten()
            .any(|candidate| candidate == &artifact_ref || candidate == normalized)
        {
            Some(record.clone())
        } else {
            None
        }
    })
}

fn record_sort_key(record: &Value) -> Option<String> {
    value_string(record, "createdAt")
        .or_else(|| value_string(record, "created_at"))
        .or_else(|| value_string(record, "id"))
        .or_else(|| value_string(record, "agent_id"))
        .or_else(|| value_string(record, "run_id"))
        .or_else(|| value_string(record, "thread_id"))
        .or_else(|| value_string(record, "turn_id"))
}

fn value_field(value: &Value, key: &str) -> Option<Value> {
    value.get(key).cloned().filter(|value| !value.is_null())
}

fn value_field_from_option(value: Option<&Value>, key: &str) -> Option<Value> {
    value.and_then(|value| value_field(value, key))
}

fn nested_value(value: Option<&Value>, path: &[&str]) -> Option<Value> {
    let mut current = value?;
    for key in path {
        current = current.get(*key)?;
    }
    if current.is_null() {
        None
    } else {
        Some(current.clone())
    }
}

fn value_string(value: &Value, key: &str) -> Option<String> {
    optional_trimmed(value.get(key).and_then(Value::as_str))
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

    #[test]
    fn rust_projects_runtime_lifecycle_route_family_shapes() {
        let core = RuntimeLifecycleProjectionCore;
        let base = RuntimeLifecycleProjectionBridgeRequest {
            operation: Some("runtime_lifecycle_projection".to_string()),
            operation_kind: Some("runtime.lifecycle_projection.agent_runs".to_string()),
            projection_kind: Some("agent_runs".to_string()),
            agent_id: Some("agent_one".to_string()),
            run_id: Some("run_one".to_string()),
            artifact_ref: Some("trace.json".to_string()),
            workspace_root: Some("/workspace/project".to_string()),
            agents: vec![
                json!({"id": "agent_two", "createdAt": "2026-01-02T00:00:00Z"}),
                json!({"id": "agent_one", "createdAt": "2026-01-01T00:00:00Z"}),
            ],
            runs: vec![
                json!({"id": "run_two", "agentId": "agent_two", "createdAt": "2026-01-02T00:00:00Z"}),
                json!({
                    "id": "run_one",
                    "agentId": "agent_one",
                    "createdAt": "2026-01-01T00:00:00Z",
                    "conversation": [{"role": "user", "content": "ship it"}],
                    "trace": {
                        "scorecard": {"score": 1},
                        "computerUse": {
                            "trace": {"steps": 1},
                            "trajectory": [{"x": 1}]
                        }
                    },
                    "artifacts": [{"id": "artifact_trace", "name": "trace.json"}]
                }),
            ],
            run: Some(json!({
                "id": "run_one",
                "agentId": "agent_one",
                "conversation": [{"role": "user", "content": "ship it"}],
                "trace": {
                    "scorecard": {"score": 1},
                    "computerUse": {
                        "trace": {"steps": 1},
                        "trajectory": [{"x": 1}]
                    }
                },
                "artifacts": [{"id": "artifact_trace", "name": "trace.json"}]
            })),
            conversation: vec![json!({"role": "user", "content": "ship it"})],
            trace: Some(json!({
                "scorecard": {"score": 1},
                "computerUse": {
                    "trace": {"steps": 1},
                    "trajectory": [{"x": 1}]
                }
            })),
            artifacts: vec![json!({"id": "artifact_trace", "name": "trace.json"})],
            ..Default::default()
        };

        let agent_runs = core.project(base.clone()).expect("agent runs");
        assert_eq!(agent_runs.projection_kind, "agent_runs");
        assert_eq!(agent_runs.record_count, 1);
        assert_eq!(agent_runs.projection[0]["id"], "run_one");

        let mut conversation_request = base.clone();
        conversation_request.projection_kind = Some("run_conversation".to_string());
        conversation_request.operation_kind =
            Some("runtime.lifecycle_projection.run_conversation".to_string());
        let conversation = core
            .project(conversation_request)
            .expect("run conversation projection");
        assert_eq!(conversation.projection[0]["content"], "ship it");

        let mut artifact_request = base.clone();
        artifact_request.projection_kind = Some("run_artifact".to_string());
        artifact_request.operation_kind =
            Some("runtime.lifecycle_projection.run_artifact".to_string());
        let artifact = core.project(artifact_request).expect("run artifact");
        assert_eq!(artifact.projection["id"], "artifact_trace");

        let mut scorecard_request = base;
        scorecard_request.projection_kind = Some("run_scorecard".to_string());
        scorecard_request.operation_kind =
            Some("runtime.lifecycle_projection.run_scorecard".to_string());
        let scorecard = core.project(scorecard_request).expect("scorecard");
        assert_eq!(scorecard.projection["score"], 1);
    }

    #[test]
    fn rust_shapes_runtime_lifecycle_command_response() {
        let response =
            project_runtime_lifecycle_response(RuntimeLifecycleProjectionBridgeRequest {
                operation: Some("runtime_lifecycle_projection".to_string()),
                operation_kind: Some("runtime.lifecycle_projection.agents".to_string()),
                projection_kind: Some("agents".to_string()),
                agents: vec![json!({"id": "agent_one", "createdAt": "2026-01-01T00:00:00Z"})],
                evidence_refs: vec!["runtime_lifecycle_rust_projection".to_string()],
                ..Default::default()
            })
            .expect("runtime lifecycle command response");

        assert_eq!(
            response["source"],
            "rust_runtime_lifecycle_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(
            response["record"]["schema_version"],
            RUNTIME_LIFECYCLE_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(response["record"]["projection_kind"], "agents");
        assert_eq!(response["record"]["projection"][0]["id"], "agent_one");
    }
}
