use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
};

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
    pub state_dir: Option<String>,
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

#[derive(Debug, Clone, Default)]
struct RuntimeLifecycleProjectionSources {
    agents: Vec<Value>,
    runs: Vec<Value>,
    events: Vec<Value>,
}

impl RuntimeLifecycleProjectionCore {
    pub fn project(
        &self,
        request: RuntimeLifecycleProjectionBridgeRequest,
    ) -> Result<RuntimeLifecycleProjectionRecord, RuntimeLifecycleProjectionCommandError> {
        reject_retired_lifecycle_candidate_transport(&request)?;
        let sources = runtime_lifecycle_sources_from_state_dir(request.state_dir.as_deref())?;
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
            .unwrap_or_else(|| "rust_runtime_lifecycle_projection_api".to_string());
        let projection = projection_for_kind(&projection_kind, &request, &sources)?;
        let record_count = match &projection {
            Value::Array(items) => items.len(),
            Value::Null => 0,
            _ => 1,
        };
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_lifecycle_state_dir_replay".to_string(),
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
    sources: &RuntimeLifecycleProjectionSources,
) -> Result<Value, RuntimeLifecycleProjectionCommandError> {
    match projection_kind {
        "agents" => Ok(Value::Array(sort_records(sources.agents.clone()))),
        "agent" => Ok(find_by_id(
            &sources.agents,
            &["id", "agent_id"],
            request.agent_id.as_deref(),
        )
        .unwrap_or(Value::Null)),
        "threads" => Ok(Value::Array(sort_records(thread_records_from_sources(
            sources,
        )))),
        "thread" => Ok(find_by_id(
            &thread_records_from_sources(sources),
            &["thread_id", "id"],
            request.thread_id.as_deref(),
        )
        .unwrap_or(Value::Null)),
        "thread_usage" => Ok(
            thread_usage_from_sources(sources, request.thread_id.as_deref()).unwrap_or(Value::Null),
        ),
        "thread_turns" => Ok(Value::Array(sort_records(thread_turns_from_sources(
            sources,
            request.thread_id.as_deref(),
        )))),
        "thread_turn" => Ok(find_by_id(
            &thread_turns_from_sources(sources, request.thread_id.as_deref()),
            &["turn_id", "id"],
            request.turn_id.as_deref(),
        )
        .unwrap_or(Value::Null)),
        "thread_events" => Ok(Value::Array(sort_event_records(events_for_thread(
            sources,
            request.thread_id.as_deref(),
        )))),
        "runs" => Ok(Value::Array(sort_records(sources.runs.clone()))),
        "agent_runs" => Ok(Value::Array(sort_records(filter_runs_for_agent(
            sources.runs.clone(),
            request.agent_id.as_deref(),
        )))),
        "run" | "run_wait" => {
            Ok(
                find_by_id(&sources.runs, &["id", "run_id"], request.run_id.as_deref())
                    .unwrap_or(Value::Null),
            )
        }
        "run_conversation" => Ok(Value::Array(
            run_for_request(sources, request)
                .and_then(|run| value_array(&run, "conversation"))
                .unwrap_or_default(),
        )),
        "run_usage" => Ok(run_for_request(sources, request)
            .map(|run| run_usage(&run))
            .unwrap_or(Value::Null)),
        "run_events" | "run_replay" => Ok(Value::Array(sort_event_records(events_for_run(
            sources,
            request.run_id.as_deref(),
        )))),
        "run_trace" => Ok(run_for_request(sources, request)
            .and_then(|run| value_field(&run, "trace"))
            .unwrap_or(Value::Null)),
        "run_computer_use_trace" => Ok(run_for_request(sources, request)
            .and_then(|run| value_field(&run, "trace"))
            .and_then(|trace| {
                nested_value(Some(&trace), &["computerUse", "trace"])
                    .or_else(|| nested_value(Some(&trace), &["computer_use", "trace"]))
                    .or_else(|| value_field_from_option(Some(&trace), "computer_use_trace"))
            })
            .unwrap_or(Value::Null)),
        "run_computer_use_trajectory" => Ok(run_for_request(sources, request)
            .and_then(|run| value_field(&run, "trace"))
            .and_then(|trace| {
                nested_value(Some(&trace), &["computerUse", "trajectory"])
                    .or_else(|| nested_value(Some(&trace), &["computer_use", "trajectory"]))
                    .or_else(|| value_field_from_option(Some(&trace), "computer_use_trajectory"))
            })
            .unwrap_or(Value::Null)),
        "run_scorecard" => Ok(run_for_request(sources, request)
            .and_then(|run| value_field(&run, "trace"))
            .and_then(|trace| value_field_from_option(Some(&trace), "scorecard"))
            .unwrap_or(Value::Null)),
        "run_artifacts" => Ok(Value::Array(
            run_for_request(sources, request)
                .and_then(|run| value_array(&run, "artifacts"))
                .unwrap_or_default(),
        )),
        "run_artifact" => Ok(run_for_request(sources, request)
            .and_then(|run| value_array(&run, "artifacts"))
            .and_then(|artifacts| find_run_artifact(&artifacts, request.artifact_ref.as_deref()))
            .unwrap_or(Value::Null)),
        _ => Err(RuntimeLifecycleProjectionCommandError::new(
            "runtime_lifecycle_projection_kind_invalid",
            format!("unsupported runtime lifecycle projection kind {projection_kind}"),
        )),
    }
}

fn reject_retired_lifecycle_candidate_transport(
    request: &RuntimeLifecycleProjectionBridgeRequest,
) -> Result<(), RuntimeLifecycleProjectionCommandError> {
    let retired_field = [
        (!request.agents.is_empty(), "agents"),
        (request.agent.is_some(), "agent"),
        (!request.threads.is_empty(), "threads"),
        (request.thread.is_some(), "thread"),
        (!request.runs.is_empty(), "runs"),
        (request.run.is_some(), "run"),
        (!request.turns.is_empty(), "turns"),
        (request.turn.is_some(), "turn"),
        (!request.events.is_empty(), "events"),
        (!request.replay.is_empty(), "replay"),
        (request.usage.is_some(), "usage"),
        (!request.conversation.is_empty(), "conversation"),
        (request.trace.is_some(), "trace"),
        (request.computer_use_trace.is_some(), "computer_use_trace"),
        (
            request.computer_use_trajectory.is_some(),
            "computer_use_trajectory",
        ),
        (request.scorecard.is_some(), "scorecard"),
        (!request.artifacts.is_empty(), "artifacts"),
        (request.artifact.is_some(), "artifact"),
    ]
    .into_iter()
    .find_map(|(present, field)| present.then_some(field));
    if let Some(field) = retired_field {
        return Err(RuntimeLifecycleProjectionCommandError::new(
            "runtime_lifecycle_projection_retired_candidate_transport",
            format!(
                "runtime lifecycle projection must replay Agentgres state_dir records; retired JS candidate field {field} is not accepted"
            ),
        ));
    }
    Ok(())
}

fn runtime_lifecycle_sources_from_state_dir(
    state_dir: Option<&str>,
) -> Result<RuntimeLifecycleProjectionSources, RuntimeLifecycleProjectionCommandError> {
    let state_dir = optional_trimmed(state_dir).ok_or_else(|| {
        RuntimeLifecycleProjectionCommandError::new(
            "runtime_lifecycle_projection_state_dir_required",
            "runtime lifecycle projection requires Agentgres state_dir replay",
        )
    })?;
    let state_root = Path::new(&state_dir);
    Ok(RuntimeLifecycleProjectionSources {
        agents: read_json_records(state_root, "agents", "agent")?,
        runs: read_json_records(state_root, "runs", "run")?,
        events: read_jsonl_records(state_root, "events", "event")?,
    })
}

fn read_json_records(
    state_root: &Path,
    dir: &str,
    label: &str,
) -> Result<Vec<Value>, RuntimeLifecycleProjectionCommandError> {
    let record_dir = state_root.join(dir);
    if !record_dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths = json_record_paths(&record_dir, "json", label)?;
    paths.sort();
    let mut records = Vec::new();
    for path in paths {
        let contents = fs::read_to_string(&path).map_err(|error| {
            RuntimeLifecycleProjectionCommandError::new(
                "runtime_lifecycle_projection_replay_read_failed",
                format!(
                    "runtime lifecycle projection could not read Agentgres {label} record {}: {error}",
                    path.display()
                ),
            )
        })?;
        let record: Value = serde_json::from_str(&contents).map_err(|error| {
            RuntimeLifecycleProjectionCommandError::new(
                "runtime_lifecycle_projection_replay_record_invalid",
                format!(
                    "runtime lifecycle projection found invalid Agentgres {label} record {}: {error}",
                    path.display()
                ),
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

fn read_jsonl_records(
    state_root: &Path,
    dir: &str,
    label: &str,
) -> Result<Vec<Value>, RuntimeLifecycleProjectionCommandError> {
    let record_dir = state_root.join(dir);
    if !record_dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths = json_record_paths(&record_dir, "jsonl", label)?;
    paths.sort();
    let mut records = Vec::new();
    for path in paths {
        let contents = fs::read_to_string(&path).map_err(|error| {
            RuntimeLifecycleProjectionCommandError::new(
                "runtime_lifecycle_projection_replay_read_failed",
                format!(
                    "runtime lifecycle projection could not read Agentgres {label} stream {}: {error}",
                    path.display()
                ),
            )
        })?;
        for (index, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let record: Value = serde_json::from_str(line).map_err(|error| {
                RuntimeLifecycleProjectionCommandError::new(
                    "runtime_lifecycle_projection_replay_record_invalid",
                    format!(
                        "runtime lifecycle projection found invalid Agentgres {label} record {}:{}: {error}",
                        path.display(),
                        index + 1
                    ),
                )
            })?;
            records.push(record);
        }
    }
    Ok(sort_event_records(records))
}

fn json_record_paths(
    record_dir: &Path,
    extension: &str,
    label: &str,
) -> Result<Vec<PathBuf>, RuntimeLifecycleProjectionCommandError> {
    let entries = fs::read_dir(record_dir).map_err(|error| {
        RuntimeLifecycleProjectionCommandError::new(
            "runtime_lifecycle_projection_replay_read_failed",
            format!(
                "runtime lifecycle projection could not read Agentgres {label} directory {}: {error}",
                record_dir.display()
            ),
        )
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            RuntimeLifecycleProjectionCommandError::new(
                "runtime_lifecycle_projection_replay_read_failed",
                format!(
                    "runtime lifecycle projection could not inspect Agentgres {label} entry: {error}"
                ),
            )
        })?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|value| value.to_str()) == Some(extension) {
            paths.push(path);
        }
    }
    Ok(paths)
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
            value_string_any(record, &["agentId", "agent_id"]).as_deref() == Some(agent_id.as_str())
        })
        .collect()
}

fn run_for_request(
    sources: &RuntimeLifecycleProjectionSources,
    request: &RuntimeLifecycleProjectionBridgeRequest,
) -> Option<Value> {
    find_by_id(&sources.runs, &["id", "run_id"], request.run_id.as_deref())
}

fn thread_records_from_sources(sources: &RuntimeLifecycleProjectionSources) -> Vec<Value> {
    sources
        .agents
        .iter()
        .filter_map(|agent| thread_record_for_agent(agent, sources))
        .collect()
}

fn thread_record_for_agent(
    agent: &Value,
    sources: &RuntimeLifecycleProjectionSources,
) -> Option<Value> {
    let agent_id = agent_id_from_agent(agent)?;
    let thread_id = thread_id_for_agent(&agent_id);
    let runs = filter_runs_for_agent(sources.runs.clone(), Some(&agent_id));
    let latest_run = latest_record(&runs);
    let latest_run_id = latest_run
        .as_ref()
        .and_then(|run| value_string_any(run, &["id", "run_id"]));
    let latest_turn_id = latest_run
        .as_ref()
        .and_then(|run| value_string_any(run, &["runtimeTurnId", "runtime_turn_id", "turn_id"]))
        .or_else(|| latest_run_id.as_deref().map(turn_id_for_run));
    let created_at = value_string_any(agent, &["createdAt", "created_at"]).unwrap_or_default();
    let updated_at = latest_run
        .as_ref()
        .and_then(|run| value_string_any(run, &["updatedAt", "updated_at"]))
        .or_else(|| value_string_any(agent, &["updatedAt", "updated_at"]))
        .unwrap_or_else(|| created_at.clone());
    let workspace_root = value_string_any(agent, &["cwd", "workspace_root"]).unwrap_or_default();
    let latest_seq = events_for_thread(sources, Some(&thread_id))
        .iter()
        .filter_map(event_seq)
        .max()
        .unwrap_or(0);
    let title = latest_run
        .as_ref()
        .and_then(|run| value_string_any(run, &["objective", "title"]))
        .unwrap_or_else(|| workspace_root.clone());
    let runtime_controls = value_field(agent, "runtimeControls")
        .or_else(|| value_field(agent, "runtime_controls"))
        .unwrap_or_else(|| json!({}));
    let usage = thread_usage_for_agent(&thread_id, &agent_id, &runs);
    Some(json!({
        "schema_version": "ioi.runtime.thread.v1",
        "thread_id": thread_id,
        "session_id": value_string_any(agent, &["runtimeSessionId", "runtime_session_id"]).unwrap_or_else(|| agent_id.clone()),
        "agent_id": agent_id,
        "workspace_root": workspace_root,
        "title": title,
        "mode": nested_string(Some(&runtime_controls), &["mode"]).unwrap_or_else(|| "agent".to_string()),
        "approval_mode": nested_string(Some(&runtime_controls), &["approval_mode"]).unwrap_or_else(|| "suggest".to_string()),
        "trust_profile": "local_private",
        "model_route": value_string_any(agent, &["model_route", "model_id", "modelId"]),
        "status": thread_status_for_agent(value_string_any(agent, &["status"]).as_deref()),
        "latest_turn_id": latest_turn_id,
        "latest_seq": latest_seq,
        "event_stream_id": event_stream_id_for_thread(&thread_id),
        "agentgres_projection_ref": format!("agents/{}.json", agent_id),
        "created_at": created_at,
        "updated_at": updated_at,
        "archived_at": if value_string_any(agent, &["status"]).as_deref() == Some("archived") {
            value_string_any(agent, &["updatedAt", "updated_at"])
        } else {
            None
        },
        "workspace": workspace_root,
        "requested_model": value_string_any(agent, &["requestedModelId", "requested_model_id", "model_id"]).unwrap_or_else(|| "auto".to_string()),
        "model_route_id": value_string_any(agent, &["modelRouteId", "model_route_id"]),
        "model_route_receipt_id": value_string_any(agent, &["modelRouteReceiptId", "model_route_receipt_id"]),
        "selected_model": value_string_any(agent, &["modelId", "model_id"]).unwrap_or_else(|| "auto".to_string()),
        "runtime_controls": runtime_controls,
        "memory_count": 0,
        "archived": value_string_any(agent, &["status"]).as_deref() == Some("archived"),
        "evidence_refs": ["agentgres_canonical_state_projection", "rust_runtime_lifecycle_state_dir_replay"],
        "runtime_profile": value_string_any(agent, &["runtimeProfile", "runtime_profile"]).unwrap_or_else(|| "fixture".to_string()),
        "usage": usage,
        "usage_telemetry": usage,
    }))
}

fn thread_turns_from_sources(
    sources: &RuntimeLifecycleProjectionSources,
    thread_id: Option<&str>,
) -> Vec<Value> {
    let normalized_thread_id = optional_trimmed(thread_id);
    sources
        .runs
        .iter()
        .filter(|run| {
            normalized_thread_id
                .as_ref()
                .map(|thread_id| run_thread_id(run).as_deref() == Some(thread_id.as_str()))
                .unwrap_or(true)
        })
        .filter_map(|run| turn_record_for_run(run, sources))
        .collect()
}

fn turn_record_for_run(run: &Value, sources: &RuntimeLifecycleProjectionSources) -> Option<Value> {
    let run_id = value_string_any(run, &["id", "run_id"])?;
    let agent_id = run_agent_id(run)?;
    let thread_id = thread_id_for_agent(&agent_id);
    let turn_id = value_string_any(run, &["runtimeTurnId", "runtime_turn_id", "turn_id"])
        .unwrap_or_else(|| turn_id_for_run(&run_id));
    let events = events_for_run(sources, Some(&run_id));
    let seq_start = events.iter().filter_map(event_seq).min().unwrap_or(0);
    let seq_end = events.iter().filter_map(event_seq).max().unwrap_or(0);
    let status = value_string_any(run, &["turnStatus", "turn_status", "status"])
        .unwrap_or_else(|| "completed".to_string());
    let is_open = matches!(
        status.as_str(),
        "queued" | "running" | "waiting_for_approval" | "waiting_for_input"
    );
    let usage = run_usage(run);
    Some(json!({
        "schema_version": "ioi.runtime.turn.v1",
        "turn_id": turn_id,
        "thread_id": thread_id,
        "parent_turn_id": Value::Null,
        "request_id": run_id,
        "status": status,
        "input_item_ids": event_item_ids(&events, Some("turn.started")),
        "output_item_ids": event_item_ids(&events, None),
        "events": events,
        "seq_start": seq_start,
        "seq_end": seq_end,
        "started_at": value_string_any(run, &["createdAt", "created_at"]),
        "completed_at": if is_open { None } else { value_string_any(run, &["updatedAt", "updated_at"]) },
        "mode": value_string_any(run, &["threadMode", "thread_mode", "mode"]).unwrap_or_else(|| "agent".to_string()),
        "approval_mode": "suggest",
        "model_route_decision_id": value_string_any(run, &["modelRouteDecisionId", "model_route_decision_id"]),
        "usage": usage,
        "usage_telemetry": usage,
        "result": value_string_any(run, &["result"]).unwrap_or_default(),
        "output": value_string_any(run, &["result"]).unwrap_or_default(),
        "text": value_string_any(run, &["result"]).unwrap_or_default(),
    }))
}

fn thread_usage_from_sources(
    sources: &RuntimeLifecycleProjectionSources,
    thread_id: Option<&str>,
) -> Option<Value> {
    let thread_id = optional_trimmed(thread_id)?;
    let agent_id = agent_id_for_thread(&thread_id);
    let runs = filter_runs_for_agent(sources.runs.clone(), Some(&agent_id));
    Some(thread_usage_for_agent(&thread_id, &agent_id, &runs))
}

fn thread_usage_for_agent(thread_id: &str, agent_id: &str, runs: &[Value]) -> Value {
    json!({
        "thread_id": thread_id,
        "agent_id": agent_id,
        "run_count": runs.len(),
        "total_tokens": runs.iter().map(run_total_tokens).sum::<u64>(),
    })
}

fn run_usage(run: &Value) -> Value {
    value_field(run, "usage_telemetry")
        .or_else(|| value_field(run, "usage"))
        .unwrap_or_else(|| {
            json!({
                "run_id": value_string_any(run, &["id", "run_id"]),
                "total_tokens": run_total_tokens(run),
            })
        })
}

fn events_for_thread(
    sources: &RuntimeLifecycleProjectionSources,
    thread_id: Option<&str>,
) -> Vec<Value> {
    let Some(thread_id) = optional_trimmed(thread_id) else {
        return Vec::new();
    };
    let event_stream_id = event_stream_id_for_thread(&thread_id);
    sources
        .events
        .iter()
        .filter(|event| {
            value_string_any(event, &["thread_id"]).as_deref() == Some(thread_id.as_str())
                || value_string_any(event, &["event_stream_id"]).as_deref()
                    == Some(event_stream_id.as_str())
        })
        .cloned()
        .collect()
}

fn events_for_run(sources: &RuntimeLifecycleProjectionSources, run_id: Option<&str>) -> Vec<Value> {
    let Some(run_id) = optional_trimmed(run_id) else {
        return Vec::new();
    };
    let turn_id = turn_id_for_run(&run_id);
    sources
        .events
        .iter()
        .filter(|event| {
            value_string_any(event, &["run_id"]).as_deref() == Some(run_id.as_str())
                || value_string_any(event, &["turn_id"]).as_deref() == Some(turn_id.as_str())
        })
        .cloned()
        .collect()
}

fn event_item_ids(events: &[Value], source_kind: Option<&str>) -> Vec<String> {
    events
        .iter()
        .filter(|event| match source_kind {
            Some(kind) => value_string_any(event, &["event_kind"]).as_deref() == Some(kind),
            None => value_string_any(event, &["event_kind"]).as_deref() != Some("turn.started"),
        })
        .filter_map(|event| value_string_any(event, &["item_id"]))
        .collect()
}

fn latest_record(records: &[Value]) -> Option<Value> {
    records
        .iter()
        .max_by(|left, right| {
            record_sort_key(left)
                .unwrap_or_default()
                .cmp(&record_sort_key(right).unwrap_or_default())
        })
        .cloned()
}

fn run_total_tokens(run: &Value) -> u64 {
    nested_u64(Some(run), &["usage_telemetry", "total_tokens"])
        .or_else(|| nested_u64(Some(run), &["usage", "total_tokens"]))
        .or_else(|| nested_u64(Some(run), &["trace", "usage", "total_tokens"]))
        .unwrap_or(0)
}

fn run_thread_id(run: &Value) -> Option<String> {
    run_agent_id(run).map(|agent_id| thread_id_for_agent(&agent_id))
}

fn agent_id_from_agent(agent: &Value) -> Option<String> {
    value_string_any(agent, &["id", "agent_id"])
}

fn run_agent_id(run: &Value) -> Option<String> {
    value_string_any(run, &["agentId", "agent_id"])
}

fn thread_id_for_agent(agent_id: &str) -> String {
    agent_id
        .strip_prefix("agent_")
        .map(|suffix| format!("thread_{suffix}"))
        .unwrap_or_else(|| format!("thread_{agent_id}"))
}

fn agent_id_for_thread(thread_id: &str) -> String {
    thread_id
        .strip_prefix("thread_")
        .map(|suffix| format!("agent_{suffix}"))
        .unwrap_or_else(|| thread_id.to_string())
}

fn turn_id_for_run(run_id: &str) -> String {
    run_id
        .strip_prefix("run_")
        .map(|suffix| format!("turn_{suffix}"))
        .unwrap_or_else(|| format!("turn_{run_id}"))
}

fn event_stream_id_for_thread(thread_id: &str) -> String {
    format!("{thread_id}:events")
}

fn thread_status_for_agent(status: Option<&str>) -> &'static str {
    match status {
        Some("archived") | Some("closed") => "archived",
        Some("failed") | Some("error") => "failed",
        _ => "active",
    }
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
    value_string_any(
        record,
        &[
            "createdAt",
            "created_at",
            "updatedAt",
            "updated_at",
            "id",
            "agent_id",
            "run_id",
            "thread_id",
            "turn_id",
        ],
    )
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

fn nested_string(value: Option<&Value>, path: &[&str]) -> Option<String> {
    nested_value(value, path).and_then(|value| value.as_str().map(str::to_string))
}

fn nested_u64(value: Option<&Value>, path: &[&str]) -> Option<u64> {
    let mut current = value?;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_u64()
}

fn value_array(value: &Value, key: &str) -> Option<Vec<Value>> {
    value.get(key).and_then(Value::as_array).cloned()
}

fn event_seq(value: &Value) -> Option<u64> {
    value.get("seq").and_then(Value::as_u64)
}

fn value_string(value: &Value, key: &str) -> Option<String> {
    optional_trimmed(value.get(key).and_then(Value::as_str))
}

fn value_string_any(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| value_string(value, key))
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
        let state_dir = write_runtime_lifecycle_state();
        let base = RuntimeLifecycleProjectionBridgeRequest {
            operation: Some("runtime_lifecycle_projection".to_string()),
            operation_kind: Some("runtime.lifecycle_projection.agent_runs".to_string()),
            projection_kind: Some("agent_runs".to_string()),
            agent_id: Some("agent_one".to_string()),
            run_id: Some("run_one".to_string()),
            artifact_ref: Some("trace.json".to_string()),
            workspace_root: Some("/workspace/project".to_string()),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
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

        let mut replay_request = RuntimeLifecycleProjectionBridgeRequest {
            projection_kind: Some("run_replay".to_string()),
            operation_kind: Some("runtime.lifecycle_projection.run_replay".to_string()),
            run_id: Some("run_one".to_string()),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            ..Default::default()
        };
        let replay = core.project(replay_request.clone()).expect("run replay");
        assert_eq!(replay.projection[0]["event_id"], "event_run_one_started");
        replay_request.projection_kind = Some("threads".to_string());
        replay_request.operation_kind = Some("runtime.lifecycle_projection.threads".to_string());
        let threads = core.project(replay_request).expect("threads");
        assert_eq!(threads.projection[0]["thread_id"], "thread_one");
    }

    #[test]
    fn rust_shapes_runtime_lifecycle_direct_record() {
        let state_dir = write_runtime_lifecycle_state();
        let record = RuntimeLifecycleProjectionCore::default()
            .project(RuntimeLifecycleProjectionBridgeRequest {
                operation: Some("runtime_lifecycle_projection".to_string()),
                operation_kind: Some("runtime.lifecycle_projection.agents".to_string()),
                projection_kind: Some("agents".to_string()),
                state_dir: Some(state_dir.to_string_lossy().to_string()),
                evidence_refs: vec!["runtime_lifecycle_rust_projection".to_string()],
                ..Default::default()
            })
            .expect("runtime lifecycle direct record");
        let record = record.to_value();

        assert_eq!(record["source"], "rust_runtime_lifecycle_projection_api");
        assert_eq!(
            record["schema_version"],
            RUNTIME_LIFECYCLE_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record["projection_kind"], "agents");
        assert_eq!(record["projection"][0]["id"], "agent_one");
    }

    #[test]
    fn rust_requires_state_dir_for_runtime_lifecycle_projection() {
        let error = RuntimeLifecycleProjectionCore::default()
            .project(RuntimeLifecycleProjectionBridgeRequest {
                operation_kind: Some("runtime.lifecycle_projection.agents".to_string()),
                projection_kind: Some("agents".to_string()),
                ..Default::default()
            })
            .expect_err("state_dir is required");
        assert_eq!(
            error.code(),
            "runtime_lifecycle_projection_state_dir_required"
        );
    }

    #[test]
    fn rust_rejects_retired_runtime_lifecycle_candidate_transport() {
        let state_dir = write_runtime_lifecycle_state();
        let error = RuntimeLifecycleProjectionCore::default()
            .project(RuntimeLifecycleProjectionBridgeRequest {
                operation_kind: Some("runtime.lifecycle_projection.agents".to_string()),
                projection_kind: Some("agents".to_string()),
                state_dir: Some(state_dir.to_string_lossy().to_string()),
                agents: vec![json!({"id": "agent_candidate"})],
                ..Default::default()
            })
            .expect_err("candidate transport is retired");
        assert_eq!(
            error.code(),
            "runtime_lifecycle_projection_retired_candidate_transport"
        );
    }

    fn write_runtime_lifecycle_state() -> std::path::PathBuf {
        let state_dir = std::env::temp_dir().join(format!(
            "ioi-runtime-lifecycle-projection-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(state_dir.join("agents")).expect("agents dir");
        std::fs::create_dir_all(state_dir.join("runs")).expect("runs dir");
        std::fs::create_dir_all(state_dir.join("events")).expect("events dir");
        std::fs::write(
            state_dir.join("agents/agent_one.json"),
            serde_json::to_string(&json!({
                "id": "agent_one",
                "createdAt": "2026-01-01T00:00:00Z",
                "updatedAt": "2026-01-01T00:01:00Z",
                "cwd": "/workspace/project"
            }))
            .expect("agent one json"),
        )
        .expect("agent one");
        std::fs::write(
            state_dir.join("agents/agent_two.json"),
            serde_json::to_string(&json!({
                "id": "agent_two",
                "createdAt": "2026-01-02T00:00:00Z",
                "updatedAt": "2026-01-02T00:01:00Z"
            }))
            .expect("agent two json"),
        )
        .expect("agent two");
        std::fs::write(
            state_dir.join("runs/run_one.json"),
            serde_json::to_string(&json!({
                "id": "run_one",
                "agentId": "agent_one",
                "createdAt": "2026-01-01T00:00:00Z",
                "updatedAt": "2026-01-01T00:02:00Z",
                "conversation": [{"role": "user", "content": "ship it"}],
                "usage": {"total_tokens": 7},
                "trace": {
                    "scorecard": {"score": 1},
                    "computerUse": {
                        "trace": {"steps": 1},
                        "trajectory": [{"x": 1}]
                    }
                },
                "artifacts": [{"id": "artifact_trace", "name": "trace.json"}]
            }))
            .expect("run one json"),
        )
        .expect("run one");
        std::fs::write(
            state_dir.join("runs/run_two.json"),
            serde_json::to_string(&json!({
                "id": "run_two",
                "agentId": "agent_two",
                "createdAt": "2026-01-02T00:00:00Z",
                "updatedAt": "2026-01-02T00:02:00Z"
            }))
            .expect("run two json"),
        )
        .expect("run two");
        let event_lines = [
            json!({
                "event_id": "event_run_one_started",
                "event_stream_id": "thread_one:events",
                "thread_id": "thread_one",
                "run_id": "run_one",
                "turn_id": "turn_one",
                "event_kind": "turn.started",
                "seq": 1,
                "item_id": "turn_one:item:input"
            }),
            json!({
                "event_id": "event_run_one_completed",
                "event_stream_id": "thread_one:events",
                "thread_id": "thread_one",
                "run_id": "run_one",
                "turn_id": "turn_one",
                "event_kind": "turn.completed",
                "seq": 2,
                "item_id": "turn_one:item:output"
            }),
        ]
        .into_iter()
        .map(|value| serde_json::to_string(&value).expect("event json"))
        .collect::<Vec<_>>()
        .join("\n");
        std::fs::write(
            state_dir.join("events/thread_one.jsonl"),
            format!("{event_lines}\n"),
        )
        .expect("events");
        state_dir
    }
}
