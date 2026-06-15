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
const RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION: &str = "ioi.runtime.usage-telemetry.v1";
const AUTHORITY_EVIDENCE_SUMMARY_SCHEMA_VERSION: &str = "ioi.authority-evidence-summary.v1";
const AUTHORITY_EVIDENCE_SUMMARY_LIST_SCHEMA_VERSION: &str =
    "ioi.authority-evidence-summary-list.v1";
const DEFAULT_CONTEXT_WINDOW_TOKENS: u64 = 128_000;
const FALLBACK_COST_USD_PER_TOKEN: f64 = 0.000001;

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
    pub group_by: Option<String>,
    #[serde(default)]
    pub capability_ref: Option<String>,
    #[serde(default)]
    pub route_id: Option<String>,
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
        "usage_list" => Ok(usage_list_projection(sources, request)),
        "authority_evidence_summary" => Ok(authority_evidence_summary_projection(sources, request)),
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

fn usage_list_projection(
    sources: &RuntimeLifecycleProjectionSources,
    request: &RuntimeLifecycleProjectionBridgeRequest,
) -> Value {
    let group_by =
        optional_trimmed_lower(request.group_by.as_deref()).unwrap_or_else(|| "run".to_string());
    let agent_id = optional_trimmed(request.agent_id.as_deref());
    let runs = filter_runs_for_agent(sources.runs.clone(), agent_id.as_deref());
    let usage = if group_by == "thread" {
        let mut thread_ids = runs
            .iter()
            .filter_map(run_thread_id)
            .collect::<Vec<String>>();
        thread_ids.sort();
        thread_ids.dedup();
        thread_ids
            .into_iter()
            .map(|thread_id| {
                let agent_id = agent_id_for_thread(&thread_id);
                let thread_runs = filter_runs_for_agent(runs.clone(), Some(&agent_id));
                let records = thread_runs
                    .iter()
                    .map(|run| run_usage_telemetry(run, Some(thread_id.as_str())))
                    .collect::<Vec<Value>>();
                aggregate_usage_records(&records, "thread", Some(&thread_id), Some(&agent_id))
            })
            .collect::<Vec<Value>>()
    } else {
        runs.iter()
            .map(|run| run_usage_telemetry(run, None))
            .collect::<Vec<Value>>()
    };
    json!({
        "schema_version": RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
        "object": "ioi.runtime_usage_list",
        "group_by": if group_by == "thread" { "thread" } else { "run" },
        "count": usage.len(),
        "usage": usage,
        "source": "rust_runtime_lifecycle_state_dir_replay",
        "generated_at": "rust_runtime_lifecycle_projection_time"
    })
}

fn run_usage_telemetry(run: &Value, thread_id_override: Option<&str>) -> Value {
    let explicit = value_field(run, "usage_telemetry")
        .or_else(|| value_field(run, "usage"))
        .or_else(|| nested_value(Some(run), &["trace", "usage_telemetry"]))
        .or_else(|| nested_value(Some(run), &["trace", "usage"]))
        .unwrap_or_else(|| json!({}));
    let provider_usage = nested_value(Some(&explicit), &["usage"])
        .or_else(|| nested_value(Some(&explicit), &["provider_usage"]))
        .unwrap_or_else(|| explicit.clone());
    let route = value_field(run, "model_route_decision")
        .or_else(|| nested_value(Some(run), &["trace", "model_route_decision"]))
        .unwrap_or_else(|| json!({}));
    let prompt_text = value_string_any(run, &["objective"]).unwrap_or_default();
    let result_text = value_string_any(run, &["result"]).unwrap_or_default();
    let input_tokens = u64_field_any(&provider_usage, &["input_tokens", "prompt_tokens"])
        .unwrap_or_else(|| estimated_token_count(&prompt_text));
    let output_tokens = u64_field_any(&provider_usage, &["output_tokens", "completion_tokens"])
        .unwrap_or_else(|| estimated_token_count(&result_text));
    let reasoning_tokens = u64_field_any(&provider_usage, &["reasoning_tokens"]).unwrap_or(0);
    let cached_input_tokens = u64_field_any(&provider_usage, &["cached_input_tokens"]).unwrap_or(0);
    let tool_result_tokens = u64_field_any(&provider_usage, &["tool_result_tokens"]).unwrap_or(0);
    let compacted_tokens = u64_field_any(&provider_usage, &["compacted_tokens"]).unwrap_or(0);
    let total_tokens = u64_field_any(&provider_usage, &["total_tokens"])
        .or_else(|| u64_field_any(&explicit, &["total_tokens"]))
        .unwrap_or(input_tokens + output_tokens + reasoning_tokens + tool_result_tokens);
    let estimated_cost_usd = f64_field_any(&explicit, &["estimated_cost_usd", "cost_estimate_usd"])
        .or_else(|| {
            f64_field_any(
                &provider_usage,
                &["estimated_cost_usd", "cost_estimate_usd"],
            )
        })
        .or_else(|| {
            u64_field_any(&provider_usage, &["estimated_cost_micros"])
                .map(|value| value as f64 / 1_000_000.0)
        })
        .unwrap_or(total_tokens as f64 * FALLBACK_COST_USD_PER_TOKEN);
    let estimated_cost_micros = u64_field_any(&provider_usage, &["estimated_cost_micros"])
        .unwrap_or_else(|| (estimated_cost_usd * 1_000_000.0).round() as u64);
    let context_window_tokens = u64_field_any(&explicit, &["context_window_tokens"])
        .or_else(|| u64_field_any(&provider_usage, &["context_window_tokens"]))
        .or_else(|| {
            u64_field_any(
                &route,
                &[
                    "context_window_tokens",
                    "model_context_window_tokens",
                    "max_context_tokens",
                ],
            )
        })
        .unwrap_or(DEFAULT_CONTEXT_WINDOW_TOKENS);
    let context_used_tokens = u64_field_any(&explicit, &["context_used_tokens"])
        .unwrap_or_else(|| total_tokens.saturating_sub(cached_input_tokens));
    let context_pressure = round_ratio(if context_window_tokens > 0 {
        context_used_tokens as f64 / context_window_tokens as f64
    } else {
        0.0
    });
    let agent_id = run_agent_id(run);
    let run_id = value_string_any(run, &["id", "run_id"]);
    let thread_id = thread_id_override
        .map(str::to_string)
        .or_else(|| value_string_any(run, &["thread_id"]))
        .or_else(|| agent_id.as_deref().map(thread_id_for_agent));
    let route_id = value_string_any(&explicit, &["route_id"])
        .or_else(|| value_string_any(&route, &["route_id"]))
        .or_else(|| value_string_any(run, &["model_route_id", "modelRouteId"]));
    let estimated = !(explicit.is_object() && !explicit.as_object().unwrap().is_empty());
    json!({
        "schema_version": RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
        "object": "ioi.runtime_usage_telemetry",
        "scope": "run",
        "thread_id": thread_id,
        "turn_id": value_string_any(run, &["turn_id", "runtimeTurnId", "runtime_turn_id"]).or_else(|| run_id.as_deref().map(turn_id_for_run)),
        "run_id": run_id,
        "agent_id": agent_id,
        "provider": value_string_any(&provider_usage, &["provider"]).or_else(|| value_string_any(&explicit, &["provider"])).or_else(|| value_string_any(&route, &["provider_id"])).unwrap_or_else(|| "local".to_string()),
        "model": value_string_any(&provider_usage, &["model"]).or_else(|| value_string_any(&explicit, &["model"])).or_else(|| value_string_any(&route, &["selected_model"])).or_else(|| value_string_any(run, &["model_id", "modelId", "requested_model_id", "requestedModelId"])).unwrap_or_else(|| "unknown".to_string()),
        "route_id": route_id,
        "model_route_id": route_id,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "reasoning_tokens": reasoning_tokens,
        "cached_input_tokens": cached_input_tokens,
        "tool_result_tokens": tool_result_tokens,
        "compacted_tokens": compacted_tokens,
        "total_tokens": total_tokens,
        "estimated_cost_micros": estimated_cost_micros,
        "estimated_cost_usd": round_usd(estimated_cost_usd),
        "currency": value_string_any(&explicit, &["currency"]).or_else(|| value_string_any(&provider_usage, &["currency"])).unwrap_or_else(|| "USD".to_string()),
        "context_window_tokens": context_window_tokens,
        "context_used_tokens": context_used_tokens,
        "context_pressure": context_pressure,
        "context_pressure_status": context_pressure_status(context_pressure),
        "latency_ms": u64_field_any(&provider_usage, &["latency_ms"]).unwrap_or(0),
        "estimated": estimated,
        "source_counts": {"runs": 1, "subagents": 0},
        "source_refs": run_id.map(|id| vec![id]).unwrap_or_default(),
        "source": "rust_runtime_lifecycle_state_dir_replay",
        "generated_at": "rust_runtime_lifecycle_projection_time"
    })
}

fn aggregate_usage_records(
    records: &[Value],
    scope: &str,
    thread_id: Option<&str>,
    agent_id: Option<&str>,
) -> Value {
    let sum = |key: &str| -> u64 {
        records
            .iter()
            .filter_map(|record| u64_field_any(record, &[key]))
            .sum()
    };
    let cost_usd = records
        .iter()
        .filter_map(|record| f64_field_any(record, &["estimated_cost_usd"]))
        .sum::<f64>();
    let context_window_tokens = records
        .iter()
        .filter_map(|record| u64_field_any(record, &["context_window_tokens"]))
        .max()
        .unwrap_or(DEFAULT_CONTEXT_WINDOW_TOKENS);
    let context_used_tokens = sum("context_used_tokens");
    let context_pressure = round_ratio(if context_window_tokens > 0 {
        context_used_tokens as f64 / context_window_tokens as f64
    } else {
        0.0
    });
    let source_refs = records
        .iter()
        .flat_map(|record| string_array(record.get("source_refs")))
        .collect::<Vec<String>>();
    json!({
        "schema_version": RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
        "object": "ioi.runtime_usage_telemetry",
        "scope": scope,
        "thread_id": thread_id,
        "agent_id": agent_id,
        "provider": "aggregate",
        "model": "aggregate",
        "route_id": Value::Null,
        "model_route_id": Value::Null,
        "input_tokens": sum("input_tokens"),
        "output_tokens": sum("output_tokens"),
        "reasoning_tokens": sum("reasoning_tokens"),
        "cached_input_tokens": sum("cached_input_tokens"),
        "tool_result_tokens": sum("tool_result_tokens"),
        "compacted_tokens": sum("compacted_tokens"),
        "total_tokens": sum("total_tokens"),
        "estimated_cost_micros": sum("estimated_cost_micros"),
        "estimated_cost_usd": round_usd(cost_usd),
        "currency": "USD",
        "context_window_tokens": context_window_tokens,
        "context_used_tokens": context_used_tokens,
        "context_pressure": context_pressure,
        "context_pressure_status": context_pressure_status(context_pressure),
        "latency_ms": sum("latency_ms"),
        "estimated": true,
        "source_counts": {"runs": records.len(), "subagents": 0},
        "source_refs": unique_strings(source_refs),
        "source": "rust_runtime_lifecycle_state_dir_replay",
        "generated_at": "rust_runtime_lifecycle_projection_time"
    })
}

fn authority_evidence_summary_projection(
    sources: &RuntimeLifecycleProjectionSources,
    request: &RuntimeLifecycleProjectionBridgeRequest,
) -> Value {
    let filters = json!({
        "thread_id": optional_trimmed(request.thread_id.as_deref()),
        "run_id": optional_trimmed(request.run_id.as_deref()),
        "capability_ref": optional_trimmed(request.capability_ref.as_deref()),
        "route_id": optional_trimmed(request.route_id.as_deref()),
    });
    let mut rows = sources
        .events
        .iter()
        .filter(|event| authority_evidence_source_event(event))
        .flat_map(authority_evidence_rows_from_runtime_event)
        .filter(|row| authority_evidence_row_matches_filters(row, request))
        .collect::<Vec<Value>>();
    rows.sort_by(|left, right| {
        let right_seq = event_seq(right).unwrap_or(0);
        let left_seq = event_seq(left).unwrap_or(0);
        right_seq.cmp(&left_seq).then_with(|| {
            value_string_any(right, &["created_at"])
                .unwrap_or_default()
                .cmp(&value_string_any(left, &["created_at"]).unwrap_or_default())
        })
    });
    json!({
        "schema_version": AUTHORITY_EVIDENCE_SUMMARY_LIST_SCHEMA_VERSION,
        "object": "ioi.authority_evidence_summary_list",
        "source": "rust_runtime_lifecycle_state_dir_replay",
        "generated_at": "rust_runtime_lifecycle_projection_time",
        "row_count": rows.len(),
        "filters": filters,
        "items": rows,
    })
}

fn authority_evidence_source_event(event: &Value) -> bool {
    let payload = value_field(event, "payload_summary")
        .or_else(|| value_field(event, "payload"))
        .unwrap_or_else(|| json!({}));
    let haystack = [
        value_string_any(
            event,
            &[
                "event_kind",
                "source_event_kind",
                "component_kind",
                "payload_schema_version",
            ],
        ),
        value_string_any(
            &payload,
            &[
                "event_kind",
                "reason",
                "source_kind",
                "schema_version",
                "issue_code",
            ],
        ),
        nested_string(Some(&payload), &["result_summary", "reason"]),
    ]
    .into_iter()
    .flatten()
    .map(|value| value.to_ascii_lowercase())
    .collect::<Vec<String>>()
    .join(" ");
    haystack.contains("capability")
        && (haystack.contains("workflowruncapabilitypreflightblocked")
            || haystack.contains("workflow_capability_preflight_blocked")
            || haystack.contains("ioi.workflow.capability-preflight.v1")
            || haystack.contains("capability_preflight"))
}

fn authority_evidence_rows_from_runtime_event(event: &Value) -> Vec<Value> {
    let payload_summary = value_field(event, "payload_summary").unwrap_or_else(|| json!({}));
    let fallback_payload = if payload_summary
        .as_object()
        .map(|value| !value.is_empty())
        .unwrap_or(false)
    {
        payload_summary
    } else {
        value_field(event, "payload").unwrap_or_else(|| json!({}))
    };
    let event_receipt_refs = unique_strings(
        [
            string_array(event.get("receipt_refs")),
            string_array(fallback_payload.get("receipt_refs")),
        ]
        .concat(),
    );
    let event_policy_decision_refs = unique_strings(
        [
            string_array(event.get("policy_decision_refs")),
            string_array(fallback_payload.get("policy_decision_refs")),
        ]
        .concat(),
    );
    let rows = value_array_any(&fallback_payload, &["rows", "capability_rows"]);
    if !rows.is_empty() {
        return rows
            .iter()
            .enumerate()
            .filter_map(|(index, row)| {
                authority_evidence_row_from_preflight_row(
                    event,
                    &fallback_payload,
                    row,
                    index,
                    &event_receipt_refs,
                    &event_policy_decision_refs,
                )
            })
            .collect();
    }
    string_array(fallback_payload.get("capability_refs"))
        .iter()
        .enumerate()
        .filter_map(|(index, capability_ref)| {
            authority_evidence_row_from_preflight_row(
                event,
                &fallback_payload,
                &json!({"capability_ref": capability_ref}),
                index,
                &event_receipt_refs,
                &event_policy_decision_refs,
            )
        })
        .collect()
}

fn authority_evidence_row_from_preflight_row(
    event: &Value,
    payload: &Value,
    row: &Value,
    row_index: usize,
    event_receipt_refs: &[String],
    event_policy_decision_refs: &[String],
) -> Option<Value> {
    let capability_ref = value_string_any(
        row,
        &[
            "capability_ref",
            "model_capability_ref",
            "tool_capability_ref",
            "connector_capability_ref",
        ],
    )
    .unwrap_or_default();
    let route_id =
        value_string_any(row, &["route_id"]).or_else(|| value_string_any(payload, &["route_id"]));
    let authority_scopes = unique_strings(
        [
            string_array(row.get("authority_scopes")),
            string_array(payload.get("authority_scopes")),
        ]
        .concat(),
    );
    let authority_scope_requirements = unique_strings(
        [
            string_array(row.get("authority_scope_requirements")),
            string_array(payload.get("authority_scope_requirements")),
        ]
        .concat(),
    );
    let receipt_refs = unique_strings(
        [
            event_receipt_refs.to_vec(),
            string_array(row.get("receipt_refs")),
            string_array(row.get("last_repair_receipt_refs")),
            string_array(row.get("preflight_receipt_refs")),
        ]
        .concat(),
    );
    let policy_decision_refs = unique_strings(
        [
            event_policy_decision_refs.to_vec(),
            string_array(row.get("policy_decision_refs")),
        ]
        .concat(),
    );
    if receipt_refs.is_empty()
        || (capability_ref.is_empty()
            && route_id.is_none()
            && authority_scopes.is_empty()
            && authority_scope_requirements.is_empty())
    {
        return None;
    }
    let source_run_id = value_string_any(payload, &["run_id", "source_run_id"])
        .or_else(|| value_string_any(row, &["run_id", "source_run_id"]));
    let event_id = value_string_any(event, &["event_id"]);
    let created_at = value_string_any(event, &["created_at"])
        .or_else(|| value_string_any(payload, &["created_at"]));
    let node_id = value_string_any(row, &["node_id"])
        .or_else(|| value_string_any(event, &["workflow_node_id"]))
        .or_else(|| value_string_any(payload, &["workflow_node_id"]));
    Some(json!({
        "schema_version": AUTHORITY_EVIDENCE_SUMMARY_SCHEMA_VERSION,
        "id": format!(
            "authority_evidence_{}_{}",
            safe_id(event_id.as_deref().or(source_run_id.as_deref()).unwrap_or("event")),
            row_index + 1
        ),
        "capability_ref": capability_ref,
        "route_id": route_id,
        "authority_scopes": authority_scopes,
        "authority_scope_requirements": authority_scope_requirements,
        "receipt_refs": receipt_refs,
        "policy_decision_refs": policy_decision_refs,
        "source_run_id": source_run_id,
        "source_event_id": event_id,
        "thread_id": value_string_any(event, &["thread_id"]),
        "turn_id": value_string_any(event, &["turn_id"]),
        "workflow_graph_id": value_string_any(event, &["workflow_graph_id"]),
        "workflow_node_id": node_id,
        "node_id": value_string_any(row, &["node_id"]).or_else(|| node_id.clone()),
        "node_type": value_string_any(row, &["node_type"]),
        "binding_kind": value_string_any(row, &["binding_kind"]),
        "component_kind": value_string_any(event, &["component_kind"]),
        "status": value_string_any(event, &["status"]).or_else(|| value_string_any(payload, &["status"])).or_else(|| value_string_any(row, &["status"])),
        "reason": value_string_any(payload, &["reason", "issue_code"]).or_else(|| value_string_any(row, &["reason"])),
        "created_at": created_at,
        "created_at_ms": Value::Null,
        "event_seq": event_seq(event),
        "source": "rust_runtime_lifecycle_state_dir_replay"
    }))
}

fn authority_evidence_row_matches_filters(
    row: &Value,
    request: &RuntimeLifecycleProjectionBridgeRequest,
) -> bool {
    if let Some(thread_id) = optional_trimmed(request.thread_id.as_deref()) {
        if value_string_any(row, &["thread_id"]).as_deref() != Some(thread_id.as_str()) {
            return false;
        }
    }
    if let Some(run_id) = optional_trimmed(request.run_id.as_deref()) {
        if value_string_any(row, &["source_run_id"]).as_deref() != Some(run_id.as_str()) {
            return false;
        }
    }
    if let Some(capability_ref) = optional_trimmed(request.capability_ref.as_deref()) {
        if value_string_any(row, &["capability_ref"]).as_deref() != Some(capability_ref.as_str()) {
            return false;
        }
    }
    if let Some(route_id) = optional_trimmed(request.route_id.as_deref()) {
        if value_string_any(row, &["route_id"]).as_deref() != Some(route_id.as_str()) {
            return false;
        }
    }
    true
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
    value
        .get("seq")
        .and_then(Value::as_u64)
        .or_else(|| value.get("event_seq").and_then(Value::as_u64))
}

fn value_string(value: &Value, key: &str) -> Option<String> {
    optional_trimmed(value.get(key).and_then(Value::as_str))
}

fn value_string_any(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| value_string(value, key))
}

fn value_array_any(value: &Value, keys: &[&str]) -> Vec<Value> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_array).cloned())
        .unwrap_or_default()
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| match item {
                    Value::String(text) => optional_trimmed(Some(text)),
                    other => optional_trimmed(Some(&other.to_string())),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut output = Vec::new();
    for value in values {
        if !output.contains(&value) {
            output.push(value);
        }
    }
    output
}

fn u64_field_any(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(|candidate| {
            candidate
                .as_u64()
                .or_else(|| candidate.as_str()?.parse().ok())
        })
    })
}

fn f64_field_any(value: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(|candidate| {
            candidate
                .as_f64()
                .or_else(|| candidate.as_str()?.parse::<f64>().ok())
        })
    })
}

fn estimated_token_count(value: &str) -> u64 {
    if value.is_empty() {
        0
    } else {
        std::cmp::max(1, value.len().div_ceil(4) as u64)
    }
}

fn context_pressure_status(pressure: f64) -> &'static str {
    if pressure >= 0.85 {
        "high"
    } else if pressure >= 0.6 {
        "elevated"
    } else {
        "nominal"
    }
}

fn round_ratio(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn round_usd(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

fn safe_id(value: &str) -> String {
    let mut output = String::new();
    let mut previous_dash = false;
    for ch in value.trim().to_ascii_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch);
            previous_dash = false;
        } else if !previous_dash && !output.is_empty() {
            output.push('-');
            previous_dash = true;
        }
        if output.len() >= 80 {
            break;
        }
    }
    let output = output.trim_matches('-').to_string();
    if output.is_empty() {
        "unknown".to_string()
    } else {
        output
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

        let usage = core
            .project(RuntimeLifecycleProjectionBridgeRequest {
                projection_kind: Some("usage_list".to_string()),
                operation_kind: Some("runtime.lifecycle_projection.usage_list".to_string()),
                agent_id: Some("agent_one".to_string()),
                group_by: Some("thread".to_string()),
                state_dir: Some(state_dir.to_string_lossy().to_string()),
                ..Default::default()
            })
            .expect("usage list");
        assert_eq!(usage.projection["group_by"], "thread");
        assert_eq!(usage.projection["usage"][0]["scope"], "thread");
        assert_eq!(usage.projection["usage"][0]["total_tokens"], 7);

        let authority = core
            .project(RuntimeLifecycleProjectionBridgeRequest {
                projection_kind: Some("authority_evidence_summary".to_string()),
                operation_kind: Some(
                    "runtime.lifecycle_projection.authority_evidence_summary".to_string(),
                ),
                thread_id: Some("thread_one".to_string()),
                run_id: Some("run_one".to_string()),
                capability_ref: Some("capability:model.route".to_string()),
                route_id: Some("route-alpha".to_string()),
                state_dir: Some(state_dir.to_string_lossy().to_string()),
                ..Default::default()
            })
            .expect("authority evidence summary");
        assert_eq!(authority.projection["row_count"], 1);
        assert_eq!(
            authority.projection["items"][0]["receipt_refs"][0],
            "receipt_authority_one"
        );
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
            json!({
                "event_id": "event_run_one_authority",
                "event_stream_id": "thread_one:events",
                "thread_id": "thread_one",
                "run_id": "run_one",
                "turn_id": "turn_one",
                "event_kind": "workflow_capability_preflight_blocked",
                "component_kind": "capability_preflight",
                "seq": 3,
                "payload_summary": {
                    "schema_version": "ioi.workflow.capability-preflight.v1",
                    "run_id": "run_one",
                    "route_id": "route-alpha",
                    "rows": [{
                        "capability_ref": "capability:model.route",
                        "authority_scope_requirements": ["model.invoke"],
                        "receipt_refs": ["receipt_authority_one"]
                    }]
                }
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
