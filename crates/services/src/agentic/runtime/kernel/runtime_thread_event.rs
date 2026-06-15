use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

use super::agentgres_admission::{
    AgentgresAdmissionCore, AgentgresAdmissionError, StorageBackendWriteAdmissionRecord,
    StorageBackendWriteProposal, STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION,
};

pub const RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-event-admission-request.v1";
pub const RUNTIME_THREAD_EVENT_ADMISSION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-event-admission.v1";
pub const RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-event-projection-request.v1";
pub const RUNTIME_THREAD_EVENT_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-event-projection.v1";
pub const RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-event-replay-request.v1";
pub const RUNTIME_THREAD_EVENT_REPLAY_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-event-replay.v1";
pub const RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-turn-projection-request.v1";
pub const RUNTIME_THREAD_TURN_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.thread-turn-projection.v1";

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeThreadEventAdmissionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    InvalidProjectionKind(String),
    InvalidReplayKind(String),
    InvalidThreadTurnProjectionKind(String),
    InvalidCursorField(String),
    ReplayStateDirRequired,
    ReplayReadFailed(String),
    ReplayRecordInvalid(String),
    RetiredReplayEventTransport,
    CursorOutOfRange {
        event_stream_id: Option<String>,
        last_event_id: Option<String>,
        since_seq: Option<u64>,
        latest_seq: u64,
    },
    MissingReceiptRefs,
    Agentgres(AgentgresAdmissionError),
    HashFailed(String),
}

impl From<AgentgresAdmissionError> for RuntimeThreadEventAdmissionError {
    fn from(error: AgentgresAdmissionError) -> Self {
        Self::Agentgres(error)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeThreadEventAdmissionRequest {
    pub schema_version: String,
    pub event: Value,
    #[serde(default)]
    pub latest_seq: Option<u64>,
    #[serde(default)]
    pub expected_head: Option<String>,
    #[serde(default)]
    pub state_root_before: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeThreadEventAdmissionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub event_id: String,
    pub event_stream_id: String,
    pub thread_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    pub event_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_status: Option<String>,
    pub seq: u64,
    pub latest_seq: u64,
    pub expected_heads: Vec<String>,
    pub state_root_before: String,
    pub state_root_after: String,
    pub resulting_head: String,
    pub operation_ref: String,
    pub projection_watermark: String,
    pub payload_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub storage_admission: StorageBackendWriteAdmissionRecord,
    pub event: Value,
    pub admission_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeThreadEventAdmissionProtocolRequest {
    pub request: RuntimeThreadEventAdmissionRequest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeThreadEventProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub projection_kind: String,
    #[serde(default)]
    pub thread_id: String,
    #[serde(default)]
    pub event_stream_id: String,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub agent: Option<Value>,
    #[serde(default)]
    pub runs: Vec<Value>,
    #[serde(default)]
    pub latest_seq: Option<u64>,
    #[serde(default)]
    pub expected_head: Option<String>,
    #[serde(default)]
    pub state_root_before: Option<String>,
    #[serde(default)]
    pub existing_idempotency_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeThreadEventProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub projection_kind: String,
    pub event_stream_id: String,
    pub thread_id: String,
    pub event_count: usize,
    pub skipped_count: usize,
    pub latest_seq: u64,
    pub resulting_seq: u64,
    pub resulting_head: String,
    pub state_root_after: String,
    pub projection_watermark: String,
    pub receipt_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub payload_refs: Vec<String>,
    pub admissions: Vec<RuntimeThreadEventAdmissionRecord>,
    pub events: Vec<Value>,
    pub projection_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeThreadEventProjectionProtocolRequest {
    pub request: RuntimeThreadEventProjectionRequest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeThreadEventReplayRequest {
    pub schema_version: String,
    #[serde(default)]
    pub replay_kind: String,
    #[serde(default)]
    pub event_stream_id: String,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub cursor: Option<Value>,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub events: Vec<Value>,
    #[serde(default)]
    pub latest_seq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeThreadEventReplayRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub replay_kind: String,
    pub event_stream_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    pub event_count: usize,
    pub latest_seq: u64,
    pub cursor_seq: u64,
    pub resulting_seq: u64,
    pub resulting_head: String,
    pub state_root_after: String,
    pub projection_watermark: String,
    pub receipt_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub payload_refs: Vec<String>,
    pub events: Vec<Value>,
    pub replay_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeThreadEventReplayProtocolRequest {
    pub request: RuntimeThreadEventReplayRequest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeThreadTurnProjectionRequest {
    pub schema_version: String,
    #[serde(default)]
    pub projection_kind: String,
    #[serde(default)]
    pub thread_schema_version: Option<String>,
    #[serde(default)]
    pub turn_schema_version: Option<String>,
    #[serde(default)]
    pub thread_id: String,
    #[serde(default)]
    pub event_stream_id: String,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub fixture_profile: Option<String>,
    #[serde(default)]
    pub runtime_profile: Option<String>,
    #[serde(default)]
    pub runtime_bridge_id: Option<String>,
    #[serde(default)]
    pub runtime_bridge_source: Option<String>,
    #[serde(default)]
    pub agent: Option<Value>,
    #[serde(default)]
    pub runs: Vec<Value>,
    #[serde(default)]
    pub run: Option<Value>,
    #[serde(default)]
    pub events: Vec<Value>,
    #[serde(default)]
    pub runtime_controls: Option<Value>,
    #[serde(default)]
    pub usage_telemetry: Option<Value>,
    #[serde(default)]
    pub memory_count: Option<u64>,
    #[serde(default)]
    pub subagent_ids: Vec<String>,
    #[serde(default)]
    pub latest_seq: Option<u64>,
    #[serde(default)]
    pub created_at_ms: Option<u64>,
    #[serde(default)]
    pub updated_at_ms: Option<u64>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub approval_mode: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeThreadTurnProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub projection_kind: String,
    pub thread_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    pub event_count: usize,
    pub latest_seq: u64,
    pub record: Value,
    pub projection_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeThreadTurnProjectionProtocolRequest {
    pub request: RuntimeThreadTurnProjectionRequest,
}

#[derive(Debug, Default, Clone)]
pub struct RuntimeThreadEventAdmissionCore;

impl RuntimeThreadEventAdmissionCore {
    pub fn admit(
        &self,
        request: &RuntimeThreadEventAdmissionRequest,
    ) -> Result<RuntimeThreadEventAdmissionRecord, RuntimeThreadEventAdmissionError> {
        request.validate()?;
        let event = request.event.as_object().expect("validated event object");
        let event_stream_id = required_event_string(event, "event_stream_id")?;
        let thread_id = required_event_string(event, "thread_id")?;
        let idempotency_key = required_event_string(event, "idempotency_key")?;
        let event_kind = required_event_string(event, "event_kind")?;
        let latest_seq = request
            .latest_seq
            .or_else(|| event.get("latest_seq").and_then(Value::as_u64))
            .unwrap_or(0);
        let seq = latest_seq + 1;
        let event_id = optional_event_string(event, "event_id").unwrap_or_else(|| {
            format!(
                "event_runtime_thread_{}",
                short_hash(&format!("{event_stream_id}:{idempotency_key}:{seq}"), 16)
            )
        });
        let created_at =
            optional_event_string(event, "created_at").unwrap_or_else(|| "rust_daemon_core".into());
        let expected_heads =
            unique_trimmed_strings(vec![request.expected_head.clone().unwrap_or_else(|| {
                format!(
                    "agentgres://runtime-events/{}/head/{}",
                    safe_component(&event_stream_id),
                    latest_seq
                )
            })]);
        let state_root_before = request.state_root_before.clone().unwrap_or_else(|| {
            format!(
                "sha256:{}",
                sha256_hex(
                    format!("runtime-thread-event-before:{event_stream_id}:{latest_seq}")
                        .as_bytes()
                )
            )
        });
        let mut admitted_event = event.clone();
        admitted_event.insert("event_id".to_string(), Value::String(event_id.clone()));
        admitted_event.insert("seq".to_string(), json!(seq));
        admitted_event.insert("created_at".to_string(), Value::String(created_at));
        let receipt_refs = unique_trimmed_strings(
            json_string_array_from_map(&admitted_event, "receipt_refs")
                .into_iter()
                .chain(
                    admitted_event
                        .get("payload_summary")
                        .and_then(Value::as_object)
                        .map(|payload| json_string_array_from_map(payload, "receipt_refs"))
                        .unwrap_or_default(),
                )
                .collect(),
        );
        if receipt_refs.is_empty() {
            return Err(RuntimeThreadEventAdmissionError::MissingReceiptRefs);
        }
        let artifact_refs =
            unique_trimmed_strings(json_string_array_from_map(&admitted_event, "artifact_refs"));
        let rollback_refs =
            unique_trimmed_strings(json_string_array_from_map(&admitted_event, "rollback_refs"));
        let event_stream_ref = safe_component(&event_stream_id);
        let payload_ref = format!("payload://runtime-events/{event_stream_ref}/events/{event_id}");
        let payload_refs = unique_trimmed_strings(
            json_string_array_from_map(&admitted_event, "payload_refs")
                .into_iter()
                .chain(std::iter::once(payload_ref.clone()))
                .collect(),
        );
        admitted_event.insert("receipt_refs".to_string(), json!(receipt_refs.clone()));
        admitted_event.insert("artifact_refs".to_string(), json!(artifact_refs.clone()));
        admitted_event.insert("rollback_refs".to_string(), json!(rollback_refs.clone()));
        admitted_event.insert("payload_refs".to_string(), json!(payload_refs.clone()));
        let event_value = Value::Object(admitted_event.clone());
        let content_hash = value_hash(&event_value)?;
        let object_ref = format!("agentgres://runtime-events/{event_stream_ref}/events/{event_id}");
        let storage_admission =
            AgentgresAdmissionCore.admit_storage_backend_write(&StorageBackendWriteProposal {
                schema_version: STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION.to_string(),
                storage_backend_ref: "agentgres://runtime-events".to_string(),
                object_ref: object_ref.clone(),
                content_hash: content_hash.clone(),
                artifact_refs: artifact_refs.clone(),
                payload_refs: payload_refs.clone(),
                receipt_refs: receipt_refs.clone(),
            })?;
        let state_root_after = format!(
            "sha256:{}",
            sha256_hex(
                serde_json::to_vec(&json!({
                    "state_root_before": state_root_before,
                    "event_id": event_id,
                    "seq": seq,
                    "content_hash": content_hash,
                    "storage_admission_hash": storage_admission.admission_hash,
                    "receipt_refs": receipt_refs,
                    "artifact_refs": artifact_refs,
                    "payload_refs": payload_refs,
                }))
                .map_err(|error| RuntimeThreadEventAdmissionError::HashFailed(error.to_string()))?
                .as_slice(),
            )
        );
        let head_suffix = state_root_after
            .trim_start_matches("sha256:")
            .chars()
            .take(24)
            .collect::<String>();
        let resulting_head =
            format!("agentgres://runtime-events/{event_stream_ref}/head/{head_suffix}");
        let operation_ref =
            format!("agentgres://runtime-events/{event_stream_ref}/operations/{event_id}");
        let projection_watermark = format!("runtime-events:{event_stream_id}:{seq}");
        admitted_event.insert(
            "agentgres_operation_ref".to_string(),
            Value::String(operation_ref.clone()),
        );
        admitted_event.insert(
            "agentgres_storage_object_ref".to_string(),
            Value::String(object_ref),
        );
        admitted_event.insert(
            "agentgres_storage_admission_hash".to_string(),
            Value::String(storage_admission.admission_hash.clone()),
        );
        admitted_event.insert(
            "expected_heads".to_string(),
            Value::Array(expected_heads.iter().cloned().map(Value::String).collect()),
        );
        admitted_event.insert(
            "state_root_before".to_string(),
            Value::String(state_root_before.clone()),
        );
        admitted_event.insert(
            "state_root_after".to_string(),
            Value::String(state_root_after.clone()),
        );
        admitted_event.insert(
            "resulting_head".to_string(),
            Value::String(resulting_head.clone()),
        );
        admitted_event.insert(
            "projection_watermark".to_string(),
            Value::String(projection_watermark.clone()),
        );
        let event_value = Value::Object(admitted_event);
        let mut record = RuntimeThreadEventAdmissionRecord {
            schema_version: RUNTIME_THREAD_EVENT_ADMISSION_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_thread_event_admission".to_string(),
            status: "admitted".to_string(),
            operation_kind: "runtime.thread_event".to_string(),
            event_id,
            event_stream_id,
            thread_id,
            turn_id: optional_event_string(event, "turn_id"),
            item_id: optional_event_string(event, "item_id"),
            event_kind,
            event_status: optional_event_string(event, "status"),
            seq,
            latest_seq,
            expected_heads,
            state_root_before,
            state_root_after,
            resulting_head,
            operation_ref,
            projection_watermark,
            payload_refs,
            receipt_refs,
            artifact_refs,
            rollback_refs,
            storage_admission,
            event: event_value,
            admission_hash: String::new(),
        };
        record.admission_hash =
            value_hash(&serde_json::to_value(&record).map_err(|error| {
                RuntimeThreadEventAdmissionError::HashFailed(error.to_string())
            })?)?;
        Ok(record)
    }

    pub fn project(
        &self,
        request: &RuntimeThreadEventProjectionRequest,
    ) -> Result<RuntimeThreadEventProjectionRecord, RuntimeThreadEventAdmissionError> {
        request.validate_projection()?;
        let candidates = self.projection_candidates(request)?;
        let existing_idempotency_keys =
            unique_trimmed_strings(request.existing_idempotency_keys.clone());
        let mut skipped_count = 0usize;
        let mut latest_seq = request.latest_seq.unwrap_or(0);
        let mut expected_head = request.expected_head.clone();
        let mut state_root_before = request.state_root_before.clone();
        let mut admissions = Vec::new();
        let mut events = Vec::new();

        for candidate in candidates {
            let idempotency_key = candidate
                .as_object()
                .and_then(|event| optional_event_string(event, "idempotency_key"))
                .ok_or(RuntimeThreadEventAdmissionError::MissingField(
                    "idempotency_key",
                ))?;
            if existing_idempotency_keys.contains(&idempotency_key) {
                skipped_count += 1;
                continue;
            }
            let admission = self.admit(&RuntimeThreadEventAdmissionRequest {
                schema_version: RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION.to_string(),
                event: candidate,
                latest_seq: Some(latest_seq),
                expected_head: expected_head.clone().or_else(|| {
                    Some(format!(
                        "agentgres://runtime-events/{}/head/{}",
                        safe_component(&request.event_stream_id),
                        latest_seq
                    ))
                }),
                state_root_before: state_root_before.clone(),
            })?;
            latest_seq = admission.seq;
            expected_head = Some(admission.resulting_head.clone());
            state_root_before = Some(admission.state_root_after.clone());
            events.push(admission.event.clone());
            admissions.push(admission);
        }

        let resulting_head = expected_head.unwrap_or_else(|| {
            format!(
                "agentgres://runtime-events/{}/head/{}",
                safe_component(&request.event_stream_id),
                latest_seq
            )
        });
        let state_root_after = state_root_before.unwrap_or_else(|| {
            default_state_root_before(&request.event_stream_id, request.latest_seq.unwrap_or(0))
        });
        let projection_watermark =
            format!("runtime-events:{}:{}", request.event_stream_id, latest_seq);
        let receipt_refs = unique_trimmed_strings(
            admissions
                .iter()
                .flat_map(|admission| admission.receipt_refs.clone())
                .collect(),
        );
        let artifact_refs = unique_trimmed_strings(
            admissions
                .iter()
                .flat_map(|admission| admission.artifact_refs.clone())
                .collect(),
        );
        let payload_refs = unique_trimmed_strings(
            admissions
                .iter()
                .flat_map(|admission| admission.payload_refs.clone())
                .collect(),
        );
        let mut record = RuntimeThreadEventProjectionRecord {
            schema_version: RUNTIME_THREAD_EVENT_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_thread_event_projection".to_string(),
            status: "projected".to_string(),
            operation_kind: "runtime.thread_event_projection".to_string(),
            projection_kind: request.projection_kind.clone(),
            event_stream_id: request.event_stream_id.clone(),
            thread_id: request.thread_id.clone(),
            event_count: events.len(),
            skipped_count,
            latest_seq: request.latest_seq.unwrap_or(0),
            resulting_seq: latest_seq,
            resulting_head,
            state_root_after,
            projection_watermark,
            receipt_refs,
            artifact_refs,
            payload_refs,
            admissions,
            events,
            projection_hash: String::new(),
        };
        record.projection_hash =
            value_hash(&serde_json::to_value(&record).map_err(|error| {
                RuntimeThreadEventAdmissionError::HashFailed(error.to_string())
            })?)?;
        Ok(record)
    }

    pub fn replay(
        &self,
        request: &RuntimeThreadEventReplayRequest,
    ) -> Result<RuntimeThreadEventReplayRecord, RuntimeThreadEventAdmissionError> {
        request.validate_replay()?;
        let replay_events = runtime_thread_replay_events_from_state_dir(request)?;
        let mut selected = replay_events
            .iter()
            .filter_map(|event| event.as_object().map(|record| (event, record)))
            .filter(|(_, record)| match request.replay_kind.as_str() {
                "stream" => {
                    optional_event_string(record, "event_stream_id").as_deref()
                        == Some(request.event_stream_id.as_str())
                }
                "turn" => optional_event_string(record, "turn_id") == request.turn_id,
                _ => false,
            })
            .map(|(event, record)| {
                validate_admitted_replay_event(record)?;
                Ok(event.clone())
            })
            .collect::<Result<Vec<_>, RuntimeThreadEventAdmissionError>>()?;
        selected.sort_by_key(|event| event.as_object().and_then(event_seq).unwrap_or(0));

        let selected_latest_seq = selected
            .iter()
            .filter_map(|event| event.as_object().and_then(event_seq))
            .max()
            .unwrap_or(0);
        let latest_seq = request.latest_seq.unwrap_or(selected_latest_seq);
        let cursor_seq = if request.replay_kind == "turn" && selected.is_empty() {
            0
        } else {
            cursor_seq_for_replay(request, &selected, latest_seq)?
        };
        let events = selected
            .into_iter()
            .filter(|event| event.as_object().and_then(event_seq).unwrap_or(0) > cursor_seq)
            .collect::<Vec<_>>();
        let last_event = events
            .last()
            .and_then(Value::as_object)
            .or_else(|| replay_events.last().and_then(Value::as_object));
        let event_stream_id = if request.event_stream_id.trim().is_empty() {
            last_event
                .and_then(|event| optional_event_string(event, "event_stream_id"))
                .unwrap_or_default()
        } else {
            request.event_stream_id.clone()
        };
        let resulting_seq = events
            .iter()
            .filter_map(|event| event.as_object().and_then(event_seq))
            .max()
            .unwrap_or(latest_seq);
        let resulting_head = last_event
            .and_then(|event| optional_event_string(event, "resulting_head"))
            .unwrap_or_else(|| {
                format!(
                    "agentgres://runtime-events/{}/head/{}",
                    safe_component(&event_stream_id),
                    resulting_seq
                )
            });
        let state_root_after = last_event
            .and_then(|event| optional_event_string(event, "state_root_after"))
            .unwrap_or_else(|| default_state_root_before(&event_stream_id, resulting_seq));
        let projection_watermark = last_event
            .and_then(|event| optional_event_string(event, "projection_watermark"))
            .unwrap_or_else(|| format!("runtime-events:{event_stream_id}:{resulting_seq}"));
        let receipt_refs = unique_trimmed_strings(
            events
                .iter()
                .filter_map(Value::as_object)
                .flat_map(|event| json_string_array_from_map(event, "receipt_refs"))
                .collect(),
        );
        let artifact_refs = unique_trimmed_strings(
            events
                .iter()
                .filter_map(Value::as_object)
                .flat_map(|event| json_string_array_from_map(event, "artifact_refs"))
                .collect(),
        );
        let payload_refs = unique_trimmed_strings(
            events
                .iter()
                .filter_map(Value::as_object)
                .flat_map(|event| json_string_array_from_map(event, "payload_refs"))
                .collect(),
        );
        let mut record = RuntimeThreadEventReplayRecord {
            schema_version: RUNTIME_THREAD_EVENT_REPLAY_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_thread_event_replay".to_string(),
            status: "projected".to_string(),
            operation_kind: "runtime.thread_event_replay".to_string(),
            replay_kind: request.replay_kind.clone(),
            event_stream_id,
            turn_id: request.turn_id.clone(),
            event_count: events.len(),
            latest_seq,
            cursor_seq,
            resulting_seq,
            resulting_head,
            state_root_after,
            projection_watermark,
            receipt_refs,
            artifact_refs,
            payload_refs,
            events,
            replay_hash: String::new(),
        };
        record.replay_hash =
            value_hash(&serde_json::to_value(&record).map_err(|error| {
                RuntimeThreadEventAdmissionError::HashFailed(error.to_string())
            })?)?;
        Ok(record)
    }

    pub fn project_thread_turn(
        &self,
        request: &RuntimeThreadTurnProjectionRequest,
    ) -> Result<RuntimeThreadTurnProjectionRecord, RuntimeThreadEventAdmissionError> {
        request.validate_thread_turn_projection()?;
        let record = match request.projection_kind.as_str() {
            "thread" => {
                let agent = request
                    .agent
                    .as_ref()
                    .and_then(Value::as_object)
                    .ok_or(RuntimeThreadEventAdmissionError::MissingField("agent"))?;
                thread_projection_record(request, agent)?
            }
            "turn" => {
                let run = request
                    .run
                    .as_ref()
                    .and_then(Value::as_object)
                    .ok_or(RuntimeThreadEventAdmissionError::MissingField("run"))?;
                turn_projection_record(request, run)?
            }
            other => {
                return Err(
                    RuntimeThreadEventAdmissionError::InvalidThreadTurnProjectionKind(
                        other.to_string(),
                    ),
                )
            }
        };
        let mut projection = RuntimeThreadTurnProjectionRecord {
            schema_version: RUNTIME_THREAD_TURN_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_thread_turn_projection".to_string(),
            status: "projected".to_string(),
            operation_kind: "runtime.thread_turn_projection".to_string(),
            projection_kind: request.projection_kind.clone(),
            thread_id: request.thread_id.clone(),
            turn_id: request.turn_id.clone(),
            event_count: request.events.len(),
            latest_seq: request.latest_seq.unwrap_or_else(|| {
                request
                    .events
                    .iter()
                    .filter_map(|event| event.as_object().and_then(event_seq))
                    .max()
                    .unwrap_or(0)
            }),
            record,
            projection_hash: String::new(),
        };
        projection.projection_hash =
            value_hash(&serde_json::to_value(&projection).map_err(|error| {
                RuntimeThreadEventAdmissionError::HashFailed(error.to_string())
            })?)?;
        Ok(projection)
    }

    fn projection_candidates(
        &self,
        request: &RuntimeThreadEventProjectionRequest,
    ) -> Result<Vec<Value>, RuntimeThreadEventAdmissionError> {
        let mut candidates = Vec::new();
        if request.projection_kind == "thread" || request.projection_kind == "thread_started" {
            let agent = request
                .agent
                .as_ref()
                .and_then(Value::as_object)
                .ok_or(RuntimeThreadEventAdmissionError::MissingField("agent"))?;
            candidates.push(thread_started_event(request, agent)?);
        }
        if request.projection_kind == "thread" || request.projection_kind == "run" {
            for run in &request.runs {
                let run = run
                    .as_object()
                    .ok_or(RuntimeThreadEventAdmissionError::MissingField("run"))?;
                for (index, event) in run_event_values(run).iter().enumerate() {
                    let event = event
                        .as_object()
                        .ok_or(RuntimeThreadEventAdmissionError::MissingField("run_event"))?;
                    candidates.push(run_thread_event(request, run, event, index)?);
                }
            }
        }
        Ok(candidates)
    }
}

pub fn admit_runtime_thread_event_response(
    request: RuntimeThreadEventAdmissionProtocolRequest,
) -> Result<Value, RuntimeThreadEventAdmissionError> {
    let record = RuntimeThreadEventAdmissionCore.admit(&request.request)?;
    Ok(json!({
        "source": "rust_runtime_thread_event_admission_protocol",
        "backend": "rust_runtime_agentgres",
        "admitted": true,
        "record": record,
        "event": record.event,
        "event_id": record.event_id,
        "seq": record.seq,
        "operation_kind": record.operation_kind,
        "operation_ref": record.operation_ref,
        "state_root_before": record.state_root_before,
        "state_root_after": record.state_root_after,
        "resulting_head": record.resulting_head,
        "projection_watermark": record.projection_watermark,
        "payload_refs": record.payload_refs,
        "receipt_refs": record.receipt_refs,
        "artifact_refs": record.artifact_refs,
        "rollback_refs": record.rollback_refs,
        "admission_hash": record.admission_hash,
        "storage_admission": record.storage_admission,
    }))
}

pub fn project_runtime_thread_events_response(
    request: RuntimeThreadEventProjectionProtocolRequest,
) -> Result<Value, RuntimeThreadEventAdmissionError> {
    let record = RuntimeThreadEventAdmissionCore.project(&request.request)?;
    Ok(json!({
        "source": "rust_runtime_thread_event_projection_protocol",
        "backend": "rust_runtime_agentgres",
        "projected": true,
        "record": record,
        "events": record.events,
        "admissions": record.admissions,
        "event_count": record.event_count,
        "skipped_count": record.skipped_count,
        "operation_kind": record.operation_kind,
        "projection_kind": record.projection_kind,
        "resulting_seq": record.resulting_seq,
        "resulting_head": record.resulting_head,
        "state_root_after": record.state_root_after,
        "projection_watermark": record.projection_watermark,
        "payload_refs": record.payload_refs,
        "receipt_refs": record.receipt_refs,
        "artifact_refs": record.artifact_refs,
        "projection_hash": record.projection_hash,
    }))
}

pub fn project_runtime_thread_event_replay_response(
    request: RuntimeThreadEventReplayProtocolRequest,
) -> Result<Value, RuntimeThreadEventAdmissionError> {
    let record = RuntimeThreadEventAdmissionCore.replay(&request.request)?;
    Ok(json!({
        "source": "rust_runtime_thread_event_replay_protocol",
        "backend": "rust_runtime_agentgres",
        "projected": true,
        "record": record,
        "events": record.events,
        "event_count": record.event_count,
        "operation_kind": record.operation_kind,
        "replay_kind": record.replay_kind,
        "latest_seq": record.latest_seq,
        "cursor_seq": record.cursor_seq,
        "resulting_seq": record.resulting_seq,
        "resulting_head": record.resulting_head,
        "state_root_after": record.state_root_after,
        "projection_watermark": record.projection_watermark,
        "payload_refs": record.payload_refs,
        "receipt_refs": record.receipt_refs,
        "artifact_refs": record.artifact_refs,
        "replay_hash": record.replay_hash,
    }))
}

pub fn project_runtime_thread_turn_projection_response(
    request: RuntimeThreadTurnProjectionProtocolRequest,
) -> Result<Value, RuntimeThreadEventAdmissionError> {
    let record = RuntimeThreadEventAdmissionCore.project_thread_turn(&request.request)?;
    Ok(json!({
        "source": "rust_runtime_thread_turn_projection_protocol",
        "backend": "rust_runtime_agentgres",
        "projected": true,
        "record": record.record,
        "projection": record,
        "event_count": record.event_count,
        "operation_kind": record.operation_kind,
        "projection_kind": record.projection_kind,
        "thread_id": record.thread_id,
        "turn_id": record.turn_id,
        "latest_seq": record.latest_seq,
        "projection_hash": record.projection_hash,
    }))
}

impl RuntimeThreadEventAdmissionRequest {
    pub fn validate(&self) -> Result<(), RuntimeThreadEventAdmissionError> {
        if self.schema_version != RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION {
            return Err(RuntimeThreadEventAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        let event = self
            .event
            .as_object()
            .ok_or(RuntimeThreadEventAdmissionError::MissingField("event"))?;
        for field in [
            "event_stream_id",
            "thread_id",
            "idempotency_key",
            "event_kind",
        ] {
            if optional_event_string(event, field).is_none() {
                return Err(RuntimeThreadEventAdmissionError::MissingField(field));
            }
        }
        Ok(())
    }
}

impl RuntimeThreadEventProjectionRequest {
    pub fn validate_projection(&self) -> Result<(), RuntimeThreadEventAdmissionError> {
        if self.schema_version != RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(RuntimeThreadEventAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if self.thread_id.trim().is_empty() {
            return Err(RuntimeThreadEventAdmissionError::MissingField("thread_id"));
        }
        if self.event_stream_id.trim().is_empty() {
            return Err(RuntimeThreadEventAdmissionError::MissingField(
                "event_stream_id",
            ));
        }
        match self.projection_kind.as_str() {
            "thread" | "thread_started" | "run" => Ok(()),
            other => Err(RuntimeThreadEventAdmissionError::InvalidProjectionKind(
                other.to_string(),
            )),
        }
    }
}

impl RuntimeThreadEventReplayRequest {
    pub fn validate_replay(&self) -> Result<(), RuntimeThreadEventAdmissionError> {
        if self.schema_version != RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION {
            return Err(RuntimeThreadEventAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        validate_cursor_shape(self.cursor.as_ref())?;
        if !self.events.is_empty() {
            return Err(RuntimeThreadEventAdmissionError::RetiredReplayEventTransport);
        }
        match self.replay_kind.as_str() {
            "stream" => {
                if self.event_stream_id.trim().is_empty() {
                    return Err(RuntimeThreadEventAdmissionError::MissingField(
                        "event_stream_id",
                    ));
                }
                Ok(())
            }
            "turn" => {
                if self
                    .turn_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_none()
                {
                    return Err(RuntimeThreadEventAdmissionError::MissingField("turn_id"));
                }
                Ok(())
            }
            other => Err(RuntimeThreadEventAdmissionError::InvalidReplayKind(
                other.to_string(),
            )),
        }
    }
}

fn runtime_thread_replay_events_from_state_dir(
    request: &RuntimeThreadEventReplayRequest,
) -> Result<Vec<Value>, RuntimeThreadEventAdmissionError> {
    let state_dir = optional_trimmed(request.state_dir.as_deref())
        .ok_or(RuntimeThreadEventAdmissionError::ReplayStateDirRequired)?;
    let events_dir = Path::new(&state_dir).join("events");
    if !events_dir.exists() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(&events_dir).map_err(|error| {
        RuntimeThreadEventAdmissionError::ReplayReadFailed(format!(
            "runtime thread-event replay could not read Agentgres events: {error}"
        ))
    })?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            RuntimeThreadEventAdmissionError::ReplayReadFailed(format!(
                "runtime thread-event replay could not inspect Agentgres event entry: {error}"
            ))
        })?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|value| value.to_str()) == Some("jsonl") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut events = Vec::new();
    for path in paths {
        let contents = fs::read_to_string(&path).map_err(|error| {
            RuntimeThreadEventAdmissionError::ReplayReadFailed(format!(
                "runtime thread-event replay could not read Agentgres event record {}: {error}",
                path.display()
            ))
        })?;
        for (index, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let event: Value = serde_json::from_str(line).map_err(|error| {
                RuntimeThreadEventAdmissionError::ReplayRecordInvalid(format!(
                    "runtime thread-event replay found invalid Agentgres event record {}:{}: {error}",
                    path.display(),
                    index + 1
                ))
            })?;
            events.push(event);
        }
    }
    events.sort_by_key(|event| event.as_object().and_then(event_seq).unwrap_or(0));
    Ok(events)
}

impl RuntimeThreadTurnProjectionRequest {
    pub fn validate_thread_turn_projection(&self) -> Result<(), RuntimeThreadEventAdmissionError> {
        if self.schema_version != RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(RuntimeThreadEventAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if self.thread_id.trim().is_empty() {
            return Err(RuntimeThreadEventAdmissionError::MissingField("thread_id"));
        }
        match self.projection_kind.as_str() {
            "thread" => Ok(()),
            "turn" => {
                if self
                    .turn_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_none()
                {
                    return Err(RuntimeThreadEventAdmissionError::MissingField("turn_id"));
                }
                Ok(())
            }
            other => Err(
                RuntimeThreadEventAdmissionError::InvalidThreadTurnProjectionKind(
                    other.to_string(),
                ),
            ),
        }
    }
}

fn required_event_string(
    event: &Map<String, Value>,
    field: &'static str,
) -> Result<String, RuntimeThreadEventAdmissionError> {
    optional_event_string(event, field).ok_or(RuntimeThreadEventAdmissionError::MissingField(field))
}

fn optional_event_string(event: &Map<String, Value>, field: &str) -> Option<String> {
    event
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn optional_json_string(map: &Map<String, Value>, fields: &[&str]) -> Option<String> {
    fields
        .iter()
        .find_map(|field| optional_event_string(map, field))
}

fn thread_projection_record(
    request: &RuntimeThreadTurnProjectionRequest,
    agent: &Map<String, Value>,
) -> Result<Value, RuntimeThreadEventAdmissionError> {
    let agent_id = optional_json_string(agent, &["agent_id", "id"])
        .ok_or(RuntimeThreadEventAdmissionError::MissingField("agent_id"))?;
    let latest_run = latest_run_for_thread(request);
    let runtime_controls = request
        .runtime_controls
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let usage = request.usage_telemetry.clone().unwrap_or_else(|| json!({}));
    let latest_run_id = latest_run
        .as_ref()
        .and_then(|run| optional_json_string(run, &["run_id", "id"]));
    let latest_turn_id = latest_run
        .as_ref()
        .and_then(|run| optional_json_string(run, &["turn_id"]))
        .or_else(|| latest_run_id.as_deref().map(turn_id_for_run));
    let latest_run_status = latest_run
        .as_ref()
        .and_then(|run| optional_json_string(run, &["turn_status", "status"]));
    let status = if latest_run_status.as_deref() == Some("interrupted") {
        "interrupted".to_string()
    } else {
        thread_status_for_agent(optional_json_string(agent, &["status"]).as_deref()).to_string()
    };
    let created_at = optional_json_string(agent, &["created_at"])
        .ok_or(RuntimeThreadEventAdmissionError::MissingField("created_at"))?;
    let updated_at = latest_run
        .as_ref()
        .and_then(|run| optional_json_string(run, &["updated_at"]))
        .or_else(|| optional_json_string(agent, &["updated_at"]))
        .unwrap_or_else(|| created_at.clone());
    let workspace_root =
        optional_json_string(agent, &["workspace_root", "cwd"]).unwrap_or_default();
    let title = latest_run
        .as_ref()
        .and_then(|run| optional_json_string(run, &["objective", "title"]))
        .unwrap_or_else(|| workspace_root.clone());
    let model_route_decision = agent
        .get("model_route_decision")
        .cloned()
        .unwrap_or(Value::Null);
    let reasoning_effort = model_route_decision
        .as_object()
        .and_then(|decision| optional_json_string(decision, &["reasoning_effort"]));
    Ok(json!({
        "schema_version": request.thread_schema_version.as_deref().unwrap_or("ioi.runtime.thread.v1"),
        "thread_id": request.thread_id,
        "session_id": request.session_id,
        "agent_id": agent_id,
        "workspace_root": workspace_root,
        "title": title,
        "mode": optional_json_string(&runtime_controls, &["mode"]).unwrap_or_else(|| "agent".to_string()),
        "approval_mode": optional_json_string(&runtime_controls, &["approval_mode"]).unwrap_or_else(|| "suggest".to_string()),
        "trust_profile": "local_private",
        "model_route": optional_json_string(agent, &["model_route", "model_id", "modelId"]),
        "status": status,
        "latest_turn_id": latest_turn_id,
        "latest_seq": request.latest_seq.unwrap_or(0),
        "event_stream_id": request.event_stream_id,
        "workflow_graph_id": Value::Null,
        "harness_binding_id": Value::Null,
        "agentgres_projection_ref": format!("agents/{agent_id}.json"),
        "created_at": created_at,
        "updated_at": updated_at,
        "archived_at": if optional_json_string(agent, &["status"]).as_deref() == Some("archived") {
            optional_json_string(agent, &["updated_at"])
        } else {
            None
        },
        "fixture_profile": request.fixture_profile,
        "created_at_ms": request.created_at_ms.unwrap_or(0),
        "updated_at_ms": request.updated_at_ms.unwrap_or(0),
        "workspace": workspace_root,
        "requested_model": optional_json_string(agent, &["requested_model_id", "model_id"]).unwrap_or_else(|| "auto".to_string()),
        "model_route_id": optional_json_string(agent, &["model_route_id"]),
        "model_route_receipt_id": optional_json_string(agent, &["model_route_receipt_id"]),
        "model_route_decision": model_route_decision,
        "selected_model": optional_json_string(agent, &["model_id"]).unwrap_or_else(|| "auto".to_string()),
        "reasoning_effort": reasoning_effort,
        "runtime_controls": Value::Object(runtime_controls),
        "memory_count": request.memory_count.unwrap_or(0),
        "archived": optional_json_string(agent, &["status"]).as_deref() == Some("archived"),
        "evidence_refs": ["agentgres_canonical_state_projection", "rust_runtime_thread_turn_projection"],
        "runtime_profile": request.runtime_profile.as_deref().unwrap_or("fixture"),
        "runtime_bridge_id": request.runtime_bridge_id,
        "runtime_bridge_source": request.runtime_bridge_source,
        "usage": usage,
        "usage_telemetry": usage,
    }))
}

fn turn_projection_record(
    request: &RuntimeThreadTurnProjectionRequest,
    run: &Map<String, Value>,
) -> Result<Value, RuntimeThreadEventAdmissionError> {
    let run_id = optional_json_string(run, &["run_id", "id"])
        .ok_or(RuntimeThreadEventAdmissionError::MissingField("run_id"))?;
    let turn_id = request
        .turn_id
        .clone()
        .or_else(|| optional_json_string(run, &["turn_id"]))
        .unwrap_or_else(|| turn_id_for_run(&run_id));
    let status = request
        .status
        .clone()
        .or_else(|| optional_json_string(run, &["status"]))
        .unwrap_or_else(|| "running".to_string());
    let is_open = matches!(
        status.as_str(),
        "queued" | "running" | "waiting_for_approval" | "waiting_for_input"
    );
    let event_objects = request
        .events
        .iter()
        .filter_map(Value::as_object)
        .collect::<Vec<_>>();
    let seq_start = event_objects
        .iter()
        .filter_map(|event| event_seq(event))
        .min();
    let seq_end = if is_open {
        None
    } else {
        event_objects
            .iter()
            .filter_map(|event| event_seq(event))
            .max()
    };
    let input_item_ids = event_objects
        .iter()
        .filter(|event| {
            optional_event_string(event, "event_kind").as_deref() == Some("turn.started")
        })
        .filter_map(|event| optional_event_string(event, "item_id"))
        .collect::<Vec<_>>();
    let output_item_ids = event_objects
        .iter()
        .filter(|event| {
            optional_event_string(event, "event_kind").as_deref() != Some("turn.started")
        })
        .filter_map(|event| optional_event_string(event, "item_id"))
        .collect::<Vec<_>>();
    let trace = run
        .get("trace")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let stop_condition = trace
        .get("stop_condition")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let quality_ledger = trace
        .get("quality_ledger")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let usage = request.usage_telemetry.clone().unwrap_or_else(|| json!({}));
    Ok(json!({
        "schema_version": request.turn_schema_version.as_deref().unwrap_or("ioi.runtime.turn.v1"),
        "turn_id": turn_id,
        "thread_id": request.thread_id,
        "parent_turn_id": Value::Null,
        "request_id": run_id,
        "status": status,
        "input_item_ids": input_item_ids,
        "output_item_ids": output_item_ids,
        "events": request.events,
        "seq_start": seq_start,
        "seq_end": seq_end,
        "started_at": optional_json_string(run, &["created_at"]),
        "completed_at": if is_open { None } else { request.completed_at.clone().or_else(|| optional_json_string(run, &["updated_at"])) },
        "mode": request.mode.as_deref().unwrap_or("agent"),
        "approval_mode": request.approval_mode.as_deref().unwrap_or("suggest"),
        "model_route_decision_id": optional_json_string(run, &["model_route_decision_id"]),
        "usage": usage,
        "usage_telemetry": usage,
        "result": optional_json_string(run, &["result"]).unwrap_or_default(),
        "output": optional_json_string(run, &["result"]).unwrap_or_default(),
        "text": optional_json_string(run, &["result"]).unwrap_or_default(),
        "stop_reason": optional_json_string(&stop_condition, &["reason"]),
        "error": if optional_json_string(run, &["status"]).as_deref() == Some("failed") {
            optional_json_string(run, &["result"])
        } else {
            None
        },
        "conversation": run.get("conversation").cloned().unwrap_or_else(|| json!([])),
        "rollback_snapshot_id": Value::Null,
        "quality_ledger_ref": optional_json_string(&quality_ledger, &["ledger_id"]),
        "workflow_execution_ref": Value::Null,
        "fixture_profile": request.fixture_profile,
        "started_at_ms": request.created_at_ms.unwrap_or(0),
        "completed_at_ms": if is_open { None } else { request.updated_at_ms },
        "error_summary": if optional_json_string(run, &["status"]).as_deref() == Some("failed") {
            optional_json_string(run, &["result"])
        } else {
            None
        },
        "model_route_decision": run.get("model_route_decision").cloned().unwrap_or(Value::Null),
        "model_route_receipt_id": optional_json_string(run, &["model_route_receipt_id"]),
        "active_skill_hook_manifest_ref": optional_json_string(run, &["active_skill_hook_manifest_ref"]),
        "active_skill_set_hash": optional_json_string(run, &["active_skill_set_hash"]),
        "active_hook_set_hash": optional_json_string(run, &["active_hook_set_hash"]),
        "memory_refs": json_string_array_from_map(run, "memory_refs"),
        "memory_write_receipt_ids": json_string_array_from_map(run, "memory_write_receipt_ids"),
        "evidence_refs": unique_trimmed_strings(vec![
            "agentgres_canonical_state_projection".to_string(),
            format!("run:{run_id}"),
            optional_json_string(run, &["active_skill_hook_manifest_ref"]).unwrap_or_default(),
        ]),
    }))
}

fn latest_run_for_thread(
    request: &RuntimeThreadTurnProjectionRequest,
) -> Option<Map<String, Value>> {
    request
        .runs
        .iter()
        .filter_map(Value::as_object)
        .cloned()
        .last()
}

fn validate_cursor_shape(cursor: Option<&Value>) -> Result<(), RuntimeThreadEventAdmissionError> {
    let Some(cursor) = cursor else {
        return Ok(());
    };
    let Some(cursor) = cursor.as_object() else {
        return Ok(());
    };
    for retired_alias in ["sinceSeq", "lastEventId"] {
        if cursor.contains_key(retired_alias) {
            return Err(RuntimeThreadEventAdmissionError::InvalidCursorField(
                retired_alias.to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_admitted_replay_event(
    event: &Map<String, Value>,
) -> Result<(), RuntimeThreadEventAdmissionError> {
    for field in [
        "event_id",
        "event_stream_id",
        "agentgres_operation_ref",
        "state_root_after",
        "resulting_head",
        "projection_watermark",
    ] {
        if optional_event_string(event, field).is_none() {
            return Err(RuntimeThreadEventAdmissionError::MissingField(field));
        }
    }
    if event_seq(event).is_none() {
        return Err(RuntimeThreadEventAdmissionError::MissingField("seq"));
    }
    if json_string_array_from_map(event, "receipt_refs").is_empty() {
        return Err(RuntimeThreadEventAdmissionError::MissingReceiptRefs);
    }
    Ok(())
}

fn event_seq(event: &Map<String, Value>) -> Option<u64> {
    event.get("seq").and_then(Value::as_u64)
}

fn cursor_seq_for_replay(
    request: &RuntimeThreadEventReplayRequest,
    selected: &[Value],
    latest_seq: u64,
) -> Result<u64, RuntimeThreadEventAdmissionError> {
    let cursor = request.cursor.as_ref();
    let cursor_seq = match cursor {
        None | Some(Value::Null) => 0,
        Some(Value::Number(number)) => number.as_u64().unwrap_or(0),
        Some(Value::String(value)) => {
            cursor_seq_for_last_event_id(request, selected, value, latest_seq)?
        }
        Some(Value::Object(cursor)) => {
            if let Some(value) = cursor.get("since_seq") {
                value.as_u64().unwrap_or(0)
            } else {
                let last_event_id = cursor
                    .get("last_event_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .unwrap_or_default();
                if last_event_id.is_empty() {
                    0
                } else {
                    cursor_seq_for_last_event_id(request, selected, last_event_id, latest_seq)?
                }
            }
        }
        _ => 0,
    };
    if cursor_seq > latest_seq {
        return Err(RuntimeThreadEventAdmissionError::CursorOutOfRange {
            event_stream_id: replay_event_stream_id(request, selected),
            last_event_id: None,
            since_seq: Some(cursor_seq),
            latest_seq,
        });
    }
    Ok(cursor_seq)
}

fn cursor_seq_for_last_event_id(
    request: &RuntimeThreadEventReplayRequest,
    selected: &[Value],
    last_event_id: &str,
    latest_seq: u64,
) -> Result<u64, RuntimeThreadEventAdmissionError> {
    if last_event_id.chars().all(|ch| ch.is_ascii_digit()) {
        return Ok(last_event_id.parse::<u64>().unwrap_or(0));
    }
    selected
        .iter()
        .filter_map(Value::as_object)
        .find(|event| optional_event_string(event, "event_id").as_deref() == Some(last_event_id))
        .and_then(event_seq)
        .ok_or_else(|| RuntimeThreadEventAdmissionError::CursorOutOfRange {
            event_stream_id: replay_event_stream_id(request, selected),
            last_event_id: Some(last_event_id.to_string()),
            since_seq: None,
            latest_seq,
        })
}

fn replay_event_stream_id(
    request: &RuntimeThreadEventReplayRequest,
    selected: &[Value],
) -> Option<String> {
    if !request.event_stream_id.trim().is_empty() {
        return Some(request.event_stream_id.clone());
    }
    selected
        .iter()
        .filter_map(Value::as_object)
        .find_map(|event| optional_event_string(event, "event_stream_id"))
}

fn thread_started_event(
    request: &RuntimeThreadEventProjectionRequest,
    agent: &Map<String, Value>,
) -> Result<Value, RuntimeThreadEventAdmissionError> {
    let agent_id = optional_json_string(agent, &["agent_id", "id"])
        .ok_or(RuntimeThreadEventAdmissionError::MissingField("agent_id"))?;
    let thread_status =
        thread_status_for_agent(optional_json_string(agent, &["status"]).as_deref());
    let workspace_root = request
        .workspace_root
        .clone()
        .or_else(|| optional_json_string(agent, &["workspace_root", "cwd"]))
        .unwrap_or_default();
    let created_at = optional_json_string(agent, &["created_at", "createdAt"])
        .or_else(|| optional_json_string(agent, &["updated_at", "updatedAt"]))
        .unwrap_or_else(|| "rust_daemon_core".to_string());
    let receipt_refs = unique_trimmed_strings(
        json_string_array_from_map(agent, "receipt_refs")
            .into_iter()
            .chain(optional_json_string(
                agent,
                &[
                    "model_route_receipt_id",
                    "agentgres_state_receipt_ref",
                    "authority_receipt_ref",
                ],
            ))
            .collect(),
    );
    let fixture_profile = optional_json_string(agent, &["fixture_profile"])
        .unwrap_or_else(|| "local_daemon_agentgres_projection".to_string());
    let payload = json!({
        "schema_version": "ioi.runtime.thread.v1",
        "object": "ioi.runtime_thread_started",
        "agent_id": agent_id,
        "thread_id": request.thread_id,
        "status": thread_status,
        "workspace_root": workspace_root,
        "receipt_refs": receipt_refs,
    });
    Ok(json!({
        "schema_version": "ioi.runtime.event.v1",
        "event_stream_id": request.event_stream_id,
        "thread_id": request.thread_id,
        "turn_id": "",
        "item_id": format!("{}:item:thread-started", request.thread_id),
        "idempotency_key": format!("thread:{}:started", request.thread_id),
        "source": "rust_daemon_core",
        "source_event_kind": "Thread.Started",
        "event_kind": "thread.started",
        "status": "completed",
        "actor": "runtime",
        "created_at": created_at,
        "workspace_root": workspace_root,
        "workflow_graph_id": Value::Null,
        "workflow_node_id": "runtime.thread-start",
        "component_kind": "thread_lifecycle",
        "tool_call_id": Value::Null,
        "approval_id": Value::Null,
        "policy_decision_refs": [],
        "rollback_refs": [],
        "payload_schema_version": "ioi.runtime.thread.v1",
        "payload": payload,
        "payload_summary": payload,
        "payload_ref": Value::Null,
        "receipt_refs": receipt_refs,
        "artifact_refs": [],
        "redaction_profile": "internal",
        "fixture_profile": fixture_profile,
    }))
}

fn run_thread_event(
    request: &RuntimeThreadEventProjectionRequest,
    run: &Map<String, Value>,
    event: &Map<String, Value>,
    index: usize,
) -> Result<Value, RuntimeThreadEventAdmissionError> {
    let run_id = optional_json_string(run, &["run_id", "id"])
        .ok_or(RuntimeThreadEventAdmissionError::MissingField("run_id"))?;
    let turn_id = optional_json_string(run, &["turn_id", "runtime_turn_id", "runtimeTurnId"])
        .unwrap_or_else(|| turn_id_for_run(&run_id));
    let event_type = optional_json_string(event, &["type", "event_type", "event_kind"])
        .unwrap_or_else(|| "runtime_event".to_string());
    let event_identity = optional_json_string(event, &["id", "event_id"])
        .unwrap_or_else(|| format!("{}:{}", event_type, index + 1));
    let data = event
        .get("data")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let workspace_root = request
        .workspace_root
        .clone()
        .or_else(|| optional_json_string(run, &["workspace_root", "cwd"]))
        .unwrap_or_default();
    let created_at = optional_json_string(event, &["created_at", "createdAt"])
        .or_else(|| optional_json_string(run, &["created_at", "createdAt"]))
        .unwrap_or_else(|| "rust_daemon_core".to_string());
    let receipt_refs = unique_trimmed_strings(
        json_string_array_from_map(event, "receipt_refs")
            .into_iter()
            .chain(json_string_array_from_map(&data, "receipt_refs"))
            .chain(optional_json_string(event, &["receipt_id", "receipt_ref"]))
            .chain(optional_json_string(&data, &["receipt_id", "receipt_ref"]))
            .collect(),
    );
    let artifact_refs = unique_trimmed_strings(
        json_string_array_from_map(event, "artifact_refs")
            .into_iter()
            .chain(json_string_array_from_map(&data, "artifact_refs"))
            .chain(json_string_array_from_map(&data, "artifact_names"))
            .collect(),
    );
    let policy_decision_refs = unique_trimmed_strings(
        json_string_array_from_map(event, "policy_decision_refs")
            .into_iter()
            .chain(json_string_array_from_map(&data, "policy_decision_refs"))
            .chain(optional_json_string(
                &data,
                &[
                    "policy_decision_id",
                    "policy_decision_ref",
                    "computer_use_policy_decision_ref",
                ],
            ))
            .collect(),
    );
    let rollback_refs = unique_trimmed_strings(
        json_string_array_from_map(event, "rollback_refs")
            .into_iter()
            .chain(json_string_array_from_map(&data, "rollback_refs"))
            .collect(),
    );
    let mut payload = data;
    payload.insert("run_id".to_string(), Value::String(run_id.clone()));
    payload.insert("event_type".to_string(), Value::String(event_type.clone()));
    payload.insert(
        "event_id".to_string(),
        Value::String(event_identity.clone()),
    );
    payload.insert("receipt_refs".to_string(), json!(receipt_refs.clone()));
    let is_diagnostics_injection = event_type == "lsp_diagnostics_injected";
    let is_diagnostics_blocking_gate = event_type == "policy_blocked"
        && optional_json_string(&payload, &["reason"]).as_deref()
            == Some("post_edit_diagnostics_findings");
    let source_event_kind = if is_diagnostics_injection {
        "LspDiagnostics.Injected".to_string()
    } else if is_diagnostics_blocking_gate {
        "LspDiagnostics.BlockingGate".to_string()
    } else {
        format!("run.{event_type}")
    };
    let payload_schema_version = optional_json_string(&payload, &["schema_version"])
        .unwrap_or_else(|| {
            runtime_payload_schema_version(&event_type, is_diagnostics_blocking_gate)
        });
    let event_kind = runtime_event_kind_for_run_event(&event_type);
    Ok(json!({
        "schema_version": "ioi.runtime.event.v1",
        "event_stream_id": request.event_stream_id,
        "thread_id": request.thread_id,
        "turn_id": turn_id,
        "item_id": format!("{}:item:{}", turn_id, short_hash(&event_identity, 12)),
        "idempotency_key": format!("run:{}:event:{}", run_id, event_identity),
        "source": if is_diagnostics_injection || is_diagnostics_blocking_gate {
            "runtime_auto"
        } else {
            "rust_daemon_core"
        },
        "source_event_kind": source_event_kind,
        "event_kind": event_kind,
        "status": runtime_event_status_for_run_event(&event_type, &payload),
        "actor": if event_type == "delta" { "assistant" } else { "runtime" },
        "created_at": created_at,
        "workspace_root": workspace_root,
        "workflow_graph_id": payload.get("workflow_graph_id").cloned().unwrap_or(Value::Null),
        "workflow_node_id": optional_json_string(&payload, &["workflow_node_id"])
            .unwrap_or_else(|| workflow_node_for_run_event(&event_type, &payload)),
        "component_kind": component_kind_for_run_event(&event_type, &payload),
        "tool_call_id": payload.get("tool_call_id").cloned().unwrap_or(Value::Null),
        "approval_id": payload.get("approval_id").cloned().unwrap_or(Value::Null),
        "policy_decision_refs": policy_decision_refs,
        "rollback_refs": rollback_refs,
        "payload_schema_version": payload_schema_version,
        "payload": Value::Object(payload.clone()),
        "payload_summary": Value::Object(payload),
        "payload_ref": Value::Null,
        "receipt_refs": receipt_refs,
        "artifact_refs": artifact_refs,
        "redaction_profile": "internal",
        "fixture_profile": "local_daemon_agentgres_projection",
    }))
}

fn run_event_values(run: &Map<String, Value>) -> Vec<Value> {
    run.get("events")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn thread_status_for_agent(status: Option<&str>) -> &'static str {
    match status {
        Some("archived") | Some("closed") => "archived",
        Some("failed") | Some("error") => "failed",
        _ => "active",
    }
}

fn turn_id_for_run(run_id: &str) -> String {
    run_id
        .strip_prefix("run_")
        .map(|suffix| format!("turn_{suffix}"))
        .unwrap_or_else(|| format!("turn_{run_id}"))
}

fn runtime_event_kind_for_run_event(event_type: &str) -> String {
    match event_type {
        "run_started" => "turn.started",
        "job_queued" => "item.created",
        "job_started" => "item.started",
        "job_failed" => "item.failed",
        "job_canceled" => "item.canceled",
        "computer_use_environment_selected" => "computer_use.environment_selected",
        "computer_use_environment_unavailable" => "computer_use.environment_unavailable",
        "computer_use_lease_acquired" => "computer_use.lease_acquired",
        "computer_use_run_state" => "computer_use.run_state",
        "computer_use_observation" => "computer_use.observation",
        "computer_use_affordance_graph" => "computer_use.affordance_graph",
        "computer_use_browser_discovery" => "computer_use.browser_discovery",
        "computer_use_action_proposed" => "computer_use.action_proposed",
        "computer_use_action_executed" => "computer_use.action_executed",
        "computer_use_verification" => "computer_use.verification",
        "computer_use_commit_gate" => "computer_use.commit_gate",
        "computer_use_trajectory_written" => "computer_use.trajectory_written",
        "computer_use_cleanup" => "computer_use.cleanup",
        "computer_use_control" => "computer_use.control",
        "lsp_diagnostics_injected" => "lsp.diagnostics.injected",
        "policy_blocked" => "policy.blocked",
        "delta" => "item.delta",
        "usage_delta" => "usage.delta",
        "context_pressure_delta" => "context.pressure_delta",
        "context_pressure_alert" => "context.pressure_alert",
        "completed" => "turn.completed",
        "canceled" => "turn.canceled",
        "failed" | "error" => "turn.failed",
        value if value.contains('.') => value,
        value => return format!("item.{value}"),
    }
    .to_string()
}

fn runtime_event_status_for_run_event(
    event_type: &str,
    payload: &Map<String, Value>,
) -> &'static str {
    match event_type {
        "computer_use_environment_unavailable" => "blocked",
        "computer_use_action_executed"
        | "computer_use_verification"
        | "computer_use_commit_gate"
        | "computer_use_trajectory_written"
        | "computer_use_cleanup" => "completed",
        value if value.starts_with("computer_use_") => "running",
        "job_queued" => "queued",
        "job_started" | "run_started" | "delta" | "usage_delta" | "context_pressure_delta" => {
            "running"
        }
        "context_pressure_alert" => {
            if optional_json_string(payload, &["alert_level"]).as_deref() == Some("blocked") {
                "blocked"
            } else {
                "warning"
            }
        }
        "lsp_diagnostics_injected" => {
            if payload
                .get("blocking")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                && optional_json_string(payload, &["diagnostic_status"]).as_deref()
                    == Some("findings")
            {
                "blocked"
            } else {
                "completed"
            }
        }
        "policy_blocked" => "blocked",
        "canceled" | "job_canceled" => "canceled",
        "failed" | "error" | "job_failed" => "failed",
        _ => "completed",
    }
}

fn component_kind_for_run_event(event_type: &str, payload: &Map<String, Value>) -> String {
    if event_type.starts_with("computer_use_") {
        return "computer_use_harness".to_string();
    }
    match event_type {
        "runtime_task" => "runtime_task",
        "runtime_checklist" => "runtime_checklist",
        "job_queued" | "job_started" | "job_completed" | "job_failed" | "job_canceled" => {
            "runtime_job"
        }
        "repository_context" => "repository_context",
        "branch_policy" => "branch_policy",
        "github_context" => "github_context",
        "issue_context" => "issue_context",
        "pr_attempt" => "pr_attempt",
        "review_gate" => "review_gate",
        "github_pr_create_plan" => "github_pr_create",
        "model_route_decision" => "model_router",
        "skill_hook_manifest" => "skill_registry",
        "hook_dry_run_plan" => "hook_policy",
        "hook_invocation_ledger" => "hook_runtime",
        "memory_update" => match optional_json_string(payload, &["operation"]).as_deref() {
            Some("subagent_inheritance") => "subagent_memory",
            Some("policy_update") => "memory_policy",
            _ => "memory_write",
        },
        "lsp_diagnostics_injected" => "lsp_diagnostics",
        "policy_blocked" => {
            if let Some(component_kind) = optional_json_string(payload, &["component_kind"]) {
                return component_kind;
            }
            "policy_gate"
        }
        "task_state" => "task_state",
        "uncertainty" => "uncertainty_gate",
        "probe" => "probe_runner",
        "postcondition_synthesized" => "postcondition_synthesizer",
        "semantic_impact" => "semantic_impact_analyzer",
        "usage_delta" | "usage_final" => "usage_telemetry",
        "context_pressure_delta" => "context_pressure",
        "context_pressure_alert" => "context_pressure_alert",
        "quality_ledger" => "quality_ledger",
        "artifact" => "artifact_store",
        "completed" | "canceled" => "completion_gate",
        "delta" => "output_writer",
        "run_started" => "runtime_thread",
        _ => "runtime_thread",
    }
    .to_string()
}

fn workflow_node_for_run_event(event_type: &str, payload: &Map<String, Value>) -> String {
    optional_json_string(payload, &["workflow_node_id"]).unwrap_or_else(|| {
        format!(
            "runtime.{}",
            component_kind_for_run_event(event_type, payload).replace('_', "-")
        )
    })
}

fn runtime_payload_schema_version(event_type: &str, is_diagnostics_blocking_gate: bool) -> String {
    if event_type == "lsp_diagnostics_injected" {
        "ioi.runtime.lsp-diagnostics-injection.v1"
    } else if is_diagnostics_blocking_gate {
        "ioi.runtime.lsp-diagnostics-blocking-gate.v1"
    } else if event_type.starts_with("computer_use_") {
        "ioi.computer-use.contract.v1"
    } else {
        "ioi.runtime.event.v1"
    }
    .to_string()
}

fn default_state_root_before(event_stream_id: &str, latest_seq: u64) -> String {
    format!(
        "sha256:{}",
        sha256_hex(
            format!("runtime-thread-event-before:{event_stream_id}:{latest_seq}").as_bytes()
        )
    )
}

fn json_string_array_from_map(map: &Map<String, Value>, field: &str) -> Vec<String> {
    map.get(field)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn unique_trimmed_strings(values: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = trimmed.to_string();
        if !unique.contains(&normalized) {
            unique.push(normalized);
        }
    }
    unique
}

fn safe_component(value: &str) -> String {
    let mut output = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            output.push(ch);
        } else {
            output.push('_');
        }
    }
    if output.is_empty() {
        "runtime_event".to_string()
    } else {
        output
    }
}

fn short_hash(value: &str, chars: usize) -> String {
    sha256_hex(value.as_bytes()).chars().take(chars).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn value_hash(value: &Value) -> Result<String, RuntimeThreadEventAdmissionError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| RuntimeThreadEventAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", sha256_hex(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admission_request() -> RuntimeThreadEventAdmissionRequest {
        RuntimeThreadEventAdmissionRequest {
            schema_version: RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION.to_string(),
            event: json!({
                "event_stream_id": "thread_1:events",
                "thread_id": "thread_1",
                "turn_id": "turn_1",
                "item_id": "turn_1:item:operator:mode",
                "idempotency_key": "thread:thread_1:mode:review",
                "source_event_kind": "OperatorControl.Mode",
                "event_kind": "thread.mode_updated",
                "status": "completed",
                "actor": "operator",
                "payload_schema_version": "ioi.runtime.thread-control.v1",
                "payload_summary": {
                    "event_kind": "ThreadModeUpdated",
                    "receipt_refs": ["receipt_thread_control"]
                },
                "receipt_refs": ["receipt_thread_control"],
                "artifact_refs": [],
                "rollback_refs": []
            }),
            latest_seq: Some(4),
            expected_head: Some("agentgres://runtime-events/thread_1_events/head/4".to_string()),
            state_root_before: None,
        }
    }

    fn projection_request() -> RuntimeThreadEventProjectionRequest {
        RuntimeThreadEventProjectionRequest {
            schema_version: RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            projection_kind: "thread".to_string(),
            thread_id: "thread_1".to_string(),
            event_stream_id: "thread_1:events".to_string(),
            workspace_root: Some("/workspace".to_string()),
            agent: Some(json!({
                "agent_id": "agent_1",
                "status": "active",
                "created_at": "2026-06-12T00:00:00.000Z",
                "workspace_root": "/workspace",
                "receipt_refs": ["receipt_agent_state"],
                "model_route_receipt_id": "receipt_model_route"
            })),
            runs: vec![json!({
                "run_id": "run_1",
                "turn_id": "turn_1",
                "workspace_root": "/workspace",
                "events": [
                    {
                        "id": "event_run_started",
                        "type": "run_started",
                        "run_id": "run_1",
                        "created_at": "2026-06-12T00:00:01.000Z",
                        "data": {
                            "receipt_id": "receipt_run_policy",
                            "workflow_node_id": "runtime.runtime-thread"
                        }
                    },
                    {
                        "id": "event_run_completed",
                        "type": "completed",
                        "run_id": "run_1",
                        "created_at": "2026-06-12T00:00:02.000Z",
                        "data": {
                            "receipt_id": "receipt_run_agentgres",
                            "artifact_refs": ["result.txt"]
                        }
                    }
                ]
            })],
            latest_seq: Some(2),
            expected_head: Some("agentgres://runtime-events/thread_1_events/head/2".to_string()),
            state_root_before: None,
            existing_idempotency_keys: vec![],
        }
    }

    fn replay_request() -> RuntimeThreadEventReplayRequest {
        replay_request_with_events().0
    }

    fn replay_request_with_events() -> (RuntimeThreadEventReplayRequest, Vec<Value>) {
        let projection = RuntimeThreadEventAdmissionCore
            .project(&projection_request())
            .expect("projection provides admitted replay events");
        let events = projection.events;
        let state_dir = write_runtime_thread_event_state("replay", &events);
        (
            RuntimeThreadEventReplayRequest {
                schema_version: RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION.to_string(),
                replay_kind: "stream".to_string(),
                event_stream_id: "thread_1:events".to_string(),
                turn_id: None,
                cursor: None,
                state_dir: Some(state_dir.to_string_lossy().to_string()),
                events: vec![],
                latest_seq: Some(projection.resulting_seq),
            },
            events,
        )
    }

    fn write_runtime_thread_event_state(label: &str, events: &[Value]) -> std::path::PathBuf {
        let state_dir = std::env::temp_dir().join(format!(
            "ioi-runtime-thread-event-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        let events_dir = state_dir.join("events");
        std::fs::create_dir_all(&events_dir).expect("events dir");
        let contents = events
            .iter()
            .map(|event| serde_json::to_string(event).expect("event json"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(events_dir.join("thread_1.jsonl"), format!("{contents}\n"))
            .expect("write runtime events");
        state_dir
    }

    fn empty_replay_request() -> RuntimeThreadEventReplayRequest {
        RuntimeThreadEventReplayRequest {
            schema_version: RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION.to_string(),
            replay_kind: "stream".to_string(),
            event_stream_id: "thread_1:events".to_string(),
            turn_id: None,
            cursor: None,
            state_dir: None,
            events: vec![],
            latest_seq: None,
        }
    }

    fn thread_turn_projection_request(projection_kind: &str) -> RuntimeThreadTurnProjectionRequest {
        let event_projection = RuntimeThreadEventAdmissionCore
            .project(&projection_request())
            .expect("projection provides turn events");
        let resulting_seq = event_projection.resulting_seq;
        let events = if projection_kind == "turn" {
            event_projection
                .events
                .into_iter()
                .filter(|event| event["turn_id"].as_str() == Some("turn_1"))
                .collect()
        } else {
            event_projection.events
        };
        RuntimeThreadTurnProjectionRequest {
            schema_version: RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            projection_kind: projection_kind.to_string(),
            thread_schema_version: Some("thread.schema".to_string()),
            turn_schema_version: Some("turn.schema".to_string()),
            thread_id: "thread_1".to_string(),
            event_stream_id: "thread_1:events".to_string(),
            turn_id: Some("turn_1".to_string()),
            session_id: Some("session:agent_1".to_string()),
            fixture_profile: Some("fixture".to_string()),
            runtime_profile: Some("runtime_service".to_string()),
            runtime_bridge_id: Some("bridge_runtime".to_string()),
            runtime_bridge_source: Some("rust_core".to_string()),
            agent: Some(json!({
                "agent_id": "agent_1",
                "workspace_root": "/workspace",
                "status": "active",
                "model_id": "qwen",
                "requested_model_id": "auto",
                "model_route_id": "route.local-first",
                "model_route_receipt_id": "receipt-route",
                "model_route_decision": { "reasoning_effort": "medium" },
                "created_at": "2026-06-12T00:00:00.000Z",
                "updated_at": "2026-06-12T00:00:01.000Z"
            })),
            runs: vec![json!({
                "run_id": "run_1",
                "agent_id": "agent_1",
                "turn_id": "turn_1",
                "objective": "Latest",
                "status": "completed",
                "turn_status": "completed",
                "result": "Done",
                "created_at": "2026-06-12T00:00:01.000Z",
                "updated_at": "2026-06-12T00:00:02.000Z"
            })],
            run: Some(json!({
                "run_id": "run_1",
                "agent_id": "agent_1",
                "turn_id": "turn_1",
                "status": "completed",
                "result": "Done",
                "created_at": "2026-06-12T00:00:01.000Z",
                "updated_at": "2026-06-12T00:00:02.000Z",
                "trace": {
                    "stop_condition": { "reason": "final" },
                    "quality_ledger": { "ledger_id": "ledger-one" }
                },
                "active_skill_hook_manifest_ref": "manifest-one",
                "active_skill_set_hash": "skill-hash",
                "active_hook_set_hash": "hook-hash",
                "memory_refs": ["memory-one"],
                "memory_write_receipt_ids": ["receipt-memory"]
            })),
            events,
            runtime_controls: Some(json!({
                "mode": "agent",
                "approval_mode": "suggest",
                "model": { "reasoning_effort": "low" }
            })),
            usage_telemetry: Some(json!({ "scope": projection_kind, "total_tokens": 12 })),
            memory_count: Some(2),
            subagent_ids: vec!["sub_one".to_string()],
            latest_seq: Some(resulting_seq),
            created_at_ms: Some(1000),
            updated_at_ms: Some(2000),
            mode: Some("agent".to_string()),
            approval_mode: Some("suggest".to_string()),
            status: Some("completed".to_string()),
            completed_at: Some("2026-06-12T00:00:02.000Z".to_string()),
        }
    }

    #[test]
    fn rust_admits_runtime_thread_event_with_agentgres_refs() {
        let record = RuntimeThreadEventAdmissionCore
            .admit(&admission_request())
            .expect("runtime thread event admitted");

        assert_eq!(
            record.schema_version,
            RUNTIME_THREAD_EVENT_ADMISSION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.operation_kind, "runtime.thread_event");
        assert_eq!(record.event_stream_id, "thread_1:events");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.turn_id.as_deref(), Some("turn_1"));
        assert_eq!(record.seq, 5);
        assert_eq!(
            record.receipt_refs,
            vec!["receipt_thread_control".to_string()]
        );
        assert_eq!(
            record.payload_refs,
            vec![
                "payload://runtime-events/thread_1_events/events/".to_string()
                    + record.event_id.as_str()
            ]
        );
        assert_eq!(record.event["event_id"], record.event_id);
        assert_eq!(record.event["seq"], json!(5));
        assert_eq!(
            record.event["receipt_refs"],
            json!(["receipt_thread_control"])
        );
        assert_eq!(
            record.event["agentgres_operation_ref"],
            record.operation_ref
        );
        assert_eq!(
            record.storage_admission.storage_backend_ref,
            "agentgres://runtime-events"
        );
        assert!(record.admission_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_rejects_runtime_thread_event_without_receipts() {
        let mut request = admission_request();
        request.event["receipt_refs"] = json!([]);
        request.event["payload_summary"]["receipt_refs"] = json!([]);
        let error = RuntimeThreadEventAdmissionCore
            .admit(&request)
            .expect_err("receipt refs are required");
        assert_eq!(error, RuntimeThreadEventAdmissionError::MissingReceiptRefs);
    }

    #[test]
    fn rust_rejects_retired_runtime_thread_event_request_aliases() {
        let request: RuntimeThreadEventAdmissionRequest = serde_json::from_value(json!({
            "schema_version": RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
            "event": {
                "eventStreamId": "thread_1:events",
                "threadId": "thread_1",
                "idempotencyKey": "idem",
                "eventKind": "thread.mode_updated",
                "receiptRefs": ["receipt_retired"]
            }
        }))
        .expect("request parses with unknown aliases ignored");
        let error = RuntimeThreadEventAdmissionCore
            .admit(&request)
            .expect_err("retired aliases must not satisfy canonical event admission");
        assert_eq!(
            error,
            RuntimeThreadEventAdmissionError::MissingField("event_stream_id")
        );
    }

    #[test]
    fn rust_core_shapes_runtime_thread_event_admission_protocol_response() {
        let response =
            admit_runtime_thread_event_response(RuntimeThreadEventAdmissionProtocolRequest {
                request: admission_request(),
            })
            .expect("runtime thread event protocol response shaped");

        assert_eq!(
            response["source"],
            "rust_runtime_thread_event_admission_protocol"
        );
        assert_eq!(response["backend"], "rust_runtime_agentgres");
        assert_eq!(response["admitted"], true);
        assert_eq!(response["operation_kind"], "runtime.thread_event");
        assert_eq!(response["event"]["event_kind"], "thread.mode_updated");
        assert_eq!(response["receipt_refs"], json!(["receipt_thread_control"]));
    }

    #[test]
    fn rust_projects_thread_started_and_run_events_with_agentgres_refs() {
        let record = RuntimeThreadEventAdmissionCore
            .project(&projection_request())
            .expect("runtime thread projection admitted");

        assert_eq!(
            record.schema_version,
            RUNTIME_THREAD_EVENT_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.operation_kind, "runtime.thread_event_projection");
        assert_eq!(record.projection_kind, "thread");
        assert_eq!(record.event_count, 3);
        assert_eq!(record.skipped_count, 0);
        assert_eq!(record.latest_seq, 2);
        assert_eq!(record.resulting_seq, 5);
        assert_eq!(record.events[0]["event_kind"], "thread.started");
        assert_eq!(record.events[1]["event_kind"], "turn.started");
        assert_eq!(record.events[2]["event_kind"], "turn.completed");
        assert_eq!(
            record.receipt_refs,
            vec![
                "receipt_agent_state".to_string(),
                "receipt_model_route".to_string(),
                "receipt_run_policy".to_string(),
                "receipt_run_agentgres".to_string()
            ]
        );
        assert!(record.projection_hash.starts_with("sha256:"));
        assert!(record
            .events
            .iter()
            .all(|event| event["agentgres_operation_ref"].as_str().is_some()));
    }

    #[test]
    fn rust_projection_skips_existing_runtime_thread_event_idempotency() {
        let mut request = projection_request();
        request.existing_idempotency_keys = vec![
            "thread:thread_1:started".to_string(),
            "run:run_1:event:event_run_started".to_string(),
        ];
        let record = RuntimeThreadEventAdmissionCore
            .project(&request)
            .expect("runtime thread projection admits only missing events");

        assert_eq!(record.event_count, 1);
        assert_eq!(record.skipped_count, 2);
        assert_eq!(record.events[0]["event_kind"], "turn.completed");
        assert_eq!(record.resulting_seq, 3);
    }

    #[test]
    fn rust_rejects_retired_runtime_thread_event_projection_request_aliases() {
        let request: RuntimeThreadEventProjectionRequest = serde_json::from_value(json!({
            "schema_version": RUNTIME_THREAD_EVENT_PROJECTION_REQUEST_SCHEMA_VERSION,
            "projectionKind": "thread",
            "threadId": "thread_1",
            "eventStreamId": "thread_1:events",
            "agent": {
                "agentId": "agent_1",
                "receiptRefs": ["receipt_agent_state"]
            }
        }))
        .expect("request parses with unknown aliases ignored");
        let error = RuntimeThreadEventAdmissionCore
            .project(&request)
            .expect_err("retired aliases must not satisfy projection");
        assert_eq!(
            error,
            RuntimeThreadEventAdmissionError::MissingField("thread_id")
        );
    }

    #[test]
    fn rust_core_shapes_runtime_thread_event_projection_protocol_response() {
        let response =
            project_runtime_thread_events_response(RuntimeThreadEventProjectionProtocolRequest {
                request: projection_request(),
            })
            .expect("runtime thread event projection response shaped");

        assert_eq!(
            response["source"],
            "rust_runtime_thread_event_projection_protocol"
        );
        assert_eq!(response["backend"], "rust_runtime_agentgres");
        assert_eq!(response["projected"], true);
        assert_eq!(response["event_count"], 3);
        assert_eq!(response["events"][0]["event_kind"], "thread.started");
        assert_eq!(response["events"][2]["event_kind"], "turn.completed");
        assert_eq!(
            response["projection_hash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:"),
            true
        );
    }

    #[test]
    fn rust_replays_runtime_thread_events_by_stream_cursor() {
        let mut request = replay_request();
        request.cursor = Some(json!({ "since_seq": 3 }));

        let record = RuntimeThreadEventAdmissionCore
            .replay(&request)
            .expect("stream replay projected by Rust");

        assert_eq!(
            record.schema_version,
            RUNTIME_THREAD_EVENT_REPLAY_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.operation_kind, "runtime.thread_event_replay");
        assert_eq!(record.replay_kind, "stream");
        assert_eq!(record.event_count, 2);
        assert_eq!(record.cursor_seq, 3);
        assert_eq!(record.events[0]["event_kind"], "turn.started");
        assert_eq!(record.events[1]["event_kind"], "turn.completed");
        assert_eq!(
            record.receipt_refs,
            vec![
                "receipt_run_policy".to_string(),
                "receipt_run_agentgres".to_string()
            ]
        );
        assert!(record.replay_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_replays_runtime_thread_events_by_turn_cursor() {
        let (mut request, events) = replay_request_with_events();
        request.replay_kind = "turn".to_string();
        request.turn_id = Some("turn_1".to_string());
        request.event_stream_id = String::new();
        request.cursor = Some(json!({ "last_event_id": events[1]["event_id"] }));

        let record = RuntimeThreadEventAdmissionCore
            .replay(&request)
            .expect("turn replay projected by Rust");

        assert_eq!(record.replay_kind, "turn");
        assert_eq!(record.turn_id.as_deref(), Some("turn_1"));
        assert_eq!(record.event_count, 1);
        assert_eq!(record.cursor_seq, 4);
        assert_eq!(record.events[0]["event_kind"], "turn.completed");
        assert_eq!(record.event_stream_id, "thread_1:events");
    }

    #[test]
    fn rust_rejects_retired_runtime_thread_event_replay_cursor_aliases() {
        let request: RuntimeThreadEventReplayRequest = serde_json::from_value(json!({
            "schema_version": RUNTIME_THREAD_EVENT_REPLAY_REQUEST_SCHEMA_VERSION,
            "replay_kind": "stream",
            "event_stream_id": "thread_1:events",
            "cursor": { "sinceSeq": 1 },
            "events": []
        }))
        .expect("request parses with unknown aliases inside cursor");
        let error = RuntimeThreadEventAdmissionCore
            .replay(&request)
            .expect_err("retired cursor aliases must not satisfy replay");
        assert_eq!(
            error,
            RuntimeThreadEventAdmissionError::InvalidCursorField("sinceSeq".to_string())
        );
    }

    #[test]
    fn rust_requires_state_dir_for_runtime_thread_event_replay() {
        let request = empty_replay_request();
        let error = RuntimeThreadEventAdmissionCore
            .replay(&request)
            .expect_err("replay requires Agentgres state dir");
        assert_eq!(
            error,
            RuntimeThreadEventAdmissionError::ReplayStateDirRequired
        );
    }

    #[test]
    fn rust_rejects_retired_runtime_thread_event_replay_event_transport() {
        let mut request = empty_replay_request();
        request.state_dir = Some("/tmp/runtime-state".to_string());
        request.events = vec![json!({
            "event_id": "event_retired_transport",
            "event_stream_id": "thread_1:events",
            "thread_id": "thread_1",
            "turn_id": "turn_1",
            "event_kind": "turn.started",
            "seq": 1,
            "agentgres_operation_ref": "agentgres://runtime-events/thread_1/events/event_retired_transport",
            "receipt_refs": ["receipt_retired_transport"]
        })];
        let error = RuntimeThreadEventAdmissionCore
            .replay(&request)
            .expect_err("JS event candidates are retired for replay");
        assert_eq!(
            error,
            RuntimeThreadEventAdmissionError::RetiredReplayEventTransport
        );
    }

    #[test]
    fn rust_rejects_runtime_thread_event_replay_without_agentgres_refs() {
        let (mut request, mut events) = replay_request_with_events();
        events[0]
            .as_object_mut()
            .expect("event object")
            .remove("agentgres_operation_ref");
        let state_dir = write_runtime_thread_event_state("missing-agentgres-ref", &events);
        request.state_dir = Some(state_dir.to_string_lossy().to_string());
        let error = RuntimeThreadEventAdmissionCore
            .replay(&request)
            .expect_err("replay requires admitted Agentgres events");
        assert_eq!(
            error,
            RuntimeThreadEventAdmissionError::MissingField("agentgres_operation_ref")
        );
    }

    #[test]
    fn rust_core_shapes_runtime_thread_event_replay_protocol_response() {
        let response =
            project_runtime_thread_event_replay_response(RuntimeThreadEventReplayProtocolRequest {
                request: replay_request(),
            })
            .expect("runtime thread event replay response shaped");

        assert_eq!(
            response["source"],
            "rust_runtime_thread_event_replay_protocol"
        );
        assert_eq!(response["backend"], "rust_runtime_agentgres");
        assert_eq!(response["projected"], true);
        assert_eq!(response["event_count"], 3);
        assert_eq!(response["events"][0]["event_kind"], "thread.started");
        assert_eq!(
            response["replay_hash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:"),
            true
        );
    }

    #[test]
    fn rust_projects_runtime_thread_record_from_canonical_facts() {
        let record = RuntimeThreadEventAdmissionCore
            .project_thread_turn(&thread_turn_projection_request("thread"))
            .expect("thread projection is Rust-shaped");

        assert_eq!(record.operation_kind, "runtime.thread_turn_projection");
        assert_eq!(record.projection_kind, "thread");
        assert_eq!(record.record["schema_version"], "thread.schema");
        assert_eq!(record.record["thread_id"], "thread_1");
        assert_eq!(record.record["title"], "Latest");
        assert_eq!(record.record["latest_turn_id"], "turn_1");
        assert_eq!(record.record["latest_seq"], json!(5));
        assert_eq!(record.record["memory_count"], json!(2));
        assert_eq!(record.record["reasoning_effort"], "medium");
        assert_eq!(record.record["runtime_profile"], "runtime_service");
        assert_eq!(record.record["runtime_bridge_id"], "bridge_runtime");
        assert_eq!(record.record["usage"], record.record["usage_telemetry"]);
        assert!(record.projection_hash.starts_with("sha256:"));
    }

    #[test]
    fn rust_projects_runtime_turn_record_from_replay_events() {
        let record = RuntimeThreadEventAdmissionCore
            .project_thread_turn(&thread_turn_projection_request("turn"))
            .expect("turn projection is Rust-shaped");

        assert_eq!(record.projection_kind, "turn");
        assert_eq!(record.turn_id.as_deref(), Some("turn_1"));
        assert_eq!(record.record["schema_version"], "turn.schema");
        assert_eq!(record.record["turn_id"], "turn_1");
        assert_eq!(record.record["seq_start"], json!(4));
        assert_eq!(record.record["seq_end"], json!(5));
        assert_eq!(
            record.record["input_item_ids"],
            json!(["turn_1:item:7c92601af0a0"])
        );
        assert_eq!(
            record.record["output_item_ids"],
            json!(["turn_1:item:63f09874e956"])
        );
        assert_eq!(record.record["stop_reason"], "final");
        assert_eq!(record.record["memory_refs"], json!(["memory-one"]));
        assert_eq!(
            record.record["active_skill_hook_manifest_ref"],
            "manifest-one"
        );
        assert_eq!(record.record["usage"], record.record["usage_telemetry"]);
    }

    #[test]
    fn rust_rejects_retired_runtime_thread_turn_projection_aliases() {
        let request: RuntimeThreadTurnProjectionRequest = serde_json::from_value(json!({
            "schema_version": RUNTIME_THREAD_TURN_PROJECTION_REQUEST_SCHEMA_VERSION,
            "projectionKind": "thread",
            "threadId": "thread_1",
            "agent": { "agentId": "agent_1" }
        }))
        .expect("request parses with retired aliases ignored");
        let error = RuntimeThreadEventAdmissionCore
            .project_thread_turn(&request)
            .expect_err("retired aliases must not satisfy thread/turn projection");
        assert_eq!(
            error,
            RuntimeThreadEventAdmissionError::MissingField("thread_id")
        );
    }

    #[test]
    fn rust_core_shapes_runtime_thread_turn_projection_protocol_response() {
        let response = project_runtime_thread_turn_projection_response(
            RuntimeThreadTurnProjectionProtocolRequest {
                request: thread_turn_projection_request("thread"),
            },
        )
        .expect("runtime thread/turn projection response shaped");

        assert_eq!(
            response["source"],
            "rust_runtime_thread_turn_projection_protocol"
        );
        assert_eq!(response["backend"], "rust_runtime_agentgres");
        assert_eq!(response["projected"], true);
        assert_eq!(response["record"]["thread_id"], "thread_1");
        assert_eq!(response["projection_kind"], "thread");
        assert_eq!(
            response["projection_hash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:"),
            true
        );
    }
}
