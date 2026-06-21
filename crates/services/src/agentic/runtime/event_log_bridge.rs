//! Runtime → daemon event-log bridge.
//!
//! Turn execution (`RuntimeAgentService`) writes the execution-layer KV via
//! [`StateAccess`](ioi_api::state::StateAccess) and emits [`KernelEvent`]s on a
//! broadcast channel, but the hypervisor daemon's HTTP projections read a
//! filesystem event log at `<state_dir>/events/<sha256(stream_id)>.jsonl`. The two
//! are otherwise decoupled processes joined only by `state_dir`: the runtime never
//! touches the daemon's log, and the daemon has no handle to the runtime KV.
//!
//! This module is the bridge. Given a runtime-produced thread event keyed by the
//! runtime `session_id`, it:
//!   1. resolves the daemon `thread_id` for that session (from the agent record the
//!      daemon persisted when the runtime-bridge thread started — it carries
//!      `runtime_session_id = hex(session_id)`),
//!   2. injects `thread_id` / `event_stream_id`,
//!   3. admits the event through the kernel (which assigns `seq` after the events
//!      already on the log), and
//!   4. appends it to `<state_dir>/events/<sha256(stream_id)>.jsonl`,
//!
//! exactly mirroring the daemon's own `admit_and_persist_event`, so daemon
//! projections (e.g. `GET /v1/threads/:id/managed-sessions`) read turn-execution
//! output as first-class runtime events. This is the one generic carrier path that
//! lets any turn-execution producer reach the daemon log; managed-session
//! projection is its first producer.

use std::{fs, io::Write, path::Path};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::kernel::runtime_thread_event::{
    RuntimeThreadEventAdmissionRequest, RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
};
use super::kernel::RuntimeKernelService;
use super::managed_session_snapshot::RuntimeManagedSessionSnapshot;

const MANAGED_SESSION_PROJECTED_EVENT_KIND: &str = "managed_session.projected";
const MANAGED_SESSION_PROJECTED_PAYLOAD_SCHEMA_VERSION: &str =
    "ioi.runtime.managed-session.event.v1";

/// The hypervisor daemon names each stream's log file by the hex SHA-256 of the
/// `event_stream_id`; replicate the same derivation so appends land in the file the
/// daemon's kernel projection reads.
fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Short, deterministic id-stable hash for event/idempotency keys.
fn short_hash(input: &str) -> String {
    sha256_hex(input)[..16].to_string()
}

/// Derive the daemon thread_id for an agent id (`agent_<x>` -> `thread_<x>`),
/// matching the daemon's `thread_id_for_agent` / JS `threadIdForAgent` convention.
fn thread_id_for_agent(agent_id: &str) -> String {
    let suffix = agent_id.strip_prefix("agent_").unwrap_or(agent_id);
    format!("thread_{suffix}")
}

/// Resolve the daemon `thread_id` for a runtime `session_id` by scanning the agent
/// records the daemon persisted (`<state_dir>/agents/*.json`) for the one whose
/// `runtime_session_id` equals `hex(session_id)` — the linkage the daemon records
/// when the runtime-bridge thread starts. Returns `None` when no thread is mapped
/// yet (e.g. a standalone runtime with no daemon-side thread), in which case the
/// bridge is a no-op rather than fabricating a thread.
pub fn resolve_thread_id_for_session(state_dir: &str, session_id: &[u8; 32]) -> Option<String> {
    let session_hex = hex::encode(session_id);
    let agents_dir = Path::new(state_dir).join("agents");
    let entries = fs::read_dir(&agents_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(record) = serde_json::from_str::<Value>(&contents) else {
            continue;
        };
        if record.get("runtime_session_id").and_then(Value::as_str) != Some(session_hex.as_str()) {
            continue;
        }
        if let Some(thread_id) = record.get("thread_id").and_then(Value::as_str) {
            return Some(thread_id.to_string());
        }
        if let Some(agent_id) = record.get("id").and_then(Value::as_str) {
            return Some(thread_id_for_agent(agent_id));
        }
    }
    None
}

/// Build a `managed_session.projected` runtime thread event carrying the snapshot's
/// session cards, keyed by `session_id` (the daemon `thread_id` / `event_stream_id`
/// are injected later by [`finalize_thread_routing`] once resolved). The field
/// shape mirrors the kernel managed-session control event so it passes admission
/// and replays through the managed-session projection consumer
/// (`managed_session_candidates_from_event` reads `payload.sessions`).
pub fn managed_session_projected_event(
    session_id: &[u8; 32],
    snapshot: &RuntimeManagedSessionSnapshot,
) -> Value {
    let sessions: Vec<Value> = snapshot
        .sessions
        .iter()
        .map(|card| serde_json::to_value(card).unwrap_or(Value::Null))
        .collect();
    let session_hex = hex::encode(session_id);
    let event_hash = short_hash(&format!(
        "{session_hex}:managed_session.projected:{}",
        snapshot.session_count
    ));
    let receipt_ref = format!("receipt_managed_session_projected_{event_hash}");
    json!({
        "event_id": format!("event_managed_session_projected_{event_hash}"),
        "item_id": format!("session:{session_hex}:item:managed_session_projected:{event_hash}"),
        "idempotency_key": format!(
            "session:{session_hex}:managed_session.projected:{}",
            snapshot.session_count
        ),
        "source": "runtime.agentic.turn_execution",
        "source_event_kind": "RuntimeTurnExecution.ManagedSessionSnapshot",
        "event_kind": MANAGED_SESSION_PROJECTED_EVENT_KIND,
        "status": "projected",
        "actor": "policy",
        "component_kind": "managed_session",
        "payload_schema_version": MANAGED_SESSION_PROJECTED_PAYLOAD_SCHEMA_VERSION,
        "payload": {
            "session_count": snapshot.session_count,
            "sessions": sessions,
        },
        "receipt_refs": [receipt_ref],
        "policy_decision_refs": [],
        "artifact_refs": [],
        "rollback_refs": [],
        "redaction_profile": "internal",
        "evidence_refs": [
            "runtime_managed_session_projection_rust_owned",
            "runtime_event_log_bridge_rust_owned",
            "agentgres_managed_session_truth_required",
        ],
    })
}

/// Inject the resolved daemon `thread_id` and its `event_stream_id` into a
/// session-keyed runtime thread event built by a turn-execution producer.
fn finalize_thread_routing(event: &mut Value, thread_id: &str) {
    if let Some(object) = event.as_object_mut() {
        object.insert("thread_id".to_string(), Value::String(thread_id.to_string()));
        object.insert(
            "event_stream_id".to_string(),
            Value::String(format!("{thread_id}:events")),
        );
    }
}

/// Append an admitted event to the daemon's persisted log (one file per stream),
/// mirroring the daemon's `append_persisted_events`.
fn append_event_line(state_dir: &str, event_stream_id: &str, event: &Value) -> Result<(), String> {
    let events_dir = Path::new(state_dir).join("events");
    fs::create_dir_all(&events_dir).map_err(|error| format!("create events dir: {error}"))?;
    let path = events_dir.join(format!("{}.jsonl", sha256_hex(event_stream_id)));
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("open event log: {error}"))?;
    let line = serde_json::to_string(event).map_err(|error| format!("serialize event: {error}"))?;
    writeln!(file, "{line}").map_err(|error| format!("write event log: {error}"))?;
    Ok(())
}

/// Admit a runtime thread event through the kernel (which assigns `seq` from the
/// stream's `latest_seq`) and append the admitted event to the daemon's log.
/// Mirrors the daemon's `admit_and_persist_event` so events produced from the
/// runtime side are indistinguishable on the log from daemon-admitted events.
pub fn admit_and_persist_runtime_event(state_dir: &str, event: Value) -> Result<Value, String> {
    let event_stream_id = event
        .get("event_stream_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if event_stream_id.is_empty() {
        return Err("runtime thread event requires event_stream_id".to_string());
    }
    let request: RuntimeThreadEventAdmissionRequest = serde_json::from_value(json!({
        "schema_version": RUNTIME_THREAD_EVENT_ADMISSION_REQUEST_SCHEMA_VERSION,
        "event": event,
        "state_dir": state_dir,
    }))
    .map_err(|error| format!("build admission request: {error}"))?;
    let record = RuntimeKernelService::new()
        .admit_runtime_thread_event(&request)
        .map_err(|error| format!("admit runtime thread event: {error:?}"))?;
    let admitted = serde_json::to_value(&record.event)
        .map_err(|error| format!("serialize admitted event: {error}"))?;
    append_event_line(state_dir, &event_stream_id, &admitted)?;
    Ok(admitted)
}

/// Bridge a managed-session snapshot onto the daemon's event log for `session_id`.
/// Resolves the daemon thread, builds + finalizes the `managed_session.projected`
/// event, and admits it. A no-op (`Ok(None)`) when the snapshot is empty or no
/// daemon thread is mapped for the session.
pub fn persist_managed_session_snapshot(
    state_dir: &str,
    session_id: &[u8; 32],
    snapshot: &RuntimeManagedSessionSnapshot,
) -> Result<Option<Value>, String> {
    if snapshot.sessions.is_empty() {
        return Ok(None);
    }
    let Some(thread_id) = resolve_thread_id_for_session(state_dir, session_id) else {
        return Ok(None);
    };
    let mut event = managed_session_projected_event(session_id, snapshot);
    finalize_thread_routing(&mut event, &thread_id);
    let admitted = admit_and_persist_runtime_event(state_dir, event)?;
    Ok(Some(admitted))
}

/// Persist a pre-serialized, session-keyed runtime thread event (the
/// [`KernelEvent::RuntimeThreadEvent`](ioi_types::app::KernelEvent) carrier
/// payload) onto the daemon log: resolve the daemon thread for the session, inject
/// routing, and admit. A no-op (`Ok(None)`) when no daemon thread is mapped.
pub fn persist_runtime_thread_event_json(
    state_dir: &str,
    session_id: &[u8; 32],
    event_json: &str,
) -> Result<Option<Value>, String> {
    let Some(thread_id) = resolve_thread_id_for_session(state_dir, session_id) else {
        return Ok(None);
    };
    let mut event: Value = serde_json::from_str(event_json)
        .map_err(|error| format!("parse runtime thread event: {error}"))?;
    finalize_thread_routing(&mut event, &thread_id);
    let admitted = admit_and_persist_runtime_event(state_dir, event)?;
    Ok(Some(admitted))
}

/// Subscribe to a runtime [`KernelEvent`](ioi_types::app::KernelEvent) broadcast and
/// persist each [`KernelEvent::RuntimeThreadEvent`] carrier onto the daemon's event
/// log at `state_dir`. Other variants are ignored (the typed-receipt mapping is a
/// separate concern). Runs until the channel closes; persistence failures are
/// logged and skipped so one bad event never tears down the bridge.
pub async fn run_event_log_bridge(
    state_dir: String,
    mut receiver: tokio::sync::broadcast::Receiver<ioi_types::app::KernelEvent>,
) {
    use ioi_types::app::KernelEvent;
    use tokio::sync::broadcast::error::RecvError;
    loop {
        match receiver.recv().await {
            Ok(KernelEvent::RuntimeThreadEvent {
                session_id,
                event_json,
            }) => {
                match persist_runtime_thread_event_json(&state_dir, &session_id, &event_json) {
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(%error, "event-log bridge failed to persist runtime thread event");
                    }
                }
            }
            Ok(_) => {}
            Err(RecvError::Closed) => break,
            Err(RecvError::Lagged(skipped)) => {
                tracing::warn!(skipped, "event-log bridge lagged; dropped runtime events");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::managed_session_snapshot::{
        RuntimeManagedSessionCard, RuntimeManagedSessionReplaySnapshot,
        RuntimeScreenshotPersistenceSnapshot, RUNTIME_MANAGED_SESSION_SCHEMA_VERSION,
    };
    use crate::agentic::runtime::kernel::runtime_managed_session_control::{
        RuntimeManagedSessionProjectionCore, RuntimeManagedSessionProjectionRequest,
        RUNTIME_MANAGED_SESSION_PROJECTION_REQUEST_SCHEMA_VERSION,
    };

    fn card(id: &str) -> RuntimeManagedSessionCard {
        RuntimeManagedSessionCard {
            id: id.to_string(),
            kind: "sandbox_browser".to_string(),
            surface_label: "Sandbox browser".to_string(),
            status: "browsing".to_string(),
            status_label: "Browsing".to_string(),
            control_state: "observe".to_string(),
            available_control_states: vec![
                "observe".to_string(),
                "take_over".to_string(),
                "return_agent".to_string(),
            ],
            waiting_for_user: false,
            waiting_reason: None,
            parent_playbook_id: None,
            parent_playbook_label: None,
            step_id: None,
            step_label: None,
            child_session_id: None,
            page_title: None,
            target: None,
            detail: "Browser inspection completed.".to_string(),
            last_tool: Some("browser__inspect".to_string()),
            action_count: 1,
            screenshot_persistence: RuntimeScreenshotPersistenceSnapshot {
                state: "quarantined".to_string(),
                sanitized_preview_ref: None,
                raw_capture_visibility: "runs_tracing".to_string(),
                redaction_required_before_product: true,
            },
            replay_ready: true,
            trace_visibility: "runs_tracing".to_string(),
        }
    }

    fn snapshot(session_id: [u8; 32], cards: Vec<RuntimeManagedSessionCard>) -> RuntimeManagedSessionSnapshot {
        let replayable_session_ids = cards
            .iter()
            .filter(|c| c.replay_ready)
            .map(|c| c.id.clone())
            .collect::<Vec<_>>();
        RuntimeManagedSessionSnapshot {
            schema_version: RUNTIME_MANAGED_SESSION_SCHEMA_VERSION.to_string(),
            session_id: hex::encode(session_id),
            session_count: cards.len(),
            sessions: cards,
            replay: RuntimeManagedSessionReplaySnapshot {
                replay_ready_count: replayable_session_ids.len(),
                replayable_session_ids,
                waiting_session_ids: Vec::new(),
                missing_persistence_count: 0,
            },
            product_lane: Vec::new(),
        }
    }

    /// Write the agent record the daemon persists when the runtime-bridge thread
    /// starts: `id = agent_<x>` and `runtime_session_id = hex(session_id)`. This is
    /// the daemon-side precondition the bridge resolves against (not an event on the
    /// log) — the linkage `RuntimeBridgeThreadStartAgentStateUpdateCore` writes.
    fn write_bridge_agent_record(state_dir: &Path, agent_suffix: &str, session_id: [u8; 32]) {
        let agents_dir = state_dir.join("agents");
        fs::create_dir_all(&agents_dir).expect("agents dir");
        let record = json!({
            "id": format!("agent_{agent_suffix}"),
            "object": "ioi.agent",
            "runtime_session_id": hex::encode(session_id),
            "runtime_bridge_status": "started",
        });
        fs::write(
            agents_dir.join(format!("agent_{agent_suffix}.json")),
            serde_json::to_string(&record).expect("agent json"),
        )
        .expect("write agent record");
    }

    fn projection_request(state_dir: &Path, thread_id: &str) -> RuntimeManagedSessionProjectionRequest {
        RuntimeManagedSessionProjectionRequest {
            schema_version: Some(
                RUNTIME_MANAGED_SESSION_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
            ),
            operation: Some("managed_session_inspection".to_string()),
            operation_kind: Some("managed_session.inspect".to_string()),
            projection_kind: Some("list".to_string()),
            thread_id: Some(thread_id.to_string()),
            state_dir: Some(state_dir.to_string_lossy().to_string()),
            source: Some("runtime.managed_session_state".to_string()),
            projection: Value::Null,
            evidence_refs: vec![],
        }
    }

    #[test]
    fn bridge_persists_managed_session_snapshot_and_kernel_projection_reads_it() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path();
        let session_id = [0x38u8; 32];
        // Daemon-side precondition: the runtime-bridge thread linkage.
        write_bridge_agent_record(state_dir, "alpha", session_id);

        // Real snapshot output (the typed value the snapshot builder produces).
        let snap = snapshot(session_id, vec![card("sandbox_browser:1")]);

        // Bridge it onto the daemon log.
        let admitted = persist_managed_session_snapshot(
            &state_dir.to_string_lossy(),
            &session_id,
            &snap,
        )
        .expect("bridge persists")
        .expect("an event was admitted");
        assert_eq!(admitted["event_kind"], "managed_session.projected");
        assert_eq!(admitted["thread_id"], "thread_alpha");
        assert!(admitted.get("seq").and_then(Value::as_u64).is_some());

        // The daemon's kernel managed-session projection reads it back from the log.
        let record = RuntimeManagedSessionProjectionCore
            .project(&projection_request(state_dir, "thread_alpha"))
            .expect("projection");
        assert_eq!(record.operation_kind, "managed_session.inspect");
        assert_eq!(record.record_count, 1);
        let sessions = record.projection.as_array().expect("sessions array");
        assert_eq!(sessions[0]["managed_session_id"], "sandbox_browser:1");
        assert_eq!(sessions[0]["kind"], "sandbox_browser");
    }

    #[test]
    fn bridge_is_noop_without_a_mapped_thread() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path();
        let session_id = [0x77u8; 32];
        // No agent record -> no session->thread linkage -> no fabricated event.
        let snap = snapshot(session_id, vec![card("sandbox_browser:1")]);
        let result = persist_managed_session_snapshot(
            &state_dir.to_string_lossy(),
            &session_id,
            &snap,
        )
        .expect("bridge ok");
        assert!(result.is_none());
        assert!(!state_dir.join("events").exists());
    }

    #[test]
    fn carrier_json_round_trips_through_the_bridge() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path();
        let session_id = [0x41u8; 32];
        write_bridge_agent_record(state_dir, "beta", session_id);

        // Producer side: build the session-keyed event and serialize it as the
        // KernelEvent::RuntimeThreadEvent carrier would.
        let snap = snapshot(session_id, vec![card("sandbox_browser:7")]);
        let event_json = serde_json::to_string(&managed_session_projected_event(&session_id, &snap))
            .expect("serialize carrier");

        let admitted = persist_runtime_thread_event_json(
            &state_dir.to_string_lossy(),
            &session_id,
            &event_json,
        )
        .expect("bridge persists")
        .expect("an event was admitted");
        assert_eq!(admitted["thread_id"], "thread_beta");
        assert_eq!(admitted["event_stream_id"], "thread_beta:events");

        let record = RuntimeManagedSessionProjectionCore
            .project(&projection_request(state_dir, "thread_beta"))
            .expect("projection");
        assert_eq!(record.record_count, 1);
        let sessions = record.projection.as_array().expect("sessions array");
        assert_eq!(sessions[0]["managed_session_id"], "sandbox_browser:7");
    }
}
