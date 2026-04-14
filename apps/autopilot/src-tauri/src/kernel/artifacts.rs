use crate::kernel::events::{build_event, register_artifact, register_event};
use crate::models::{
    AgentEvent, AgentTask, AppState, Artifact, ArtifactRef, ArtifactType,
    AssistantNotificationRecord, AssistantWorkbenchActivityRecord, ChatMessage, EventStatus,
    EventType, InterventionRecord, SessionSummary,
};
use crate::orchestrator;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ioi_memory::MemoryRuntime;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipWriter};

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn artifact_content_ref(artifact_id: &str) -> String {
    format!("ioi-memory://artifact/{}", artifact_id)
}

fn persist_artifact(
    memory_runtime: &Arc<MemoryRuntime>,
    artifact: &Artifact,
    content: &[u8],
) -> Artifact {
    orchestrator::append_artifact(memory_runtime, artifact, content);
    artifact.clone()
}

fn build_artifact(
    thread_id: &str,
    artifact_type: ArtifactType,
    title: String,
    description: String,
    metadata: Value,
    version: Option<u32>,
    parent_artifact_id: Option<String>,
) -> Artifact {
    let artifact_id = Uuid::new_v4().to_string();
    Artifact {
        artifact_id: artifact_id.clone(),
        created_at: now_iso(),
        thread_id: thread_id.to_string(),
        artifact_type,
        title,
        description,
        content_ref: artifact_content_ref(&artifact_id),
        metadata,
        version,
        parent_artifact_id,
    }
}

pub fn create_log_artifact(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
    title: &str,
    description: &str,
    output: &str,
    metadata: Value,
) -> Artifact {
    let artifact = build_artifact(
        thread_id,
        ArtifactType::Log,
        title.to_string(),
        description.to_string(),
        metadata,
        Some(1),
        None,
    );
    persist_artifact(memory_runtime, &artifact, output.as_bytes())
}

pub fn create_diff_artifact(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
    title: &str,
    description: &str,
    diff_text: &str,
    metadata: Value,
) -> Artifact {
    let artifact = build_artifact(
        thread_id,
        ArtifactType::Diff,
        title.to_string(),
        description.to_string(),
        metadata,
        Some(1),
        None,
    );
    persist_artifact(memory_runtime, &artifact, diff_text.as_bytes())
}

pub fn create_named_file_artifact(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
    path: &str,
    mime: Option<&str>,
    revision: Option<String>,
    content: &[u8],
) -> Artifact {
    let metadata = json!({
        "path": path,
        "revision": revision,
        "mime": mime,
    });
    let artifact = build_artifact(
        thread_id,
        ArtifactType::File,
        format!("File: {}", path),
        "File snapshot".to_string(),
        metadata,
        Some(1),
        None,
    );
    persist_artifact(memory_runtime, &artifact, content)
}

pub fn upsert_named_file_artifact(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
    path: &str,
    mime: Option<&str>,
    revision: Option<String>,
    content: &[u8],
) -> Artifact {
    let existing = orchestrator::load_artifacts(memory_runtime, thread_id)
        .into_iter()
        .filter(|artifact| artifact.artifact_type == ArtifactType::File)
        .filter(|artifact| {
            artifact
                .metadata
                .get("path")
                .and_then(|value| value.as_str())
                == Some(path)
        })
        .max_by_key(|artifact| artifact.version.unwrap_or(1));

    if let Some(existing) = existing.as_ref() {
        if let Some(previous) =
            orchestrator::load_artifact_content(memory_runtime, &existing.artifact_id)
        {
            if previous == content {
                return existing.clone();
            }
        }
    }

    let metadata = json!({
        "path": path,
        "revision": revision,
        "mime": mime,
    });
    let artifact = build_artifact(
        thread_id,
        ArtifactType::File,
        format!("File: {}", path),
        "File snapshot".to_string(),
        metadata,
        Some(
            existing
                .as_ref()
                .and_then(|artifact| artifact.version)
                .unwrap_or(0)
                + 1,
        ),
        existing
            .as_ref()
            .map(|artifact| artifact.artifact_id.clone()),
    );
    persist_artifact(memory_runtime, &artifact, content)
}

pub fn create_web_artifact(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
    url: &str,
    content: &str,
    citations: Vec<String>,
) -> Artifact {
    let metadata = json!({
        "url": url,
        "captured_at": now_iso(),
        "citations": citations,
    });
    let artifact = build_artifact(
        thread_id,
        ArtifactType::Web,
        format!("Web: {}", url),
        "Captured page extract".to_string(),
        metadata,
        Some(1),
        None,
    );
    persist_artifact(memory_runtime, &artifact, content.as_bytes())
}

pub fn create_run_bundle(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
    run_id: &str,
    refs: Vec<String>,
) -> Artifact {
    let metadata = json!({
        "run_id": run_id,
        "refs": refs,
    });
    let artifact = build_artifact(
        thread_id,
        ArtifactType::RunBundle,
        format!("Run Bundle {}", run_id),
        "Execution receipts and artifact references".to_string(),
        metadata.clone(),
        Some(1),
        None,
    );
    let content = serde_json::to_vec(&metadata).unwrap_or_else(|_| b"{}".to_vec());
    persist_artifact(memory_runtime, &artifact, &content)
}

pub fn create_report_artifact(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
    title: &str,
    description: &str,
    report: &Value,
) -> Artifact {
    let artifact = build_artifact(
        thread_id,
        ArtifactType::Report,
        title.to_string(),
        description.to_string(),
        report.clone(),
        Some(1),
        None,
    );
    let content = serde_json::to_vec_pretty(report).unwrap_or_else(|_| b"{}".to_vec());
    persist_artifact(memory_runtime, &artifact, &content)
}

pub fn append_run_bundle_ref(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
    run_bundle_id: &str,
    new_ref: &str,
) -> Option<Artifact> {
    let artifacts = orchestrator::load_artifacts(memory_runtime, thread_id);
    let existing = artifacts
        .iter()
        .find(|a| a.artifact_id == run_bundle_id && a.artifact_type == ArtifactType::RunBundle)?;

    let mut refs = existing
        .metadata
        .get("refs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect::<Vec<_>>();

    if refs.iter().any(|r| r == new_ref) {
        return None;
    }
    refs.push(new_ref.to_string());

    let metadata = json!({
        "run_id": existing.metadata.get("run_id").and_then(|v| v.as_str()).unwrap_or_default(),
        "refs": refs,
    });

    let next_version = existing.version.unwrap_or(1) + 1;
    let artifact = build_artifact(
        thread_id,
        ArtifactType::RunBundle,
        existing.title.clone(),
        existing.description.clone(),
        metadata.clone(),
        Some(next_version),
        Some(existing.artifact_id.clone()),
    );
    let content = serde_json::to_vec(&metadata).unwrap_or_else(|_| b"{}".to_vec());
    Some(persist_artifact(memory_runtime, &artifact, &content))
}

fn get_memory_runtime(state: &State<'_, Mutex<AppState>>) -> Result<Arc<MemoryRuntime>, String> {
    let guard = state
        .lock()
        .map_err(|_| "Failed to lock state".to_string())?;
    guard
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime unavailable".to_string())
}

fn latest_agent_answer(history: &[crate::models::ChatMessage]) -> Option<String> {
    history
        .iter()
        .rev()
        .find(|message| message.role == "agent" && !message.text.trim().is_empty())
        .map(|message| message.text.clone())
}

fn latest_chat_reply_output(events: &[AgentEvent]) -> Option<String> {
    events.iter().rev().find_map(|event| {
        let tool_name = event
            .digest
            .get("tool_name")
            .and_then(|value| value.as_str())
            .or_else(|| event.digest.get("tool").and_then(|value| value.as_str()))
            .unwrap_or_default();

        if !(tool_name.eq_ignore_ascii_case("chat__reply")
            || tool_name.eq_ignore_ascii_case("chat::reply"))
        {
            return None;
        }

        event
            .details
            .get("output")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
            .or_else(|| {
                event
                    .details
                    .get("chunk")
                    .and_then(|value| value.as_str())
                    .map(|value| value.to_string())
            })
    })
}

const CANONICAL_TRACE_BUNDLE_SCHEMA_VERSION: u32 = 1;

fn trace_scope_matches_candidate(
    scope_thread_id: &str,
    scope_session_id: &str,
    candidate_thread_id: Option<&str>,
    candidate_session_id: Option<&str>,
) -> bool {
    trim_non_empty(candidate_thread_id)
        .into_iter()
        .chain(trim_non_empty(candidate_session_id))
        .any(|value| value == scope_thread_id || value == scope_session_id)
}

fn scoped_interventions_for_trace_bundle(
    items: &[InterventionRecord],
    scope_thread_id: &str,
    scope_session_id: &str,
) -> Vec<InterventionRecord> {
    items
        .iter()
        .filter(|item| {
            trace_scope_matches_candidate(
                scope_thread_id,
                scope_session_id,
                item.thread_id.as_deref(),
                item.session_id.as_deref(),
            )
        })
        .cloned()
        .collect()
}

fn scoped_notifications_for_trace_bundle(
    items: &[AssistantNotificationRecord],
    scope_thread_id: &str,
    scope_session_id: &str,
) -> Vec<AssistantNotificationRecord> {
    items
        .iter()
        .filter(|item| {
            trace_scope_matches_candidate(
                scope_thread_id,
                scope_session_id,
                item.thread_id.as_deref(),
                item.session_id.as_deref(),
            )
        })
        .cloned()
        .collect()
}

fn workbench_activity_belongs_to_trace_scope(
    activity: &AssistantWorkbenchActivityRecord,
    scope_thread_id: &str,
    scope_session_id: &str,
) -> bool {
    assistant_workbench_evidence_thread_id(activity) == scope_thread_id
        || trace_scope_matches_candidate(
            scope_thread_id,
            scope_session_id,
            activity.thread_id.as_deref(),
            None,
        )
}

fn scoped_workbench_activities_for_trace_bundle(
    items: &[AssistantWorkbenchActivityRecord],
    scope_thread_id: &str,
    scope_session_id: &str,
) -> Vec<AssistantWorkbenchActivityRecord> {
    items
        .iter()
        .filter(|activity| {
            workbench_activity_belongs_to_trace_scope(activity, scope_thread_id, scope_session_id)
        })
        .cloned()
        .collect()
}

fn trace_bundle_session_summary(
    memory_runtime: &Arc<MemoryRuntime>,
    scope_thread_id: &str,
    scope_session_id: &str,
    task: Option<&AgentTask>,
) -> Option<SessionSummary> {
    orchestrator::get_local_sessions(memory_runtime)
        .into_iter()
        .find(|summary| {
            summary.session_id == scope_thread_id || summary.session_id == scope_session_id
        })
        .or_else(|| task.map(|task| orchestrator::session_summary_from_task(task, None)))
}

fn artifact_file_extension(artifact_type: &ArtifactType, bytes: &[u8]) -> &'static str {
    if std::str::from_utf8(bytes).is_err() {
        return "bin";
    }

    match artifact_type {
        ArtifactType::Diff => "diff",
        ArtifactType::File => "txt",
        ArtifactType::Web => "md",
        ArtifactType::RunBundle => "json",
        ArtifactType::Report => "json",
        ArtifactType::Log => "log",
    }
}

fn trim_non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn assistant_workbench_evidence_thread_id(activity: &AssistantWorkbenchActivityRecord) -> String {
    if let Some(thread_id) = trim_non_empty(activity.evidence_thread_id.as_deref()) {
        return thread_id;
    }

    if let Some(notification_id) = trim_non_empty(activity.source_notification_id.as_deref()) {
        return format!(
            "assistant-workbench:{}:notif:{}",
            activity.session_kind.trim(),
            notification_id
        );
    }

    let connector_id =
        trim_non_empty(activity.connector_id.as_deref()).unwrap_or_else(|| "connector".to_string());

    if activity.session_kind.trim() == "gmail_reply" {
        let thread_id =
            trim_non_empty(activity.thread_id.as_deref()).unwrap_or_else(|| "thread".to_string());
        return format!(
            "assistant-workbench:gmail_reply:{}:thread:{}",
            connector_id, thread_id
        );
    }

    let event_id =
        trim_non_empty(activity.event_id.as_deref()).unwrap_or_else(|| "event".to_string());
    format!(
        "assistant-workbench:meeting_prep:{}:event:{}",
        connector_id, event_id
    )
}

fn assistant_workbench_event_type(activity: &AssistantWorkbenchActivityRecord) -> EventType {
    match activity.status.trim() {
        "succeeded" => EventType::Receipt,
        "failed" => EventType::Error,
        "requested" => EventType::Warning,
        _ => EventType::InfoNote,
    }
}

fn assistant_workbench_event_status(activity: &AssistantWorkbenchActivityRecord) -> EventStatus {
    match activity.status.trim() {
        "succeeded" => EventStatus::Success,
        "failed" => EventStatus::Failure,
        _ => EventStatus::Partial,
    }
}

fn assistant_workbench_title(activity: &AssistantWorkbenchActivityRecord) -> String {
    let surface = if activity.surface.trim() == "reply-composer" {
        "Reply workbench"
    } else {
        "Meeting prep"
    };
    let action = activity.action.trim().replace('_', " ");
    match activity.status.trim() {
        "succeeded" => format!("{surface}: {action} completed"),
        "failed" => format!("{surface}: {action} failed"),
        "requested" => format!("{surface}: {action} needs operator approval"),
        _ => format!("{surface}: {action} started"),
    }
}

fn assistant_workbench_receipt_ref(
    thread_id: &str,
    activity: &AssistantWorkbenchActivityRecord,
) -> Option<String> {
    match activity.status.trim() {
        "succeeded" | "failed" | "requested" => Some(format!(
            "assistant-workbench:{}:{}",
            thread_id, activity.activity_id
        )),
        _ => None,
    }
}

fn assistant_workbench_step_index(memory_runtime: &Arc<MemoryRuntime>, thread_id: &str) -> u32 {
    orchestrator::load_events(memory_runtime, thread_id, None, None).len() as u32
}

fn assistant_workbench_artifact_refs(
    app: &AppHandle,
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
    title: &str,
    activity: &AssistantWorkbenchActivityRecord,
) -> Vec<ArtifactRef> {
    match activity.status.trim() {
        "succeeded" | "failed" | "requested" => {
            let report = json!({
                "activity": activity,
                "evidenceThreadId": thread_id,
            });
            let artifact = create_report_artifact(
                memory_runtime,
                thread_id,
                title,
                "Assistant workbench activity receipt",
                &report,
            );
            let artifact_id = artifact.artifact_id.clone();
            register_artifact(app, artifact);
            vec![ArtifactRef {
                artifact_id,
                artifact_type: ArtifactType::Report,
            }]
        }
        _ => Vec::new(),
    }
}

fn zip_options() -> FileOptions {
    FileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644)
}

fn write_zip_bytes<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    path: &str,
    bytes: &[u8],
) -> Result<(), String> {
    zip.start_file(path, zip_options())
        .map_err(|err| format!("zip start_file {path}: {err}"))?;
    zip.write_all(bytes)
        .map_err(|err| format!("zip write {path}: {err}"))?;
    Ok(())
}

fn write_zip_json<W: Write + std::io::Seek, T: Serialize>(
    zip: &mut ZipWriter<W>,
    path: &str,
    value: &T,
) -> Result<(), String> {
    let bytes =
        serde_json::to_vec_pretty(value).map_err(|err| format!("serialize {path}: {err}"))?;
    write_zip_bytes(zip, path, &bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactContentPayload {
    pub artifact_id: String,
    pub encoding: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportBundleManifest {
    pub schema_version: u32,
    pub exported_at_utc: String,
    pub thread_id: String,
    pub answer_present: bool,
    pub event_count: usize,
    pub artifact_count: usize,
    pub included_artifact_payloads: bool,
    #[serde(default)]
    pub canonical_trace_bundle_entry: Option<String>,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceBundleStats {
    pub event_count: usize,
    pub receipt_count: usize,
    pub artifact_count: usize,
    pub run_bundle_count: usize,
    pub report_artifact_count: usize,
    pub intervention_count: usize,
    pub assistant_notification_count: usize,
    pub assistant_workbench_activity_count: usize,
    pub included_artifact_payloads: bool,
    pub included_artifact_payload_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceBundleArtifactPayloadEntry {
    pub artifact_id: String,
    pub artifact_type: ArtifactType,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalTraceBundle {
    pub schema_version: u32,
    pub exported_at_utc: String,
    pub thread_id: String,
    pub session_id: String,
    pub latest_answer_markdown: String,
    pub stats: TraceBundleStats,
    #[serde(default)]
    pub session_summary: Option<SessionSummary>,
    #[serde(default)]
    pub task: Option<AgentTask>,
    #[serde(default)]
    pub history: Vec<ChatMessage>,
    #[serde(default)]
    pub events: Vec<AgentEvent>,
    #[serde(default)]
    pub receipts: Vec<AgentEvent>,
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
    #[serde(default)]
    pub artifact_payloads: Vec<TraceBundleArtifactPayloadEntry>,
    #[serde(default)]
    pub interventions: Vec<InterventionRecord>,
    #[serde(default)]
    pub assistant_notifications: Vec<AssistantNotificationRecord>,
    #[serde(default)]
    pub assistant_workbench_activities: Vec<AssistantWorkbenchActivityRecord>,
}

#[derive(Debug, Clone)]
struct CanonicalTraceBundleSource {
    thread_id: String,
    session_id: String,
    latest_answer_markdown: String,
    session_summary: Option<SessionSummary>,
    task: Option<AgentTask>,
    history: Vec<ChatMessage>,
    events: Vec<AgentEvent>,
    receipts: Vec<AgentEvent>,
    artifacts: Vec<Artifact>,
    interventions: Vec<InterventionRecord>,
    assistant_notifications: Vec<AssistantNotificationRecord>,
    assistant_workbench_activities: Vec<AssistantWorkbenchActivityRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceBundleDiffStat {
    pub label: String,
    pub left_value: String,
    pub right_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceBundleDiffSection {
    pub key: String,
    pub label: String,
    pub changed: bool,
    pub summary: String,
    #[serde(default)]
    pub left_value: Option<String>,
    #[serde(default)]
    pub right_value: Option<String>,
    #[serde(default)]
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceBundleDiffResult {
    pub schema_version: u32,
    pub compared_at_utc: String,
    pub left_thread_id: String,
    pub right_thread_id: String,
    #[serde(default)]
    pub left_session_summary: Option<SessionSummary>,
    #[serde(default)]
    pub right_session_summary: Option<SessionSummary>,
    #[serde(default)]
    pub first_divergence_key: Option<String>,
    #[serde(default)]
    pub first_divergence_summary: Option<String>,
    pub changed_section_count: usize,
    #[serde(default)]
    pub stats: Vec<TraceBundleDiffStat>,
    #[serde(default)]
    pub sections: Vec<TraceBundleDiffSection>,
}

const TRACE_BUNDLE_DIFF_SCHEMA_VERSION: u32 = 1;

#[tauri::command]
pub fn record_assistant_workbench_activity(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    mut activity: AssistantWorkbenchActivityRecord,
) -> Result<(), String> {
    let memory_runtime = get_memory_runtime(&state)?;
    let thread_id = assistant_workbench_evidence_thread_id(&activity);
    activity.evidence_thread_id = Some(thread_id.clone());

    let title = assistant_workbench_title(&activity);
    let step_index = assistant_workbench_step_index(&memory_runtime, &thread_id);
    orchestrator::append_assistant_workbench_activity(&memory_runtime, activity.clone(), 48);
    let artifact_refs =
        assistant_workbench_artifact_refs(&app, &memory_runtime, &thread_id, &title, &activity);
    let digest = json!({
        "kind": "assistant_workbench_activity",
        "session_kind": activity.session_kind.clone(),
        "surface": activity.surface.clone(),
        "action": activity.action.clone(),
        "status": activity.status.clone(),
        "connector_id": activity.connector_id.clone(),
        "source_notification_id": activity.source_notification_id.clone(),
        "thread_id": activity.thread_id.clone(),
        "event_id": activity.event_id.clone(),
        "message": activity.message.clone(),
    });
    let details = json!({
        "payload": activity.clone(),
        "summary": activity.message.clone(),
    });
    let event = build_event(
        &thread_id,
        step_index,
        assistant_workbench_event_type(&activity),
        title,
        digest,
        details,
        assistant_workbench_event_status(&activity),
        artifact_refs,
        assistant_workbench_receipt_ref(&thread_id, &activity),
        Vec::new(),
        None,
    );
    register_event(&app, event);
    let _ = app.emit("assistant-workbench-activity", &activity);
    Ok(())
}

#[tauri::command]
pub fn get_recent_assistant_workbench_activities(
    state: State<'_, Mutex<AppState>>,
    limit: Option<usize>,
) -> Result<Vec<AssistantWorkbenchActivityRecord>, String> {
    let memory_runtime = get_memory_runtime(&state)?;
    let mut activities = orchestrator::load_assistant_workbench_activities(&memory_runtime);
    if let Some(limit) = limit {
        activities.truncate(limit);
    }
    Ok(activities)
}

#[tauri::command]
pub fn set_active_assistant_workbench_session(
    app: AppHandle,
    state: State<'_, Mutex<AppState>>,
    session: Value,
) -> Result<(), String> {
    let mut state = state
        .lock()
        .map_err(|_| "App state is unavailable.".to_string())?;
    state.active_assistant_workbench_session = Some(session.clone());
    drop(state);
    let _ = app.emit("assistant-workbench-session-updated", &session);
    Ok(())
}

#[tauri::command]
pub fn get_active_assistant_workbench_session(
    state: State<'_, Mutex<AppState>>,
) -> Result<Option<Value>, String> {
    let state = state
        .lock()
        .map_err(|_| "App state is unavailable.".to_string())?;
    Ok(state.active_assistant_workbench_session.clone())
}

#[tauri::command]
pub fn get_thread_events(
    state: State<'_, Mutex<AppState>>,
    thread_id: String,
    limit: Option<usize>,
    cursor: Option<usize>,
) -> Result<Vec<AgentEvent>, String> {
    let memory_runtime = get_memory_runtime(&state)?;
    Ok(orchestrator::load_events(
        &memory_runtime,
        &thread_id,
        limit,
        cursor,
    ))
}

#[tauri::command]
pub fn get_thread_artifacts(
    state: State<'_, Mutex<AppState>>,
    thread_id: String,
) -> Result<Vec<Artifact>, String> {
    let memory_runtime = get_memory_runtime(&state)?;
    Ok(orchestrator::load_artifacts(&memory_runtime, &thread_id))
}

#[tauri::command]
pub fn get_artifact_content(
    state: State<'_, Mutex<AppState>>,
    artifact_id: String,
) -> Result<Option<ArtifactContentPayload>, String> {
    let memory_runtime = get_memory_runtime(&state)?;
    if let Some(bytes) = orchestrator::load_artifact_content(&memory_runtime, &artifact_id) {
        if let Ok(text) = String::from_utf8(bytes.clone()) {
            return Ok(Some(ArtifactContentPayload {
                artifact_id,
                encoding: "utf-8".to_string(),
                content: text,
            }));
        }
        return Ok(Some(ArtifactContentPayload {
            artifact_id,
            encoding: "base64".to_string(),
            content: STANDARD.encode(bytes),
        }));
    }
    Ok(None)
}

#[tauri::command]
pub fn get_run_bundle(
    state: State<'_, Mutex<AppState>>,
    thread_id: String,
    run_id: Option<String>,
) -> Result<Option<Artifact>, String> {
    let memory_runtime = get_memory_runtime(&state)?;
    let artifacts = orchestrator::load_artifacts(&memory_runtime, &thread_id);

    let mut bundles = artifacts
        .into_iter()
        .filter(|a| a.artifact_type == ArtifactType::RunBundle)
        .collect::<Vec<_>>();
    bundles.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    if let Some(run_id) = run_id {
        Ok(bundles.into_iter().find(|a| {
            a.metadata
                .get("run_id")
                .and_then(|v| v.as_str())
                .map(|v| v == run_id)
                .unwrap_or(false)
        }))
    } else {
        Ok(bundles.into_iter().next())
    }
}

#[tauri::command]
pub fn compare_trace_bundles(
    state: State<'_, Mutex<AppState>>,
    left_thread_id: String,
    right_thread_id: String,
) -> Result<TraceBundleDiffResult, String> {
    let left_thread_id = left_thread_id.trim().to_string();
    let right_thread_id = right_thread_id.trim().to_string();
    if left_thread_id.is_empty() || right_thread_id.is_empty() {
        return Err("left_thread_id and right_thread_id must not be empty".to_string());
    }
    if left_thread_id == right_thread_id {
        return Err("compare_trace_bundles requires two distinct thread ids".to_string());
    }

    let memory_runtime = get_memory_runtime(&state)?;
    let left = build_canonical_trace_bundle(
        load_canonical_trace_bundle_source(&memory_runtime, &left_thread_id)?,
        Vec::new(),
        false,
    );
    let right = build_canonical_trace_bundle(
        load_canonical_trace_bundle_source(&memory_runtime, &right_thread_id)?,
        Vec::new(),
        false,
    );

    Ok(compare_canonical_trace_bundles(&left, &right))
}

#[tauri::command]
pub fn get_trace_bundle(
    state: State<'_, Mutex<AppState>>,
    thread_id: String,
) -> Result<CanonicalTraceBundle, String> {
    let memory_runtime = get_memory_runtime(&state)?;
    let source = load_canonical_trace_bundle_source(&memory_runtime, &thread_id)?;
    Ok(build_canonical_trace_bundle(source, Vec::new(), false))
}

#[tauri::command]
pub fn export_trace_bundle(
    state: State<'_, Mutex<AppState>>,
    thread_id: String,
    output_path: String,
    include_artifact_payloads: bool,
) -> Result<String, String> {
    export_trace_bundle_impl(state, thread_id, output_path, include_artifact_payloads)
}

#[tauri::command]
pub fn export_thread_bundle(
    state: State<'_, Mutex<AppState>>,
    thread_id: String,
    output_path: String,
    include_artifact_payloads: bool,
) -> Result<String, String> {
    export_trace_bundle_impl(state, thread_id, output_path, include_artifact_payloads)
}

fn export_trace_bundle_impl(
    state: State<'_, Mutex<AppState>>,
    thread_id: String,
    output_path: String,
    include_artifact_payloads: bool,
) -> Result<String, String> {
    let thread_id = thread_id.trim().to_string();
    if thread_id.is_empty() {
        return Err("thread_id must not be empty".to_string());
    }

    let output_path = output_path.trim().to_string();
    if output_path.is_empty() {
        return Err("output_path must not be empty".to_string());
    }

    let output = Path::new(&output_path);
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("create export directory failed: {err}"))?;
        }
    }

    let memory_runtime = get_memory_runtime(&state)?;
    let source = load_canonical_trace_bundle_source(&memory_runtime, &thread_id)?;

    let file =
        File::create(output).map_err(|err| format!("failed to create export bundle: {err}"))?;
    let mut zip = ZipWriter::new(file);
    let mut files = Vec::<String>::new();

    write_zip_bytes(
        &mut zip,
        "answer.md",
        source.latest_answer_markdown.as_bytes(),
    )?;
    files.push("answer.md".to_string());

    write_zip_json(&mut zip, "history.json", &source.history)?;
    files.push("history.json".to_string());

    write_zip_json(&mut zip, "events.json", &source.events)?;
    files.push("events.json".to_string());

    write_zip_json(&mut zip, "receipts.json", &source.receipts)?;
    files.push("receipts.json".to_string());

    let mut artifact_payload_entries = Vec::<TraceBundleArtifactPayloadEntry>::new();
    let mut payload_path_by_artifact_id = std::collections::HashMap::<String, String>::new();
    if include_artifact_payloads {
        for artifact in &source.artifacts {
            let Some(bytes) =
                orchestrator::load_artifact_content(&memory_runtime, &artifact.artifact_id)
            else {
                continue;
            };
            let extension = artifact_file_extension(&artifact.artifact_type, &bytes);
            let path = format!("artifacts/content/{}.{}", artifact.artifact_id, extension);
            write_zip_bytes(&mut zip, &path, &bytes)?;
            payload_path_by_artifact_id.insert(artifact.artifact_id.clone(), path.clone());
            artifact_payload_entries.push(TraceBundleArtifactPayloadEntry {
                artifact_id: artifact.artifact_id.clone(),
                artifact_type: artifact.artifact_type.clone(),
                path: path.clone(),
            });
            files.push(path);
        }
    }

    let artifacts_index = source
        .artifacts
        .iter()
        .map(|artifact| {
            json!({
                "artifact_id": artifact.artifact_id,
                "created_at": artifact.created_at,
                "thread_id": artifact.thread_id,
                "artifact_type": artifact.artifact_type,
                "title": artifact.title,
                "description": artifact.description,
                "content_ref": artifact.content_ref,
                "metadata": artifact.metadata,
                "version": artifact.version,
                "parent_artifact_id": artifact.parent_artifact_id,
                "content_entry": payload_path_by_artifact_id.get(&artifact.artifact_id),
            })
        })
        .collect::<Vec<_>>();
    write_zip_json(&mut zip, "artifacts/index.json", &artifacts_index)?;
    files.push("artifacts/index.json".to_string());

    let trace_bundle_path = "trace_bundle.json".to_string();
    let trace_bundle =
        build_canonical_trace_bundle(source, artifact_payload_entries, include_artifact_payloads);
    write_zip_json(&mut zip, &trace_bundle_path, &trace_bundle)?;
    files.push(trace_bundle_path.clone());

    let manifest_path = "manifest.json".to_string();
    let mut manifest_files = files.clone();
    manifest_files.push(manifest_path.clone());
    let manifest = ExportBundleManifest {
        schema_version: 2,
        exported_at_utc: now_iso(),
        thread_id,
        answer_present: !trace_bundle.latest_answer_markdown.trim().is_empty(),
        event_count: trace_bundle.stats.event_count,
        artifact_count: trace_bundle.stats.artifact_count,
        included_artifact_payloads: include_artifact_payloads,
        canonical_trace_bundle_entry: Some(trace_bundle_path),
        files: manifest_files,
    };
    write_zip_json(&mut zip, &manifest_path, &manifest)?;

    zip.finish()
        .map_err(|err| format!("failed to finalize export bundle: {err}"))?;
    Ok(output_path)
}

fn load_canonical_trace_bundle_source(
    memory_runtime: &Arc<MemoryRuntime>,
    thread_id: &str,
) -> Result<CanonicalTraceBundleSource, String> {
    let thread_id = thread_id.trim().to_string();
    if thread_id.is_empty() {
        return Err("thread_id must not be empty".to_string());
    }

    let task = orchestrator::load_local_task(memory_runtime, &thread_id);
    let history = task
        .as_ref()
        .map(|task| task.history.clone())
        .unwrap_or_default();
    let events = orchestrator::load_events(memory_runtime, &thread_id, None, None);
    let artifacts = orchestrator::load_artifacts(memory_runtime, &thread_id);
    let session_id = task
        .as_ref()
        .and_then(|task| task.session_id.as_deref())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(thread_id.as_str())
        .to_string();
    let session_summary =
        trace_bundle_session_summary(memory_runtime, &thread_id, &session_id, task.as_ref());
    let interventions = scoped_interventions_for_trace_bundle(
        &orchestrator::load_interventions(memory_runtime),
        &thread_id,
        &session_id,
    );
    let assistant_notifications = scoped_notifications_for_trace_bundle(
        &orchestrator::load_assistant_notifications(memory_runtime),
        &thread_id,
        &session_id,
    );
    let assistant_workbench_activities = scoped_workbench_activities_for_trace_bundle(
        &orchestrator::load_assistant_workbench_activities(memory_runtime),
        &thread_id,
        &session_id,
    );
    let answer = latest_agent_answer(&history).or_else(|| latest_chat_reply_output(&events));
    let latest_answer_markdown = answer.unwrap_or_else(|| {
        "# No canonical answer was found for this run.\n\nThe event stream and artifacts are included in this export.".to_string()
    });
    let receipts = events
        .iter()
        .filter(|event| event.event_type == EventType::Receipt)
        .cloned()
        .collect::<Vec<_>>();

    Ok(CanonicalTraceBundleSource {
        thread_id,
        session_id,
        latest_answer_markdown,
        session_summary,
        task,
        history,
        events,
        receipts,
        artifacts,
        interventions,
        assistant_notifications,
        assistant_workbench_activities,
    })
}

fn build_canonical_trace_bundle(
    source: CanonicalTraceBundleSource,
    artifact_payloads: Vec<TraceBundleArtifactPayloadEntry>,
    include_artifact_payloads: bool,
) -> CanonicalTraceBundle {
    let stats = TraceBundleStats {
        event_count: source.events.len(),
        receipt_count: source.receipts.len(),
        artifact_count: source.artifacts.len(),
        run_bundle_count: source
            .artifacts
            .iter()
            .filter(|artifact| artifact.artifact_type == ArtifactType::RunBundle)
            .count(),
        report_artifact_count: source
            .artifacts
            .iter()
            .filter(|artifact| artifact.artifact_type == ArtifactType::Report)
            .count(),
        intervention_count: source.interventions.len(),
        assistant_notification_count: source.assistant_notifications.len(),
        assistant_workbench_activity_count: source.assistant_workbench_activities.len(),
        included_artifact_payloads: include_artifact_payloads,
        included_artifact_payload_count: artifact_payloads.len(),
    };

    CanonicalTraceBundle {
        schema_version: CANONICAL_TRACE_BUNDLE_SCHEMA_VERSION,
        exported_at_utc: now_iso(),
        thread_id: source.thread_id,
        session_id: source.session_id,
        latest_answer_markdown: source.latest_answer_markdown,
        stats,
        session_summary: source.session_summary,
        task: source.task,
        history: source.history,
        events: source.events,
        receipts: source.receipts,
        artifacts: source.artifacts,
        artifact_payloads,
        interventions: source.interventions,
        assistant_notifications: source.assistant_notifications,
        assistant_workbench_activities: source.assistant_workbench_activities,
    }
}

fn clip_trace_diff_text(value: &str, max_chars: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        return compact;
    }

    let clipped = compact
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    format!("{}…", clipped.trim_end())
}

fn humanize_identifier(value: &str) -> String {
    value
        .split(['_', '-', ':'])
        .filter(|segment| !segment.trim().is_empty())
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                Some(first) => {
                    let mut word = String::new();
                    word.extend(first.to_uppercase());
                    word.push_str(chars.as_str().to_lowercase().as_str());
                    word
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn summarize_optional_text(value: Option<&str>) -> String {
    trim_non_empty(value)
        .map(|value| clip_trace_diff_text(&value, 88))
        .unwrap_or_else(|| "none".to_string())
}

fn summarize_answer_headline(answer: &str) -> String {
    answer
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| {
            let stripped = line.trim_start_matches('#').trim_start_matches('-').trim();
            clip_trace_diff_text(stripped, 92)
        })
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| "No retained answer".to_string())
}

fn format_phase_label(summary: Option<&SessionSummary>) -> String {
    summary
        .and_then(|item| item.phase.as_ref())
        .map(|phase| humanize_identifier(&format!("{phase:?}")))
        .unwrap_or_else(|| "Unknown phase".to_string())
}

fn session_overview_label(bundle: &CanonicalTraceBundle) -> String {
    let title = bundle
        .session_summary
        .as_ref()
        .map(|summary| clip_trace_diff_text(summary.title.trim(), 48))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| clip_trace_diff_text(&bundle.thread_id, 24));
    let phase = format_phase_label(bundle.session_summary.as_ref());
    let step = bundle
        .session_summary
        .as_ref()
        .and_then(|summary| summary.current_step.as_deref())
        .map(|value| clip_trace_diff_text(value, 40))
        .unwrap_or_else(|| "No current step".to_string());
    format!("{title} · {phase} · {step}")
}

fn json_value_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.trim().to_string(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(flag)) => flag.to_string(),
        _ => String::new(),
    }
}

fn event_tool_name_for_diff(event: &AgentEvent) -> String {
    for key in ["tool_name", "tool", "name"] {
        let digest_value = json_value_text(event.digest.get(key));
        if !digest_value.is_empty() {
            return digest_value;
        }
        let details_value = json_value_text(event.details.get(key));
        if !details_value.is_empty() {
            return details_value;
        }
    }
    String::new()
}

fn summarize_counter(counter: &BTreeMap<String, usize>, limit: usize) -> String {
    let mut entries = counter
        .iter()
        .filter(|(_, count)| **count > 0)
        .map(|(label, count)| (label.clone(), *count))
        .collect::<Vec<_>>();
    entries.sort_by(|(left_label, left_count), (right_label, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_label.cmp(right_label))
    });

    if entries.is_empty() {
        return "none".to_string();
    }

    entries
        .into_iter()
        .take(limit)
        .map(|(label, count)| format!("{}×{}", humanize_identifier(&label), count))
        .collect::<Vec<_>>()
        .join(", ")
}

fn artifact_type_counter(artifacts: &[Artifact]) -> BTreeMap<String, usize> {
    let mut counter = BTreeMap::<String, usize>::new();
    for artifact in artifacts {
        let label = format!("{:?}", artifact.artifact_type);
        *counter.entry(label).or_default() += 1;
    }
    counter
}

fn receipt_tool_counter(events: &[AgentEvent]) -> BTreeMap<String, usize> {
    let mut counter = BTreeMap::<String, usize>::new();
    for event in events {
        if event.event_type != EventType::Receipt {
            continue;
        }
        let tool_name = event_tool_name_for_diff(event);
        if tool_name.is_empty() {
            continue;
        }
        *counter.entry(tool_name).or_default() += 1;
    }
    counter
}

fn intervention_status_counter(items: &[InterventionRecord]) -> BTreeMap<String, usize> {
    let mut counter = BTreeMap::<String, usize>::new();
    for item in items {
        *counter.entry(format!("{:?}", item.status)).or_default() += 1;
    }
    counter
}

fn intervention_type_counter(items: &[InterventionRecord]) -> BTreeMap<String, usize> {
    let mut counter = BTreeMap::<String, usize>::new();
    for item in items {
        *counter
            .entry(format!("{:?}", item.intervention_type))
            .or_default() += 1;
    }
    counter
}

fn assistant_status_counter(items: &[AssistantNotificationRecord]) -> BTreeMap<String, usize> {
    let mut counter = BTreeMap::<String, usize>::new();
    for item in items {
        *counter.entry(format!("{:?}", item.status)).or_default() += 1;
    }
    counter
}

fn assistant_class_counter(items: &[AssistantNotificationRecord]) -> BTreeMap<String, usize> {
    let mut counter = BTreeMap::<String, usize>::new();
    for item in items {
        *counter
            .entry(format!("{:?}", item.notification_class))
            .or_default() += 1;
    }
    counter
}

fn workbench_status_counter(items: &[AssistantWorkbenchActivityRecord]) -> BTreeMap<String, usize> {
    let mut counter = BTreeMap::<String, usize>::new();
    for item in items {
        *counter.entry(item.status.trim().to_string()).or_default() += 1;
    }
    counter
}

fn count_matching_receipts(events: &[AgentEvent], candidates: &[&str]) -> usize {
    events
        .iter()
        .filter(|event| event.event_type == EventType::Receipt)
        .filter(|event| {
            let tool_name = event_tool_name_for_diff(event);
            candidates
                .iter()
                .any(|candidate| tool_name.eq_ignore_ascii_case(candidate))
        })
        .count()
}

fn changed_detail(
    details: &mut Vec<String>,
    changed_labels: &mut Vec<String>,
    label: &str,
    left_value: String,
    right_value: String,
) {
    if left_value == right_value {
        return;
    }

    changed_labels.push(label.to_string());
    details.push(format!("{label}: {left_value} -> {right_value}"));
}

fn summarize_changed_labels(changed_labels: &[String]) -> String {
    match changed_labels.len() {
        0 => "Matched".to_string(),
        1 => changed_labels[0].clone(),
        2 => format!("{} and {}", changed_labels[0], changed_labels[1]),
        _ => format!(
            "{}, {}, and {} more",
            changed_labels[0],
            changed_labels[1],
            changed_labels.len() - 2
        ),
    }
}

fn artifact_title_set(artifacts: &[Artifact]) -> BTreeSet<String> {
    artifacts
        .iter()
        .map(|artifact| artifact.title.trim().to_string())
        .filter(|title| !title.is_empty())
        .collect()
}

fn summarize_title_delta(
    left: &BTreeSet<String>,
    right: &BTreeSet<String>,
    limit: usize,
) -> (String, String) {
    let removed = left
        .difference(right)
        .take(limit)
        .map(|title| clip_trace_diff_text(title, 42))
        .collect::<Vec<_>>();
    let added = right
        .difference(left)
        .take(limit)
        .map(|title| clip_trace_diff_text(title, 42))
        .collect::<Vec<_>>();

    let removed_summary = if removed.is_empty() {
        "none".to_string()
    } else {
        removed.join(", ")
    };
    let added_summary = if added.is_empty() {
        "none".to_string()
    } else {
        added.join(", ")
    };

    (added_summary, removed_summary)
}

fn compare_canonical_trace_bundles(
    left: &CanonicalTraceBundle,
    right: &CanonicalTraceBundle,
) -> TraceBundleDiffResult {
    let left_title = left
        .session_summary
        .as_ref()
        .map(|summary| summary.title.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| left.thread_id.clone());
    let right_title = right
        .session_summary
        .as_ref()
        .map(|summary| summary.title.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| right.thread_id.clone());

    let left_answer = summarize_answer_headline(&left.latest_answer_markdown);
    let right_answer = summarize_answer_headline(&right.latest_answer_markdown);

    let mut session_details = Vec::<String>::new();
    let mut session_changed_labels = Vec::<String>::new();
    changed_detail(
        &mut session_details,
        &mut session_changed_labels,
        "Title",
        clip_trace_diff_text(&left_title, 52),
        clip_trace_diff_text(&right_title, 52),
    );
    changed_detail(
        &mut session_details,
        &mut session_changed_labels,
        "Phase",
        format_phase_label(left.session_summary.as_ref()),
        format_phase_label(right.session_summary.as_ref()),
    );
    changed_detail(
        &mut session_details,
        &mut session_changed_labels,
        "Current step",
        summarize_optional_text(
            left.session_summary
                .as_ref()
                .and_then(|summary| summary.current_step.as_deref()),
        ),
        summarize_optional_text(
            right
                .session_summary
                .as_ref()
                .and_then(|summary| summary.current_step.as_deref()),
        ),
    );
    changed_detail(
        &mut session_details,
        &mut session_changed_labels,
        "Resume hint",
        summarize_optional_text(
            left.session_summary
                .as_ref()
                .and_then(|summary| summary.resume_hint.as_deref()),
        ),
        summarize_optional_text(
            right
                .session_summary
                .as_ref()
                .and_then(|summary| summary.resume_hint.as_deref()),
        ),
    );
    changed_detail(
        &mut session_details,
        &mut session_changed_labels,
        "Workspace root",
        summarize_optional_text(
            left.session_summary
                .as_ref()
                .and_then(|summary| summary.workspace_root.as_deref()),
        ),
        summarize_optional_text(
            right
                .session_summary
                .as_ref()
                .and_then(|summary| summary.workspace_root.as_deref()),
        ),
    );
    changed_detail(
        &mut session_details,
        &mut session_changed_labels,
        "Answer headline",
        left_answer.clone(),
        right_answer.clone(),
    );
    let session_changed = !session_details.is_empty();
    let session_section = TraceBundleDiffSection {
        key: "session".to_string(),
        label: "Session state".to_string(),
        changed: session_changed,
        summary: if session_changed {
            format!(
                "{} diverged between the retained runs.",
                summarize_changed_labels(&session_changed_labels)
            )
        } else {
            "Session summary, resume cues, and answer headline matched.".to_string()
        },
        left_value: Some(session_overview_label(left)),
        right_value: Some(session_overview_label(right)),
        details: session_details,
    };

    let left_intervention_statuses = intervention_status_counter(&left.interventions);
    let right_intervention_statuses = intervention_status_counter(&right.interventions);
    let left_intervention_types = intervention_type_counter(&left.interventions);
    let right_intervention_types = intervention_type_counter(&right.interventions);
    let left_notification_statuses = assistant_status_counter(&left.assistant_notifications);
    let right_notification_statuses = assistant_status_counter(&right.assistant_notifications);
    let left_notification_classes = assistant_class_counter(&left.assistant_notifications);
    let right_notification_classes = assistant_class_counter(&right.assistant_notifications);
    let left_blocking = left
        .interventions
        .iter()
        .filter(|item| item.blocking)
        .count();
    let right_blocking = right
        .interventions
        .iter()
        .filter(|item| item.blocking)
        .count();
    let mut approval_details = Vec::<String>::new();
    let mut approval_changed_labels = Vec::<String>::new();
    changed_detail(
        &mut approval_details,
        &mut approval_changed_labels,
        "Interventions",
        left.interventions.len().to_string(),
        right.interventions.len().to_string(),
    );
    changed_detail(
        &mut approval_details,
        &mut approval_changed_labels,
        "Notifications",
        left.assistant_notifications.len().to_string(),
        right.assistant_notifications.len().to_string(),
    );
    changed_detail(
        &mut approval_details,
        &mut approval_changed_labels,
        "Blocking gates",
        left_blocking.to_string(),
        right_blocking.to_string(),
    );
    changed_detail(
        &mut approval_details,
        &mut approval_changed_labels,
        "Intervention status mix",
        summarize_counter(&left_intervention_statuses, 3),
        summarize_counter(&right_intervention_statuses, 3),
    );
    changed_detail(
        &mut approval_details,
        &mut approval_changed_labels,
        "Intervention type mix",
        summarize_counter(&left_intervention_types, 3),
        summarize_counter(&right_intervention_types, 3),
    );
    changed_detail(
        &mut approval_details,
        &mut approval_changed_labels,
        "Notification status mix",
        summarize_counter(&left_notification_statuses, 3),
        summarize_counter(&right_notification_statuses, 3),
    );
    changed_detail(
        &mut approval_details,
        &mut approval_changed_labels,
        "Notification class mix",
        summarize_counter(&left_notification_classes, 3),
        summarize_counter(&right_notification_classes, 3),
    );
    let approvals_changed = !approval_details.is_empty();
    let approvals_section = TraceBundleDiffSection {
        key: "approvals".to_string(),
        label: "Approvals and interventions".to_string(),
        changed: approvals_changed,
        summary: if approvals_changed {
            format!(
                "{} changed across the operator approval path.",
                summarize_changed_labels(&approval_changed_labels)
            )
        } else {
            "Approval gates and operator notifications matched.".to_string()
        },
        left_value: Some(format!(
            "{} interventions · {} notifications",
            left.interventions.len(),
            left.assistant_notifications.len()
        )),
        right_value: Some(format!(
            "{} interventions · {} notifications",
            right.interventions.len(),
            right.assistant_notifications.len()
        )),
        details: approval_details,
    };

    let left_delegate_receipts = count_matching_receipts(
        &left.events,
        &["agent__delegate", "agent::delegate", "delegate"],
    );
    let right_delegate_receipts = count_matching_receipts(
        &right.events,
        &["agent__delegate", "agent::delegate", "delegate"],
    );
    let left_await_receipts = count_matching_receipts(
        &left.events,
        &["agent__await", "agent::await_result", "await_result"],
    );
    let right_await_receipts = count_matching_receipts(
        &right.events,
        &["agent__await", "agent::await_result", "await_result"],
    );
    let left_workbench_statuses = workbench_status_counter(&left.assistant_workbench_activities);
    let right_workbench_statuses = workbench_status_counter(&right.assistant_workbench_activities);
    let left_receipt_tools = receipt_tool_counter(&left.events);
    let right_receipt_tools = receipt_tool_counter(&right.events);
    let mut worker_details = Vec::<String>::new();
    let mut worker_changed_labels = Vec::<String>::new();
    changed_detail(
        &mut worker_details,
        &mut worker_changed_labels,
        "Delegate receipts",
        left_delegate_receipts.to_string(),
        right_delegate_receipts.to_string(),
    );
    changed_detail(
        &mut worker_details,
        &mut worker_changed_labels,
        "Await-result receipts",
        left_await_receipts.to_string(),
        right_await_receipts.to_string(),
    );
    changed_detail(
        &mut worker_details,
        &mut worker_changed_labels,
        "Workbench activity count",
        left.assistant_workbench_activities.len().to_string(),
        right.assistant_workbench_activities.len().to_string(),
    );
    changed_detail(
        &mut worker_details,
        &mut worker_changed_labels,
        "Workbench status mix",
        summarize_counter(&left_workbench_statuses, 3),
        summarize_counter(&right_workbench_statuses, 3),
    );
    changed_detail(
        &mut worker_details,
        &mut worker_changed_labels,
        "Receipt tool mix",
        summarize_counter(&left_receipt_tools, 4),
        summarize_counter(&right_receipt_tools, 4),
    );
    let workers_changed = !worker_details.is_empty();
    let workers_section = TraceBundleDiffSection {
        key: "workers".to_string(),
        label: "Workers and playbooks".to_string(),
        changed: workers_changed,
        summary: if workers_changed {
            format!(
                "{} changed across delegation and worker receipts.",
                summarize_changed_labels(&worker_changed_labels)
            )
        } else {
            "Delegation receipts and worker activity matched.".to_string()
        },
        left_value: Some(format!(
            "{} delegate · {} await_result · {} workbench",
            left_delegate_receipts,
            left_await_receipts,
            left.assistant_workbench_activities.len()
        )),
        right_value: Some(format!(
            "{} delegate · {} await_result · {} workbench",
            right_delegate_receipts,
            right_await_receipts,
            right.assistant_workbench_activities.len()
        )),
        details: worker_details,
    };

    let left_artifact_types = artifact_type_counter(&left.artifacts);
    let right_artifact_types = artifact_type_counter(&right.artifacts);
    let left_artifact_titles = artifact_title_set(&left.artifacts);
    let right_artifact_titles = artifact_title_set(&right.artifacts);
    let (added_titles, removed_titles) =
        summarize_title_delta(&left_artifact_titles, &right_artifact_titles, 3);
    let mut artifact_details = Vec::<String>::new();
    let mut artifact_changed_labels = Vec::<String>::new();
    changed_detail(
        &mut artifact_details,
        &mut artifact_changed_labels,
        "Artifact count",
        left.artifacts.len().to_string(),
        right.artifacts.len().to_string(),
    );
    changed_detail(
        &mut artifact_details,
        &mut artifact_changed_labels,
        "Artifact type mix",
        summarize_counter(&left_artifact_types, 4),
        summarize_counter(&right_artifact_types, 4),
    );
    changed_detail(
        &mut artifact_details,
        &mut artifact_changed_labels,
        "Added retained outputs",
        "none".to_string(),
        added_titles,
    );
    changed_detail(
        &mut artifact_details,
        &mut artifact_changed_labels,
        "Removed retained outputs",
        removed_titles,
        "none".to_string(),
    );
    let artifacts_changed = !artifact_details.is_empty();
    let artifacts_section = TraceBundleDiffSection {
        key: "artifacts".to_string(),
        label: "Artifacts and outputs".to_string(),
        changed: artifacts_changed,
        summary: if artifacts_changed {
            format!(
                "{} changed in the retained output set.",
                summarize_changed_labels(&artifact_changed_labels)
            )
        } else {
            "Artifact counts and retained outputs matched.".to_string()
        },
        left_value: Some(format!("{} retained artifacts", left.artifacts.len())),
        right_value: Some(format!("{} retained artifacts", right.artifacts.len())),
        details: artifact_details,
    };

    let left_last_event = left
        .events
        .last()
        .map(|event| clip_trace_diff_text(event.title.trim(), 52))
        .unwrap_or_else(|| "No retained events".to_string());
    let right_last_event = right
        .events
        .last()
        .map(|event| clip_trace_diff_text(event.title.trim(), 52))
        .unwrap_or_else(|| "No retained events".to_string());
    let left_event_types = {
        let mut counter = BTreeMap::<String, usize>::new();
        for event in &left.events {
            *counter
                .entry(format!("{:?}", event.event_type))
                .or_default() += 1;
        }
        counter
    };
    let right_event_types = {
        let mut counter = BTreeMap::<String, usize>::new();
        for event in &right.events {
            *counter
                .entry(format!("{:?}", event.event_type))
                .or_default() += 1;
        }
        counter
    };
    let mut runtime_details = Vec::<String>::new();
    let mut runtime_changed_labels = Vec::<String>::new();
    changed_detail(
        &mut runtime_details,
        &mut runtime_changed_labels,
        "Event count",
        left.events.len().to_string(),
        right.events.len().to_string(),
    );
    changed_detail(
        &mut runtime_details,
        &mut runtime_changed_labels,
        "Receipt count",
        left.receipts.len().to_string(),
        right.receipts.len().to_string(),
    );
    changed_detail(
        &mut runtime_details,
        &mut runtime_changed_labels,
        "Event type mix",
        summarize_counter(&left_event_types, 4),
        summarize_counter(&right_event_types, 4),
    );
    changed_detail(
        &mut runtime_details,
        &mut runtime_changed_labels,
        "Receipt tool mix",
        summarize_counter(&left_receipt_tools, 4),
        summarize_counter(&right_receipt_tools, 4),
    );
    changed_detail(
        &mut runtime_details,
        &mut runtime_changed_labels,
        "Last retained event",
        left_last_event,
        right_last_event,
    );
    let runtime_changed = !runtime_details.is_empty();
    let runtime_section = TraceBundleDiffSection {
        key: "runtime_events".to_string(),
        label: "Runtime events".to_string(),
        changed: runtime_changed,
        summary: if runtime_changed {
            format!(
                "{} changed in the retained event stream.",
                summarize_changed_labels(&runtime_changed_labels)
            )
        } else {
            "Event counts and receipt mix matched.".to_string()
        },
        left_value: Some(format!(
            "{} events · {} receipts",
            left.events.len(),
            left.receipts.len()
        )),
        right_value: Some(format!(
            "{} events · {} receipts",
            right.events.len(),
            right.receipts.len()
        )),
        details: runtime_details,
    };

    let sections = vec![
        session_section,
        approvals_section,
        workers_section,
        artifacts_section,
        runtime_section,
    ];
    let first_divergence = sections.iter().find(|section| section.changed);
    let changed_section_count = sections.iter().filter(|section| section.changed).count();
    let stats = vec![
        TraceBundleDiffStat {
            label: "Events".to_string(),
            left_value: left.events.len().to_string(),
            right_value: right.events.len().to_string(),
        },
        TraceBundleDiffStat {
            label: "Receipts".to_string(),
            left_value: left.receipts.len().to_string(),
            right_value: right.receipts.len().to_string(),
        },
        TraceBundleDiffStat {
            label: "Artifacts".to_string(),
            left_value: left.artifacts.len().to_string(),
            right_value: right.artifacts.len().to_string(),
        },
        TraceBundleDiffStat {
            label: "Approvals".to_string(),
            left_value: (left.interventions.len() + left.assistant_notifications.len()).to_string(),
            right_value: (right.interventions.len() + right.assistant_notifications.len())
                .to_string(),
        },
        TraceBundleDiffStat {
            label: "Workers".to_string(),
            left_value: (left_delegate_receipts
                + left_await_receipts
                + left.assistant_workbench_activities.len())
            .to_string(),
            right_value: (right_delegate_receipts
                + right_await_receipts
                + right.assistant_workbench_activities.len())
            .to_string(),
        },
    ];

    TraceBundleDiffResult {
        schema_version: TRACE_BUNDLE_DIFF_SCHEMA_VERSION,
        compared_at_utc: now_iso(),
        left_thread_id: left.thread_id.clone(),
        right_thread_id: right.thread_id.clone(),
        left_session_summary: left.session_summary.clone(),
        right_session_summary: right.session_summary.clone(),
        first_divergence_key: first_divergence.map(|section| section.key.clone()),
        first_divergence_summary: first_divergence.map(|section| section.summary.clone()),
        changed_section_count,
        stats,
        sections,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AgentPhase, AssistantNotificationClass, AssistantNotificationStatus, ChatMessage,
        EventStatus, InterventionStatus, InterventionType, NotificationSeverity,
    };

    #[test]
    fn latest_agent_answer_prefers_last_agent_message() {
        let history = vec![
            ChatMessage {
                role: "user".to_string(),
                text: "question".to_string(),
                timestamp: 1,
            },
            ChatMessage {
                role: "agent".to_string(),
                text: "answer 1".to_string(),
                timestamp: 2,
            },
            ChatMessage {
                role: "agent".to_string(),
                text: "answer 2".to_string(),
                timestamp: 3,
            },
        ];

        assert_eq!(latest_agent_answer(&history).as_deref(), Some("answer 2"));
    }

    #[test]
    fn latest_chat_reply_output_extracts_output_field() {
        let events = vec![AgentEvent {
            event_id: "evt-1".to_string(),
            timestamp: "2026-02-19T00:00:00Z".to_string(),
            thread_id: "thread-a".to_string(),
            step_index: 1,
            event_type: EventType::CommandRun,
            title: "Ran chat".to_string(),
            digest: json!({ "tool_name": "chat__reply" }),
            details: json!({ "output": "final answer" }),
            artifact_refs: Vec::new(),
            receipt_ref: None,
            input_refs: Vec::new(),
            status: EventStatus::Success,
            duration_ms: None,
        }];

        assert_eq!(
            latest_chat_reply_output(&events).as_deref(),
            Some("final answer")
        );
    }

    #[test]
    fn artifact_extension_falls_back_to_binary_when_not_utf8() {
        assert_eq!(
            artifact_file_extension(&ArtifactType::Log, &[0xff, 0xfe]),
            "bin"
        );
    }

    #[test]
    fn scoped_interventions_include_thread_and_session_matches() {
        let mut thread_match = InterventionRecord::default();
        thread_match.item_id = "thread".to_string();
        thread_match.thread_id = Some("thread-1".to_string());

        let mut session_match = InterventionRecord::default();
        session_match.item_id = "session".to_string();
        session_match.session_id = Some("session-1".to_string());

        let mut other = InterventionRecord::default();
        other.item_id = "other".to_string();
        other.thread_id = Some("thread-2".to_string());

        let scoped = scoped_interventions_for_trace_bundle(
            &[thread_match, session_match, other],
            "thread-1",
            "session-1",
        );
        let ids = scoped
            .into_iter()
            .map(|item| item.item_id)
            .collect::<Vec<_>>();

        assert_eq!(ids, vec!["thread".to_string(), "session".to_string()]);
    }

    #[test]
    fn workbench_activity_scope_prefers_evidence_thread() {
        let activity = AssistantWorkbenchActivityRecord {
            activity_id: "activity-1".to_string(),
            session_kind: "gmail_reply".to_string(),
            surface: "gate".to_string(),
            action: "send".to_string(),
            status: "succeeded".to_string(),
            message: "Sent reply".to_string(),
            timestamp_ms: 1,
            source_notification_id: None,
            connector_id: None,
            thread_id: Some("gmail-thread".to_string()),
            event_id: None,
            evidence_thread_id: Some("trace-thread".to_string()),
            detail: None,
        };

        assert!(workbench_activity_belongs_to_trace_scope(
            &activity,
            "trace-thread",
            "session-1",
        ));
        assert!(!workbench_activity_belongs_to_trace_scope(
            &activity,
            "other-thread",
            "session-1",
        ));
    }

    #[test]
    fn compare_trace_bundles_surfaces_first_divergence() {
        let timestamp = "2026-04-04T12:00:00Z".to_string();
        let left_receipt = AgentEvent {
            event_id: "evt-left-2".to_string(),
            timestamp: timestamp.clone(),
            thread_id: "left-session".to_string(),
            step_index: 1,
            event_type: EventType::Receipt,
            title: "Delegated".to_string(),
            digest: json!({ "tool_name": "agent__delegate" }),
            details: json!({}),
            artifact_refs: Vec::new(),
            receipt_ref: None,
            input_refs: Vec::new(),
            status: EventStatus::Success,
            duration_ms: None,
        };
        let right_receipt = AgentEvent {
            event_id: "evt-right-2".to_string(),
            timestamp: timestamp.clone(),
            thread_id: "right-session".to_string(),
            step_index: 1,
            event_type: EventType::Receipt,
            title: "Awaited".to_string(),
            digest: json!({ "tool_name": "agent__await" }),
            details: json!({}),
            artifact_refs: Vec::new(),
            receipt_ref: None,
            input_refs: Vec::new(),
            status: EventStatus::Success,
            duration_ms: None,
        };

        let left = CanonicalTraceBundle {
            schema_version: CANONICAL_TRACE_BUNDLE_SCHEMA_VERSION,
            exported_at_utc: timestamp.clone(),
            thread_id: "left-session".to_string(),
            session_id: "left-session".to_string(),
            latest_answer_markdown: "Left answer".to_string(),
            stats: TraceBundleStats {
                event_count: 2,
                receipt_count: 1,
                artifact_count: 1,
                run_bundle_count: 0,
                report_artifact_count: 1,
                intervention_count: 1,
                assistant_notification_count: 0,
                assistant_workbench_activity_count: 0,
                included_artifact_payloads: false,
                included_artifact_payload_count: 0,
            },
            session_summary: Some(SessionSummary {
                session_id: "left-session".to_string(),
                title: "Left session".to_string(),
                timestamp: 1,
                phase: Some(AgentPhase::Running),
                current_step: Some("Planning".to_string()),
                resume_hint: Some("Resume left".to_string()),
                workspace_root: Some("/tmp/left".to_string()),
            }),
            task: None,
            history: Vec::new(),
            events: vec![
                AgentEvent {
                    event_id: "evt-left-1".to_string(),
                    timestamp: timestamp.clone(),
                    thread_id: "left-session".to_string(),
                    step_index: 0,
                    event_type: EventType::InfoNote,
                    title: "Started".to_string(),
                    digest: json!({}),
                    details: json!({}),
                    artifact_refs: Vec::new(),
                    receipt_ref: None,
                    input_refs: Vec::new(),
                    status: EventStatus::Success,
                    duration_ms: None,
                },
                left_receipt.clone(),
            ],
            receipts: vec![left_receipt],
            artifacts: vec![Artifact {
                artifact_id: "artifact-left".to_string(),
                created_at: timestamp.clone(),
                thread_id: "left-session".to_string(),
                artifact_type: ArtifactType::Report,
                title: "Left report".to_string(),
                description: "Left report".to_string(),
                content_ref: "ioi-memory://artifact/artifact-left".to_string(),
                metadata: json!({}),
                version: Some(1),
                parent_artifact_id: None,
            }],
            artifact_payloads: Vec::new(),
            interventions: vec![InterventionRecord {
                item_id: "gate-left".to_string(),
                rail: Default::default(),
                intervention_type: InterventionType::ApprovalGate,
                status: InterventionStatus::Pending,
                severity: NotificationSeverity::High,
                blocking: true,
                title: "Gate".to_string(),
                summary: "Needs approval".to_string(),
                reason: None,
                recommended_action: None,
                consequence_if_ignored: None,
                created_at_ms: 1,
                updated_at_ms: 1,
                due_at_ms: None,
                expires_at_ms: None,
                snoozed_until_ms: None,
                dedupe_key: String::new(),
                thread_id: Some("left-session".to_string()),
                session_id: Some("left-session".to_string()),
                workflow_id: None,
                run_id: None,
                delivery_state: Default::default(),
                privacy: Default::default(),
                source: Default::default(),
                artifact_refs: Vec::new(),
                source_event_ids: Vec::new(),
                policy_refs: Default::default(),
                actions: Vec::new(),
                target: None,
                request_hash: None,
                policy_hash: None,
                approval_scope: None,
                sensitive_action_type: None,
                error_class: None,
                blocked_stage: None,
                retry_available: None,
                recovery_hint: None,
            }],
            assistant_notifications: Vec::new(),
            assistant_workbench_activities: Vec::new(),
        };
        let right = CanonicalTraceBundle {
            schema_version: CANONICAL_TRACE_BUNDLE_SCHEMA_VERSION,
            exported_at_utc: timestamp.clone(),
            thread_id: "right-session".to_string(),
            session_id: "right-session".to_string(),
            latest_answer_markdown: "Right answer".to_string(),
            stats: TraceBundleStats {
                event_count: 2,
                receipt_count: 1,
                artifact_count: 2,
                run_bundle_count: 0,
                report_artifact_count: 1,
                intervention_count: 0,
                assistant_notification_count: 1,
                assistant_workbench_activity_count: 0,
                included_artifact_payloads: false,
                included_artifact_payload_count: 0,
            },
            session_summary: Some(SessionSummary {
                session_id: "right-session".to_string(),
                title: "Right session".to_string(),
                timestamp: 2,
                phase: Some(AgentPhase::Complete),
                current_step: Some("Completed".to_string()),
                resume_hint: Some("Review output".to_string()),
                workspace_root: Some("/tmp/right".to_string()),
            }),
            task: None,
            history: Vec::new(),
            events: vec![
                AgentEvent {
                    event_id: "evt-right-1".to_string(),
                    timestamp: timestamp.clone(),
                    thread_id: "right-session".to_string(),
                    step_index: 0,
                    event_type: EventType::InfoNote,
                    title: "Started".to_string(),
                    digest: json!({}),
                    details: json!({}),
                    artifact_refs: Vec::new(),
                    receipt_ref: None,
                    input_refs: Vec::new(),
                    status: EventStatus::Success,
                    duration_ms: None,
                },
                right_receipt.clone(),
            ],
            receipts: vec![right_receipt],
            artifacts: vec![
                Artifact {
                    artifact_id: "artifact-right-1".to_string(),
                    created_at: timestamp.clone(),
                    thread_id: "right-session".to_string(),
                    artifact_type: ArtifactType::Report,
                    title: "Right report".to_string(),
                    description: "Right report".to_string(),
                    content_ref: "ioi-memory://artifact/artifact-right-1".to_string(),
                    metadata: json!({}),
                    version: Some(1),
                    parent_artifact_id: None,
                },
                Artifact {
                    artifact_id: "artifact-right-2".to_string(),
                    created_at: timestamp.clone(),
                    thread_id: "right-session".to_string(),
                    artifact_type: ArtifactType::File,
                    title: "Right file".to_string(),
                    description: "Right file".to_string(),
                    content_ref: "ioi-memory://artifact/artifact-right-2".to_string(),
                    metadata: json!({}),
                    version: Some(1),
                    parent_artifact_id: None,
                },
            ],
            artifact_payloads: Vec::new(),
            interventions: Vec::new(),
            assistant_notifications: vec![AssistantNotificationRecord {
                item_id: "notif-right".to_string(),
                rail: Default::default(),
                notification_class: AssistantNotificationClass::ValuableCompletion,
                status: AssistantNotificationStatus::Acknowledged,
                severity: NotificationSeverity::Low,
                title: "Done".to_string(),
                summary: "Completed".to_string(),
                reason: None,
                recommended_action: None,
                consequence_if_ignored: None,
                created_at_ms: 1,
                updated_at_ms: 1,
                due_at_ms: None,
                expires_at_ms: None,
                snoozed_until_ms: None,
                dedupe_key: String::new(),
                thread_id: Some("right-session".to_string()),
                session_id: Some("right-session".to_string()),
                workflow_id: None,
                run_id: None,
                delivery_state: Default::default(),
                privacy: Default::default(),
                source: Default::default(),
                artifact_refs: Vec::new(),
                source_event_ids: Vec::new(),
                policy_refs: Default::default(),
                actions: Vec::new(),
                target: None,
                priority_score: 0.0,
                confidence_score: 0.0,
                ranking_reason: Vec::new(),
            }],
            assistant_workbench_activities: Vec::new(),
        };

        let diff = compare_canonical_trace_bundles(&left, &right);

        assert_eq!(diff.changed_section_count, 5);
        assert_eq!(diff.first_divergence_key.as_deref(), Some("session"));
        assert_eq!(diff.sections.len(), 5);
        assert!(diff
            .sections
            .iter()
            .find(|section| section.key == "workers")
            .is_some_and(|section| section.changed));
        assert!(diff
            .sections
            .iter()
            .find(|section| section.key == "artifacts")
            .is_some_and(|section| section.changed));
    }
}
