use crate::models::{AgentEvent, Artifact, ArtifactType, EventType};
use crate::orchestrator;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ioi_scs::SovereignContextStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tauri::State;
use uuid::Uuid;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::models::AppState;

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn artifact_content_ref(artifact_id: &str) -> String {
    format!("scs://artifact/{}", artifact_id)
}

fn persist_artifact(
    scs: &Arc<Mutex<SovereignContextStore>>,
    artifact: &Artifact,
    content: &[u8],
) -> Artifact {
    orchestrator::append_artifact(scs, artifact, content);
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
    scs: &Arc<Mutex<SovereignContextStore>>,
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
    persist_artifact(scs, &artifact, output.as_bytes())
}

pub fn create_diff_artifact(
    scs: &Arc<Mutex<SovereignContextStore>>,
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
    persist_artifact(scs, &artifact, diff_text.as_bytes())
}

pub fn create_file_artifact(
    scs: &Arc<Mutex<SovereignContextStore>>,
    thread_id: &str,
    path: &str,
    revision: Option<String>,
    content: &str,
) -> Artifact {
    let metadata = json!({
        "path": path,
        "revision": revision,
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
    persist_artifact(scs, &artifact, content.as_bytes())
}

pub fn create_web_artifact(
    scs: &Arc<Mutex<SovereignContextStore>>,
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
    persist_artifact(scs, &artifact, content.as_bytes())
}

pub fn create_run_bundle(
    scs: &Arc<Mutex<SovereignContextStore>>,
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
    persist_artifact(scs, &artifact, &content)
}

pub fn create_report_artifact(
    scs: &Arc<Mutex<SovereignContextStore>>,
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
    persist_artifact(scs, &artifact, &content)
}

pub fn append_run_bundle_ref(
    scs: &Arc<Mutex<SovereignContextStore>>,
    thread_id: &str,
    run_bundle_id: &str,
    new_ref: &str,
) -> Option<Artifact> {
    let artifacts = orchestrator::load_artifacts(scs, thread_id);
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
    Some(persist_artifact(scs, &artifact, &content))
}

fn get_scs(
    state: &State<'_, Mutex<AppState>>,
) -> Result<Arc<Mutex<SovereignContextStore>>, String> {
    let guard = state
        .lock()
        .map_err(|_| "Failed to lock state".to_string())?;
    guard
        .studio_scs
        .clone()
        .ok_or_else(|| "SCS store unavailable".to_string())
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
    pub files: Vec<String>,
}

#[tauri::command]
pub fn get_thread_events(
    state: State<'_, Mutex<AppState>>,
    thread_id: String,
    limit: Option<usize>,
    cursor: Option<usize>,
) -> Result<Vec<AgentEvent>, String> {
    let scs = get_scs(&state)?;
    Ok(orchestrator::load_events(&scs, &thread_id, limit, cursor))
}

#[tauri::command]
pub fn get_thread_artifacts(
    state: State<'_, Mutex<AppState>>,
    thread_id: String,
) -> Result<Vec<Artifact>, String> {
    let scs = get_scs(&state)?;
    Ok(orchestrator::load_artifacts(&scs, &thread_id))
}

#[tauri::command]
pub fn get_artifact_content(
    state: State<'_, Mutex<AppState>>,
    artifact_id: String,
) -> Result<Option<ArtifactContentPayload>, String> {
    let scs = get_scs(&state)?;
    if let Some(bytes) = orchestrator::load_artifact_content(&scs, &artifact_id) {
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
    let scs = get_scs(&state)?;
    let artifacts = orchestrator::load_artifacts(&scs, &thread_id);

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
pub fn export_thread_bundle(
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

    let scs = get_scs(&state)?;
    let events = orchestrator::load_events(&scs, &thread_id, None, None);
    let artifacts = orchestrator::load_artifacts(&scs, &thread_id);
    let history = orchestrator::load_local_task(&scs, &thread_id)
        .map(|task| task.history)
        .unwrap_or_default();

    let answer = latest_agent_answer(&history).or_else(|| latest_chat_reply_output(&events));
    let answer_text = answer.unwrap_or_else(|| {
        "# No canonical answer was found for this run.\n\nThe event stream and artifacts are included in this export.".to_string()
    });

    let receipts = events
        .iter()
        .filter(|event| event.event_type == EventType::Receipt)
        .cloned()
        .collect::<Vec<_>>();

    let file =
        File::create(output).map_err(|err| format!("failed to create export bundle: {err}"))?;
    let mut zip = ZipWriter::new(file);
    let mut files = Vec::<String>::new();

    write_zip_bytes(&mut zip, "answer.md", answer_text.as_bytes())?;
    files.push("answer.md".to_string());

    write_zip_json(&mut zip, "history.json", &history)?;
    files.push("history.json".to_string());

    write_zip_json(&mut zip, "events.json", &events)?;
    files.push("events.json".to_string());

    write_zip_json(&mut zip, "receipts.json", &receipts)?;
    files.push("receipts.json".to_string());

    let mut payload_path_by_artifact_id = std::collections::HashMap::<String, String>::new();
    if include_artifact_payloads {
        for artifact in &artifacts {
            let Some(bytes) = orchestrator::load_artifact_content(&scs, &artifact.artifact_id)
            else {
                continue;
            };
            let extension = artifact_file_extension(&artifact.artifact_type, &bytes);
            let path = format!("artifacts/content/{}.{}", artifact.artifact_id, extension);
            write_zip_bytes(&mut zip, &path, &bytes)?;
            payload_path_by_artifact_id.insert(artifact.artifact_id.clone(), path.clone());
            files.push(path);
        }
    }

    let artifacts_index = artifacts
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

    let manifest_path = "manifest.json".to_string();
    let mut manifest_files = files.clone();
    manifest_files.push(manifest_path.clone());
    let manifest = ExportBundleManifest {
        schema_version: 1,
        exported_at_utc: now_iso(),
        thread_id,
        answer_present: !answer_text.trim().is_empty(),
        event_count: events.len(),
        artifact_count: artifacts.len(),
        included_artifact_payloads: include_artifact_payloads,
        files: manifest_files,
    };
    write_zip_json(&mut zip, &manifest_path, &manifest)?;

    zip.finish()
        .map_err(|err| format!("failed to finalize export bundle: {err}"))?;
    Ok(output_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ChatMessage, EventStatus};

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
}
