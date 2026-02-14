use crate::models::{AgentEvent, Artifact, ArtifactType};
use crate::orchestrator;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ioi_scs::SovereignContextStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tauri::State;
use uuid::Uuid;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactContentPayload {
    pub artifact_id: String,
    pub encoding: String,
    pub content: String,
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
