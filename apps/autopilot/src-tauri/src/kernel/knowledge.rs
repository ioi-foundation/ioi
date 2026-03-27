use crate::models::{
    AppState, KnowledgeCollectionEntryContent, KnowledgeCollectionEntryRecord,
    KnowledgeCollectionRecord, KnowledgeCollectionSearchHit, KnowledgeCollectionSourceRecord,
};
use crate::orchestrator::{load_knowledge_collections, save_knowledge_collections};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_memory::{HybridArchivalMemoryQuery, MemoryRuntime, NewArchivalMemoryRecord};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;

const KNOWLEDGE_CHUNK_SIZE: usize = 4_096;
const KNOWLEDGE_INSPECT_ID_OFFSET: u64 = 1_000_000_000_000;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn slugify(input: &str) -> String {
    let mut out = String::new();
    let mut last_was_sep = false;
    for ch in input.trim().chars() {
        let lowered = ch.to_ascii_lowercase();
        if lowered.is_ascii_alphanumeric() {
            out.push(lowered);
            last_was_sep = false;
        } else if !last_was_sep {
            out.push('-');
            last_was_sep = true;
        }
    }
    out.trim_matches('-').to_string()
}

fn preview_text(input: &str, max_chars: usize) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut preview: String = compact.chars().take(max_chars).collect();
    if compact.chars().count() > max_chars {
        preview.push_str("...");
    }
    preview
}

fn knowledge_artifact_thread_id(collection_id: &str) -> Result<[u8; 32], String> {
    let digest = sha256(format!("autopilot::knowledge::{}", collection_id).as_bytes())
        .map_err(|error| format!("Failed to derive knowledge artifact key: {}", error))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn entry_scope(collection_id: &str, entry_id: &str) -> String {
    format!("autopilot.knowledge.{}.{}", collection_id, entry_id)
}

fn entry_inspect_id(record_id: i64) -> Option<u64> {
    u64::try_from(record_id)
        .ok()
        .and_then(|value| KNOWLEDGE_INSPECT_ID_OFFSET.checked_add(value))
}

fn collection_mut<'a>(
    collections: &'a mut [KnowledgeCollectionRecord],
    collection_id: &str,
) -> Result<&'a mut KnowledgeCollectionRecord, String> {
    collections
        .iter_mut()
        .find(|collection| collection.collection_id == collection_id)
        .ok_or_else(|| format!("Knowledge collection '{}' was not found.", collection_id))
}

fn collection_ref<'a>(
    collections: &'a [KnowledgeCollectionRecord],
    collection_id: &str,
) -> Result<&'a KnowledgeCollectionRecord, String> {
    collections
        .iter()
        .find(|collection| collection.collection_id == collection_id)
        .ok_or_else(|| format!("Knowledge collection '{}' was not found.", collection_id))
}

fn runtime_resources(
    state: &State<'_, Mutex<AppState>>,
) -> Result<(Arc<MemoryRuntime>, Arc<dyn InferenceRuntime>), String> {
    let guard = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?;
    let memory_runtime = guard
        .memory_runtime
        .clone()
        .ok_or("Memory runtime not initialized".to_string())?;
    let inference_runtime = guard
        .inference_runtime
        .clone()
        .ok_or("Inference runtime not initialized".to_string())?;
    Ok((memory_runtime, inference_runtime))
}

fn memory_runtime_only(state: &State<'_, Mutex<AppState>>) -> Result<Arc<MemoryRuntime>, String> {
    let guard = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?;
    guard
        .memory_runtime
        .clone()
        .ok_or("Memory runtime not initialized".to_string())
}

async fn ingest_entry(
    memory_runtime: &Arc<MemoryRuntime>,
    inference: &Arc<dyn InferenceRuntime>,
    collection_id: &str,
    entry_id: &str,
    title: &str,
    kind: &str,
    raw_bytes: &[u8],
) -> Result<KnowledgeCollectionEntryRecord, String> {
    let artifact_thread_id = knowledge_artifact_thread_id(collection_id)?;
    let artifact_id = format!("knowledge.entry.{}.{}", collection_id, entry_id);
    let content_text = String::from_utf8_lossy(raw_bytes).to_string();
    let chunks = content_text
        .as_bytes()
        .chunks(KNOWLEDGE_CHUNK_SIZE)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect::<Vec<_>>();

    let artifact_metadata = serde_json::to_string(&json!({
        "collection_id": collection_id,
        "entry_id": entry_id,
        "title": title,
        "kind": kind,
        "trust_level": "standard",
    }))
    .map_err(|error| format!("Failed to serialize knowledge artifact metadata: {}", error))?;

    memory_runtime
        .upsert_artifact_json(artifact_thread_id, &artifact_id, &artifact_metadata)
        .map_err(|error| format!("Failed to persist knowledge artifact metadata: {}", error))?;
    memory_runtime
        .put_artifact_blob(artifact_thread_id, &artifact_id, raw_bytes)
        .map_err(|error| format!("Failed to persist knowledge artifact bytes: {}", error))?;

    let scope = entry_scope(collection_id, entry_id);
    let timestamp_ms = now_ms();
    let mut archival_record_ids = Vec::new();

    for (chunk_index, chunk_text) in chunks.iter().enumerate() {
        let normalized = chunk_text.trim();
        if normalized.is_empty() {
            continue;
        }

        let metadata_json = serde_json::to_string(&json!({
            "collection_id": collection_id,
            "entry_id": entry_id,
            "title": title,
            "kind": kind,
            "artifact_id": artifact_id,
            "chunk_index": chunk_index,
            "chunk_count": chunks.len(),
            "trust_level": "standard",
            "created_at_ms": timestamp_ms,
        }))
        .map_err(|error| format!("Failed to serialize knowledge entry metadata: {}", error))?;

        let record_id = memory_runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: scope.clone(),
                thread_id: None,
                kind: "knowledge_entry_chunk".to_string(),
                content: normalized.to_string(),
                metadata_json,
            })
            .map_err(|error| format!("Failed to persist knowledge archival record: {}", error))?
            .ok_or("Archival memory store unavailable".to_string())?;
        archival_record_ids.push(record_id);

        match inference.embed_text(normalized).await {
            Ok(vector) => {
                if let Err(error) = memory_runtime.upsert_archival_embedding(record_id, &vector) {
                    eprintln!(
                        "[Knowledge] Failed to persist embedding for record {}: {}",
                        record_id, error
                    );
                }
            }
            Err(error) => {
                eprintln!(
                    "[Knowledge] Embedding failed for collection={} entry={} record={}: {}",
                    collection_id, entry_id, record_id, error
                );
            }
        }
    }

    Ok(KnowledgeCollectionEntryRecord {
        entry_id: entry_id.to_string(),
        title: title.to_string(),
        kind: kind.to_string(),
        scope,
        artifact_id,
        byte_count: raw_bytes.len(),
        chunk_count: chunks.len(),
        archival_record_ids,
        created_at_ms: timestamp_ms,
        updated_at_ms: timestamp_ms,
        content_preview: preview_text(&content_text, 220),
    })
}

#[tauri::command]
pub async fn get_knowledge_collections(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<KnowledgeCollectionRecord>, String> {
    let memory_runtime = memory_runtime_only(&state)?;
    Ok(load_knowledge_collections(&memory_runtime))
}

#[tauri::command]
pub async fn create_knowledge_collection(
    state: State<'_, Mutex<AppState>>,
    name: String,
    description: Option<String>,
) -> Result<KnowledgeCollectionRecord, String> {
    let memory_runtime = memory_runtime_only(&state)?;
    let label = name.trim();
    if label.is_empty() {
        return Err("Knowledge collection name is required.".to_string());
    }

    let mut collections = load_knowledge_collections(&memory_runtime);
    let base_id = slugify(label);
    if base_id.is_empty() {
        return Err("Knowledge collection name must contain letters or numbers.".to_string());
    }
    let mut collection_id = base_id.clone();
    let mut suffix = 2usize;
    while collections
        .iter()
        .any(|collection| collection.collection_id == collection_id)
    {
        collection_id = format!("{}-{}", base_id, suffix);
        suffix += 1;
    }

    let timestamp_ms = now_ms();
    let collection = KnowledgeCollectionRecord {
        collection_id,
        label: label.to_string(),
        description: description.unwrap_or_default().trim().to_string(),
        created_at_ms: timestamp_ms,
        updated_at_ms: timestamp_ms,
        active: true,
        entries: Vec::new(),
        sources: Vec::new(),
    };
    collections.push(collection.clone());
    save_knowledge_collections(&memory_runtime, &collections);
    Ok(collection)
}

#[tauri::command]
pub async fn reset_knowledge_collection(
    state: State<'_, Mutex<AppState>>,
    collection_id: String,
) -> Result<(), String> {
    let memory_runtime = memory_runtime_only(&state)?;
    let mut collections = load_knowledge_collections(&memory_runtime);
    let collection = collection_mut(&mut collections, &collection_id)?;
    collection.entries.clear();
    collection.updated_at_ms = now_ms();
    save_knowledge_collections(&memory_runtime, &collections);
    Ok(())
}

#[tauri::command]
pub async fn delete_knowledge_collection(
    state: State<'_, Mutex<AppState>>,
    collection_id: String,
) -> Result<(), String> {
    let memory_runtime = memory_runtime_only(&state)?;
    let mut collections = load_knowledge_collections(&memory_runtime);
    let original_len = collections.len();
    collections.retain(|collection| collection.collection_id != collection_id);
    if collections.len() == original_len {
        return Err(format!(
            "Knowledge collection '{}' was not found.",
            collection_id
        ));
    }
    save_knowledge_collections(&memory_runtime, &collections);
    Ok(())
}

#[tauri::command]
pub async fn add_knowledge_text_entry(
    state: State<'_, Mutex<AppState>>,
    collection_id: String,
    title: String,
    content: String,
) -> Result<KnowledgeCollectionEntryRecord, String> {
    let (memory_runtime, inference) = runtime_resources(&state)?;
    let mut collections = load_knowledge_collections(&memory_runtime);
    let collection = collection_mut(&mut collections, &collection_id)?;
    let title = title.trim();
    let content = content.trim();
    if title.is_empty() {
        return Err("Entry title is required.".to_string());
    }
    if content.is_empty() {
        return Err("Entry content is required.".to_string());
    }
    let entry_base = slugify(title);
    let entry_id = format!(
        "{}-{}",
        if entry_base.is_empty() {
            "entry"
        } else {
            entry_base.as_str()
        },
        now_ms()
    );
    let entry = ingest_entry(
        &memory_runtime,
        &inference,
        &collection.collection_id,
        &entry_id,
        title,
        "text",
        content.as_bytes(),
    )
    .await?;
    collection.entries.insert(0, entry.clone());
    collection.updated_at_ms = now_ms();
    save_knowledge_collections(&memory_runtime, &collections);
    Ok(entry)
}

#[tauri::command]
pub async fn import_knowledge_file(
    state: State<'_, Mutex<AppState>>,
    collection_id: String,
    file_path: String,
) -> Result<KnowledgeCollectionEntryRecord, String> {
    let path = Path::new(&file_path);
    if !path.exists() {
        return Err(format!("File not found: {}", file_path));
    }

    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("imported-file")
        .to_string();
    let raw_bytes = fs::read(path).map_err(|error| format!("Failed to read file: {}", error))?;

    let (memory_runtime, inference) = runtime_resources(&state)?;
    let mut collections = load_knowledge_collections(&memory_runtime);
    let collection = collection_mut(&mut collections, &collection_id)?;
    let entry_base = slugify(&file_name);
    let entry_id = format!(
        "{}-{}",
        if entry_base.is_empty() {
            "file"
        } else {
            entry_base.as_str()
        },
        now_ms()
    );
    let entry = ingest_entry(
        &memory_runtime,
        &inference,
        &collection.collection_id,
        &entry_id,
        &file_name,
        "file",
        &raw_bytes,
    )
    .await?;
    collection.entries.insert(0, entry.clone());
    collection.updated_at_ms = now_ms();
    save_knowledge_collections(&memory_runtime, &collections);
    Ok(entry)
}

#[tauri::command]
pub async fn remove_knowledge_collection_entry(
    state: State<'_, Mutex<AppState>>,
    collection_id: String,
    entry_id: String,
) -> Result<(), String> {
    let memory_runtime = memory_runtime_only(&state)?;
    let mut collections = load_knowledge_collections(&memory_runtime);
    let collection = collection_mut(&mut collections, &collection_id)?;
    let original_len = collection.entries.len();
    collection
        .entries
        .retain(|entry| entry.entry_id != entry_id);
    if collection.entries.len() == original_len {
        return Err(format!(
            "Knowledge entry '{}' was not found in collection '{}'.",
            entry_id, collection_id
        ));
    }
    collection.updated_at_ms = now_ms();
    save_knowledge_collections(&memory_runtime, &collections);
    Ok(())
}

#[tauri::command]
pub async fn get_knowledge_collection_entry_content(
    state: State<'_, Mutex<AppState>>,
    collection_id: String,
    entry_id: String,
) -> Result<KnowledgeCollectionEntryContent, String> {
    let memory_runtime = memory_runtime_only(&state)?;
    let collections = load_knowledge_collections(&memory_runtime);
    let collection = collection_ref(&collections, &collection_id)?;
    let entry = collection
        .entries
        .iter()
        .find(|entry| entry.entry_id == entry_id)
        .ok_or_else(|| {
            format!(
                "Knowledge entry '{}' was not found in collection '{}'.",
                entry_id, collection_id
            )
        })?;
    let bytes = memory_runtime
        .load_artifact_blob(&entry.artifact_id)
        .map_err(|error| format!("Failed to load knowledge artifact content: {}", error))?
        .ok_or_else(|| format!("Knowledge artifact '{}' was not found.", entry.artifact_id))?;
    Ok(KnowledgeCollectionEntryContent {
        collection_id,
        entry_id,
        title: entry.title.clone(),
        kind: entry.kind.clone(),
        artifact_id: entry.artifact_id.clone(),
        byte_count: bytes.len(),
        content: String::from_utf8_lossy(&bytes).to_string(),
    })
}

#[tauri::command]
pub async fn search_knowledge_collection(
    state: State<'_, Mutex<AppState>>,
    collection_id: String,
    query: String,
    limit: Option<usize>,
) -> Result<Vec<KnowledgeCollectionSearchHit>, String> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let (memory_runtime, inference) = runtime_resources(&state)?;
    let collections = load_knowledge_collections(&memory_runtime);
    let collection = collection_ref(&collections, &collection_id)?;
    let scopes = collection
        .entries
        .iter()
        .map(|entry| entry.scope.clone())
        .collect::<Vec<_>>();
    if scopes.is_empty() {
        return Ok(Vec::new());
    }

    let embedding = inference
        .embed_text(trimmed)
        .await
        .map_err(|error| format!("Knowledge search embedding failed: {}", error))?;
    let limit = limit.unwrap_or(6).max(1).min(24);
    let hits = memory_runtime
        .hybrid_search_archival_memory(&HybridArchivalMemoryQuery {
            scopes,
            thread_id: None,
            text: trimmed.to_string(),
            embedding: Some(embedding),
            limit,
            candidate_limit: (limit * 8).max(24),
            allowed_trust_levels: vec![
                "standard".to_string(),
                "runtime_observed".to_string(),
                "runtime_derived".to_string(),
                "runtime_controlled".to_string(),
            ],
        })
        .map_err(|error| format!("Knowledge archival search failed: {}", error))?;

    Ok(hits
        .into_iter()
        .map(|hit| {
            let metadata = serde_json::from_str::<Value>(&hit.record.metadata_json)
                .unwrap_or_else(|_| json!({}));
            let entry_id = metadata
                .get("entry_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let title = metadata
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or(hit.record.kind.as_str())
                .to_string();
            KnowledgeCollectionSearchHit {
                collection_id: collection_id.clone(),
                entry_id,
                title,
                scope: hit.record.scope,
                score: hit.score,
                lexical_score: hit.lexical_score,
                semantic_score: hit.semantic_score,
                trust_level: hit.trust_level,
                snippet: preview_text(&hit.record.content, 220),
                archival_record_id: hit.record.id,
                inspect_id: entry_inspect_id(hit.record.id),
            }
        })
        .collect())
}

#[tauri::command]
pub async fn add_knowledge_collection_source(
    state: State<'_, Mutex<AppState>>,
    collection_id: String,
    uri: String,
    poll_interval_minutes: Option<u64>,
) -> Result<KnowledgeCollectionSourceRecord, String> {
    let memory_runtime = memory_runtime_only(&state)?;
    let mut collections = load_knowledge_collections(&memory_runtime);
    let collection = collection_mut(&mut collections, &collection_id)?;
    let uri = uri.trim();
    if uri.is_empty() {
        return Err("Source URI is required.".to_string());
    }
    let source = KnowledgeCollectionSourceRecord {
        source_id: format!("source-{}", now_ms()),
        kind: if uri.starts_with("http://") || uri.starts_with("https://") {
            "url".to_string()
        } else {
            "path".to_string()
        },
        uri: uri.to_string(),
        poll_interval_minutes,
        enabled: true,
        sync_status: "configured".to_string(),
        last_synced_at_ms: None,
        last_error: None,
    };
    collection.sources.push(source.clone());
    collection.updated_at_ms = now_ms();
    save_knowledge_collections(&memory_runtime, &collections);
    Ok(source)
}

#[tauri::command]
pub async fn remove_knowledge_collection_source(
    state: State<'_, Mutex<AppState>>,
    collection_id: String,
    source_id: String,
) -> Result<(), String> {
    let memory_runtime = memory_runtime_only(&state)?;
    let mut collections = load_knowledge_collections(&memory_runtime);
    let collection = collection_mut(&mut collections, &collection_id)?;
    let original_len = collection.sources.len();
    collection
        .sources
        .retain(|source| source.source_id != source_id);
    if collection.sources.len() == original_len {
        return Err(format!(
            "Knowledge source '{}' was not found in collection '{}'.",
            source_id, collection_id
        ));
    }
    collection.updated_at_ms = now_ms();
    save_knowledge_collections(&memory_runtime, &collections);
    Ok(())
}
