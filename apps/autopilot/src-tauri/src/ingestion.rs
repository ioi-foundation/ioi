// apps/autopilot/src-tauri/src/ingestion.rs

use crate::models::AppState;
use ioi_memory::NewArchivalMemoryRecord;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use tauri::State;

const CHUNK_SIZE: usize = 4096;

#[derive(serde::Serialize)]
pub struct IngestionResult {
    pub file_name: String,
    pub total_size: u64,
    pub chunks_created: usize,
    pub record_ids: Vec<i64>,
}

#[tauri::command]
pub async fn ingest_file(
    state: State<'_, Mutex<AppState>>,
    file_path: String,
) -> Result<IngestionResult, String> {
    let path = Path::new(&file_path);
    if !path.exists() {
        return Err(format!("File not found: {}", file_path));
    }

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // 1. Acquire Resources
    let (memory_runtime, inference) = {
        let guard = state.lock().map_err(|_| "Failed to lock app state")?;
        let memory_runtime = guard
            .memory_runtime
            .clone()
            .ok_or("Memory runtime not initialized")?;
        let inf = guard
            .inference_runtime
            .clone()
            .ok_or("Inference runtime not initialized")?;
        (memory_runtime, inf)
    };

    // 2. Read & Chunk
    let content = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;
    let total_size = content.len() as u64;

    // Simple byte-window chunking with lossy UTF-8 decoding keeps ingestion resilient
    // while moving the resulting searchable text into the new archival memory lane.
    let chunks = content
        .chunks(CHUNK_SIZE)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect::<Vec<_>>();
    let mut record_ids = Vec::new();

    // 3. Process Chunks (Store + Embed)
    for (chunk_index, chunk_text) in chunks.iter().enumerate() {
        let normalized = chunk_text.trim();
        if normalized.is_empty() {
            continue;
        }

        let metadata_json = serde_json::to_string(&json!({
            "file_name": file_name,
            "file_path": file_path,
            "chunk_index": chunk_index,
            "chunk_count": chunks.len(),
            "total_size": total_size,
            "trust_level": "standard",
        }))
        .map_err(|e| format!("Failed to serialize ingestion metadata: {}", e))?;

        let record_id = memory_runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: "autopilot.retrieval".to_string(),
                thread_id: None,
                kind: "file_chunk".to_string(),
                content: normalized.to_string(),
                metadata_json,
            })
            .map_err(|e| format!("Failed to persist archival memory: {}", e))?
            .ok_or("Archival memory store unavailable")?;
        record_ids.push(record_id);

        match inference.embed_text(normalized).await {
            Ok(vector) => {
                if let Err(error) = memory_runtime.upsert_archival_embedding(record_id, &vector) {
                    eprintln!(
                        "[Ingestion] Failed to store embedding for record {}: {}",
                        record_id, error
                    );
                }
            }
            Err(error) => {
                eprintln!(
                    "[Ingestion] Embedding failed for record {}: {}",
                    record_id, error
                );
            }
        }
    }

    Ok(IngestionResult {
        file_name,
        total_size,
        chunks_created: chunks.len(),
        record_ids,
    })
}
