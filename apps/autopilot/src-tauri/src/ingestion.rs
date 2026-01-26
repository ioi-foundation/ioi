// apps/autopilot/src-tauri/src/ingestion.rs

use crate::models::AppState;
use ioi_scs::{FrameType, SovereignContextStore, VectorIndex};
use ioi_api::vm::inference::InferenceRuntime; // [FIX] Import trait for embed_text
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tauri::State;
use ioi_crypto::algorithms::hash::sha256; // [NEW] Import for hashing

const CHUNK_SIZE: usize = 4096;

#[derive(serde::Serialize)]
pub struct IngestionResult {
    pub file_name: String,
    pub total_size: u64,
    pub chunks_created: usize,
    pub frame_ids: Vec<u64>,
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
    let (scs_arc, inference) = {
        let guard = state.lock().map_err(|_| "Failed to lock app state")?;
        let scs = guard.studio_scs.clone().ok_or("SCS not initialized")?;
        let inf = guard.inference_runtime.clone().ok_or("Inference runtime not initialized")?;
        (scs, inf)
    };

    // 2. Read & Chunk
    let content = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;
    let total_size = content.len() as u64;
    
    // Simple splitting for binary; for text files, line-splitting is better but this suffices for MVP
    let chunks: Vec<&[u8]> = content.chunks(CHUNK_SIZE).collect();
    let mut frame_ids = Vec::new();

    // 3. Process Chunks (Store)
    // We lock SCS for the batch to ensure consistency
    {
        let mut store = scs_arc.lock().map_err(|_| "Failed to lock SCS")?;
        let block_height = 0;
        let mhnsw_root = [0u8; 32];

        for chunk in &chunks {
            // [NEW] Calculate content hash for integrity/deduplication
            let hash_res = sha256(chunk).map_err(|e| format!("Hash failed: {}", e))?;
            let mut content_hash = [0u8; 32];
            content_hash.copy_from_slice(hash_res.as_ref());

            // A. Store Raw Frame
            // We use a zero-hash for mhnsw_root initially; typically updated after commit.
            // We use the content hash as the session_id/context identifier.
            let frame_id = store.append_frame(
                FrameType::Observation,
                chunk,
                block_height,
                mhnsw_root,
                content_hash,
            ).map_err(|e| format!("Failed to write frame: {}", e))?;

            frame_ids.push(frame_id);
        }
        
        // C. Commit Index changes to disk (System Frame) - Done later
    } // Drop Store Lock

    // 4. Post-Processing: Generate Embeddings & Update Index
    // We do this AFTER the initial write to avoid holding the write lock during slow inference.
    for (i, &frame_id) in frame_ids.iter().enumerate() {
        let chunk = chunks[i];
        if let Ok(text) = std::str::from_utf8(chunk) {
             // Only embed if it looks like text and isn't empty
             if !text.trim().is_empty() {
                 match inference.embed_text(text).await {
                     Ok(vector) => {
                         // Re-acquire lock briefly to insert into index
                         let store = scs_arc.lock().map_err(|_| "Failed to lock SCS")?;
                         
                         // Helper to get or create index
                         // Note: get_vector_index returns Arc<Mutex<Option<VectorIndex>>>
                         let index_arc = store.get_vector_index().map_err(|e| e.to_string())?;
                         let mut index_guard = index_arc.lock().map_err(|_| "Failed to lock index")?;
                         
                         if index_guard.is_none() {
                             // Initialize with defaults: M=16, ef_construction=200
                             *index_guard = Some(VectorIndex::new(16, 200));
                         }
                         
                         if let Some(idx) = index_guard.as_mut() {
                             if let Err(e) = idx.insert(frame_id, vector) {
                                 eprintln!("[Ingestion] Failed to index frame {}: {}", frame_id, e);
                             }
                         }
                     },
                     Err(e) => {
                         eprintln!("[Ingestion] Embedding failed for frame {}: {}", frame_id, e);
                     }
                 }
             }
        }
    }
    
    // 5. Final Commit of Index to persist the new vectors
    {
        let mut store = scs_arc.lock().map_err(|_| "Failed to lock SCS")?;
        let index_arc = store.get_vector_index().map_err(|e| e.to_string())?;
        let index_guard = index_arc.lock().map_err(|_| "Failed to lock index")?;
        if let Some(idx) = index_guard.as_ref() {
            store.commit_index(idx).map_err(|e| format!("Final index commit failed: {}", e))?;
            println!("[Ingestion] Committed vector index for {}", file_name);
        }
    }

    Ok(IngestionResult {
        file_name,
        total_size,
        chunks_created: chunks.len(),
        frame_ids,
    })
}