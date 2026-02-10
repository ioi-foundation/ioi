// Path: crates/services/src/agentic/desktop/service/memory.rs

use super::DesktopAgentService;
use crate::agentic::normaliser::OutputNormaliser;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_scs::{FrameType, RetentionClass};
use ioi_types::app::agentic::{
    ChatMessage, InferenceOptions, SemanticFact, StepTrace, SwarmManifest,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::json;

/// Retrieve a Swarm Manifest from the Market or SCS.
pub async fn fetch_swarm_manifest(
    service: &DesktopAgentService,
    hash: [u8; 32],
) -> Option<SwarmManifest> {
    let scs_mutex = service.scs.as_ref()?;
    let store = scs_mutex.lock().ok()?;

    if let Some(&fid) = store.visual_index.get(&hash) {
        if let Ok(bytes) = store.read_frame_payload(fid) {
            if let Ok(manifest) = codec::from_bytes_canonical::<SwarmManifest>(&bytes) {
                return Some(manifest);
            }
        }
    }
    None
}

/// Hybrid Retrieval of Episodic Memory using mHNSW index.
pub async fn retrieve_context_hybrid(
    service: &DesktopAgentService,
    query: &str,
    _visual_phash: Option<[u8; 32]>,
) -> String {
    let scs_mutex = match &service.scs {
        Some(m) => m,
        None => return "".to_string(),
    };

    // Use reasoning model to embed the query
    let embedding_res = service.reasoning_inference.embed_text(query).await;

    let embedding = match embedding_res {
        Ok(vec) => vec,
        Err(e) => {
            log::warn!("Failed to generate embedding for RAG: {}", e);
            return "".to_string();
        }
    };

    let results = {
        let scs = match scs_mutex.lock() {
            Ok(s) => s,
            Err(_) => return "".to_string(),
        };

        let index_mutex = match scs.get_vector_index() {
            Ok(idx) => idx,
            Err(e) => {
                log::warn!("Failed to get vector index: {}", e);
                return "".to_string();
            }
        };

        let idx = match index_mutex.lock() {
            Ok(i) => i,
            Err(_) => return "".to_string(),
        };

        if let Some(index) = idx.as_ref() {
            // Use Hybrid Search to get metadata (Type, VisualHash)
            index.search_hybrid(&embedding, 5)
        } else {
            Ok(vec![])
        }
    };

    let matches = match results {
        Ok(m) => m,
        Err(e) => {
            log::warn!("RAG search failed: {}", e);
            return "".to_string();
        }
    };

    if matches.is_empty() {
        return "".to_string();
    }

    let mut output = String::new();
    let mut top_snippet_included = false;

    let scs = match scs_mutex.lock() {
        Ok(s) => s,
        Err(_) => return "".to_string(),
    };

    for (i, (frame_id, distance, f_type, _)) in matches.iter().enumerate() {
        if *distance > 0.35 {
            continue;
        } // Relevance threshold

        if let Ok(payload) = scs.read_frame_payload(*frame_id) {
            if let Ok(text) = String::from_utf8(payload.to_vec()) {
                let confidence = (1.0 - distance) * 100.0;
                let type_str = format!("{:?}", f_type);

                // Pointer Entry
                output.push_str(&format!(
                    "- [ID:{}] Kind:{} Conf:{:.0}% | ",
                    frame_id, type_str, confidence
                ));

                // Micro-Snippet Logic
                if i == 0 && !top_snippet_included {
                    // Include first 3 lines of top result
                    let snippet: String = text.lines().take(3).collect::<Vec<_>>().join(" ");
                    output.push_str(&format!("Snippet: \"{}...\"\n", snippet));
                    top_snippet_included = true;
                } else {
                    // Just the first 60 chars (Header/Summary)
                    let summary = if text.len() > 60 {
                        format!("{}...", &text[..60])
                    } else {
                        text
                    };
                    output.push_str(&format!("Summary: \"{}\"\n", summary));
                }
            }
        }
    }

    output
}

async fn extract_facts(service: &DesktopAgentService, text: &str) -> Vec<SemanticFact> {
    if text.len() < 20 {
        return vec![];
    }

    let prompt = format!(
        "SYSTEM: Extract important facts from the text below as a JSON list of tuples.\n\
            Schema: [{{\"subject\": \"string\", \"predicate\": \"string\", \"object\": \"string\"}}]\n\
            Text: \"{}\"\n\
            Output JSON only:",
        text.replace('"', "\\\"")
    );

    let options = InferenceOptions {
        temperature: 0.0,
        ..Default::default()
    };

    let model_hash = [0u8; 32];

    match service
        .reasoning_inference
        .execute_inference(model_hash, prompt.as_bytes(), options)
        .await
    {
        Ok(bytes) => {
            let s = String::from_utf8_lossy(&bytes);
            let start = s.find('[').unwrap_or(0);
            let end = s.rfind(']').map(|i| i + 1).unwrap_or(s.len());
            if start < end {
                serde_json::from_str(&s[start..end]).unwrap_or_default()
            } else {
                vec![]
            }
        }
        Err(_) => vec![],
    }
}

pub async fn append_chat_to_scs(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    msg: &ChatMessage,
    block_height: u64,
) -> Result<[u8; 32], TransactionError> {
    let scs_mutex = service.scs.as_ref().ok_or(TransactionError::Invalid(
        "Internal: SCS not available".into(),
    ))?;

    // 1. Persist Raw Frame
    let (frame_id, checksum) = {
        let mut store = scs_mutex
            .lock()
            .map_err(|_| TransactionError::Invalid("Internal: SCS lock poisoned".into()))?;

        let payload =
            codec::to_bytes_canonical(msg).map_err(|e| TransactionError::Serialization(e))?;

        let id = store
            .append_frame(
                FrameType::Thought,
                &payload,
                block_height,
                [0u8; 32],
                session_id,
                RetentionClass::Ephemeral,
            )
            .map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;

        let frame = store
            .toc
            .frames
            .get(id as usize)
            .ok_or(TransactionError::Invalid(
                "Internal: Frame not found".into(),
            ))?;

        (id, frame.checksum)
    };

    // 2. Semantic Indexing
    let facts = extract_facts(service, &msg.content).await;
    let mut vectors = Vec::new();

    if let Ok(vec) = service.reasoning_inference.embed_text(&msg.content).await {
        vectors.push(vec);
    }

    for fact in facts {
        if let Ok(json_str) = serde_json::to_string(&fact) {
            if let Ok(_canonical_bytes) = OutputNormaliser::normalise_and_hash(&json_str) {
                if let Ok(vec) = service.reasoning_inference.embed_text(&json_str).await {
                    vectors.push(vec);
                }
            }
        }
    }

    // C. Insert into Index
    if !vectors.is_empty() {
        let store = scs_mutex
            .lock()
            .map_err(|_| TransactionError::Invalid("SCS lock".into()))?;
        if let Ok(index_arc) = store.get_vector_index() {
            let mut index = index_arc
                .lock()
                .map_err(|_| TransactionError::Invalid("Index lock".into()))?;
            if let Some(idx) = index.as_mut() {
                for vec in vectors {
                    if let Err(e) =
                        idx.insert_with_metadata(frame_id, vec, FrameType::Thought, [0u8; 32])
                    {
                        log::warn!("Failed to index vector for frame {}: {}", frame_id, e);
                    }
                }
            }
        }
    }

    Ok(checksum)
}

pub fn hydrate_session_history(
    service: &DesktopAgentService,
    session_id: [u8; 32],
) -> Result<Vec<ChatMessage>, TransactionError> {
    let scs_mutex = service.scs.as_ref().ok_or(TransactionError::Invalid(
        "Internal: SCS not available".into(),
    ))?;

    let store = scs_mutex
        .lock()
        .map_err(|_| TransactionError::Invalid("Internal: SCS lock poisoned".into()))?;

    let mut history = Vec::new();

    if let Some(frame_ids) = store.session_index.get(&session_id) {
        for &id in frame_ids {
            let frame = store.toc.frames.get(id as usize).unwrap();

            if matches!(frame.frame_type, FrameType::Thought) {
                let payload = store
                    .read_frame_payload(id)
                    .map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;

                if let Ok(msg) = codec::from_bytes_canonical::<ChatMessage>(&payload) {
                    history.push(msg);
                }
            }
        }
    }

    history.sort_by_key(|m| m.timestamp);
    Ok(history)
}

pub fn fetch_failure_context(
    service: &DesktopAgentService,
    session_id: [u8; 32],
) -> Result<Vec<StepTrace>, TransactionError> {
    let scs_mutex = service.scs.as_ref().ok_or(TransactionError::Invalid(
        "Internal: SCS not available".into(),
    ))?;

    let store = scs_mutex
        .lock()
        .map_err(|_| TransactionError::Invalid("Internal: SCS lock poisoned".into()))?;

    let mut failures = Vec::new();

    if let Some(frame_ids) = store.session_index.get(&session_id) {
        for &id in frame_ids {
            let frame = store.toc.frames.get(id as usize).unwrap();

            if matches!(frame.frame_type, FrameType::System) {
                let payload = store
                    .read_frame_payload(id)
                    .map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;

                if let Ok(trace) = codec::from_bytes_canonical::<StepTrace>(&payload) {
                    if !trace.success {
                        failures.push(trace);
                    }
                }
            }
        }
    }

    Ok(failures)
}

pub async fn inspect_frame(
    service: &DesktopAgentService,
    frame_id: u64,
) -> Result<String, TransactionError> {
    let scs_mutex = service
        .scs
        .as_ref()
        .ok_or(TransactionError::Invalid("SCS not available".into()))?;

    let (payload, frame_type) = {
        let store = scs_mutex
            .lock()
            .map_err(|_| TransactionError::Invalid("SCS lock".into()))?;
        let frame = store
            .toc
            .frames
            .get(frame_id as usize)
            .ok_or(TransactionError::Invalid("Frame not found".into()))?;
        let payload = store
            .read_frame_payload(frame_id)
            .map_err(|e| TransactionError::Invalid(e.to_string()))?;
        (payload, frame.frame_type)
    };

    match frame_type {
        FrameType::Observation => {
            let b64 = BASE64.encode(&payload);
            let prompt = json!([
                { "role": "user", "content": [
                    { "type": "text", "text": "Analyze this screenshot from history. Describe the UI state, active window, visible text, and any interactive elements." },
                    { "type": "image_url", "image_url": { "url": format!("data:image/jpeg;base64,{}", b64) } }
                ]}
            ]);

            let input_bytes = serde_json::to_vec(&prompt).unwrap();
            let options = InferenceOptions {
                max_tokens: 300,
                ..Default::default()
            };

            let out_bytes = service
                .fast_inference
                .execute_inference([0u8; 32], &input_bytes, options)
                .await
                .map_err(|e| TransactionError::Invalid(format!("Captioning failed: {}", e)))?;

            Ok(String::from_utf8_lossy(&out_bytes).to_string())
        }
        FrameType::Thought | FrameType::Action => {
            if let Ok(s) = String::from_utf8(payload) {
                Ok(s)
            } else {
                Ok("<Binary Data>".into())
            }
        }
        _ => Ok(format!("<Frame Type {:?}>", frame_type)),
    }
}
