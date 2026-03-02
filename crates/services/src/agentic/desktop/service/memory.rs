// Path: crates/services/src/agentic/desktop/service/memory.rs

use super::DesktopAgentService;
use crate::agentic::desktop::types::{
    MessagePrivacyMetadata, RecordedMessage, DEFAULT_MESSAGE_PRIVACY_POLICY_ID,
    DEFAULT_MESSAGE_PRIVACY_POLICY_VERSION, DEFAULT_MESSAGE_REDACTION_VERSION,
    MESSAGE_SANITIZED_PLACEHOLDER,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hex;
use ioi_crypto::algorithms::hash::sha256;
use ioi_scs::{FrameType, RetentionClass};
use ioi_state::tree::mhnsw::proof::RetrievalSearchPolicy;
use ioi_types::app::agentic::{ChatMessage, InferenceOptions, StepTrace, SwarmManifest};
use ioi_types::app::{RedactionMap, RedactionType, WorkloadScsRetrieveReceipt};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use parity_scale_codec::Encode;
use serde_json::json;
use std::collections::HashSet;
use tokio::time::{timeout, Duration, Instant};

const SCS_SEMANTIC_INDEXING_BUDGET: Duration = Duration::from_secs(2);

fn should_embed_for_semantic_indexing(role: &str) -> bool {
    role.eq_ignore_ascii_case("user") || role.eq_ignore_ascii_case("assistant")
}

#[derive(Debug, Clone)]
pub struct HybridRetrievalResult {
    pub output: String,
    pub receipt: Option<WorkloadScsRetrieveReceipt>,
}

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
    retrieve_context_hybrid_with_receipt(service, query, _visual_phash)
        .await
        .output
}

/// Hybrid Retrieval with a structured receipt payload suitable for workload events.
pub async fn retrieve_context_hybrid_with_receipt(
    service: &DesktopAgentService,
    query: &str,
    _visual_phash: Option<[u8; 32]>,
) -> HybridRetrievalResult {
    let default_policy = RetrievalSearchPolicy {
        k: 5,
        ef_search: 64,
        candidate_limit: 32,
        distance_metric: "cosine_distance".to_string(),
        embedding_normalized: true,
    };
    let query_hash = sha256(query.as_bytes())
        .ok()
        .map(hex::encode)
        .unwrap_or_default();

    let empty_failure_receipt = |error_class: Option<String>| WorkloadScsRetrieveReceipt {
        tool_name: "memory__search".to_string(),
        backend: "scs:mhnsw".to_string(),
        query_hash: query_hash.clone(),
        index_root: String::new(),
        k: default_policy.k,
        ef_search: default_policy.ef_search,
        candidate_limit: default_policy.candidate_limit,
        candidate_count_total: 0,
        candidate_count_reranked: 0,
        candidate_truncated: false,
        distance_metric: default_policy.distance_metric.clone(),
        embedding_normalized: default_policy.embedding_normalized,
        proof_ref: None,
        proof_hash: None,
        certificate_mode: Some("single_level_lb".to_string()),
        success: false,
        error_class,
    };

    let scs_mutex = match &service.scs {
        Some(m) => m,
        None => {
            return HybridRetrievalResult {
                output: "".to_string(),
                receipt: None,
            }
        }
    };

    // Use reasoning model to embed the query
    let embedding_res = service.reasoning_inference.embed_text(query).await;

    let embedding = match embedding_res {
        Ok(vec) => vec,
        Err(e) => {
            log::warn!("Failed to generate embedding for RAG: {}", e);
            return HybridRetrievalResult {
                output: "".to_string(),
                receipt: Some(empty_failure_receipt(Some("UnexpectedState".to_string()))),
            };
        }
    };

    let results = {
        let scs = match scs_mutex.lock() {
            Ok(s) => s,
            Err(_) => {
                return HybridRetrievalResult {
                    output: "".to_string(),
                    receipt: Some(empty_failure_receipt(Some("UnexpectedState".to_string()))),
                }
            }
        };

        let index_mutex = match scs.get_vector_index() {
            Ok(idx) => idx,
            Err(e) => {
                log::warn!("Failed to get vector index: {}", e);
                return HybridRetrievalResult {
                    output: "".to_string(),
                    receipt: Some(empty_failure_receipt(Some("UnexpectedState".to_string()))),
                };
            }
        };

        let mut idx = match index_mutex.lock() {
            Ok(i) => i,
            Err(_) => {
                return HybridRetrievalResult {
                    output: "".to_string(),
                    receipt: Some(empty_failure_receipt(Some("UnexpectedState".to_string()))),
                }
            }
        };

        if let Some(index) = idx.as_mut() {
            index.search_hybrid_with_certificate(&embedding, &default_policy)
        } else {
            Err(anyhow::anyhow!("vector index unavailable"))
        }
    };

    let (matches, certified_proof) = match results {
        Ok(m) => m,
        Err(e) => {
            log::warn!("RAG search failed: {}", e);
            return HybridRetrievalResult {
                output: "".to_string(),
                receipt: Some(empty_failure_receipt(Some("UnexpectedState".to_string()))),
            };
        }
    };

    let mut output = String::new();
    let mut top_snippet_included = false;

    let scs = match scs_mutex.lock() {
        Ok(s) => s,
        Err(_) => {
            return HybridRetrievalResult {
                output: "".to_string(),
                receipt: Some(empty_failure_receipt(Some("UnexpectedState".to_string()))),
            }
        }
    };

    for (i, (frame_id, distance, f_type, _)) in matches.iter().enumerate() {
        if *distance > 0.35 {
            continue;
        } // Relevance threshold

        if let Ok(payload) = scs.read_frame_payload(*frame_id) {
            let text = codec::from_bytes_canonical::<RecordedMessage>(&payload)
                .ok()
                .map(|message| message.scrubbed_for_scs);

            if let Some(text) = text {
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
                    let mut summary: String = text.chars().take(60).collect();
                    if text.chars().count() > 60 {
                        summary.push_str("...");
                    }
                    output.push_str(&format!("Summary: \"{}\"\n", summary));
                }
            }
        }
    }

    let proof_bytes = certified_proof.encode();
    let proof_hash = sha256(&proof_bytes).ok().map(hex::encode);

    let receipt = WorkloadScsRetrieveReceipt {
        tool_name: "memory__search".to_string(),
        backend: "scs:mhnsw".to_string(),
        query_hash: if query_hash.is_empty() {
            query_hash.clone()
        } else {
            query_hash
        },
        index_root: hex::encode(certified_proof.certificate.index_root),
        k: default_policy.k,
        ef_search: default_policy.ef_search,
        candidate_limit: default_policy.candidate_limit,
        candidate_count_total: certified_proof.candidate_count_total,
        candidate_count_reranked: certified_proof.candidate_count_total,
        candidate_truncated: false,
        distance_metric: default_policy.distance_metric.clone(),
        embedding_normalized: default_policy.embedding_normalized,
        proof_ref: proof_hash
            .as_ref()
            .map(|h| format!("scs://retrieval-certificate/{}", h)),
        proof_hash,
        certificate_mode: Some("single_level_lb".to_string()),
        success: true,
        error_class: None,
    };

    HybridRetrievalResult {
        output,
        receipt: Some(receipt),
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

    let recorded_message = build_recorded_message(&service.scrubber, msg).await;

    // 1. Persist Canonical Message Envelope
    let (frame_id, checksum) = {
        let mut store = scs_mutex
            .lock()
            .map_err(|_| TransactionError::Invalid("Internal: SCS lock poisoned".into()))?;

        let payload = codec::to_bytes_canonical(&recorded_message)
            .map_err(|e| TransactionError::Serialization(e))?;

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
    // Keep indexing best-effort and bounded so action completion never waits on
    // long-running inference calls.
    let semantic_index_started_at = Instant::now();
    let semantic_budget_remaining =
        || SCS_SEMANTIC_INDEXING_BUDGET.saturating_sub(semantic_index_started_at.elapsed());

    let mut vectors = Vec::new();

    let remaining = semantic_budget_remaining();
    if should_embed_for_semantic_indexing(&recorded_message.role) && !remaining.is_zero() {
        match timeout(
            remaining,
            service
                .reasoning_inference
                .embed_text(&recorded_message.scrubbed_for_scs),
        )
        .await
        {
            Ok(Ok(vec)) => vectors.push(vec),
            Ok(Err(e)) => {
                log::warn!("SCS root message embedding failed: {}", e);
            }
            Err(_) => {
                log::warn!(
                    "SCS root message embedding timed out for session {} after {:?}.",
                    hex::encode(&session_id[..4]),
                    SCS_SEMANTIC_INDEXING_BUDGET
                );
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
    hydrate_session_history_surface(service, session_id, false)
}

pub fn hydrate_session_history_raw(
    service: &DesktopAgentService,
    session_id: [u8; 32],
) -> Result<Vec<ChatMessage>, TransactionError> {
    hydrate_session_history_surface(service, session_id, true)
}

fn hydrate_session_history_surface(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    raw: bool,
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
            let Some(frame) = store.toc.frames.get(id as usize) else {
                continue;
            };

            if matches!(frame.frame_type, FrameType::Thought) {
                let payload = store
                    .read_frame_payload(id)
                    .map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;

                if let Some(msg) = decode_session_message(&payload, raw) {
                    history.push(msg);
                }
            }
        }
    }

    history.sort_by_key(|m| m.timestamp);
    Ok(history)
}

fn decode_session_message(payload: &[u8], raw: bool) -> Option<ChatMessage> {
    if let Ok(message) = codec::from_bytes_canonical::<RecordedMessage>(&payload) {
        let content = if raw {
            if message.raw_content.is_empty() {
                message.scrubbed_for_model.clone()
            } else {
                message.raw_content
            }
        } else if message.scrubbed_for_model.is_empty() {
            message.scrubbed_for_scs
        } else {
            message.scrubbed_for_model
        };

        Some(ChatMessage {
            role: message.role,
            content,
            timestamp: message.timestamp_ms,
            trace_hash: message.trace_hash,
        })
    } else {
        None
    }
}

fn redact_fields_from_map(redaction_map: &RedactionMap) -> Vec<String> {
    let mut fields: Vec<String> = redaction_map
        .entries
        .iter()
        .map(|entry| match &entry.redaction_type {
            RedactionType::Pii => "pii".to_string(),
            RedactionType::Secret => "secret".to_string(),
            RedactionType::Custom(custom) => format!("custom:{custom}"),
        })
        .collect();

    let unique: HashSet<String> = fields.drain(..).collect();
    let mut normalized: Vec<String> = unique.into_iter().collect();
    normalized.sort_unstable();
    normalized
}

async fn scrub_message_text_for_ingest(
    scrubber: &crate::agentic::pii_scrubber::PiiScrubber,
    input: &str,
) -> (String, Vec<String>) {
    match scrubber.scrub(input).await {
        Ok((scrubbed, redaction_map)) => (scrubbed, redact_fields_from_map(&redaction_map)),
        Err(_) => (
            MESSAGE_SANITIZED_PLACEHOLDER.to_string(),
            vec!["scrubber_failure".to_string()],
        ),
    }
}

async fn build_recorded_message(
    scrubber: &crate::agentic::pii_scrubber::PiiScrubber,
    msg: &ChatMessage,
) -> RecordedMessage {
    let (scrubbed_for_model, sensitive_fields_mask) =
        scrub_message_text_for_ingest(scrubber, &msg.content).await;
    let scrubbed_for_model_hash = sha256(scrubbed_for_model.as_bytes())
        .ok()
        .map(|digest| hex::encode(digest));
    RecordedMessage {
        role: msg.role.clone(),
        timestamp_ms: msg.timestamp,
        trace_hash: msg.trace_hash,
        raw_content: msg.content.clone(),
        scrubbed_for_model: scrubbed_for_model.clone(),
        scrubbed_for_scs: scrubbed_for_model,
        raw_reference: None,
        privacy_metadata: MessagePrivacyMetadata {
            redaction_version: DEFAULT_MESSAGE_REDACTION_VERSION.to_string(),
            sensitive_fields_mask,
            policy_id: DEFAULT_MESSAGE_PRIVACY_POLICY_ID.to_string(),
            policy_version: DEFAULT_MESSAGE_PRIVACY_POLICY_VERSION.to_string(),
            scrubbed_for_model_hash,
        },
    }
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
                .execute_inference(
                    [0u8; 32],
                    &service
                        .prepare_cloud_inference_input(
                            None,
                            "desktop_agent",
                            "model_hash:0000000000000000000000000000000000000000000000000000000000000000",
                            &input_bytes,
                        )
                        .await?,
                    options,
                )
                .await
                .map_err(|e| TransactionError::Invalid(format!("Captioning failed: {}", e)))?;

            Ok(String::from_utf8_lossy(&out_bytes).to_string())
        }
        FrameType::Thought | FrameType::Action => {
            if let Ok(recorded) = codec::from_bytes_canonical::<RecordedMessage>(&payload) {
                return Ok(recorded.raw_content);
            }
            Ok("<Non-Recorded Payload>".into())
        }
        _ => Ok(format!("<Frame Type {:?}>", frame_type)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::mock::MockInferenceRuntime;
    use ioi_api::vm::inference::InferenceRuntime;
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_scs::{SovereignContextStore, StoreConfig};
    use ioi_types::app::{ActionRequest, ContextSlice};
    use ioi_types::error::VmError;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::Instant;

    fn sample_recorded_message() -> RecordedMessage {
        RecordedMessage {
            role: "user".to_string(),
            timestamp_ms: 123,
            trace_hash: None,
            raw_content: "raw secret: password=abc123".to_string(),
            scrubbed_for_model: "raw secret: [REDACTED_PII]".to_string(),
            scrubbed_for_scs: "raw secret: [REDACTED_PII]".to_string(),
            raw_reference: None,
            privacy_metadata: MessagePrivacyMetadata {
                redaction_version: "v1".to_string(),
                sensitive_fields_mask: vec!["pii".to_string()],
                policy_id: "desktop-agent/default".to_string(),
                policy_version: "1".to_string(),
                scrubbed_for_model_hash: None,
            },
        }
    }

    #[test]
    fn decode_recorded_messages_for_model_surface() {
        let encoded_recorded =
            codec::to_bytes_canonical(&sample_recorded_message()).expect("recorded encode");
        let model_msg = decode_session_message(&encoded_recorded, false);
        assert!(model_msg.is_some());
        let model_msg = model_msg.expect("model decode");
        assert_eq!(model_msg.role, "user");
        assert_eq!(model_msg.content, "raw secret: [REDACTED_PII]");
    }

    #[test]
    fn decode_recorded_message_prefers_raw_content_for_raw_surface() {
        let encoded_recorded =
            codec::to_bytes_canonical(&sample_recorded_message()).expect("recorded encode");
        let raw_msg = decode_session_message(&encoded_recorded, true);
        assert!(raw_msg.is_some());
        let raw_msg = raw_msg.expect("raw decode");
        assert_eq!(raw_msg.content, "raw secret: password=abc123");
    }

    struct NoopGuiDriver;

    #[async_trait]
    impl GuiDriver for NoopGuiDriver {
        async fn capture_screen(
            &self,
            _crop_rect: Option<(i32, i32, u32, u32)>,
        ) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_tree(&self) -> Result<String, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }

        async fn register_som_overlay(
            &self,
            _map: std::collections::HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    fn build_test_service_with_temp_scs_with_inference(
        inference: Arc<dyn InferenceRuntime>,
    ) -> (DesktopAgentService, std::path::PathBuf) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |time| time.as_nanos());
        let path = std::env::temp_dir().join(format!("ioi_service_memory_tests_{ts}.scs"));

        let config = StoreConfig {
            chain_id: 1,
            owner_id: [9u8; 32],
            identity_key: [7u8; 32],
        };

        let store = SovereignContextStore::create(&path, config).expect("scs create");
        let service = DesktopAgentService::new(
            Arc::new(NoopGuiDriver),
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            inference,
        )
        .with_scs(Arc::new(Mutex::new(store)));

        (service, path)
    }

    fn build_test_service_with_temp_scs() -> (DesktopAgentService, std::path::PathBuf) {
        build_test_service_with_temp_scs_with_inference(Arc::new(MockInferenceRuntime))
    }

    struct SlowInferenceRuntime;

    #[async_trait]
    impl InferenceRuntime for SlowInferenceRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(b"[]".to_vec())
        }

        async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(vec![0.0, 1.0, 2.0])
        }

        async fn load_model(
            &self,
            _model_hash: [u8; 32],
            _path: &std::path::Path,
        ) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    struct NoExecuteInferenceRuntime;

    #[async_trait]
    impl InferenceRuntime for NoExecuteInferenceRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            panic!("append_chat_to_scs must not call execute_inference");
        }

        async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
            Ok(vec![0.0, 1.0, 2.0])
        }

        async fn load_model(
            &self,
            _model_hash: [u8; 32],
            _path: &std::path::Path,
        ) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    struct NoInferenceRuntime;

    #[async_trait]
    impl InferenceRuntime for NoInferenceRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            panic!("append_chat_to_scs must not call execute_inference");
        }

        async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
            panic!("append_chat_to_scs must not call embed_text for tool/system roles");
        }

        async fn load_model(
            &self,
            _model_hash: [u8; 32],
            _path: &std::path::Path,
        ) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn append_and_hydrate_session_history_keeps_raw_and_model_surfaces_separated() {
        let (service, path) = build_test_service_with_temp_scs();
        let session_id = [11u8; 32];
        let msg = ChatMessage {
            role: "user".to_string(),
            content: "please use API_KEY=sk_live_123456789".to_string(),
            timestamp: 1_700_000_000_000u64,
            trace_hash: None,
        };

        let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
        assert!(append_res.is_ok());

        let model_surface = service.hydrate_session_history(session_id);
        assert!(model_surface.is_ok());
        let model_msgs = model_surface.expect("model hydration");
        assert_eq!(model_msgs.len(), 1);
        assert!(!model_msgs[0].content.contains("sk_live_123456789"));

        let raw_surface = service.hydrate_session_history_raw(session_id);
        assert!(raw_surface.is_ok());
        let raw_msgs = raw_surface.expect("raw hydration");
        assert_eq!(raw_msgs.len(), 1);
        assert!(raw_msgs[0].content.contains("sk_live_123456789"));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn append_chat_to_scs_enforces_semantic_indexing_budget() {
        let (service, path) =
            build_test_service_with_temp_scs_with_inference(Arc::new(SlowInferenceRuntime));
        let session_id = [33u8; 32];
        let msg = ChatMessage {
            role: "assistant".to_string(),
            content: "This is long enough to trigger semantic fact extraction and embedding work."
                .to_string(),
            timestamp: 1_700_000_000_123u64,
            trace_hash: None,
        };

        let started = Instant::now();
        let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
        let elapsed = started.elapsed();

        assert!(append_res.is_ok());
        assert!(
            elapsed < SCS_SEMANTIC_INDEXING_BUDGET + Duration::from_secs(3),
            "append_chat_to_scs exceeded semantic indexing budget: {:?}",
            elapsed
        );

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn append_chat_to_scs_avoids_execute_inference_for_fact_extraction() {
        let (service, path) =
            build_test_service_with_temp_scs_with_inference(Arc::new(NoExecuteInferenceRuntime));
        let session_id = [44u8; 32];
        let msg = ChatMessage {
            role: "tool".to_string(),
            content: "Tool Output (os__launch_app): Launched background process 'gnome-calculator' (PID: 555837)"
                .to_string(),
            timestamp: 1_700_000_000_456u64,
            trace_hash: None,
        };

        let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
        assert!(append_res.is_ok());

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn append_chat_to_scs_skips_inference_for_tool_messages() {
        let (service, path) =
            build_test_service_with_temp_scs_with_inference(Arc::new(NoInferenceRuntime));
        let session_id = [55u8; 32];
        let msg = ChatMessage {
            role: "tool".to_string(),
            content: "Tool Output (os__launch_app): Launched background process 'calculator'"
                .to_string(),
            timestamp: 1_700_000_000_789u64,
            trace_hash: None,
        };

        let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
        assert!(append_res.is_ok());

        let _ = std::fs::remove_file(path);
    }
}
