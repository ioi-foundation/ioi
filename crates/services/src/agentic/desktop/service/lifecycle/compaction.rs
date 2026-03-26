use crate::agentic::desktop::service::memory::{
    kick_memory_enrichment, record_memory_session_evaluation,
};
use crate::agentic::desktop::service::DesktopAgentService;
use ioi_memory::{NewArchivalMemoryRecord, NewEnrichmentJob};
use ioi_types::error::TransactionError;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

const MEMORY_RUNTIME_COMPACTION_SCOPE: &str = "desktop.compaction";
const COMPACTION_RECORD_KIND: &str = "session_compaction_summary";
const COMPACTION_MAX_MESSAGES: usize = 128;
const COMPACTION_MAX_CHARS_PER_MESSAGE: usize = 1_024;

fn unix_timestamp_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    let mut truncated = String::new();
    let mut chars = text.chars();
    for _ in 0..max_chars {
        if let Some(ch) = chars.next() {
            truncated.push(ch);
        } else {
            return truncated;
        }
    }

    if chars.next().is_some() {
        truncated.push_str("...");
    }

    truncated
}

fn compactable_transcript_lines(messages: &[ioi_memory::StoredTranscriptMessage]) -> Vec<String> {
    let start = messages.len().saturating_sub(COMPACTION_MAX_MESSAGES);
    messages[start..]
        .iter()
        .filter_map(|message| {
            let content = if !message.store_content.trim().is_empty() {
                message.store_content.trim()
            } else if !message.model_content.trim().is_empty() {
                message.model_content.trim()
            } else {
                message.raw_content.trim()
            };

            if content.is_empty() {
                return None;
            }

            Some(format!(
                "{}: {}",
                message.role,
                truncate_chars(content, COMPACTION_MAX_CHARS_PER_MESSAGE)
            ))
        })
        .collect()
}

/// Performs the "Refactoring Notes" process:
/// 1. Reads the bounded transcript window from the active session checkpoint.
/// 2. Summarizes it into an archival session summary record.
/// 3. Leaves raw transcript durability to the runtime instead of epoch/key rotation.
pub async fn perform_cognitive_compaction(
    service: &DesktopAgentService,
    session_id: [u8; 32],
) -> Result<(), TransactionError> {
    let Some(memory_runtime) = service.memory_runtime.as_ref() else {
        return Ok(());
    };

    let transcript_messages = memory_runtime
        .load_transcript_messages(session_id)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;
    let transcript_lines = compactable_transcript_lines(&transcript_messages);

    if transcript_lines.is_empty() {
        return Ok(());
    }

    log::info!(
        "Cognitive Compaction: Summarizing {} transcript messages...",
        transcript_lines.len()
    );

    let prompt = format!(
        "SYSTEM: Summarize the following desktop-agent session transcript into a concise set of facts, decisions, and skills learned.\n\
         Prefer durable outcomes over transient chatter. Keep the active goal, important constraints, and successful working logic.\n\
         Discard retries, verbose tool logs, and redundant status narration.\n\n\
         TRANSCRIPT:\n{}",
        transcript_lines.join("\n")
    );

    let options = ioi_types::app::agentic::InferenceOptions {
        temperature: 0.0,
        ..Default::default()
    };

    let summary_bytes = service
        .reasoning_inference
        .execute_inference(
            [0u8; 32],
            &service
                .prepare_cloud_inference_input(
                    Some(session_id),
                    "desktop_agent",
                    "model_hash:0000000000000000000000000000000000000000000000000000000000000000",
                    prompt.as_bytes(),
                )
                .await?,
            options,
        )
        .await
        .map_err(|e| TransactionError::Invalid(format!("Compaction inference failed: {}", e)))?;

    let summary = String::from_utf8_lossy(&summary_bytes).trim().to_string();
    if summary.is_empty() {
        return Ok(());
    }

    let metadata_json = serde_json::to_string(&json!({
        "kind": COMPACTION_RECORD_KIND,
        "session_id": hex::encode(session_id),
        "message_count": transcript_messages.len(),
        "compacted_message_count": transcript_lines.len(),
        "compacted_at_ms": unix_timestamp_ms_now(),
        "trust_level": "runtime_derived",
    }))
    .map_err(|error| TransactionError::Serialization(error.to_string()))?;

    let record_id = memory_runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: MEMORY_RUNTIME_COMPACTION_SCOPE.to_string(),
            thread_id: Some(session_id),
            kind: COMPACTION_RECORD_KIND.to_string(),
            content: summary.clone(),
            metadata_json,
        })
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;

    if let Some(record_id) = record_id {
        let payload_json = serde_json::to_string(&json!({
            "source_record_id": record_id,
        }))
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;
        if let Err(error) = memory_runtime.enqueue_enrichment_job(&NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "archival.embedding".to_string(),
            payload_json,
            dedupe_key: Some(format!("archival.embedding:{record_id}")),
        }) {
            log::warn!(
                "Failed to enqueue compaction embedding enrichment for record {}: {}",
                record_id,
                error
            );
        } else {
            kick_memory_enrichment(service, "compaction");
        }
    }

    if let Err(error) = record_memory_session_evaluation(
        memory_runtime,
        session_id,
        transcript_messages.len(),
        transcript_lines.len(),
        &summary,
    ) {
        log::warn!(
            "Failed to persist memory session evaluation for {}: {}",
            hex::encode(session_id),
            error
        );
    }

    log::info!("Cognitive Compaction Complete: session summary archived in memory runtime.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::desktop::service::DesktopAgentService;
    use async_trait::async_trait;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::InferenceRuntime;
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_memory::{ArchivalMemoryQuery, MemoryRuntime, StoredTranscriptMessage};
    use ioi_types::app::agentic::InferenceOptions;
    use ioi_types::app::{ActionRequest, ContextSlice};
    use ioi_types::error::VmError;
    use std::sync::Arc;

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

    struct StaticInferenceRuntime;

    #[async_trait]
    impl InferenceRuntime for StaticInferenceRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            Ok(b"Condensed summary of the completed workflow.".to_vec())
        }

        async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
            Ok(vec![0.0, 1.0, 0.0])
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
    async fn cognitive_compaction_archives_runtime_backed_session_summary() {
        let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("runtime"));
        let session_id = [7u8; 32];
        runtime
            .append_transcript_message(
                session_id,
                &StoredTranscriptMessage {
                    role: "user".to_string(),
                    timestamp_ms: 1,
                    raw_content: "Open the dashboard and export the report.".to_string(),
                    model_content: "Open the dashboard and export the report.".to_string(),
                    store_content: "Open the dashboard and export the report.".to_string(),
                    ..Default::default()
                },
            )
            .expect("append transcript");
        runtime
            .append_transcript_message(
                session_id,
                &StoredTranscriptMessage {
                    role: "assistant".to_string(),
                    timestamp_ms: 2,
                    raw_content: "Opened the dashboard and exported the CSV.".to_string(),
                    model_content: "Opened the dashboard and exported the CSV.".to_string(),
                    store_content: "Opened the dashboard and exported the CSV.".to_string(),
                    ..Default::default()
                },
            )
            .expect("append transcript");

        let inference: Arc<dyn InferenceRuntime> = Arc::new(StaticInferenceRuntime);
        let service = DesktopAgentService::new(
            Arc::new(NoopGuiDriver),
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            inference,
        )
        .with_memory_runtime(runtime.clone());

        perform_cognitive_compaction(&service, session_id)
            .await
            .expect("compaction should succeed");

        let records = runtime
            .search_archival_memory(&ArchivalMemoryQuery {
                scope: MEMORY_RUNTIME_COMPACTION_SCOPE.to_string(),
                thread_id: Some(session_id),
                text: "workflow".to_string(),
                limit: 10,
            })
            .expect("search archival memory");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, COMPACTION_RECORD_KIND);
        assert_eq!(
            records[0].content,
            "Condensed summary of the completed workflow."
        );
    }
}
