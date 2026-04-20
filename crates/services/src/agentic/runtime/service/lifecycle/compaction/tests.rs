use super::*;
use crate::agentic::runtime::service::RuntimeAgentService;
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
    let service = RuntimeAgentService::new(
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
