// Path: crates/services/tests/envelope_integration.rs

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_memory::MemoryRuntime;
use ioi_services::agentic::runtime::service::RuntimeAgentService;
use ioi_types::app::agentic::ChatMessage;
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;

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
        _map: HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

fn build_service_with_memory_runtime() -> RuntimeAgentService {
    let service = RuntimeAgentService::new(
        Arc::new(NoopGuiDriver),
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        Arc::new(MockInferenceRuntime),
    )
    .with_memory_runtime(Arc::new(
        MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"),
    ));

    service
}

#[tokio::test]
async fn model_surface_is_scrubbed_and_raw_surface_preserves_input() {
    let service = build_service_with_memory_runtime();
    let session_id = [4u8; 32];
    let secret_msg = ChatMessage {
        role: "user".to_string(),
        content: "email john@example.com api_key sk_live_abcd1234abcd1234".to_string(),
        timestamp: 10,
        trace_hash: None,
    };

    let _append = service
        .append_chat_to_scs(session_id, &secret_msg, 0)
        .await
        .expect("append message");
    assert_ne!(_append, [0u8; 32]);

    let model_history = service
        .hydrate_session_history(session_id)
        .expect("hydrate model history");
    let raw_history = service
        .hydrate_session_history_raw(session_id)
        .expect("hydrate raw history");
    assert_eq!(model_history.len(), 1);
    assert_eq!(raw_history.len(), 1);
    assert!(raw_history[0].content.contains("john@example.com"));
    assert!(raw_history[0].content.contains("sk_live_abcd1234abcd1234"));
    assert!(!model_history[0].content.contains("john@example.com"));
    assert!(!model_history[0]
        .content
        .contains("sk_live_abcd1234abcd1234"));
}
