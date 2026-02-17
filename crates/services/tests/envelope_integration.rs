// Path: crates/services/tests/envelope_integration.rs

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_scs::{SovereignContextStore, StoreConfig};
use ioi_services::agentic::desktop::service::DesktopAgentService;
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;
use ioi_types::app::agentic::ChatMessage;

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

fn build_service_with_scs_store() -> (DesktopAgentService, PathBuf) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("ioi_service_envelope_integration_{ts}.scs"));

    let config = StoreConfig {
        chain_id: 1,
        owner_id: [11u8; 32],
        identity_key: [12u8; 32],
    };

    let store = SovereignContextStore::create(&path, config).expect("create scs store");
    let service = DesktopAgentService::new(
        Arc::new(NoopGuiDriver),
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        Arc::new(MockInferenceRuntime),
    )
    .with_scs(Arc::new(Mutex::new(store)));

    (service, path)
}

#[tokio::test]
async fn model_surface_is_scrubbed_and_raw_surface_preserves_input() {
    let (service, path) = build_service_with_scs_store();
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
    assert!(raw_history[0]
        .content
        .contains("sk_live_abcd1234abcd1234"));
    assert!(!model_history[0].content.contains("john@example.com"));
    assert!(!model_history[0]
        .content
        .contains("sk_live_abcd1234abcd1234"));

    let _ = std::fs::remove_file(path);
}
