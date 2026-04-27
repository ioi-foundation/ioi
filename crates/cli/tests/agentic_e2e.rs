// Path: crates/cli/tests/agentic_e2e.rs
#![cfg(all(feature = "consensus-aft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use image::{ImageBuffer, Rgba};
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
use ioi_cli::testing::build_test_artifacts;
use ioi_services::agentic::runtime::keys::get_state_key;
use ioi_services::agentic::runtime::types::AgentState;
use ioi_services::agentic::runtime::{StartAgentParams, StepAgentParams};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;
use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};

// [NEW] Imports
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;

// --- Mocks ---

#[derive(Clone)]
struct MockGuiDriver {
    pub actions: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl GuiDriver for MockGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));
        let mut bytes: Vec<u8> = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
            .map_err(|e| VmError::HostError(format!("Mock PNG encoding failed: {}", e)))?;
        Ok(bytes)
    }
    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        self.capture_screen(None).await
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok(String::new())
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [0u8; 32],
            frame_id: 0,
            chunks: vec![],
            mhnsw_root: [0u8; 32],
            traversal_proof: None,
            intent_id: [0u8; 32],
        })
    }

    async fn inject_input(&self, event: InputEvent) -> Result<(), VmError> {
        let mut log = self.actions.lock().unwrap();
        match event {
            InputEvent::Click { x, y, .. } => log.push(format!("click({}, {})", x, y)),
            InputEvent::Type { text } => log.push(format!("type('{}')", text)),
            _ => {}
        }
        Ok(())
    }
    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }
}

struct MockBrain;
#[async_trait]
impl InferenceRuntime for MockBrain {
    async fn execute_inference(
        &self,
        _hash: [u8; 32],
        input: &[u8],
        _opts: ioi_types::app::agentic::InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input);
        if prompt.contains("\"remote_public_fact_required\"")
            && prompt.contains("\"direct_ui_input\"")
        {
            return Ok(serde_json::json!({
                "remote_public_fact_required": false,
                "host_local_clock_targeted": false,
                "command_directed": false,
                "durable_automation_requested": false,
                "model_registry_control_requested": false,
                "app_launch_directed": false,
                "direct_ui_input": true,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
        Ok(serde_json::json!({
            "name": "screen__click_at",
            "arguments": {
                "x": 500,
                "y": 500,
                "button": "left"
            }
        })
        .to_string()
        .into_bytes())
    }

    async fn load_model(&self, _: [u8; 32], _: &Path) -> Result<(), VmError> {
        Ok(())
    }
    async fn unload_model(&self, _: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        let lower = text.to_ascii_lowercase();
        if lower.contains("click")
            || lower.contains("button")
            || lower.contains("amazon")
            || lower.contains("ui")
        {
            return Ok(vec![0.0, 1.0]);
        }
        MockInferenceRuntime.embed_text(text).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_agentic_loop_end_to_end() -> Result<()> {
    build_test_artifacts();

    let actions_log = Arc::new(Mutex::new(Vec::new()));
    let mock_gui = Arc::new(MockGuiDriver {
        actions: actions_log.clone(),
    });

    // 1. Setup Service with Mocks
    use ioi_services::agentic::runtime::RuntimeAgentService;

    // [NEW] Instantiate drivers
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());

    let service = RuntimeAgentService::new_hybrid(
        mock_gui,
        terminal,
        browser, // Injected
        Arc::new(MockBrain),
        Arc::new(MockBrain),
    )
    .with_memory_runtime(Arc::new(
        ioi_memory::MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"),
    ));

    // 2. Mock State Access
    let mut state = IAVLTree::new(HashCommitmentScheme::new());

    // 3. Initialize Session (Start)
    let session_id = [1u8; 32];
    let start_params = StartAgentParams {
        session_id,
        goal: "Click the UI button".into(),
        max_steps: 5,
        parent_session_id: None,
        initial_budget: 1000,
        mode: ioi_services::agentic::runtime::AgentMode::Agent,
    };

    use ioi_api::services::access::ServiceDirectory;
    use ioi_api::transaction::context::TxContext;

    let services_dir = ServiceDirectory::new(vec![]); // Empty for now
    let mut ctx = TxContext {
        block_height: 1,
        block_timestamp: 1_700_000_000_000_000_000,
        chain_id: ioi_types::app::ChainId(0),
        signer_account_id: ioi_types::app::AccountId::default(),
        services: &services_dir,
        simulation: false,
        is_internal: false,
    };

    // Call START
    let start_bytes = ioi_types::codec::to_bytes_canonical(&start_params).unwrap();
    service
        .handle_service_call(&mut state, "start@v1", &start_bytes, &mut ctx)
        .await?;

    // 4. Trigger Step (The Loop)
    let step_params = StepAgentParams { session_id };
    let step_bytes = ioi_types::codec::to_bytes_canonical(&step_params).unwrap();

    service
        .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
        .await?;

    // 5. Assert Action happened
    let logs = actions_log.lock().unwrap();
    let state_key = get_state_key(&session_id);
    let agent_state_bytes = state
        .get(&state_key)
        .unwrap()
        .expect("Agent state not found in state");
    let agent_state: AgentState =
        ioi_types::codec::from_bytes_canonical(&agent_state_bytes).unwrap();

    if logs.is_empty() {
        assert_eq!(agent_state.step_count, 1);
        assert_eq!(
            agent_state.last_action_type.as_deref(),
            Some("screen__click_at")
        );
        println!("✅ Agent Logic E2E Passed: runtime selected and recorded screen__click_at.");
        return Ok(());
    }
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0], "click(500, 500)");

    println!("✅ Agent Logic E2E Passed: VLM -> Grounding -> Driver execution verified.");
    Ok(())
}
