// Path: crates/cli/tests/agentic_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use image::{ImageBuffer, Rgba};
use ioi_api::services::BlockchainService;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_cli::testing::build_test_artifacts;
use ioi_services::agentic::desktop::{StartAgentParams, StepAgentParams};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, ContextSlice};
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
    async fn capture_screen(&self) -> Result<Vec<u8>, VmError> {
        let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));
        let mut bytes: Vec<u8> = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
            .map_err(|e| VmError::HostError(format!("Mock PNG encoding failed: {}", e)))?;
        Ok(bytes)
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok("<root><window title='Amazon' /></root>".to_string())
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [0u8; 32],
            frame_id: 0,
            chunks: vec![b"<root><window title='Amazon' /></root>".to_vec()],
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
}

struct MockBrain;
#[async_trait]
impl InferenceRuntime for MockBrain {
    async fn execute_inference(
        &self,
        _hash: [u8; 32],
        _input: &[u8],
        _opts: ioi_types::app::agentic::InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        // Deterministic "Zombie" Brain
        Ok(b"click 500 500".to_vec())
    }

    async fn load_model(&self, _: [u8; 32], _: &Path) -> Result<(), VmError> {
        Ok(())
    }
    async fn unload_model(&self, _: [u8; 32]) -> Result<(), VmError> {
        Ok(())
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
    use ioi_services::agentic::desktop::DesktopAgentService;

    // [NEW] Instantiate drivers
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());

    let service = DesktopAgentService::new_hybrid(
        mock_gui,
        terminal,
        browser, // Injected
        Arc::new(MockBrain),
        Arc::new(MockBrain),
    );

    // 2. Mock State Access
    let mut state = IAVLTree::new(HashCommitmentScheme::new());

    // 3. Initialize Session (Start)
    let session_id = [1u8; 32];
    let start_params = StartAgentParams {
        session_id,
        goal: "Buy t-shirt".into(),
        max_steps: 5,
        parent_session_id: None,
        initial_budget: 1000,
    };

    use ioi_api::services::access::ServiceDirectory;
    use ioi_api::transaction::context::TxContext;

    let services_dir = ServiceDirectory::new(vec![]); // Empty for now
    let mut ctx = TxContext {
        block_height: 1,
        block_timestamp: ibc_primitives::Timestamp::now(),
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
    assert_eq!(logs.len(), 1);
    // MockBrain returns "click 500 500".
    // 500/1000 = 0.5.
    // 0.5 * 1920 = 960. 0.5 * 1080 = 540.
    assert_eq!(logs[0], "click(960, 540)");

    println!("✅ Agent Logic E2E Passed: VLM -> Grounding -> Driver execution verified.");
    Ok(())
}
