// Path: crates/cli/tests/agent_hybrid_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::BlockchainService;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_cli::testing::build_test_artifacts;
use ioi_services::agentic::desktop::{StartAgentParams, StepAgentParams};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::{
    app::{ActionRequest, ContextSlice},
    codec,
    error::VmError,
};
use serde_json::json;
use std::path::Path;
use std::sync::{Arc, Mutex};

// [FIX] Imports for valid PNG generation
use image::{ImageBuffer, ImageFormat, Rgba};
use std::io::Cursor;

// [NEW] Imports
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;

// Mocks
#[derive(Clone)]
struct MockGuiDriver;
#[async_trait]
impl GuiDriver for MockGuiDriver {
    async fn capture_screen(&self) -> Result<Vec<u8>, VmError> {
        // [FIX] Generate a valid 1x1 PNG image to satisfy image::load_from_memory
        let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));

        let mut bytes: Vec<u8> = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .map_err(|e| VmError::HostError(format!("Mock PNG encoding failed: {}", e)))?;

        Ok(bytes)
    }
    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok("".into())
    }
    async fn capture_context(&self, _: &ActionRequest) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [0; 32],
            frame_id: 0,
            chunks: vec![],
            mhnsw_root: [0; 32],
            traversal_proof: None,
            intent_id: [0; 32],
        })
    }
    async fn inject_input(&self, _: InputEvent) -> Result<(), VmError> {
        Ok(())
    }
}

// "Big Brain" - Only handles logic/planning, fails on clicks
struct ReasoningBrain {
    called: Arc<Mutex<bool>>,
}
#[async_trait]
impl InferenceRuntime for ReasoningBrain {
    async fn execute_inference(
        &self,
        _: [u8; 32],
        _: &[u8],
        _: ioi_types::app::agentic::InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        *self.called.lock().unwrap() = true;
        // First step (planning) -> returns a click
        let tool_call = json!({
            "name": "gui__click",
            "arguments": { "x": 10, "y": 10 }
        });
        Ok(tool_call.to_string().into_bytes())
    }
    async fn load_model(&self, _: [u8; 32], _: &Path) -> Result<(), VmError> {
        Ok(())
    }
    async fn unload_model(&self, _: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

// "Fast Brain" - Handles execution loop
struct FastBrain {
    called: Arc<Mutex<bool>>,
}
#[async_trait]
impl InferenceRuntime for FastBrain {
    async fn execute_inference(
        &self,
        _: [u8; 32],
        _: &[u8],
        _: ioi_types::app::agentic::InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        *self.called.lock().unwrap() = true;
        // Fast loop response
        let tool_call = json!({
            "name": "gui__click",
            "arguments": { "x": 20, "y": 20 }
        });
        Ok(tool_call.to_string().into_bytes())
    }
    async fn load_model(&self, _: [u8; 32], _: &Path) -> Result<(), VmError> {
        Ok(())
    }
    async fn unload_model(&self, _: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_hybrid_routing_logic() -> Result<()> {
    build_test_artifacts();

    let gui = Arc::new(MockGuiDriver);
    let reasoner_called = Arc::new(Mutex::new(false));
    let fast_called = Arc::new(Mutex::new(false));

    let reasoning = Arc::new(ReasoningBrain {
        called: reasoner_called.clone(),
    });
    let fast = Arc::new(FastBrain {
        called: fast_called.clone(),
    });

    use ioi_services::agentic::desktop::DesktopAgentService;

    // [NEW] Instantiate drivers
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());

    let service = DesktopAgentService::new_hybrid(gui, terminal, browser, fast, reasoning);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());

    use ioi_api::services::access::ServiceDirectory;
    use ioi_api::transaction::context::TxContext;
    let services_dir = ServiceDirectory::new(vec![]);
    let mut ctx = TxContext {
        block_height: 1,
        block_timestamp: ibc_primitives::Timestamp::now(),
        chain_id: ioi_types::app::ChainId(0),
        signer_account_id: ioi_types::app::AccountId::default(),
        services: &services_dir,
        simulation: false,
        is_internal: false,
    };

    let session_id = [1u8; 32];
    let start_params = StartAgentParams {
        session_id,
        goal: "Test".into(),
        max_steps: 5,
        parent_session_id: None,
        initial_budget: 1000,
    };
    let step_params = StepAgentParams { session_id };

    // 1. Start Session
    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params).unwrap(),
            &mut ctx,
        )
        .await?;

    // 2. Step 1: Initial Planning (Should use Reasoning)
    // Step count is 0.
    service
        .handle_service_call(
            &mut state,
            "step@v1",
            &codec::to_bytes_canonical(&step_params).unwrap(),
            &mut ctx,
        )
        .await?;

    assert!(
        *reasoner_called.lock().unwrap(),
        "Step 1 should use Reasoning model"
    );
    assert!(
        !*fast_called.lock().unwrap(),
        "Step 1 should NOT use Fast model"
    );

    // Reset flags
    *reasoner_called.lock().unwrap() = false;

    // 3. Step 2: Execution Loop (Should use Fast)
    // Last action was "gui__click" (from Reasoning brain output above).
    // State now has last_action_type = "gui__click".
    service
        .handle_service_call(
            &mut state,
            "step@v1",
            &codec::to_bytes_canonical(&step_params).unwrap(),
            &mut ctx,
        )
        .await?;

    assert!(
        *fast_called.lock().unwrap(),
        "Step 2 should use Fast model (reflex)"
    );
    assert!(
        !*reasoner_called.lock().unwrap(),
        "Step 2 should NOT use Reasoning model"
    );

    println!("✅ Hybrid Routing E2E Passed: Switched brains correctly.");
    Ok(())
}
