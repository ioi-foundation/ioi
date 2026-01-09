// Path: crates/cli/tests/agentic_e2e.rs
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
use ioi_types::{error::VmError, keys::*};
use std::path::Path;
use std::sync::{Arc, Mutex};

// --- Mocks ---

#[derive(Clone)]
struct MockGuiDriver {
    pub actions: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl GuiDriver for MockGuiDriver {
    async fn capture_screen(&self) -> Result<Vec<u8>, VmError> {
        Ok(vec![0; 100]) // Dummy screenshot
    }
    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok("<root><window title='Amazon' /></root>".to_string())
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
    async fn execute_inference(&self, _hash: [u8; 32], _input: &[u8]) -> Result<Vec<u8>, VmError> {
        // Deterministic "Zombie" Brain
        // Output format must match what `grounding::parse_vlm_action` expects
        // The simple parser expects "click x y"
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
    let service = DesktopAgentService::new(mock_gui, Arc::new(MockBrain));

    // 2. Mock State Access
    // We can use `ioi_state::tree::iavl::IAVLTree` (real state) in memory.
    let mut state = IAVLTree::new(HashCommitmentScheme::new());

    // 3. Initialize Session (Start)
    let session_id = [1u8; 32];
    let start_params = StartAgentParams {
        session_id,
        goal: "Buy t-shirt".into(),
        max_steps: 5,
    };

    // We need to call `handle_service_call`.
    // We need a dummy TxContext.
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
    // `grounding.rs` logic handles clamping/scaling.
    // `MockGuiDriver` logs "click(x, y)".
    // 500 is within 1000 range.
    // If screen is 1920x1080 (hardcoded in desktop.rs for MVP), 500/1000 = 0.5.
    // 0.5 * 1920 = 960. 0.5 * 1080 = 540.
    assert_eq!(logs[0], "click(960, 540)");

    println!("✅ Agent Logic E2E Passed: VLM -> Grounding -> Driver execution verified.");
    Ok(())
}
