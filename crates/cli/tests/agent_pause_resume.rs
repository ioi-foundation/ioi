// Path: crates/cli/tests/agent_pause_resume.rs
#![cfg(all(feature = "consensus-aft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::BlockchainService;
// [FIX] Import StateAccess trait to use .get()
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
use ioi_cli::testing::build_test_artifacts;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_memory::MemoryRuntime;
use ioi_services::agentic::runtime::{
    AgentState, AgentStatus, ResumeAgentParams, StartAgentParams, StepAgentParams,
};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::{
    app::{ActionRequest, ContextSlice},
    codec,
    error::VmError,
};
use serde_json::json;
use std::path::Path;
use std::sync::Arc;

// [FIX] Imports for valid PNG generation
use image::{ImageBuffer, ImageFormat, Rgba};
use std::io::Cursor;

#[derive(Clone)]
struct MockGuiDriver;
#[async_trait]
impl GuiDriver for MockGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        // [FIX] Generate a valid 1x1 PNG image to satisfy image::load_from_memory
        let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));

        let mut bytes: Vec<u8> = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .map_err(|e| VmError::HostError(format!("Mock PNG encoding failed: {}", e)))?;

        Ok(bytes)
    }
    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        self.capture_screen(None).await
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
    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }
}

struct PausingBrain;
#[async_trait]
impl InferenceRuntime for PausingBrain {
    async fn execute_inference(
        &self,
        _: [u8; 32],
        _: &[u8],
        _: ioi_types::app::agentic::InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let tool_call = json!({
            "name": "agent__pause",
            "arguments": { "reason": "Ask human" }
        });
        Ok(tool_call.to_string().into_bytes())
    }
    async fn load_model(&self, _: [u8; 32], _: &Path) -> Result<(), VmError> {
        Ok(())
    }
    async fn unload_model(&self, _: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        MockInferenceRuntime.embed_text(text).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_agent_pause_resume() -> Result<()> {
    build_test_artifacts();

    let gui = Arc::new(MockGuiDriver);
    let brain = Arc::new(PausingBrain);

    use ioi_services::agentic::runtime::RuntimeAgentService;
    let service = RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        brain.clone(),
        brain.clone(),
    )
    .with_memory_runtime(Arc::new(
        MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"),
    ));
    let mut state = IAVLTree::new(HashCommitmentScheme::new());

    use ioi_api::services::access::ServiceDirectory;
    use ioi_api::transaction::context::TxContext;
    let services_dir = ServiceDirectory::new(vec![]);
    let mut ctx = TxContext {
        block_height: 1,
        block_timestamp: 1_700_000_000_000_000_000,
        chain_id: ioi_types::app::ChainId(0),
        signer_account_id: ioi_types::app::AccountId::default(),
        services: &services_dir,
        simulation: false,
        is_internal: false,
    };

    let session_id = [1u8; 32];

    // 1. Start
    // Use a concrete command goal so the pause comes from the mock brain, not
    // the intent-clarification gate.
    let start_params = StartAgentParams {
        session_id,
        goal: "Run pwd in the terminal".into(),
        max_steps: 5,
        parent_session_id: None,
        initial_budget: 1000,
        mode: ioi_services::agentic::runtime::AgentMode::Agent,
    };
    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params).unwrap(),
            &mut ctx,
        )
        .await?;

    let step_params = StepAgentParams { session_id };
    let step_bytes = codec::to_bytes_canonical(&step_params).unwrap();

    // 2. Step: Agent Calls Pause
    service
        .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
        .await?;

    // Check Status
    let key = [b"agent::state::".as_slice(), session_id.as_slice()].concat();
    let state_paused: AgentState =
        codec::from_bytes_canonical(&state.get(&key).unwrap().unwrap()).unwrap();
    assert_eq!(state_paused.status, AgentStatus::Paused("Ask human".into()));

    // 3. Attempt Step (Should fail)
    let res = service
        .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
        .await;
    assert!(res.is_err());
    let paused_error = res.unwrap_err().to_string();
    assert!(
        paused_error.contains("Agent not running") && paused_error.contains("Paused"),
        "Expected paused agent rejection, got: {}",
        paused_error
    );

    // 4. Resume
    let resume_params = ResumeAgentParams {
        session_id,
        approval_token: None,
    };
    let resume_bytes = codec::to_bytes_canonical(&resume_params).unwrap();
    service
        .handle_service_call(&mut state, "resume@v1", &resume_bytes, &mut ctx)
        .await?;

    // Check Status
    let state_running: AgentState =
        codec::from_bytes_canonical(&state.get(&key).unwrap().unwrap()).unwrap();
    assert_eq!(state_running.status, AgentStatus::Running);
    // [FIX] Update assertion logic as duplicate logs might be pruned or formatted differently
    // The presence of "Action: ..." log confirms the step ran.
    // The *new* log should be "System: Resumed..."
    let history = service
        .hydrate_session_history(session_id)
        .expect("session transcript should load");
    assert!(
        history.iter().any(|msg| msg.content.contains("Resumed")),
        "Transcript should contain resumption log: {:?}",
        history
    );

    println!("✅ Agent Pause/Resume E2E Passed");
    Ok(())
}
