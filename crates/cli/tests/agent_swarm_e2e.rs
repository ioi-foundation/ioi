// Path: crates/cli/tests/agent_swarm_e2e.rs
#![cfg(all(feature = "consensus-aft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::BlockchainService;
// [FIX] Import StateAccess
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
use ioi_cli::testing::build_test_artifacts;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_memory::MemoryRuntime;
use ioi_services::agentic::runtime::{AgentState, StartAgentParams, StepAgentParams};
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

// [NEW] Imports for valid PNG generation
use image::{ImageBuffer, ImageFormat, Rgba};
use std::io::Cursor;

// Mocks
#[derive(Clone)]
struct MockGuiDriver;
#[async_trait]
impl GuiDriver for MockGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        // Generate a valid 1x1 PNG image to satisfy image::load_from_memory
        let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255])); // Red pixel

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

struct SwarmMockBrain {
    child_session_id_hex: Mutex<Option<String>>,
}

impl SwarmMockBrain {
    fn set_child_session_id(&self, child_session_id: [u8; 32]) {
        *self.child_session_id_hex.lock().unwrap() = Some(hex::encode(child_session_id));
    }
}

#[async_trait]
impl InferenceRuntime for SwarmMockBrain {
    async fn execute_inference(
        &self,
        _hash: [u8; 32],
        _input: &[u8],
        _opts: ioi_types::app::agentic::InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let child_id_hex = self
            .child_session_id_hex
            .lock()
            .unwrap()
            .clone()
            .expect("child session id should be seeded before awaiting");
        let tool_call = json!({
            "name": "agent__await",
            "arguments": { "child_session_id_hex": child_id_hex }
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
async fn test_agent_delegation_flow() -> Result<()> {
    build_test_artifacts();
    let gui = Arc::new(MockGuiDriver);
    let brain = Arc::new(SwarmMockBrain {
        child_session_id_hex: Mutex::new(None),
    });
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

    // 1. Start Parent
    let parent_id = [1u8; 32];
    let start_params = StartAgentParams {
        session_id: parent_id,
        goal: "Wait for the child worker result".into(),
        max_steps: 10,
        parent_session_id: None,
        initial_budget: 1000,
        mode: ioi_services::agentic::runtime::AgentMode::Agent,
    };
    let start_bytes = codec::to_bytes_canonical(&start_params).unwrap();
    service
        .handle_service_call(&mut state, "start@v1", &start_bytes, &mut ctx)
        .await?;

    // 2. Seed a child worker directly so this test focuses on the
    // await/merge lifecycle rather than delegate-tool routing.
    let child_id = [2u8; 32];
    let child_start = StartAgentParams {
        session_id: child_id,
        goal: "Click the button in the UI".into(),
        max_steps: 10,
        parent_session_id: Some(parent_id),
        initial_budget: 100,
        mode: ioi_services::agentic::runtime::AgentMode::Agent,
    };
    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&child_start).unwrap(),
            &mut ctx,
        )
        .await?;
    brain.set_child_session_id(child_id);

    // 3. Parent Step 1: Await while the child is still running.
    let step_params = StepAgentParams {
        session_id: parent_id,
    };
    let step_bytes = codec::to_bytes_canonical(&step_params).unwrap();
    service
        .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
        .await?;

    let parent_key = [b"agent::state::".as_slice(), parent_id.as_slice()].concat();
    let parent_bytes = state.get(&parent_key).unwrap().unwrap();
    let parent_state_after_child_start: AgentState =
        codec::from_bytes_canonical(&parent_bytes).unwrap();
    assert!(
        parent_state_after_child_start
            .child_session_ids
            .contains(&child_id),
        "Parent should track the seeded child session"
    );
    let parent_history = service
        .hydrate_session_history(parent_id)
        .expect("parent transcript should load");

    // [FIX] Check for message existence in transcript instead of relying on exact last position
    let found = parent_history.iter().any(|msg| {
        msg.content.contains("Child is still running") || msg.content.contains("Running (paused:")
    });
    assert!(
        found,
        "Parent should be told to wait. Transcript: {:?}",
        parent_history
    );

    // 4. Force complete the child worker.
    let child_key = [b"agent::state::".as_slice(), child_id.as_slice()].concat();
    let mut child_state: AgentState =
        codec::from_bytes_canonical(&state.get(&child_key).unwrap().unwrap()).unwrap();
    child_state.status =
        ioi_services::agentic::runtime::AgentStatus::Completed(Some("Done".into()));
    state
        .insert(
            &child_key,
            &codec::to_bytes_canonical(&child_state).unwrap(),
        )
        .unwrap();

    // 5. Parent Step 2: Await again, which should merge the child result.
    service
        .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
        .await?;

    // Verify
    let parent_bytes_final = state.get(&parent_key).unwrap().unwrap();
    let _parent_state_final: AgentState = codec::from_bytes_canonical(&parent_bytes_final).unwrap();
    let parent_history_final = service
        .hydrate_session_history(parent_id)
        .expect("parent transcript should load");

    // [FIX] Robust check
    let found_result = parent_history_final.iter().any(|msg| {
        msg.content.contains("Child Result: Done")
            || (msg.content.contains("Sub-Worker handoff") && msg.content.contains("Done"))
    });
    assert!(
        found_result,
        "Parent should receive child result. Transcript: {:?}",
        parent_history_final
    );

    println!("✅ Agent Swarm Await Loop E2E Passed");
    Ok(())
}
