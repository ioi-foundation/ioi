// Path: crates/cli/tests/agent_swarm_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::BlockchainService;
// [FIX] Import StateAccess
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_cli::testing::build_test_artifacts;
use ioi_services::agentic::desktop::{AgentState, StartAgentParams, StepAgentParams};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::{
    app::{ActionRequest, ContextSlice},
    codec,
    error::VmError,
};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, Mutex};

// [NEW] Imports for valid PNG generation
use image::{ImageBuffer, Rgba, ImageFormat};
use std::io::Cursor;

// Mocks
#[derive(Clone)]
struct MockGuiDriver;
#[async_trait]
impl GuiDriver for MockGuiDriver {
    async fn capture_screen(&self) -> Result<Vec<u8>, VmError> {
        // Generate a valid 1x1 PNG image to satisfy image::load_from_memory
        let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255])); // Red pixel
        
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
            data: vec![],
            provenance_proof: vec![],
            intent_id: [0; 32],
        })
    }
    async fn inject_input(&self, _: InputEvent) -> Result<(), VmError> {
        Ok(())
    }
}

struct SwarmMockBrain {
    // 1. Parent Delegate
    // 2. Child Runs (loops 3 times)
    // 3. Parent Awaits (loops until child done)
    call_count: Mutex<usize>,
}

#[async_trait]
impl InferenceRuntime for SwarmMockBrain {
    async fn execute_inference(
        &self,
        _hash: [u8; 32],
        _input: &[u8],
        _opts: ioi_types::app::agentic::InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let mut count = self.call_count.lock().unwrap();
        *count += 1;

        let prompt_str = String::from_utf8_lossy(_input);

        // Simple mock logic:
        // If prompts contains "Goal: Manage team", it's the parent.
        // If prompt contains "Goal: Click button", it's the child.

        if prompt_str.contains("Goal: Manage team") {
            if *count == 1 {
                // First step: Delegate
                let tool_call = json!({
                    "name": "agent__delegate",
                    "arguments": { "goal": "Click button", "budget": 500 }
                });
                return Ok(tool_call.to_string().into_bytes());
            } else {
                // Subsequent steps: Await
                // Need to know child ID. In mock, we can hardcode or just return a placeholder that will fail parsing if not right.
                // But wait, the service calculates the child ID deterministically.
                // Let's just output `agent__await_result` with a placeholder, relying on the test harness to check logic flow
                // Actually, to test the loop, we need the valid child ID.
                // We can re-calculate it here or just check the prompt history in the service.
                // For this test, we'll just return a dummy wait action. The service will try to look it up.
                // We need the CHILD ID.
                // Parent ID = [1;32], Step = 0.
                let parent_id = [1u8; 32];
                let mut seed = parent_id.to_vec();
                seed.extend_from_slice(&0u32.to_le_bytes());
                let child_id_vec = ioi_crypto::algorithms::hash::sha256(&seed)
                    .unwrap()
                    .to_vec();
                let child_id_hex = hex::encode(child_id_vec);

                let tool_call = json!({
                    "name": "agent__await_result",
                    "arguments": { "child_session_id_hex": child_id_hex }
                });
                return Ok(tool_call.to_string().into_bytes());
            }
        } else {
            // Child logic
            let tool_call = json!({
                "name": "gui__click",
                "arguments": { "x": 100, "y": 100, "button": "left" }
            });
            return Ok(tool_call.to_string().into_bytes());
        }
    }
    async fn load_model(&self, _: [u8; 32], _: &Path) -> Result<(), VmError> {
        Ok(())
    }
    async fn unload_model(&self, _: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_agent_delegation_flow() -> Result<()> {
    build_test_artifacts();
    let gui = Arc::new(MockGuiDriver);
    let brain = Arc::new(SwarmMockBrain {
        call_count: Mutex::new(0),
    });
    use ioi_services::agentic::desktop::DesktopAgentService;
    let service = DesktopAgentService::new_hybrid(gui, brain.clone(), brain.clone());
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

    // 1. Start Parent
    let parent_id = [1u8; 32];
    let start_params = StartAgentParams {
        session_id: parent_id,
        goal: "Manage team".into(),
        max_steps: 10,
        parent_session_id: None,
        initial_budget: 1000,
    };
    let start_bytes = codec::to_bytes_canonical(&start_params).unwrap();
    service
        .handle_service_call(&mut state, "start@v1", &start_bytes, &mut ctx)
        .await?;

    // 2. Parent Step 1: Delegate
    let step_params = StepAgentParams {
        session_id: parent_id,
    };
    let step_bytes = codec::to_bytes_canonical(&step_params).unwrap();
    service
        .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
        .await?;

    // Calculate Child ID
    let mut seed = parent_id.to_vec();
    seed.extend_from_slice(&0u32.to_le_bytes());
    let child_id_vec = ioi_crypto::algorithms::hash::sha256(&seed)
        .unwrap()
        .to_vec();
    let mut child_id = [0u8; 32];
    child_id.copy_from_slice(&child_id_vec);

    // 3. Parent Step 2: Await (Child is Running, so this should say "Please wait")
    service
        .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
        .await?;

    // Check history
    let parent_key = [b"agent::state::".as_slice(), parent_id.as_slice()].concat();
    let parent_bytes = state.get(&parent_key).unwrap().unwrap();
    let parent_state: AgentState = codec::from_bytes_canonical(&parent_bytes).unwrap();

    let last_msg = parent_state.history.last().unwrap();
    assert!(
        last_msg.contains("Child is still running"),
        "Parent should be told to wait"
    );

    // 4. Child Step 1: Work
    let child_step_params = StepAgentParams {
        session_id: child_id,
    };
    let child_step_bytes = codec::to_bytes_canonical(&child_step_params).unwrap();
    service
        .handle_service_call(&mut state, "step@v1", &child_step_bytes, &mut ctx)
        .await?;

    // 5. Force Complete Child (Simulate completion for test)
    // Normally child runs until max_steps or Done.
    // Let's manually set child status to Completed.
    let child_key = [b"agent::state::".as_slice(), child_id.as_slice()].concat();
    let mut child_state: AgentState =
        codec::from_bytes_canonical(&state.get(&child_key).unwrap().unwrap()).unwrap();
    child_state.status =
        ioi_services::agentic::desktop::AgentStatus::Completed(Some("Done".into()));
    state
        .insert(
            &child_key,
            &codec::to_bytes_canonical(&child_state).unwrap(),
        )
        .unwrap();

    // 6. Parent Step 3: Await (Now should succeed)
    service
        .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
        .await?;

    // Verify
    let parent_bytes_final = state.get(&parent_key).unwrap().unwrap();
    let parent_state_final: AgentState = codec::from_bytes_canonical(&parent_bytes_final).unwrap();
    let last_msg_final = parent_state_final.history.last().unwrap();

    assert!(
        last_msg_final.contains("Child Result: Done"),
        "Parent should receive child result"
    );

    println!("✅ Agent Swarm Await Loop E2E Passed");
    Ok(())
}