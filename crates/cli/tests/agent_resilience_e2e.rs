// Path: crates/cli/tests/agent_resilience_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::BlockchainService;
// [FIX] Import StateAccess trait to use .get()
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
use serde_json::json;
use std::path::Path;
use std::sync::{Arc, Mutex};

// [FIX] Imports for valid PNG generation
use image::{ImageBuffer, ImageFormat, Rgba};
use std::io::Cursor;

#[derive(Clone)]
struct MockGuiDriver {
    // Fail first 2 clicks, succeed 3rd
    fail_count: Arc<Mutex<u32>>,
}

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
            data: vec![],
            provenance_proof: vec![],
            intent_id: [0; 32],
        })
    }
    async fn inject_input(&self, _: InputEvent) -> Result<(), VmError> {
        let mut count = self.fail_count.lock().unwrap();
        if *count < 2 {
            *count += 1;
            return Err(VmError::HostError("Click drifted".into()));
        }
        Ok(())
    }
}

struct ResilientBrain;
#[async_trait]
impl InferenceRuntime for ResilientBrain {
    async fn execute_inference(
        &self,
        _hash: [u8; 32],
        _input: &[u8],
        _opts: ioi_types::app::agentic::InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        // Always try to click the same button
        let tool_call = json!({
            "name": "gui__click",
            "arguments": { "x": 100, "y": 100, "button": "left" }
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
async fn test_agent_self_healing() -> Result<()> {
    build_test_artifacts();

    let gui = Arc::new(MockGuiDriver {
        fail_count: Arc::new(Mutex::new(0)),
    });
    let brain = Arc::new(ResilientBrain);

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

    let session_id = [1u8; 32];
    let start_params = StartAgentParams {
        session_id,
        goal: "Click".into(),
        max_steps: 5,
        parent_session_id: None,
        initial_budget: 1000,
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

    // Step 1: Fail (Count 0 -> 1)
    service
        .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
        .await?;

    // Check State
    let key = [b"agent::state::".as_slice(), session_id.as_slice()].concat();
    let state_1: AgentState =
        codec::from_bytes_canonical(&state.get(&key).unwrap().unwrap()).unwrap();
    assert_eq!(state_1.consecutive_failures, 1);

    // Step 2: Fail (Count 1 -> 2)
    service
        .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
        .await?;
    let state_2: AgentState =
        codec::from_bytes_canonical(&state.get(&key).unwrap().unwrap()).unwrap();
    assert_eq!(state_2.consecutive_failures, 2);

    // Step 3: Success (Count 2 -> 0)
    service
        .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
        .await?;
    let state_3: AgentState =
        codec::from_bytes_canonical(&state.get(&key).unwrap().unwrap()).unwrap();
    assert_eq!(state_3.consecutive_failures, 0);

    println!("✅ Agent Self-Healing E2E Passed: Recovered after 2 failures.");
    Ok(())
}
