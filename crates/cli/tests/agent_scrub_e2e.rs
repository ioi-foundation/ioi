// Path: crates/cli/tests/agent_scrub_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::BlockchainService;
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
            data: vec![],
            provenance_proof: vec![],
            intent_id: [0; 32],
        })
    }
    async fn inject_input(&self, _: InputEvent) -> Result<(), VmError> {
        Ok(())
    }
}

struct LeakBrain {
    // Capture prompt to verify scrubbing
    pub received_prompt: Arc<Mutex<String>>,
}
#[async_trait]
impl InferenceRuntime for LeakBrain {
    async fn execute_inference(
        &self,
        _: [u8; 32],
        input: &[u8],
        _: ioi_types::app::agentic::InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input).to_string();
        *self.received_prompt.lock().unwrap() = prompt;

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

#[tokio::test(flavor = "multi_thread")]
async fn test_agent_input_scrubbing() -> Result<()> {
    build_test_artifacts();

    let received_prompt = Arc::new(Mutex::new(String::new()));
    let gui = Arc::new(MockGuiDriver);
    let brain = Arc::new(LeakBrain {
        received_prompt: received_prompt.clone(),
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

    let session_id = [1u8; 32];

    // 1. Start with Sensitive Goal
    let sensitive_goal = "Login with sk_live_12345secret";
    let start_params = StartAgentParams {
        session_id,
        goal: sensitive_goal.into(),
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

    // 2. Step: Triggers Prompt Construction and Scrubbing
    service
        .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
        .await?;

    // 3. Verify what the brain received
    let prompt = received_prompt.lock().unwrap().clone();

    assert!(
        !prompt.contains("sk_live_12345secret"),
        "Secret leaked to LLM!"
    );
    assert!(
        prompt.contains("<REDACTED:API_KEY>"),
        "Redaction placeholder missing"
    );

    println!("✅ Agent Input Scrubbing E2E Passed");
    Ok(())
}
