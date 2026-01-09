// Path: crates/cli/tests/agent_trace_e2e.rs
#![cfg(all(
    feature = "consensus-admft",
    feature = "vm-wasm",
    feature = "state-iavl"
))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_cli::testing::build_test_artifacts;
use ioi_types::app::agentic::{AgentSkill, InferenceOptions, StepTrace};
use ioi_types::app::ContextSlice;
use ioi_types::codec;
use ioi_types::error::VmError;
use serde_json::json;
use std::path::Path;
use std::sync::{Arc, Mutex};

// [FIX] Import params from services
use ioi_services::agentic::desktop::{StartAgentParams, StepAgentParams};

// --- Mock Components for Validation ---

#[derive(Clone)]
struct MockGuiDriver;
#[async_trait]
impl GuiDriver for MockGuiDriver {
    async fn capture_screen(&self) -> Result<Vec<u8>, VmError> {
        Ok(b"mock_screenshot_png".to_vec()) // Dummy PNG bytes
    }
    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok("<root><button id='login'>Login</button></root>".to_string())
    }
    // Implement the Substrate slicing method
    async fn capture_context(
        &self,
        _intent: &ioi_types::app::ActionRequest,
    ) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [1u8; 32],
            data: b"<root><button id='login'>Login</button></root>".to_vec(),
            provenance_proof: vec![],
            intent_id: [0u8; 32],
        })
    }
    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Ok(()) // Action succeeds
    }
}

// Mock Brain that simulates GPT-4 behavior
#[derive(Clone)]
struct MockBrain {
    // Store the last prompt we received to verify Skill Injection
    pub last_prompt: Arc<Mutex<String>>,
}
#[async_trait]
impl InferenceRuntime for MockBrain {
    async fn execute_inference(
        &self,
        _hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        // Capture prompt for assertion
        let prompt_str = String::from_utf8_lossy(input_context).to_string();
        *self.last_prompt.lock().unwrap() = prompt_str;

        // Simulate Tool Call Output (JSON)
        // This validates that the Kernel can parse structured outputs
        let tool_call = json!({
            "name": "gui__click",
            "arguments": {
                "x": 100,
                "y": 200,
                "button": "left"
            }
        });
        Ok(tool_call.to_string().into_bytes())
    }
    async fn load_model(&self, _: [u8; 32], _: &Path) -> Result<(), VmError> {
        Ok(())
    }
    async fn unload_model(&self, _: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
    async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
        Ok(vec![0.1; 384])
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_agent_trace_and_skill_injection() -> Result<()> {
    build_test_artifacts();

    let last_prompt = Arc::new(Mutex::new(String::new()));
    let mock_brain = Arc::new(MockBrain {
        last_prompt: last_prompt.clone(),
    });
    let mock_gui = Arc::new(MockGuiDriver);

    // --- Manual Setup (In-Process Service Test) ---
    use ioi_api::services::BlockchainService;
    use ioi_api::state::StateAccess;
    use ioi_services::agentic::desktop::DesktopAgentService;
    use ioi_state::primitives::hash::HashCommitmentScheme;
    use ioi_state::tree::iavl::IAVLTree;

    let service = DesktopAgentService::new(mock_gui, mock_brain);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());

    // 2. Inject a Skill into the Substrate
    let skill = AgentSkill {
        name: "test-login-skill".to_string(),
        description: "How to login to the test app".to_string(),
        content: "Use the gui__click tool on coordinates 100, 200.".to_string(),
        resources: vec![],
    };

    // Use the canonical SKILL_INDEX_PREFIX defined in desktop.rs (b"skills::vector::")
    let skill_key = [
        b"skills::vector::".as_slice(),
        b"test-login-skill".as_slice(),
    ]
    .concat();
    state
        .insert(&skill_key, &codec::to_bytes_canonical(&skill).unwrap())
        .unwrap();

    // 3. Start Session
    let session_id = [1u8; 32];
    let start_params = StartAgentParams {
        session_id,
        // [FIX] Simplified goal to ensure keyword match in MVP search logic
        goal: "Login".to_string(),
        max_steps: 5,
    };

    // Dummy Context
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

    let start_bytes = codec::to_bytes_canonical(&start_params).unwrap();
    service
        .handle_service_call(&mut state, "start@v1", &start_bytes, &mut ctx)
        .await
        .unwrap();

    // 4. Trigger Step (The Loop)
    let step_params = StepAgentParams { session_id };
    let step_bytes = codec::to_bytes_canonical(&step_params).unwrap();

    service
        .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
        .await
        .unwrap();

    // 5. ASSERTIONS

    // A. Verify Skill Injection
    let captured_prompt = last_prompt.lock().unwrap();
    assert!(
        captured_prompt.contains("test-login-skill"),
        "Prompt missing skill name"
    );
    assert!(
        captured_prompt.contains("Use the gui__click tool"),
        "Prompt missing skill instructions"
    );
    println!("✅ Skill Injection Verified");

    // B. Verify Black Box Trace
    // Trace key format: trace::{session_id}::{step_count}
    // step_count was 0 before this step.
    let trace_key = [
        b"agent::trace::".as_slice(),
        session_id.as_slice(),
        &0u32.to_le_bytes(),
    ]
    .concat();
    let trace_bytes = state
        .get(&trace_key)
        .unwrap()
        .expect("Trace not found in state");

    let trace: StepTrace = codec::from_bytes_canonical(&trace_bytes).unwrap();

    assert_eq!(trace.step_index, 0);
    assert_eq!(trace.session_id, session_id);
    assert!(trace.full_prompt.contains("test-login-skill")); // Trace captures the augmented prompt
    assert!(trace.raw_output.contains("gui__click")); // Trace captures model output
    assert!(trace.success, "Step marked as failed in trace");

    println!("✅ Execution Trace Verified");

    Ok(())
}
