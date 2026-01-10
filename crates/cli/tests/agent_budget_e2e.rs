// Path: crates/cli/tests/agent_budget_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::BlockchainService;
// [FIX] Import StateAccess trait to use .get()
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_cli::testing::build_test_artifacts;
use ioi_services::agentic::desktop::{AgentState, AgentStatus, StartAgentParams, StepAgentParams};
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

struct CostlyBrain;
#[async_trait]
impl InferenceRuntime for CostlyBrain {
    async fn execute_inference(
        &self,
        _: [u8; 32],
        _input: &[u8],
        _: ioi_types::app::agentic::InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        // Return a verbose output to consume budget
        let verbose_output = "a".repeat(100);
        let tool_call = json!({
            "name": "gui__click",
            "arguments": { "x": 10, "y": 10, "note": verbose_output }
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
async fn test_agent_budget_limit() -> Result<()> {
    build_test_artifacts();

    let gui = Arc::new(MockGuiDriver);
    let brain = Arc::new(CostlyBrain);

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

    // 1. Start with VERY LOW budget
    let start_params = StartAgentParams {
        session_id,
        goal: "Spend".into(),
        max_steps: 5,
        parent_session_id: None,
        initial_budget: 20, // 20 tokens is approx 80 chars.
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

    // 2. Trigger Step.
    // The prompt + verbose output > 80 chars. Should fail.
    // However, the cost calculation happens AFTER the call.
    // So the first step might succeed but zero the budget, and the SECOND step fails.

    // Step 1: Might succeed but drain budget.
    let res1 = service
        .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
        .await;

    // Check state after step 1
    let key = [b"agent::state::".as_slice(), session_id.as_slice()].concat();
    let state_1: AgentState =
        codec::from_bytes_canonical(&state.get(&key).unwrap().unwrap()).unwrap();

    // Step 1 drained it?
    if state_1.budget == 0 {
        // Step 2 should fail immediately
        let res2 = service
            .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
            .await;

        // [FIX] Robust assertion: either "Agent not running" (if state persisted as Failed)
        // OR "Budget Exhausted" (if check happens before status check) is acceptable proof of enforcement.
        match res2 {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("Budget Exhausted") || msg.contains("Agent not running"),
                    "Unexpected error: {}",
                    msg
                );
            }
            Ok(_) => panic!("Step 2 should have failed due to zero budget"),
        }

        let state_final: AgentState =
            codec::from_bytes_canonical(&state.get(&key).unwrap().unwrap()).unwrap();

        // Ensure status reflects failure
        assert!(
            matches!(state_final.status, AgentStatus::Failed(_)),
            "Final status should be Failed, got {:?}",
            state_final.status
        );
    } else {
        // If initial step didn't drain it fully (due to short prompt in test), loop until it does.
        // But with initial_budget=20, and output=100 chars, it MUST drain in step 1.
        // Cost = (input + output) / 4. 100/4 = 25 tokens. 25 > 20.
        // So step 1 should have set budget to 0 and status to Failed.
        // And `handle_service_call` returns error.

        assert!(res1.is_err());
        assert_eq!(state_1.budget, 0);
        assert!(matches!(state_1.status, AgentStatus::Failed(_)));
    }

    println!("✅ Agent Budget Enforcement E2E Passed");
    Ok(())
}
