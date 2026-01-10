// Path: crates/cli/tests/agent_pause_resume_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::BlockchainService;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_cli::testing::build_test_artifacts;
use ioi_services::agentic::desktop::{
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

#[derive(Clone)]
struct MockGuiDriver;
#[async_trait]
impl GuiDriver for MockGuiDriver {
    async fn capture_screen(&self) -> Result<Vec<u8>, VmError> {
        Ok(vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
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
}

#[tokio::test(flavor = "multi_thread")]
async fn test_agent_pause_resume() -> Result<()> {
    build_test_artifacts();

    let gui = Arc::new(MockGuiDriver);
    let brain = Arc::new(PausingBrain);

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

    // 1. Start
    let start_params = StartAgentParams {
        session_id,
        goal: "Ask".into(),
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
    assert!(res.unwrap_err().to_string().contains("Agent is paused"));

    // 4. Resume
    let resume_params = ResumeAgentParams { session_id };
    let resume_bytes = codec::to_bytes_canonical(&resume_params).unwrap();
    service
        .handle_service_call(&mut state, "resume@v1", &resume_bytes, &mut ctx)
        .await?;

    // Check Status
    let state_running: AgentState =
        codec::from_bytes_canonical(&state.get(&key).unwrap().unwrap()).unwrap();
    assert_eq!(state_running.status, AgentStatus::Running);
    assert!(state_running.history.last().unwrap().contains("Resumed"));

    println!("✅ Agent Pause/Resume E2E Passed");
    Ok(())
}
