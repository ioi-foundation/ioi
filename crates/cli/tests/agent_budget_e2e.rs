// Path: crates/cli/tests/agent_budget_e2e.rs
#![cfg(all(feature = "consensus-aft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::BlockchainService;
// [FIX] Import StateAccess trait to use .get()
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_cli::testing::build_test_artifacts;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_memory::MemoryRuntime;
use ioi_services::agentic::runtime::{AgentState, AgentStatus, StartAgentParams};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::{
    app::{ActionRequest, ContextSlice},
    codec,
    error::VmError,
};
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

#[tokio::test(flavor = "multi_thread")]
async fn test_agent_budget_limit() -> Result<()> {
    build_test_artifacts();

    let gui = Arc::new(MockGuiDriver);
    let brain = Arc::new(MockInferenceRuntime);

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

    let parent_id = [1u8; 32];

    // Start a parent agent with a small delegation budget.
    let start_params = StartAgentParams {
        session_id: parent_id,
        goal: "Coordinate a small task".into(),
        max_steps: 5,
        parent_session_id: None,
        initial_budget: 20,
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

    let child_id = [2u8; 32];
    let child_start = StartAgentParams {
        session_id: child_id,
        goal: "Click the UI button".into(),
        max_steps: 5,
        parent_session_id: Some(parent_id),
        initial_budget: 100,
        mode: ioi_services::agentic::runtime::AgentMode::Agent,
    };
    let res = service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&child_start).unwrap(),
            &mut ctx,
        )
        .await;

    let key = [b"agent::state::".as_slice(), parent_id.as_slice()].concat();
    let state_after_step: AgentState =
        codec::from_bytes_canonical(&state.get(&key).unwrap().unwrap()).unwrap();
    assert_eq!(
        state_after_step.budget, 20,
        "A rejected child start should not burn the parent's budget"
    );
    assert!(
        state_after_step.child_session_ids.is_empty(),
        "A rejected child start should not register a child session"
    );
    assert!(
        matches!(state_after_step.status, AgentStatus::Running),
        "A rejected child start should leave the parent running, got {:?}",
        state_after_step.status
    );
    let child_key = [b"agent::state::".as_slice(), child_id.as_slice()].concat();
    assert!(
        state.get(&child_key).unwrap().is_none(),
        "A rejected child start should not create child state"
    );

    let msg = match res {
        Err(e) => e.to_string(),
        Ok(_) => panic!("Over-budget child start should fail immediately"),
    };
    assert!(
        msg.contains("Insufficient parent budget for delegation"),
        "Unexpected error: {}",
        msg
    );

    println!("✅ Agent Budget Enforcement E2E Passed");
    Ok(())
}
