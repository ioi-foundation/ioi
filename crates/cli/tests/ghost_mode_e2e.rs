// Path: crates/cli/tests/ghost_mode_e2e.rs
#![cfg(all(
    feature = "consensus-admft",
    feature = "vm-wasm",
    feature = "state-iavl"
))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_cli::testing::build_test_artifacts;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{chain_event::Event as ChainEventEnum, SubscribeEventsRequest};
use ioi_services::agentic::desktop::{DesktopAgentService, StartAgentParams, StepAgentParams};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{ActionContext, ActionRequest, ContextSlice, KernelEvent};
use ioi_types::codec;
use ioi_types::error::VmError;
use serde_json::json;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;

// [FIX] Imports for valid PNG generation
use image::{ImageBuffer, ImageFormat, Rgba};
use std::io::Cursor;

// --- Mocks ---

#[derive(Clone)]
struct MockGuiDriver {
    // Inject the broadcast sender so the driver can emit events to the kernel bus
    event_sender: broadcast::Sender<KernelEvent>,
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
        Ok("<root/>".into())
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

    async fn inject_input(&self, event: InputEvent) -> Result<(), VmError> {
        // SIMULATE GHOST EVENT EMISSION
        // In the real IoiGuiDriver, this happens in the operator.
        // Here we mock it to verify the pipeline.
        let desc = format!("{:?}", event);
        let _ = self.event_sender.send(KernelEvent::GhostInput {
            device: "mock_gui".into(),
            description: desc,
        });
        Ok(())
    }
}

struct ClickerBrain;
#[async_trait]
impl InferenceRuntime for ClickerBrain {
    async fn execute_inference(
        &self,
        _: [u8; 32],
        _: &[u8],
        _: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        // Output a tool call that triggers the GUI driver
        let tool_call = json!({
            "name": "gui__click",
            "arguments": { "x": 100, "y": 200, "button": "left" }
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
async fn test_ghost_mode_event_pipeline() -> Result<()> {
    // 1. Setup Environment
    build_test_artifacts();

    // The shared event bus for the Kernel
    let (event_tx, mut event_rx) = broadcast::channel(100);

    // Setup Service with Mock Driver connected to the event bus
    let gui = Arc::new(MockGuiDriver {
        event_sender: event_tx.clone(),
    });
    let brain = Arc::new(ClickerBrain);

    let mut service = DesktopAgentService::new_hybrid(gui, brain.clone(), brain.clone());
    // Important: The service itself doesn't emit the GhostInput, the DRIVER does.
    // But the service emits AgentStep. We will check for both.
    service = service.with_event_sender(event_tx.clone());

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
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

    // 2. Start Agent (Initialize State)
    let start_params = StartAgentParams {
        session_id,
        goal: "Click something".into(),
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

    // 3. Step Agent (Triggers Brain -> Output "gui__click" -> Service Calls Driver -> Driver Emits GhostEvent)
    let step_params = StepAgentParams { session_id };
    service
        .handle_service_call(
            &mut state,
            "step@v1",
            &codec::to_bytes_canonical(&step_params).unwrap(),
            &mut ctx,
        )
        .await?;

    // 4. Verify Events in Bus
    // We expect:
    // 1. AgentStep (emitted by service)
    // 2. GhostInput (emitted by driver)

    let mut found_ghost = false;
    let mut found_step = false;

    // Drain channel
    while let Ok(event) = event_rx.try_recv() {
        match event {
            KernelEvent::GhostInput {
                device,
                description,
            } => {
                println!("Got GhostInput: {} - {}", device, description);
                if description.contains("Click") && description.contains("100") {
                    found_ghost = true;
                }
            }
            KernelEvent::AgentStep(trace) => {
                println!("Got AgentStep: Step {}", trace.step_index);
                if trace.raw_output.contains("gui__click") {
                    found_step = true;
                }
            }
            _ => {}
        }
    }

    assert!(found_step, "AgentStep event missing from bus");
    assert!(found_ghost, "GhostInput event missing from bus");

    println!("✅ Ghost Mode Event Pipeline Verified");
    Ok(())
}
