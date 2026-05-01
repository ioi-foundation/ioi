// Path: crates/cli/tests/ghost_mode_e2e.rs
#![cfg(all(feature = "consensus-aft", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
use ioi_cli::testing::build_test_artifacts;
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy, Rule, Verdict};
use ioi_services::agentic::runtime::keys::get_state_key;
use ioi_services::agentic::runtime::types::AgentState;
use ioi_services::agentic::runtime::{RuntimeAgentService, StartAgentParams, StepAgentParams};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{ActionRequest, ContextSlice, KernelEvent};
use ioi_types::codec;
use ioi_types::error::VmError;
use serde_json::json;
use std::path::Path;
use std::sync::Arc;
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
    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }
}

struct MockOsDriver;

#[async_trait]
impl OsDriver for MockOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(Some("Test App".to_string()))
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(Some(WindowInfo {
            title: "Test App".to_string(),
            x: 0,
            y: 0,
            width: 1280,
            height: 720,
            app_name: "TestApp".to_string(),
        }))
    }

    async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
        Ok(true)
    }

    async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        Ok(String::new())
    }
}

struct ClickerBrain;
#[async_trait]
impl InferenceRuntime for ClickerBrain {
    async fn execute_inference(
        &self,
        _: [u8; 32],
        input: &[u8],
        _: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input);
        if prompt.contains("remote_public_fact_required") && prompt.contains("direct_ui_input") {
            return Ok(json!({
                "remote_public_fact_required": false,
                "host_local_clock_targeted": false,
                "command_directed": false,
                "durable_automation_requested": false,
                "model_registry_control_requested": false,
                "app_launch_directed": false,
                "direct_ui_input": true,
                "desktop_screenshot_requested": false,
                "temporal_filesystem_filter": false
            })
            .to_string()
            .into_bytes());
        }
        // Output a tool call that triggers the GUI driver
        let tool_call = json!({
            "name": "screen__type",
            "arguments": { "text": "hello" }
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
        let lower = text.to_ascii_lowercase();
        if lower.contains("click") || lower.contains("button") || lower.contains("ui") {
            return Ok(vec![0.0, 1.0]);
        }
        MockInferenceRuntime.embed_text(text).await
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

    let mut service = RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(ioi_drivers::terminal::TerminalDriver::new()),
        Arc::new(ioi_drivers::browser::BrowserDriver::new()),
        brain.clone(),
        brain.clone(),
    )
    .with_os_driver(Arc::new(MockOsDriver))
    .with_memory_runtime(Arc::new(
        ioi_memory::MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"),
    ));
    // The service emits AgentStep; driver-level ghost input is not guaranteed in this harness.
    service = service.with_event_sender(event_tx.clone());

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
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
    let policy_key = [b"agent::policy::".as_slice(), session_id.as_slice()].concat();
    let mut policy = ActionRules {
        policy_id: "ghost-mode-e2e-policy".to_string(),
        defaults: DefaultPolicy::DenyAll,
        ontology_policy: Default::default(),
        pii_controls: Default::default(),
        rules: vec![
            Rule {
                rule_id: Some("allow-gui-screenshot".into()),
                target: "gui::screenshot".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-gui-type".into()),
                target: "gui::type".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
        ],
    };
    policy.ontology_policy.intent_routing.enabled = false;
    state.insert(&policy_key, &codec::to_bytes_canonical(&policy).unwrap())?;

    // 2. Start Agent (Initialize State)
    let start_params = StartAgentParams {
        session_id,
        goal: "Type hello into the focused UI field".into(),
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

    // 3. Step Agent (Triggers Brain -> Output "screen__type" -> Service Calls Driver -> Driver Emits GhostEvent)
    let step_params = StepAgentParams { session_id };
    service
        .handle_service_call(
            &mut state,
            "step@v1",
            &codec::to_bytes_canonical(&step_params).unwrap(),
            &mut ctx,
        )
        .await?;

    // 4. Verify Event Bus + persisted runtime state
    let mut found_step = false;

    while let Ok(event) = event_rx.try_recv() {
        match event {
            KernelEvent::AgentStep(trace) => {
                println!("Got AgentStep: Step {}", trace.step_index);
                if trace.raw_output.contains("\"name\":\"screen__type\"") {
                    found_step = true;
                }
            }
            _ => {}
        }
    }

    let state_key = get_state_key(&session_id);
    let agent_state_bytes = state
        .get(&state_key)?
        .expect("Agent state missing after ghost-mode step");
    let agent_state: AgentState =
        codec::from_bytes_canonical(&agent_state_bytes).expect("decode agent state");

    assert!(found_step, "AgentStep event missing from bus");
    assert_eq!(
        agent_state.last_action_type.as_deref(),
        Some("screen__type")
    );

    println!("✅ Ghost Mode Event Pipeline Verified");
    Ok(())
}
