// Path: crates/cli/tests/agent_hybrid_e2e.rs
#![cfg(all(feature = "consensus-aft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
use ioi_cli::testing::build_test_artifacts;
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy, Rule, Verdict};
use ioi_services::agentic::runtime::{StartAgentParams, StepAgentParams};
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

// [NEW] Imports
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;

// Mocks
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

// "Big Brain" - Only handles logic/planning, fails on clicks
struct ReasoningBrain {
    called: Arc<Mutex<bool>>,
}
#[async_trait]
impl InferenceRuntime for ReasoningBrain {
    async fn execute_inference(
        &self,
        _: [u8; 32],
        input: &[u8],
        _: ioi_types::app::agentic::InferenceOptions,
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
        *self.called.lock().unwrap() = true;
        // First step (planning) -> returns a click
        let tool_call = json!({
            "name": "screen",
            "arguments": { "action": "left_click", "coordinate": [10, 10] }
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

// "Fast Brain" - Handles execution loop
struct FastBrain {
    called: Arc<Mutex<bool>>,
}
#[async_trait]
impl InferenceRuntime for FastBrain {
    async fn execute_inference(
        &self,
        _: [u8; 32],
        _: &[u8],
        _: ioi_types::app::agentic::InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        *self.called.lock().unwrap() = true;
        // Fast loop response
        let tool_call = json!({
            "name": "screen",
            "arguments": { "action": "left_click", "coordinate": [20, 20] }
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
async fn test_hybrid_routing_logic() -> Result<()> {
    build_test_artifacts();

    let gui = Arc::new(MockGuiDriver);
    let reasoner_called = Arc::new(Mutex::new(false));
    let fast_called = Arc::new(Mutex::new(false));

    let reasoning = Arc::new(ReasoningBrain {
        called: reasoner_called.clone(),
    });
    let fast = Arc::new(FastBrain {
        called: fast_called.clone(),
    });

    use ioi_services::agentic::runtime::RuntimeAgentService;

    // [NEW] Instantiate drivers
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());

    let service = RuntimeAgentService::new_hybrid(gui, terminal, browser, fast, reasoning)
        .with_os_driver(Arc::new(MockOsDriver))
        .with_memory_runtime(Arc::new(
            ioi_memory::MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"),
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

    let session_id = [1u8; 32];
    let policy_key = [b"agent::policy::".as_slice(), session_id.as_slice()].concat();
    let policy = ActionRules {
        policy_id: "hybrid-routing-e2e-policy".to_string(),
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
                rule_id: Some("allow-gui-click".into()),
                target: "gui::click".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
        ],
    };
    state.insert(&policy_key, &codec::to_bytes_canonical(&policy).unwrap())?;

    let start_params = StartAgentParams {
        session_id,
        goal: "Click the UI button".into(),
        max_steps: 5,
        parent_session_id: None,
        initial_budget: 1000,
        mode: ioi_services::agentic::runtime::AgentMode::Agent,
    };
    let step_params = StepAgentParams { session_id };

    // 1. Start Session
    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params).unwrap(),
            &mut ctx,
        )
        .await?;

    // 2. Step 1: Initial Planning (Should use Reasoning)
    // Step count is 0.
    service
        .handle_service_call(
            &mut state,
            "step@v1",
            &codec::to_bytes_canonical(&step_params).unwrap(),
            &mut ctx,
        )
        .await?;
    assert!(
        *reasoner_called.lock().unwrap(),
        "Step 1 should use Reasoning model"
    );

    // Reset flags
    *reasoner_called.lock().unwrap() = false;

    // 3. Step 2: Visual UI work should remain on the reasoning path.
    // The fast model is intentionally not used for foreground UI actions.
    service
        .handle_service_call(
            &mut state,
            "step@v1",
            &codec::to_bytes_canonical(&step_params).unwrap(),
            &mut ctx,
        )
        .await?;

    assert!(
        !*fast_called.lock().unwrap(),
        "Visual foreground UI work should not use the fast model"
    );
    assert!(
        *reasoner_called.lock().unwrap(),
        "Step 2 should continue using the reasoning model for UI work"
    );

    println!("✅ Hybrid Routing E2E Passed: UI work stayed on the reasoning path.");
    Ok(())
}
