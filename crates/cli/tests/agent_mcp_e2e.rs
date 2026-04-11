// Path: crates/cli/tests/agent_mcp_e2e.rs
#![cfg(all(feature = "consensus-aft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
// [NEW] Import OsDriver trait
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};

use ioi_cli::testing::build_test_artifacts;
use ioi_memory::MemoryRuntime;
use ioi_services::agentic::runtime::keys::get_state_key;
use ioi_services::agentic::runtime::types::AgentState;
use ioi_services::agentic::runtime::{StartAgentParams, StepAgentParams};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::{
    CapabilityId, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState, StepTrace,
};
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::codec;
use ioi_types::error::VmError;
use serde_json::json;
use std::path::Path;
use std::sync::Arc;

use image::{ImageBuffer, ImageFormat, Rgba};
use std::io::Cursor;

use ioi_api::services::access::ServiceDirectory;
use ioi_api::transaction::context::TxContext;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;

// [NEW] Imports for Policy Injection
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy, Rule, Verdict};

// Mock GUI Driver (Minimal)
#[derive(Clone)]
struct MockGuiDriver;
#[async_trait]
impl GuiDriver for MockGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
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

// [NEW] Mock OS Driver
struct MockOsDriver;
#[async_trait]
impl OsDriver for MockOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(Some("Terminal".to_string()))
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(Some(WindowInfo {
            title: "Terminal".to_string(),
            x: 0,
            y: 0,
            width: 1280,
            height: 720,
            app_name: "Terminal".to_string(),
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

// Mock Brain that calls the MCP tool
struct McpBrain;
#[async_trait]
impl InferenceRuntime for McpBrain {
    async fn execute_inference(
        &self,
        _: [u8; 32],
        _: &[u8],
        _: ioi_types::app::agentic::InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        // The agent decides to call the MCP tool
        let tool_call = json!({
            "name": "echo_server__echo", // Namespaced tool name
            "arguments": { "message": "Hello MCP" }
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
        if lower.contains("mcp")
            || lower.contains("tool")
            || lower.contains("echo")
            || lower.contains("call")
        {
            return Ok(vec![1.0, 0.0]);
        }
        MockInferenceRuntime.embed_text(text).await
    }
}

fn resolved_conversation_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "conversation.reply".to_string(),
        scope: IntentScopeProfile::Conversation,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("conversation.reply")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "test".to_string(),
        matrix_source_hash: [1u8; 32],
        receipt_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_agent_mcp_integration() -> Result<()> {
    build_test_artifacts();

    let mcp_manager = Arc::new(McpManager::new());

    use ioi_services::agentic::runtime::RuntimeAgentService;
    let gui = Arc::new(MockGuiDriver);
    let brain = Arc::new(McpBrain);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    // [NEW] Instantiate OS Driver
    let os_driver = Arc::new(MockOsDriver);

    let service =
        RuntimeAgentService::new_hybrid(gui, terminal, browser, brain.clone(), brain.clone())
            .with_mcp_manager(mcp_manager)
            .with_memory_runtime(Arc::new(
                MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"),
            ))
            .with_os_driver(os_driver);

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

    // [NEW] Inject a permissive policy for this session
    let policy_key = [b"agent::policy::", session_id.as_slice()].concat();
    let policy = ActionRules {
        policy_id: "mcp-test-policy".to_string(),
        defaults: DefaultPolicy::DenyAll,
        ontology_policy: Default::default(),
        pii_controls: Default::default(),
        rules: vec![
            Rule {
                rule_id: Some("allow-echo".into()),
                target: "echo_server__echo".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-gui".into()),
                target: "gui::screenshot".into(), // Implicitly required by step logic
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-click".into()),
                target: "gui::click".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
        ],
    };
    state
        .insert(&policy_key, &codec::to_bytes_canonical(&policy).unwrap())
        .unwrap();

    let start_params = StartAgentParams {
        session_id,
        goal: "Call the MCP echo tool".into(),
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

    let state_key = get_state_key(&session_id);
    let mut agent_state: AgentState = codec::from_bytes_canonical(
        &state
            .get(&state_key)?
            .expect("agent state missing after start"),
    )
    .expect("decode agent state");
    agent_state.resolved_intent = Some(resolved_conversation_intent());
    agent_state.awaiting_intent_clarification = false;
    state.insert(
        &state_key,
        &codec::to_bytes_canonical(&agent_state).unwrap(),
    )?;

    let step_params = StepAgentParams { session_id };
    service
        .handle_service_call(
            &mut state,
            "step@v1",
            &codec::to_bytes_canonical(&step_params).unwrap(),
            &mut ctx,
        )
        .await?;

    let trace_prefix = [b"agent::trace::".as_slice(), session_id.as_slice()].concat();
    let traces = state
        .prefix_scan(&trace_prefix)?
        .filter_map(|entry| entry.ok().map(|(_, bytes)| bytes))
        .filter_map(|bytes| codec::from_bytes_canonical::<StepTrace>(&bytes).ok())
        .collect::<Vec<_>>();
    let agent_state: AgentState = codec::from_bytes_canonical(
        &state
            .get(&state_key)?
            .expect("agent state missing after step"),
    )
    .expect("decode agent state");
    let found_mcp_tool_call = traces
        .iter()
        .any(|trace| trace.raw_output.contains("echo_server__echo"));
    assert!(
        found_mcp_tool_call,
        "Agent traces should contain the MCP tool call attempt. status={:?} step_count={} last_action_type={:?} traces={:?}",
        agent_state.status,
        agent_state.step_count,
        agent_state.last_action_type,
        traces,
    );

    println!("✅ Agent MCP Integration E2E Passed");
    Ok(())
}
