// Path: crates/cli/tests/agent_mcp_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
// [NEW] Import OsDriver trait
use ioi_api::vm::drivers::os::OsDriver;

use ioi_cli::testing::build_test_artifacts;
use ioi_services::agentic::desktop::{StartAgentParams, StepAgentParams};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::codec;
use ioi_types::error::VmError;
use serde_json::json;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

use image::{ImageBuffer, ImageFormat, Rgba};
use std::io::Cursor;

use ioi_drivers::mcp::{McpManager, McpServerConfig};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::transaction::context::TxContext;

// [NEW] Imports for Policy Injection
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy, Rule, Verdict};

// Mock GUI Driver (Minimal)
#[derive(Clone)]
struct MockGuiDriver;
#[async_trait]
impl GuiDriver for MockGuiDriver {
    async fn capture_screen(&self) -> Result<Vec<u8>, VmError> { 
        let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));

        let mut bytes: Vec<u8> = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .map_err(|e| VmError::HostError(format!("Mock PNG encoding failed: {}", e)))?;

        Ok(bytes)
    }

    async fn capture_tree(&self) -> Result<String, VmError> { Ok("".into()) }
    async fn capture_context(&self, _: &ActionRequest) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [0; 32], frame_id: 0, chunks: vec![], mhnsw_root: [0; 32], traversal_proof: None, intent_id: [0; 32],
        })
    }
    async fn inject_input(&self, _: InputEvent) -> Result<(), VmError> { Ok(()) }
}

// [NEW] Mock OS Driver
struct MockOsDriver;
#[async_trait]
impl OsDriver for MockOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(Some("Terminal".to_string()))
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
    async fn load_model(&self, _: [u8; 32], _: &Path) -> Result<(), VmError> { Ok(()) }
    async fn unload_model(&self, _: [u8; 32]) -> Result<(), VmError> { Ok(()) }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_agent_mcp_integration() -> Result<()> {
    build_test_artifacts();

    let script_content = r#"
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });

rl.on('line', (line) => {
    const req = JSON.parse(line);
    if (req.method === 'initialize') {
        console.log(JSON.stringify({ jsonrpc: "2.0", id: req.id, result: { protocolVersion: "2024-11-05", capabilities: {}, serverInfo: { name: "echo", version: "1.0" } } }));
    } else if (req.method === 'tools/list') {
        console.log(JSON.stringify({ jsonrpc: "2.0", id: req.id, result: { tools: [{ name: "echo", description: "Echoes back", inputSchema: { type: "object", properties: { message: { type: "string" } } } }] } }));
    } else if (req.method === 'tools/call') {
        const msg = req.params.arguments.message;
        console.log(JSON.stringify({ jsonrpc: "2.0", id: req.id, result: { content: [{ type: "text", text: `Echo: ${msg}` }] } }));
    }
});
"#;
    
    let temp_dir = tempfile::tempdir()?;
    let script_path = temp_dir.path().join("mcp_echo.js");
    std::fs::write(&script_path, script_content)?;

    let mcp_manager = Arc::new(McpManager::new());
    
    let config = McpServerConfig {
        command: "node".to_string(),
        args: vec![script_path.to_string_lossy().to_string()],
        env: HashMap::new(),
    };

    mcp_manager.start_server("echo_server", config).await?;

    use ioi_services::agentic::desktop::DesktopAgentService;
    let gui = Arc::new(MockGuiDriver);
    let brain = Arc::new(McpBrain);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    // [NEW] Instantiate OS Driver
    let os_driver = Arc::new(MockOsDriver);

    let service = DesktopAgentService::new_hybrid(
        gui,
        terminal,
        browser, 
        brain.clone(),
        brain.clone()
    )
    .with_mcp_manager(mcp_manager)
    .with_os_driver(os_driver);

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

    // [NEW] Inject a permissive policy for this session
    let policy_key = [b"agent::policy::", session_id.as_slice()].concat();
    let policy = ActionRules {
        policy_id: "mcp-test-policy".to_string(),
        defaults: DefaultPolicy::DenyAll,
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
            }
        ],
    };
    state.insert(&policy_key, &codec::to_bytes_canonical(&policy).unwrap()).unwrap();

    let start_params = StartAgentParams {
        session_id,
        goal: "Test MCP".into(),
        max_steps: 5,
        parent_session_id: None,
        initial_budget: 1000,
    };
    service.handle_service_call(&mut state, "start@v1", &codec::to_bytes_canonical(&start_params).unwrap(), &mut ctx).await?;

    let step_params = StepAgentParams { session_id };
    service.handle_service_call(&mut state, "step@v1", &codec::to_bytes_canonical(&step_params).unwrap(), &mut ctx).await?;

    use ioi_services::agentic::desktop::AgentState;
    let key = ioi_services::agentic::desktop::keys::get_state_key(&session_id);
    let bytes = state.get(&key).unwrap().unwrap();
    let agent_state: AgentState = codec::from_bytes_canonical(&bytes).unwrap();

    let found_echo = agent_state.history.iter().any(|h| h.contains("Echo: Hello MCP"));
    assert!(found_echo, "Agent history should contain MCP tool output. History: {:?}", agent_state.history);

    println!("✅ Agent MCP Integration E2E Passed");
    Ok(())
}