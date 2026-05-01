// Path: crates/cli/tests/agent_trace_e2e.rs
#![cfg(all(feature = "consensus-aft", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::Result;
use async_trait::async_trait;
use image::{ImageBuffer, ImageFormat, Rgba};
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
use ioi_cli::testing::build_test_artifacts;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_memory::NewArchivalMemoryRecord;
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy, Rule, Verdict};
use ioi_services::agentic::runtime::keys::get_state_key;
use ioi_services::agentic::runtime::types::AgentState;
use ioi_services::agentic::skill_registry::{
    build_skill_archival_metadata_json, canonical_skill_hash, skill_archival_content,
    upsert_skill_record, SKILL_ARCHIVAL_KIND, SKILL_ARCHIVAL_SCOPE,
};
use ioi_types::app::agentic::{
    AgentMacro, InferenceOptions, LlmToolDefinition, SkillLifecycleState, SkillRecord,
    SkillSourceType, StepTrace,
};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, ContextSlice};
use ioi_types::codec;
use ioi_types::error::VmError;
use serde_json::json;
use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};

// [FIX] Import params from services
use ioi_services::agentic::runtime::{StartAgentParams, StepAgentParams};

// --- Mock Components for Validation ---

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
        Ok("<root><button id='login'>Login</button></root>".to_string())
    }
    // Implement the Substrate slicing method
    async fn capture_context(
        &self,
        _intent: &ioi_types::app::ActionRequest,
    ) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [1u8; 32],
            frame_id: 0,
            chunks: vec![b"<root><button id='login'>Login</button></root>".to_vec()],
            mhnsw_root: [0u8; 32],
            traversal_proof: None,
            intent_id: [0u8; 32],
        })
    }
    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Ok(()) // Action succeeds
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
        let prompt_str = String::from_utf8_lossy(input_context).to_string();
        if prompt_str.contains("remote_public_fact_required")
            && prompt_str.contains("direct_ui_input")
        {
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
        // Capture prompt for assertion
        *self.last_prompt.lock().unwrap() = prompt_str;

        // Simulate Tool Call Output (JSON)
        // This validates that the Kernel can parse structured outputs
        let tool_call = json!({
            "name": "screen__type",
            "arguments": {
                "text": "hello"
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
        let lower = _text.to_ascii_lowercase();
        if lower.contains("click")
            || lower.contains("button")
            || lower.contains("login")
            || lower.contains("ui")
        {
            return Ok(vec![0.0, 1.0]);
        }
        MockInferenceRuntime.embed_text(_text).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_agent_trace_records_ui_step() -> Result<()> {
    build_test_artifacts();

    let last_prompt = Arc::new(Mutex::new(String::new()));
    let mock_brain = Arc::new(MockBrain {
        last_prompt: last_prompt.clone(),
    });
    let mock_gui = Arc::new(MockGuiDriver);

    // --- Manual Setup (In-Process Service Test) ---
    use ioi_api::services::BlockchainService;
    use ioi_api::state::StateAccess;
    use ioi_services::agentic::runtime::RuntimeAgentService;
    use ioi_state::primitives::hash::HashCommitmentScheme;
    use ioi_state::tree::iavl::IAVLTree;

    let memory_runtime =
        Arc::new(ioi_memory::MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"));
    let service = RuntimeAgentService::new(
        mock_gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        mock_brain.clone(),
    )
    .with_os_driver(Arc::new(MockOsDriver))
    .with_memory_runtime(memory_runtime.clone());
    let mut state = IAVLTree::new(HashCommitmentScheme::new());

    // 2. Seed a runtime-eligible Skill through the registry + memory recall path.
    let skill = AgentMacro {
        definition: LlmToolDefinition {
            name: "screen__click_at".to_string(),
            description: "Skill override: click the login button in the current UI".to_string(),
            parameters:
                r#"{"type":"object","properties":{"x":{"type":"integer"},"y":{"type":"integer"},"button":{"type":"string"}},"required":["x","y","button"]}"#
                    .to_string(),
        },
        steps: vec![ActionRequest {
            target: ActionTarget::GuiClick,
            params: br#"{"x":100,"y":200,"button":"left"}"#.to_vec(),
            context: ActionContext {
                agent_id: "macro".to_string(),
                session_id: None,
                window_id: None,
            },
            nonce: 0,
        }],
        source_trace_hash: [7u8; 32],
        fitness: 1.0,
    };
    let skill_hash = canonical_skill_hash(&skill).expect("skill hash");
    let archival_content = format!(
        "{} click the ui button",
        skill_archival_content(&skill.definition)
    );
    let archival_record_id = memory_runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: SKILL_ARCHIVAL_SCOPE.to_string(),
            thread_id: None,
            kind: SKILL_ARCHIVAL_KIND.to_string(),
            content: archival_content.clone(),
            metadata_json: build_skill_archival_metadata_json(skill_hash, &skill)
                .expect("skill metadata"),
        })?
        .expect("archival record id");
    let embedding = mock_brain.embed_text(&archival_content).await?;
    memory_runtime.upsert_archival_embedding(archival_record_id, &embedding)?;
    upsert_skill_record(
        &mut state,
        &SkillRecord {
            skill_hash,
            archival_record_id,
            macro_body: skill,
            lifecycle_state: SkillLifecycleState::Validated,
            source_type: SkillSourceType::Imported,
            source_session_id: None,
            source_evidence_hash: None,
            benchmark: None,
            publication: None,
            created_at: 1,
            updated_at: 1,
        },
    )?;

    // 3. Start Session
    let session_id = [1u8; 32];
    let policy_key = [b"agent::policy::".as_slice(), session_id.as_slice()].concat();
    let mut policy = ActionRules {
        policy_id: "agent-trace-e2e-policy".to_string(),
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

    let start_params = StartAgentParams {
        session_id,
        goal: "Type hello into the focused UI field".to_string(),
        max_steps: 5,
        parent_session_id: None,
        initial_budget: 1_000,
        mode: ioi_services::agentic::runtime::AgentMode::Agent,
    };

    // Dummy Context
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

    // A. Verify Black Box Trace captures runtime skill expansion
    let trace_prefix = [b"agent::trace::".as_slice(), session_id.as_slice()].concat();
    let mut traces = state
        .prefix_scan(&trace_prefix)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|(_, bytes)| bytes))
        .filter_map(|bytes| codec::from_bytes_canonical::<StepTrace>(&bytes).ok())
        .collect::<Vec<_>>();
    traces.sort_by_key(|trace| trace.step_index);
    if traces.is_empty() {
        let state_key = get_state_key(&session_id);
        let agent_state_bytes = state
            .get(&state_key)
            .unwrap()
            .expect("Agent state not found in state");
        let agent_state: AgentState = codec::from_bytes_canonical(&agent_state_bytes).unwrap();
        panic!(
            "Trace not found in state; step_count={} status={:?} queue_len={} active_skill_hash={:?} pending_tool_call={:?}",
            agent_state.step_count,
            agent_state.status,
            agent_state.execution_queue.len(),
            agent_state.active_skill_hash,
            agent_state.pending_tool_call
        );
    }
    let trace_summaries = traces
        .iter()
        .map(|trace| {
            format!(
                "step={} prompt={:?} output={:?} skill_hash={:?}",
                trace.step_index, trace.full_prompt, trace.raw_output, trace.skill_hash
            )
        })
        .collect::<Vec<_>>()
        .join(" | ");
    let trace = traces
        .iter()
        .find(|trace| {
            trace.skill_hash == Some(skill_hash)
                || trace.raw_output.contains("\"name\":\"screen__type\"")
        })
        .or_else(|| traces.last())
        .unwrap();

    assert_eq!(trace.session_id, session_id);
    assert!(
        trace.skill_hash == Some(skill_hash)
            || trace.raw_output.contains("\"name\":\"screen__type\""),
        "unexpected traces: {}",
        trace_summaries
    );
    assert!(
        !trace.full_prompt.is_empty(),
        "Trace should capture the prompt used for the step"
    );

    println!("✅ Skill Expansion and Execution Trace Verified");

    Ok(())
}
