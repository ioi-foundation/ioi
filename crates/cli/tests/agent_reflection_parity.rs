use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_scs::{SovereignContextStore, StoreConfig};
use ioi_services::agentic::desktop::service::step::cognition::think;
use ioi_services::agentic::desktop::service::step::perception::PerceptionContext;
use ioi_services::agentic::desktop::types::{AgentState, AgentStatus, ExecutionTier};
use ioi_services::agentic::desktop::{AgentMode, DesktopAgentService};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;

#[derive(Clone, Default)]
struct NoOpGui;

#[async_trait]
impl GuiDriver for NoOpGui {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        Ok(vec![])
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        Ok(vec![])
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok(String::new())
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Err(VmError::HostError(
            "capture_context is unused in this test".to_string(),
        ))
    }

    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }
}

#[derive(Default)]
struct MockReflectionRuntime {
    prompts: Mutex<Vec<String>>,
}

#[async_trait]
impl InferenceRuntime for MockReflectionRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context).to_string();
        self.prompts
            .lock()
            .expect("prompt mutex should not be poisoned")
            .push(prompt.clone());

        if prompt.contains("Classify the required mode") {
            return Ok(br#"{"mode":"Visual"}"#.to_vec());
        }

        Ok(br#"{"name":"agent__pause","arguments":{"reason":"reflection-test"}}"#.to_vec())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

fn reflection_test_agent_state(session_id: [u8; 32]) -> AgentState {
    AgentState {
        session_id,
        goal: "fix bug".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 5,
        max_steps: 10,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 100,
        tokens_used: 0,
        consecutive_failures: 2,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_visual_hash: None,
        recent_actions: vec!["attempt::TargetNotFound::deadbeef".to_string()],
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: vec![],
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target: None,
        resolved_intent: None,

        awaiting_intent_clarification: false,

        working_directory: ".".to_string(),
        command_history: Default::default(),
        active_lens: None,
        pending_search_completion: None,
    }
}

#[tokio::test]
async fn cognition_injects_failure_analysis_block_on_error() {
    let temp_dir = tempdir().expect("tempdir should be created");
    let scs_path = temp_dir.path().join("reflection.scs");
    let scs = SovereignContextStore::create(
        &scs_path,
        StoreConfig {
            chain_id: 1,
            owner_id: [0u8; 32],
            identity_key: [0x11; 32],
        },
    )
    .expect("SCS store should be created");

    let runtime = Arc::new(MockReflectionRuntime::default());
    let service = DesktopAgentService::new_hybrid(
        Arc::new(NoOpGui),
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime.clone(),
        runtime.clone(),
    )
    .with_scs(Arc::new(Mutex::new(scs)));

    let session_id = [0x44; 32];
    let state = reflection_test_agent_state(session_id);
    let perception = PerceptionContext {
        tier: ExecutionTier::DomHeadless,
        screenshot_base64: None,
        visual_phash: [0u8; 32],
        active_window_title: "VSCode".to_string(),
        project_index: String::new(),
        agents_md_content: String::new(),
        memory_pointers: String::new(),
        available_tools: vec![],
        tool_desc: String::new(),
        visual_verification_note: None,
        last_failure_reason: Some(
            "TargetNotFound (fingerprint: attempt::TargetNotFound::deadbeef)".to_string(),
        ),
        consecutive_failures: 2,
    };

    let _ = think(&service, &state, &perception, session_id)
        .await
        .expect("cognition should succeed");

    let prompts = runtime
        .prompts
        .lock()
        .expect("prompt mutex should not be poisoned");

    let system_prompt = prompts
        .iter()
        .find(|p| {
            p.contains(
                "SYSTEM: You are a local desktop assistant operating inside the IOI runtime.",
            )
        })
        .expect("system prompt should be captured");

    assert!(system_prompt.contains("FAILURE ANALYSIS REQUIRED"));
    assert!(system_prompt.contains("Consecutive Failures: 2"));
    assert!(system_prompt.contains("TargetNotFound"));
    assert!(system_prompt.contains("attempt::TargetNotFound::deadbeef"));
}
