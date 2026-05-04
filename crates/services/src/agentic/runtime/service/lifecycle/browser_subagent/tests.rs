use super::*;
use crate::agentic::runtime::keys::get_state_key;
use crate::agentic::runtime::service::lifecycle::worker_results::parse_child_session_id_hex;
use crate::agentic::runtime::utils::persist_agent_state;
use async_trait::async_trait;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_memory::MemoryRuntime;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::{AccountId, ChainId, ContextSlice};
use ioi_types::error::VmError;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;
use tempfile::tempdir;

#[derive(Clone)]
struct NoopGuiDriver;

#[async_trait]
impl GuiDriver for NoopGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        let mut img = image::ImageBuffer::<image::Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, image::Rgba([255, 0, 0, 255]));
        let mut bytes = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
            .map_err(|error| VmError::HostError(format!("mock PNG encode failed: {}", error)))?;
        Ok(bytes)
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        self.capture_screen(None).await
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok("<root/>".to_string())
    }

    async fn capture_context(
        &self,
        _intent: &ioi_types::app::ActionRequest,
    ) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [0u8; 32],
            frame_id: 0,
            chunks: vec![b"<root/>".to_vec()],
            mhnsw_root: [0u8; 32],
            traversal_proof: None,
            intent_id: [0u8; 32],
        })
    }

    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }

    async fn register_som_overlay(
        &self,
        _map: HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

fn build_parent_state(goal: &str) -> AgentState {
    AgentState {
        session_id: [0x91; 32],
        goal: goal.to_string(),
        runtime_route_frame: None,
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 8,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: Vec::new(),
        budget: 12,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: Vec::new(),
        mode: crate::agentic::runtime::types::AgentMode::Agent,
        current_tier: crate::agentic::runtime::types::ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: Vec::new(),
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: Default::default(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
        target: None,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: Default::default(),
        active_lens: None,
    }
}

fn build_test_service(
    event_sender: tokio::sync::broadcast::Sender<ioi_types::app::KernelEvent>,
) -> (RuntimeAgentService, tempfile::TempDir) {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let runtime = Arc::new(MockInferenceRuntime);
    let temp_dir = tempdir().expect("tempdir should open");
    let memory_path = temp_dir.path().join("browser-subagent.sqlite");
    let memory_runtime =
        Arc::new(MemoryRuntime::open_sqlite(&memory_path).expect("sqlite memory should open"));
    let service = RuntimeAgentService::new(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime,
    )
    .with_memory_runtime(memory_runtime)
    .with_event_sender(event_sender);
    (service, temp_dir)
}

fn test_call_context<'a>(services: &'a ServiceDirectory) -> ServiceCallContext<'a> {
    ServiceCallContext {
        block_height: 1,
        block_timestamp: 1,
        chain_id: ChainId(1),
        signer_account_id: AccountId([7u8; 32]),
        services,
        simulation: false,
        is_internal: false,
    }
}

fn persisted_child_state(
    session_id: [u8; 32],
    parent_session_id: [u8; 32],
    status: AgentStatus,
) -> AgentState {
    let mut state = build_parent_state("Collect the DOM evidence and return one report.");
    state.session_id = session_id;
    state.parent_session_id = Some(parent_session_id);
    state.status = status;
    state.goal = "Inspect the browser and summarize the result.".to_string();
    state
}

#[test]
fn browser_subagent_request_parser_accepts_media_and_reuse_fields() {
    let payload = serde_json::json!({
        "name": "browser__subagent",
        "arguments": {
            "task_name": "Capture docs snippet",
            "task_summary": "Open the docs and copy the auth section",
            "recording_name": "auth-docs-run",
            "task": "Visit the docs and return the auth example.",
            "reused_subagent_id": "abc123",
            "media_paths": [" screenshot.png ", "", "notes.txt"]
        }
    });

    let request = browser_subagent_request_from_dynamic(&payload)
        .expect("request should parse")
        .expect("request should match browser subagent");

    assert_eq!(request.task_name, "Capture docs snippet");
    assert_eq!(request.reused_subagent_id.as_deref(), Some("abc123"));
    assert_eq!(
        request.media_paths,
        vec!["screenshot.png".to_string(), "notes.txt".to_string()]
    );
}

#[test]
fn browser_subagent_request_parser_rejects_missing_task_summary() {
    let payload = serde_json::json!({
        "name": "browser__subagent",
        "arguments": {
            "task_name": "Capture docs snippet",
            "recording_name": "auth-docs-run",
            "task": "Visit the docs and return the auth example."
        }
    });

    let error = browser_subagent_request_from_dynamic(&payload)
        .expect_err("missing task_summary should fail");
    assert!(error.contains("requires a non-empty 'task_summary' field"));
}

#[test]
fn browser_subagent_goal_includes_media_paths_and_contract() {
    let request = BrowserSubagentRequest {
        task_name: "Capture docs snippet".to_string(),
        task_summary: "Open the docs and copy the auth section".to_string(),
        recording_name: "auth-docs-run".to_string(),
        task: "Visit the docs and return the auth example.".to_string(),
        reused_subagent_id: None,
        media_paths: vec!["/tmp/screenshot.png".to_string()],
    };

    let goal = build_browser_subagent_goal(&request);

    assert!(goal.contains("[MEDIA PATHS]"));
    assert!(goal.contains("- /tmp/screenshot.png"));
    assert!(goal.contains("[SUBAGENT CONTRACT]"));
    assert!(goal.contains("Return one final semantic report to the parent."));
}

#[tokio::test(flavor = "current_thread")]
async fn browser_subagent_reuse_path_returns_completed_child_report() {
    let (tx, _rx) = tokio::sync::broadcast::channel(8);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state("Validate the browser subagent handoff.");
    let child_session_id = [0x44; 32];
    let child_state = persisted_child_state(
        child_session_id,
        parent_state.session_id,
        AgentStatus::Completed(Some(
            "Observed state: auth section visible.\nGoal status: complete.".to_string(),
        )),
    );
    let child_key = get_state_key(&child_session_id);
    persist_agent_state(
        &mut state,
        &child_key,
        &child_state,
        service.memory_runtime.as_ref(),
    )
    .expect("child state should persist");

    let request = BrowserSubagentRequest {
        task_name: "Capture docs snippet".to_string(),
        task_summary: "Open the docs and copy the auth section".to_string(),
        recording_name: "auth-docs-run".to_string(),
        task: "Visit the docs and return the auth example.".to_string(),
        reused_subagent_id: Some(hex::encode(child_session_id)),
        media_paths: Vec::new(),
    };
    let services = ServiceDirectory::new(Vec::new());
    let outcome = run_browser_subagent(
        &service,
        &mut state,
        &mut parent_state,
        [0x51; 32],
        1,
        0,
        test_call_context(&services),
        &request,
    )
    .await
    .expect("browser subagent reuse should succeed");

    assert!(outcome.success);
    assert_eq!(outcome.status, "completed");
    assert_eq!(
        parse_child_session_id_hex(&outcome.child_session_id_hex)
            .expect("child session id should decode"),
        child_session_id
    );
    assert!(outcome
        .final_report
        .contains("Observed state: auth section visible."));
}

#[tokio::test(flavor = "current_thread")]
async fn browser_subagent_reuse_path_surfaces_paused_child_reason() {
    let (tx, _rx) = tokio::sync::broadcast::channel(8);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state("Validate the paused browser subagent handoff.");
    let child_session_id = [0x45; 32];
    let child_state = persisted_child_state(
        child_session_id,
        parent_state.session_id,
        AgentStatus::Paused("Approval required before logging in.".to_string()),
    );
    let child_key = get_state_key(&child_session_id);
    persist_agent_state(
        &mut state,
        &child_key,
        &child_state,
        service.memory_runtime.as_ref(),
    )
    .expect("child state should persist");

    let request = BrowserSubagentRequest {
        task_name: "Capture docs snippet".to_string(),
        task_summary: "Open the docs and copy the auth section".to_string(),
        recording_name: "auth-docs-run".to_string(),
        task: "Visit the docs and return the auth example.".to_string(),
        reused_subagent_id: Some(hex::encode(child_session_id)),
        media_paths: Vec::new(),
    };
    let services = ServiceDirectory::new(Vec::new());
    let outcome = run_browser_subagent(
        &service,
        &mut state,
        &mut parent_state,
        [0x52; 32],
        1,
        0,
        test_call_context(&services),
        &request,
    )
    .await
    .expect("paused browser subagent should still return control");

    assert!(!outcome.success);
    assert_eq!(outcome.status, "paused");
    assert!(outcome
        .final_report
        .contains("Approval required before logging in."));
    assert!(outcome
        .final_report
        .contains("Browser subagent paused and returned control to the parent"));
}

#[tokio::test(flavor = "current_thread")]
async fn browser_subagent_reuse_path_surfaces_failed_child_reason() {
    let (tx, _rx) = tokio::sync::broadcast::channel(8);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state("Validate the failed browser subagent handoff.");
    let child_session_id = [0x46; 32];
    let child_state = persisted_child_state(
        child_session_id,
        parent_state.session_id,
        AgentStatus::Failed("Selector lookup timed out after navigation.".to_string()),
    );
    let child_key = get_state_key(&child_session_id);
    persist_agent_state(
        &mut state,
        &child_key,
        &child_state,
        service.memory_runtime.as_ref(),
    )
    .expect("child state should persist");

    let request = BrowserSubagentRequest {
        task_name: "Capture docs snippet".to_string(),
        task_summary: "Open the docs and copy the auth section".to_string(),
        recording_name: "auth-docs-run".to_string(),
        task: "Visit the docs and return the auth example.".to_string(),
        reused_subagent_id: Some(hex::encode(child_session_id)),
        media_paths: Vec::new(),
    };
    let services = ServiceDirectory::new(Vec::new());
    let error = run_browser_subagent(
        &service,
        &mut state,
        &mut parent_state,
        [0x53; 32],
        1,
        0,
        test_call_context(&services),
        &request,
    )
    .await
    .expect_err("failed child sessions should surface as an error to the parent");

    assert!(error.contains("ERROR_CLASS=UnexpectedState"));
    assert!(error.contains("Selector lookup timed out after navigation."));
}
